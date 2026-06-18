#!/usr/bin/env python3
"""
Verify crates/cipher-profile/tests/fixtures/cascade_cess_kat.json.

Dependencies:
  pip install blake3 cryptography

Layout (see crates/cipher-profile/src/cascade.rs):
- Inner layers use empty AAD; only the outermost layer receives the profile AAD.
- The committed outer ciphertext is the **outermost** AEAD output only (for the
  built-in two-layer profiles: Serpent EtM), not a concatenation of inner ChaCha
  || MAC || Serpent on the wire. Therefore the 32-byte inter-layer HMAC-BLAKE3
  does **not** appear at a fixed offset inside expected_ciphertext_hex; it sits at
  bytes [80:112) of the **intermediate** blob (ChaCha ciphertext || MAC) recorded
  in intermediate_before_outer_hex.

standard (0x0001): full ciphertext recomputed with HKDF-BLAKE3 + ChaCha20-Poly1305.

conservative / conservative-shamir / high-assurance: recomputes intermediate_before_outer_hex
from IKM and plaintext (inner ChaCha with empty AAD + inter-layer MAC). Verifies outer
blob length matches Serpent EtM framing; does not recompute Serpent.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

try:
    import blake3
except ImportError:
    blake3 = None  # type: ignore[misc, assignment]

HMAC_BLOCK = 64
INTER_LAYER_MAC_LEN = 32
POLY1305_LEN = 16
SERPENT_ETM_TAG_LEN = 32


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _fixture_path() -> Path:
    return (
        _repo_root()
        / "crates"
        / "cipher-profile"
        / "tests"
        / "fixtures"
        / "cascade_cess_kat.json"
    )


def _hex_u16_be(suite_id: int) -> str:
    return f"{suite_id:04x}"


def cess_inner_cascade_layer_key_info(suite_id: int, layer_index: int) -> bytes:
    return f"cess-inner-{_hex_u16_be(suite_id)}-l{layer_index}-key".encode()


def cess_inner_cascade_layer_nonce_info(suite_id: int, layer_index: int) -> bytes:
    return f"cess-inner-{_hex_u16_be(suite_id)}-l{layer_index}-nonce".encode()


def cess_blake3_integrity_info(suite_id: int) -> bytes:
    return f"cess-blake3-integrity-{_hex_u16_be(suite_id)}".encode()


def cess_blake3_integrity_gap_info(suite_id: int, after_layer_index: int) -> bytes:
    return f"cess-blake3-integrity-{_hex_u16_be(suite_id)}-gap-l{after_layer_index}".encode()


def normalize_hmac_key(key: bytes) -> bytearray:
    out = bytearray(HMAC_BLOCK)
    if len(key) > HMAC_BLOCK:
        h = blake3_hash(key)
        out[:32] = h
    else:
        out[: len(key)] = key
    return out


def blake3_hash(data: bytes) -> bytes:
    assert blake3 is not None
    return blake3.blake3(data).digest(length=32)


def hmac_blake3(key: bytes, data: bytes) -> bytes:
    k = normalize_hmac_key(key)
    ipad = bytes(x ^ 0x36 for x in k)
    opad = bytes(x ^ 0x5C for x in k)
    inner = blake3_hash(ipad + data)
    return blake3_hash(opad + inner)


def hkdf_blake3(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    if not salt:
        salt = bytes(32)
    prk = hmac_blake3(salt, ikm)
    okm = bytearray()
    t = b""
    counter = 1
    while len(okm) < length:
        block_input = t + info + bytes([counter])
        t = hmac_blake3(prk, block_input)
        okm.extend(t)
        counter = (counter + 1) & 0xFF
    return bytes(okm[:length])


def chacha_poly1305_seal(key32: bytes, nonce12: bytes, aad: bytes, plaintext: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    return ChaCha20Poly1305(key32).encrypt(nonce12, plaintext, aad)


def recompute_standard_ciphertext(ikm: bytes, aad: bytes, plaintext: bytes, suite_id: int) -> bytes:
    kinfo = cess_inner_cascade_layer_key_info(suite_id, 0)
    ninfo = cess_inner_cascade_layer_nonce_info(suite_id, 0)
    key_okm = hkdf_blake3(ikm, b"", kinfo, 32)
    nonce_okm = hkdf_blake3(ikm, b"", ninfo, 32)
    nonce12 = nonce_okm[:12]
    return chacha_poly1305_seal(key_okm, nonce12, aad, plaintext)


def recompute_intermediate_chacha_mac(
    ikm: bytes, plaintext: bytes, suite_id: int
) -> tuple[bytes, bytes, bytes]:
    """
    Inner ChaCha uses empty AAD (not the profile AAD). Returns
    (inner_chacha_ct, inter_mac, inner||mac).
    """
    kinfo = cess_inner_cascade_layer_key_info(suite_id, 0)
    ninfo = cess_inner_cascade_layer_nonce_info(suite_id, 0)
    key_okm = hkdf_blake3(ikm, b"", kinfo, 32)
    nonce_okm = hkdf_blake3(ikm, b"", ninfo, 32)
    nonce12 = nonce_okm[:12]
    inner_ct = chacha_poly1305_seal(key_okm, nonce12, b"", plaintext)
    gap_info = cess_blake3_integrity_gap_info(suite_id, 0)
    mac_key = hkdf_blake3(ikm, b"", gap_info, 32)
    mac_msg = cess_blake3_integrity_info(suite_id) + inner_ct
    mac = hmac_blake3(mac_key, mac_msg)
    return inner_ct, mac, inner_ct + mac


def expected_two_layer_outer_len(plaintext_len: int) -> int:
    inner = plaintext_len + POLY1305_LEN
    with_mac = inner + INTER_LAYER_MAC_LEN
    return with_mac + SERPENT_ETM_TAG_LEN


def verify_row(
    profile: str,
    suite_id: int,
    expected_outer: bytes,
    intermediate_hex: str | None,
    ikm: bytes,
    aad: bytes,
    plaintext: bytes,
) -> tuple[bool, list[str], list[str]]:
    ok = True
    independent: list[str] = []
    structural: list[str] = []

    if profile == "standard":
        if suite_id != 0x0001:
            ok = False
            structural.append(f"FAIL: suite_id expected 0x0001, got {suite_id:#06x}")
        try:
            got = recompute_standard_ciphertext(ikm, aad, plaintext, suite_id)
        except Exception as e:
            ok = False
            independent.append(f"FAIL: recomputation raised: {e}")
            return ok, independent, structural
        if got != expected_outer:
            ok = False
            independent.append(
                f"FAIL: full ciphertext mismatch (len {len(expected_outer)} vs {len(got)})"
            )
        else:
            independent.append(
                "OK: all outer bytes = HKDF-BLAKE3(ikm, salt=empty, info="
                f"{cess_inner_cascade_layer_key_info(suite_id, 0)!r} / "
                f"{cess_inner_cascade_layer_nonce_info(suite_id, 0)!r}) "
                "+ ChaCha20-Poly1305(AAD=fixture aad) per crates/cess/src/hkdf_blake3.rs"
            )
        return ok, independent, structural

    if profile in ("conservative", "conservative-shamir", "high-assurance"):
        elen = expected_two_layer_outer_len(len(plaintext))
        if len(expected_outer) != elen:
            ok = False
            structural.append(
                f"FAIL: outer Serpent blob length {len(expected_outer)} != {elen}"
            )
            return ok, independent, structural
        structural.append(
            f"OK: outer ciphertext length {elen} = Serpent EtM output over "
            f"({len(plaintext)}+{POLY1305_LEN}+{INTER_LAYER_MAC_LEN})-byte input "
            f"(inner ChaCha||inter MAC), i.e. {elen - SERPENT_ETM_TAG_LEN}+{SERPENT_ETM_TAG_LEN}"
        )
        structural.append(
            "NOTE: outer bytes are Serpent EtM only; ChaCha20-Poly1305 Poly1305 tag "
            f"({POLY1305_LEN} B) is inside the decrypted intermediate, not at a fixed offset here"
        )

        if not intermediate_hex:
            ok = False
            structural.append("FAIL: missing intermediate_before_outer_hex in fixture")
            return ok, independent, structural

        try:
            inner_ct, inter_mac, recomposed = recompute_intermediate_chacha_mac(
                ikm, plaintext, suite_id
            )
        except Exception as e:
            ok = False
            independent.append(f"FAIL: intermediate recompute: {e}")
            return ok, independent, structural

        committed_inter = bytes.fromhex(intermediate_hex.strip())
        if recomposed != committed_inter:
            ok = False
            independent.append(
                "FAIL: recomputed intermediate (inner ChaCha empty AAD + inter MAC) "
                "!= fixture intermediate_before_outer_hex"
            )
        else:
            independent.append(
                "OK: intermediate_before_outer_hex (112 B) = ChaCha20-Poly1305("
                f"HKDF info cess-inner-{suite_id:04x}-l0-{{key,nonce}}, AAD=b'') "
                f"|| HMAC-BLAKE3(HKDF info {cess_blake3_integrity_gap_info(suite_id, 0)!r}, "
                "msg=cess_blake3_integrity_info || inner_chacha_ct)"
            )
        independent.append(
            f"OK: within that intermediate, bytes [0:{len(inner_ct)}) are inner ciphertext; "
            f"bytes [{len(inner_ct)}:{len(inner_ct) + INTER_LAYER_MAC_LEN}) are inter-layer MAC"
        )

        structural.append(
            f"NOT independently verified: outer Serpent-256 EtM ({len(expected_outer)} B): "
            f"body [{0}:{len(expected_outer) - SERPENT_ETM_TAG_LEN}) and "
            f"HMAC-SHA256 tag [{len(expected_outer) - SERPENT_ETM_TAG_LEN}:] "
            f"({SERPENT_ETM_TAG_LEN} B per crates/vault/src/serpent_cipher.rs)"
        )
        return ok, independent, structural

    ok = False
    structural.append(f"FAIL: unknown profile {profile!r}")
    return ok, independent, structural


def _parse_suite_id(s: str | None) -> int:
    if not s:
        raise ValueError("missing suite_id")
    return int(s, 16)


def main() -> int:
    if blake3 is None:
        print("ERROR: pip install blake3", file=sys.stderr)
        return 1
    try:
        import cryptography  # noqa: F401
    except ImportError:
        print("ERROR: pip install cryptography", file=sys.stderr)
        return 1

    path = _fixture_path()
    if not path.is_file():
        print(f"ERROR: missing fixture {path}", file=sys.stderr)
        return 1
    doc = json.loads(path.read_text(encoding="utf-8"))
    ikm = bytes.fromhex(doc["ikm_hex"])
    aad = bytes.fromhex(doc["aad_hex"])
    plaintext = bytes.fromhex(doc["plaintext_hex"])

    print(f"Fixture: {path}")
    print(
        "HKDF-BLAKE3: empty salt -> 32 zero octets for extract (crates/cess/src/hkdf_blake3.rs). "
        "UTF-8 info strings: crates/cess/src/inner_info.rs."
    )
    print()

    any_fail = False
    for row in doc["vectors"]:
        profile = row["profile"]
        suite_id = _parse_suite_id(row.get("suite_id"))
        expected_outer = bytes.fromhex(row["expected_ciphertext_hex"])
        inter_hex = row.get("intermediate_before_outer_hex")
        inter_s = inter_hex if isinstance(inter_hex, str) else None
        ok, ind, st = verify_row(
            profile, suite_id, expected_outer, inter_s, ikm, aad, plaintext
        )
        if not ok:
            any_fail = True
        result = "PASS" if ok else "FAIL"
        print(f"profile: {profile}  suite_id: {row.get('suite_id')}  RESULT: {result}")
        print("  independently verified:")
        for line in ind:
            print(f"    - {line}")
        print("  structural / not independently verified:")
        for line in st:
            print(f"    - {line}")
        print()

    print(
        "Auditor note: for two-layer rows, 'externally verified' in this script means Python "
        "recomputed the intermediate blob and ChaCha/MAC sub-steps from the fixture inputs and "
        "CESS info labels; the Serpent outer layer is length-checked only. The full outer "
        "ciphertext remains locked by Rust integration tests (cascade_cess_kat.rs)."
    )
    return 1 if any_fail else 0


if __name__ == "__main__":
    sys.exit(main())
