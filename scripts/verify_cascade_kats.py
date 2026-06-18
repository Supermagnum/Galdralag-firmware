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
from IKM and plaintext (inner ChaCha with empty AAD + inter-layer MAC). Verifies the trailing
32-byte Serpent EtM tag: HMAC-SHA256(MAC key, aad || nonce_16 || body) per
crates/vault/src/serpent_cipher.rs, where MAC key is the trailing 32 bytes of HKDF-BLAKE3
expand-to-64 with info = cess_inner_cascade_etm64_info (outer layer index, '-serpent256' tail;
see crates/cess/src/inner_info.rs and encrypt_layer_cess for Serpent256 in cascade.rs).
Serpent-CTR keystream over the 112-byte body is not recomputed here.
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


def cess_inner_layer_index_suffix(layer_index: int) -> bytes:
    """Match crates/cess/src/inner_info.rs push_layer_index (decimal layer index)."""
    out = bytearray(b"-l")
    li = layer_index
    if li < 10:
        out.append(ord("0") + li)
    elif li < 100:
        out.append(ord("0") + li // 10)
        out.append(ord("0") + li % 10)
    else:
        out.append(ord("0") + li // 100)
        out.append(ord("0") + (li // 10) % 10)
        out.append(ord("0") + li % 10)
    return bytes(out)


def cess_inner_cascade_etm64_info_serpent256(suite_id: int, layer_index: int) -> bytes:
    """cess_inner_cascade_etm64_info(..., Serpent256) in crates/cess/src/inner_info.rs."""
    return (
        b"cess-inner-"
        + _hex_u16_be(suite_id).encode("ascii")
        + cess_inner_layer_index_suffix(layer_index)
        + b"-serpent256"
    )


def serpent_etm_hmac_sha256_tag(mac_key32: bytes, aad: bytes, nonce16: bytes, body: bytes) -> bytes:
    from cryptography.hazmat.primitives import hashes, hmac

    h = hmac.HMAC(mac_key32, hashes.SHA256())
    h.update(aad)
    h.update(nonce16)
    h.update(body)
    return h.finalize()


def outer_serpent_etm_mac_key_and_nonce(ikm: bytes, suite_id: int, outer_layer_index: int) -> tuple[bytes, bytes]:
    """
    Serpent outer layer: 64-byte HKDF-BLAKE3 OKM from cess_inner_cascade_etm64_info;
    SerpentKey::from_okm64 uses okm[0:32] cipher, okm[32:64] MAC (vault serpent_cipher.rs).
    Nonce: first 16 bytes of HKDF-BLAKE3(..., cess_inner_cascade_layer_nonce_info, 32).
    """
    etm = cess_inner_cascade_etm64_info_serpent256(suite_id, outer_layer_index)
    okm64 = hkdf_blake3(ikm, b"", etm, 64)
    mac_key = okm64[32:64]
    n_inf = cess_inner_cascade_layer_nonce_info(suite_id, outer_layer_index)
    n_okm = hkdf_blake3(ikm, b"", n_inf, 32)
    nonce16 = n_okm[:16]
    return mac_key, nonce16


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

        outer_layer_idx = 1
        body = expected_outer[: len(expected_outer) - SERPENT_ETM_TAG_LEN]
        tag_commit = expected_outer[len(expected_outer) - SERPENT_ETM_TAG_LEN :]
        try:
            mac_key, nonce16 = outer_serpent_etm_mac_key_and_nonce(ikm, suite_id, outer_layer_idx)
            tag_calc = serpent_etm_hmac_sha256_tag(mac_key, aad, nonce16, body)
        except Exception as e:
            ok = False
            independent.append(f"FAIL: outer Serpent EtM HMAC recompute raised: {e}")
            return ok, independent, structural
        if tag_calc != tag_commit:
            ok = False
            independent.append(
                "FAIL: outer Serpent EtM HMAC-SHA256 tag mismatch "
                f"(expected {tag_commit.hex()}, got {tag_calc.hex()})"
            )
        else:
            etm_inf = cess_inner_cascade_etm64_info_serpent256(suite_id, outer_layer_idx)
            independent.append(
                "OK: Outer HMAC-SHA256 tag: independently verified "
                f"(HMAC-SHA256(key=okm64[32:64], msg=aad||nonce16||body); "
                f"okm64=HKDF-BLAKE3(ikm, info={etm_inf!r}); "
                f"nonce16=HKDF-BLAKE3(ikm, info={cess_inner_cascade_layer_nonce_info(suite_id, outer_layer_idx)!r})[:16]; "
                "cryptography.hazmat.primitives.hmac; matches crates/vault/src/serpent_cipher.rs compute_tag)"
            )

        structural.append(
            "NOT independently verified: Serpent-256 CTR keystream over the 112-byte body "
            "(body bytes match fixture only implicitly via HMAC binding)"
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
        "Auditor note: for two-layer rows, this script independently recomputes "
        "intermediate_before_outer_hex (inner ChaCha + inter-layer HMAC-BLAKE3), verifies the "
        "outer 32-byte Serpent EtM tag as HMAC-SHA256 over aad||nonce||body with MAC key and "
        "nonce derived like cipher-profile (HKDF-BLAKE3 info from cess inner_info + vault EtM), "
        "and does not re-run Serpent-CTR. Full outer bytes remain cross-checked by Rust "
        "(cascade_cess_kat.rs). These checks are not duplicated in the upstream CESS cess_runner "
        "(see docs/CESS_CONFORMANCE.md gap section)."
    )
    return 1 if any_fail else 0


if __name__ == "__main__":
    sys.exit(main())
