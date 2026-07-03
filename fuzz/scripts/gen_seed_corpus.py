#!/usr/bin/env python3
"""
Generate checked-in fuzz seed corpora under fuzz/seed_corpus/<target>/.

Run from anywhere:
  python3 fuzz/scripts/gen_seed_corpus.py

Or:
  python3 fuzz/scripts/gen_seed_corpus.py --repo-root /path/to/Galdralag-firmware

cargo-fuzz accepts an explicit corpus directory as the second argument (run from `fuzz/`):
  cargo fuzz run chacha_roundtrip seed_corpus/chacha_roundtrip/
"""

from __future__ import annotations

import argparse
import json
import shutil
import struct
from pathlib import Path


def repo_root_from_script() -> Path:
    return Path(__file__).resolve().parent.parent.parent


def write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def serialise_init_bp256r1() -> bytes:
    """Matches ephemeral_session::handshake::tests::sample_init (BP256r1)."""
    version = 0x01
    curve = 0x01
    epk = bytes(65)
    fp = bytes(64)
    sig = bytes(10)
    out = bytearray()
    out.append(version)
    out.append(curve)
    out.append(len(epk))
    out.extend(epk)
    out.append(len(fp))
    out.extend(fp)
    out.extend(struct.pack(">H", len(sig)))
    out.extend(sig)
    return bytes(out)


def serialise_resp_bp256r1() -> bytes:
    """Matches ephemeral_session::handshake::tests::sample_resp (BP256r1)."""
    version = 0x01
    curve = 0x01
    epk = bytes(65)
    fp = bytes(64)
    iepk = bytes(65)
    sig = bytes(10)
    out = bytearray()
    out.append(version)
    out.append(curve)
    out.append(len(epk))
    out.extend(epk)
    out.append(len(fp))
    out.extend(fp)
    out.append(len(iepk))
    out.extend(iepk)
    out.extend(struct.pack(">H", len(sig)))
    out.extend(sig)
    return bytes(out)


# Wire ids: cipher-profile/src/layer.rs
LAYER_AES = 0x01
LAYER_CHACHA = 0x02
LAYER_TWOFISH = 0x03
LAYER_SERPENT = 0x04

# ephemeral_session::SessionCurve
CURVE_BP256 = 0x01
CURVE_BP384 = 0x02


def profile_to_bytes(
    name: str,
    desc: str,
    curve: int,
    layers: list[int],
    shamir_k: int,
    shamir_n: int,
) -> bytes:
    nb = name.encode("utf-8")
    db = desc.encode("utf-8")
    if len(nb) > 64 or len(db) > 128:
        raise ValueError("name or description too long")
    if not (1 <= len(layers) <= 4):
        raise ValueError("layer count")
    out = bytearray()
    out.append(len(nb))
    out.extend(nb)
    out.append(len(db))
    out.extend(db)
    out.append(curve)
    out.append(len(layers))
    for wid in layers:
        out.append(wid)
    out.append(shamir_k)
    out.append(shamir_n)
    return bytes(out)


def builtin_profiles() -> dict[str, bytes]:
    """Must match crates/cipher-profile/src/registry.rs builtins."""
    return {
        "standard": profile_to_bytes(
            "standard",
            "Single ChaCha20-Poly1305; BP256r1 ECDHE",
            CURVE_BP256,
            [LAYER_CHACHA],
            0,
            0,
        ),
        "conservative": profile_to_bytes(
            "conservative",
            "Serpent then ChaCha; BP256r1",
            CURVE_BP256,
            [LAYER_SERPENT, LAYER_CHACHA],
            0,
            0,
        ),
        "conservative-shamir": profile_to_bytes(
            "conservative-shamir",
            "Same as conservative; Shamir 3-of-5",
            CURVE_BP256,
            [LAYER_SERPENT, LAYER_CHACHA],
            3,
            5,
        ),
    }


def layer_count_byte_index(profile_bytes: bytes) -> int:
    """Index of the layer-count byte in `CipherProfile::to_bytes` output."""
    i = 0
    nl = profile_bytes[i]
    i += 1 + nl
    dl = profile_bytes[i]
    i += 1 + dl
    return i + 1


def first_wycheproof_group_pkcs8(json_path: Path) -> bytes | None:
    """Wycheproof RSA JSON stores `privateKeyPkcs8` on each test group, not each test case."""
    with json_path.open(encoding="utf-8") as f:
        doc = json.load(f)
    for g in doc.get("testGroups", []):
        h = g.get("privateKeyPkcs8")
        if isinstance(h, str) and len(h) >= 32:
            return bytes.fromhex(h)
    return None


# brainpool384.rs test G_SEC1 (97 bytes)
G384_SEC1 = bytes(
    [
        0x04,
        0x1D,
        0x1C,
        0x64,
        0xF0,
        0x68,
        0xCF,
        0x45,
        0xFF,
        0xA2,
        0xA6,
        0x3A,
        0x81,
        0xB7,
        0xC1,
        0x3F,
        0x6B,
        0x88,
        0x47,
        0xA3,
        0xE7,
        0x7E,
        0xF1,
        0x4F,
        0xE3,
        0xDB,
        0x7F,
        0xCA,
        0xFE,
        0x0C,
        0xBD,
        0x10,
        0xE8,
        0xE8,
        0x26,
        0xE0,
        0x34,
        0x36,
        0xD6,
        0x46,
        0xAA,
        0xEF,
        0x87,
        0xB2,
        0xE2,
        0x47,
        0xD4,
        0xAF,
        0x1E,
        0x8A,
        0xBE,
        0x1D,
        0x75,
        0x20,
        0xF9,
        0xC2,
        0xA4,
        0x5C,
        0xB1,
        0xEB,
        0x8E,
        0x95,
        0xCF,
        0xD5,
        0x52,
        0x62,
        0xB7,
        0x0B,
        0x29,
        0xFE,
        0xEC,
        0x58,
        0x64,
        0xE1,
        0x9C,
        0x05,
        0x4F,
        0xF9,
        0x91,
        0x29,
        0x28,
        0x0E,
        0x46,
        0x46,
        0x21,
        0x77,
        0x91,
        0x81,
        0x11,
        0x42,
        0x82,
        0x03,
        0x41,
        0x26,
        0x3C,
        0x53,
        0x15,
    ]
)


def main() -> None:
    ap = argparse.ArgumentParser(description="Write fuzz/seed_corpus seed files.")
    ap.add_argument(
        "--repo-root",
        type=Path,
        default=None,
        help="Repository root (default: parent of fuzz/scripts)",
    )
    args = ap.parse_args()
    root = args.repo_root.resolve() if args.repo_root else repo_root_from_script()
    seed_root = root / "fuzz" / "seed_corpus"
    vault_data = root / "crates" / "vault" / "tests" / "data"

    init_full = serialise_init_bp256r1()
    resp_full = serialise_resp_bp256r1()

    hs = seed_root / "fuzz_ephemeral_handshake"
    write_bytes(hs / "init_valid.bin", init_full)
    write_bytes(hs / "resp_valid.bin", resp_full)
    write_bytes(hs / "init_trunc4.bin", init_full[:-4])
    write_bytes(hs / "resp_trunc8.bin", resp_full[:-8])
    write_bytes(hs / "init_bad_curve.bin", bytes([0x01, 0xFF]) + init_full[2:])
    write_bytes(hs / "init_bad_version.bin", bytes([0x02, 0x01]) + init_full[2:])

    # AEAD / shamir: length >= 8 (first 8 bytes seed)
    blob32 = bytes(range(32))
    blob64 = bytes((i * 7 + 13) & 0xFF for i in range(64))
    for name in ("chacha_roundtrip", "serpent_aead", "twofish_aead"):
        d = seed_root / name
        write_bytes(d / "seed_8.bin", bytes(range(8)))
        write_bytes(d / "seed_32.bin", blob32)
        write_bytes(d / "seed_64.bin", blob64)

    sham = seed_root / "shamir_split_recover"
    # At least 8 bytes: harness indexes data[0..8] for the TRNG seed.
    write_bytes(sham / "seed_8.bin", bytes(range(8)))
    write_bytes(sham / "seed_64.bin", blob64)

    prof = seed_root / "fuzz_cipher_profile"
    b = builtin_profiles()
    for key, raw in b.items():
        write_bytes(prof / f"profile_{key}.bin", raw)
    std = b["standard"]
    bad_layers = bytearray(std)
    bad_layers[layer_count_byte_index(std)] = 0
    write_bytes(prof / "profile_layer_count_zero.bin", bytes(bad_layers))
    bad255 = bytearray(std)
    bad255[layer_count_byte_index(std)] = 255
    write_bytes(prof / "profile_layer_count_255.bin", bytes(bad255))
    flip = bytearray(std)
    flip[len(flip) // 2] ^= 0x01
    write_bytes(prof / "profile_standard_flip_mid.bin", bytes(flip))

    rsa_targets = ("rsa_der_import", "rsa_oaep_decrypt", "rsa_pss_verify")
    for t in rsa_targets:
        d = seed_root / t
        d.mkdir(parents=True, exist_ok=True)
        for fname in ("rsa_2048_fuzz.pk8", "rsa_1024_priv.pk8"):
            src = vault_data / fname
            if src.is_file():
                shutil.copyfile(src, d / fname)
    wyche = vault_data / "wycheproof" / "rsa_pkcs1_2048_test.json"
    if wyche.is_file():
        pk8 = first_wycheproof_group_pkcs8(wyche)
        if pk8:
            for t in rsa_targets:
                write_bytes(seed_root / t / "wycheproof_tc_private_pkcs8.bin", pk8)

    write_bytes(seed_root / "brainpool384_ecdh" / "generator_sec1_uncompressed.bin", G384_SEC1)
    # Extra malformed / edge SEC1 blobs
    write_bytes(seed_root / "brainpool384_ecdh" / "truncated_generator.bin", G384_SEC1[:48])

    print(f"Wrote seed corpus under {seed_root}")


if __name__ == "__main__":
    main()
