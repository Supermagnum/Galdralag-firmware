//! Conformance tests for what this crate implements: **outer** ChaCha20-Poly1305 over plaintext
//! `suite_id_be || inner_blob` (CESS Section 6.6, Section 8.3): `nonce (12) || ciphertext ||
//! Poly1305 tag`, empty AAD.
//!
//! **Informative layout arithmetic:** Tests below use **inner_overhead** values (**18 / 50 / 82 /
//! 114**) that match the **classical** inner profile shapes (suite id, optional Ed25519, optional
//! keyed BLAKE3 tag, bulk, inner Poly1305). The CESS spec does **not** define a normative **single
//! buffer** total such as **131 / 163 / …** bytes for a full message; uncompressed P384 points are
//! often **97** octets in SEC1, but that is not a fixed on-wire packaging table in **`spec/CESS-v0.2.md`**.
//! The test `spec_gap_full_wire_includes_97_byte_pubkey_prefix` compares **hypothetical** packaging
//! (97 + 16 + outer ciphertext + tag versus this crate’s **28** + outer plaintext + tag) for intuition only.
//!
//! **Remote indistinguishability:** CESS normatively aligns **outer** tag failure, **Ed25519**
//! failure, and **unknown** **`suite_id`** (registry + Section 8.5). This crate still exposes
//! [`crate::CessCryptoError`] vs [`crate::CessWireError`]; a unified caller-facing error belongs in
//! an integrating layer.
//!
//! **Primitive KATs** for Serpent, Twofish, cascades, ECDH, Ed25519, keyed BLAKE3, and full matrix
//! coverage are in the **CESS** repo (`vectors/`, `runner/`). This module only includes an RFC
//! 8439 ChaCha20-Poly1305 vector for the **same AEAD** dependency used in [`crate::seal_mode_a_outer`].

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use crate::{
    assemble_mode_a_outer_plaintext, is_listed_suite_id, open_mode_a_outer, parse_mode_a_outer_plaintext,
    seal_mode_a_outer, CessCryptoError, CessWireError,
};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

/// Spec Section 2: ephemeral P384 pubkey (97) + outer Poly1305 tag (16).
const SPEC_OUTER_WRAPPER_OVERHEAD: usize = 113;
/// This crate: ChaCha nonce + Poly1305 tag (RFC 8439 AEAD over outer plaintext).
const CESS_OUTER_AEAD_OVERHEAD: usize = 12 + 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ClassicalProfile {
    /// Inner overhead 18; total spec overhead 131 (113 + 18).
    UnsignedNoBlake3,
    /// Inner overhead 50; total spec overhead 163.
    UnsignedBlake3,
    /// Inner overhead 82; total spec overhead 195.
    SignedNoBlake3,
    /// Inner overhead 114; total spec overhead 227.
    SignedBlake3,
}

impl ClassicalProfile {
    fn inner_overhead(self) -> usize {
        match self {
            ClassicalProfile::UnsignedNoBlake3 => 18,
            ClassicalProfile::UnsignedBlake3 => 50,
            ClassicalProfile::SignedNoBlake3 => 82,
            ClassicalProfile::SignedBlake3 => 114,
        }
    }

    fn total_spec_overhead(self) -> usize {
        SPEC_OUTER_WRAPPER_OVERHEAD + self.inner_overhead()
    }
}

/// Maps a **classical** registry `suite_id` (Section 3 tables) to its inner profile.
/// PQ KEM rows from the lookup table (CESS spec: tested separately).
fn is_pq_listed_suite_id(suite_id: u16) -> bool {
    matches!(
        suite_id,
        0x0100..=0x0102 | 0x0110..=0x0112 | 0x0120..=0x0122
    )
}

/// Returns `None` for PQ rows and for IDs not covered by the classical tables.
fn classical_spec_profile(suite_id: u16) -> Option<ClassicalProfile> {
    match suite_id {
        0x0001..=0x0007 => Some(ClassicalProfile::UnsignedNoBlake3),
        0x0010 | 0x0011 | 0x0012 | 0x0021 | 0x0025 | 0x0029 | 0x002d => {
            Some(ClassicalProfile::UnsignedNoBlake3)
        }
        0x0008 | 0x000a | 0x000c | 0x000e | 0x000f | 0x0014 | 0x0016 | 0x0019 | 0x001c | 0x001f
        | 0x0023 | 0x0027 | 0x002b | 0x002f => Some(ClassicalProfile::UnsignedBlake3),
        0x0200..=0x0206 | 0x0018 | 0x001b | 0x001e | 0x0022 | 0x0026 | 0x002a | 0x002e => {
            Some(ClassicalProfile::SignedNoBlake3)
        }
        0x0009 | 0x000b | 0x000d | 0x0013 | 0x0015 | 0x0017 | 0x001a | 0x001d | 0x0020 | 0x0024
        | 0x0028 | 0x002c | 0x0030 | 0x0207 => Some(ClassicalProfile::SignedBlake3),
        _ => None,
    }
}

/// Outer plaintext length for bulk plaintext length `n` (bytes of inner AEAD payload).
fn outer_plaintext_len(n: usize, profile: ClassicalProfile) -> usize {
    n + profile.inner_overhead()
}

/// Wire length produced by this crate: `nonce || ct || tag` over outer plaintext.
fn cess_mode_a_wire_len(n: usize, profile: ClassicalProfile) -> usize {
    CESS_OUTER_AEAD_OVERHEAD + outer_plaintext_len(n, profile)
}

/// Builds a synthetic `inner_blob` for length and offset tests (zeros for non-bulk fields).
fn synthetic_inner_blob(n: usize, profile: ClassicalProfile) -> Vec<u8> {
    let mut v = Vec::new();
    match profile {
        ClassicalProfile::UnsignedNoBlake3 => {
            v.extend_from_slice(&vec![0u8; n]);
            v.extend_from_slice(&[0u8; 16]);
        }
        ClassicalProfile::UnsignedBlake3 => {
            v.extend_from_slice(&[0u8; 32]);
            v.extend_from_slice(&vec![0u8; n]);
            v.extend_from_slice(&[0u8; 16]);
        }
        ClassicalProfile::SignedNoBlake3 => {
            v.extend_from_slice(&[0u8; 64]);
            v.extend_from_slice(&vec![0u8; n]);
            v.extend_from_slice(&[0u8; 16]);
        }
        ClassicalProfile::SignedBlake3 => {
            v.extend_from_slice(&[0u8; 64]);
            v.extend_from_slice(&[0u8; 32]);
            v.extend_from_slice(&vec![0u8; n]);
            v.extend_from_slice(&[0u8; 16]);
        }
    }
    v
}

#[test]
fn every_listed_non_pq_suite_id_has_classical_spec_profile() {
    for &(low, high) in crate::LISTED_SUITE_ID_RANGES {
        for suite_id in low..=high {
            if is_pq_listed_suite_id(suite_id) {
                assert!(
                    classical_spec_profile(suite_id).is_none(),
                    "PQ suite_id {suite_id:#06x} must not map to classical Section 3 profile"
                );
                continue;
            }
            assert!(
                classical_spec_profile(suite_id).is_some(),
                "listed suite_id {suite_id:#06x} missing classical_spec_profile mapping; update spec_tests"
            );
        }
    }
}

#[test]
fn spec_section_3_overhead_totals_match_tables() {
    for p in [
        ClassicalProfile::UnsignedNoBlake3,
        ClassicalProfile::UnsignedBlake3,
        ClassicalProfile::SignedNoBlake3,
        ClassicalProfile::SignedBlake3,
    ] {
        assert_eq!(p.total_spec_overhead(), SPEC_OUTER_WRAPPER_OVERHEAD + p.inner_overhead());
    }
    assert_eq!(ClassicalProfile::UnsignedNoBlake3.total_spec_overhead(), 131);
    assert_eq!(ClassicalProfile::UnsignedBlake3.total_spec_overhead(), 163);
    assert_eq!(ClassicalProfile::SignedNoBlake3.total_spec_overhead(), 195);
    assert_eq!(ClassicalProfile::SignedBlake3.total_spec_overhead(), 227);
}

#[test]
fn cess_wire_len_is_n_plus_inner_overhead_plus_28() {
    let n = 64usize;
    for p in [
        ClassicalProfile::UnsignedNoBlake3,
        ClassicalProfile::UnsignedBlake3,
        ClassicalProfile::SignedNoBlake3,
        ClassicalProfile::SignedBlake3,
    ] {
        assert_eq!(cess_mode_a_wire_len(n, p), 28 + n + p.inner_overhead());
    }
}

#[test]
fn length_vectors_n0_and_n64_all_classical_suite_ids() {
    let k_outer = [0x5au8; 32];
    let nonce = [0x3cu8; 12];
    for &(low, high) in crate::LISTED_SUITE_ID_RANGES {
        for suite_id in low..=high {
            let Some(profile) = classical_spec_profile(suite_id) else {
                continue;
            };
            for n in [0usize, 64usize] {
                let inner = synthetic_inner_blob(n, profile);
                let plain = assemble_mode_a_outer_plaintext(suite_id, &inner).unwrap();
                assert_eq!(plain.len(), outer_plaintext_len(n, profile));
                let wire = seal_mode_a_outer(&k_outer, &nonce, &plain).unwrap();
                assert_eq!(wire.len(), cess_mode_a_wire_len(n, profile));
                let back = open_mode_a_outer(&k_outer, &wire).unwrap();
                assert_eq!(back, plain);
            }
        }
    }
}

#[test]
fn cascade_extra_length_n1_unsigned_no_blake3() {
    let suite_id = 0x0003u16;
    let profile = ClassicalProfile::UnsignedNoBlake3;
    let n = 1usize;
    let k_outer = [7u8; 32];
    let nonce = [9u8; 12];
    let inner = synthetic_inner_blob(n, profile);
    let plain = assemble_mode_a_outer_plaintext(suite_id, &inner).unwrap();
    let wire = seal_mode_a_outer(&k_outer, &nonce, &plain).unwrap();
    assert_eq!(wire.len(), cess_mode_a_wire_len(n, profile));
    assert_eq!(open_mode_a_outer(&k_outer, &wire).unwrap(), plain);
}

#[test]
fn field_offsets_unsigned_no_blake3_section_7() {
    let suite_id = 0x0001u16;
    let n = 11usize;
    let profile = ClassicalProfile::UnsignedNoBlake3;
    let inner = synthetic_inner_blob(n, profile);
    let plain = assemble_mode_a_outer_plaintext(suite_id, &inner).unwrap();
    assert_eq!(&plain[0..2], &[0x00, 0x01]);
    assert_eq!(&plain[2..2 + n], &inner[..n]);
    assert_eq!(&plain[2 + n..], &inner[n..]);
    assert_eq!(plain.len(), 2 + n + 16);
}

#[test]
fn field_offsets_unsigned_blake3_section_7() {
    let suite_id = 0x0008u16;
    let n = 5usize;
    let profile = ClassicalProfile::UnsignedBlake3;
    let inner = synthetic_inner_blob(n, profile);
    let plain = assemble_mode_a_outer_plaintext(suite_id, &inner).unwrap();
    assert_eq!(&plain[0..2], &[0x00, 0x08]);
    assert_eq!(&plain[2..34], &inner[0..32]);
    assert_eq!(&plain[34..34 + n], &inner[32..32 + n]);
    assert_eq!(&plain[34 + n..], &inner[32 + n..]);
}

#[test]
fn field_offsets_signed_no_blake3_section_7() {
    let suite_id = 0x0200u16;
    let n = 7usize;
    let profile = ClassicalProfile::SignedNoBlake3;
    let inner = synthetic_inner_blob(n, profile);
    let plain = assemble_mode_a_outer_plaintext(suite_id, &inner).unwrap();
    assert_eq!(&plain[0..2], &[0x02, 0x00]);
    assert_eq!(&plain[2..66], &inner[0..64]);
    assert_eq!(&plain[66..66 + n], &inner[64..64 + n]);
    assert_eq!(&plain[66 + n..], &inner[64 + n..]);
}

#[test]
fn field_offsets_signed_blake3_section_7() {
    let suite_id = 0x0009u16;
    let n = 4usize;
    let profile = ClassicalProfile::SignedBlake3;
    let inner = synthetic_inner_blob(n, profile);
    let plain = assemble_mode_a_outer_plaintext(suite_id, &inner).unwrap();
    assert_eq!(&plain[0..2], &[0x00, 0x09]);
    assert_eq!(&plain[2..66], &inner[0..64]);
    assert_eq!(&plain[66..98], &inner[64..96]);
    assert_eq!(&plain[98..98 + n], &inner[96..96 + n]);
    assert_eq!(&plain[98 + n..], &inner[96 + n..]);
}

#[test]
fn seal_open_roundtrip_every_listed_suite_id() {
    let k_outer = [0x11u8; 32];
    let nonce = [0x22u8; 12];
    let inner = b"inner";
    for &(low, high) in crate::LISTED_SUITE_ID_RANGES {
        for suite_id in low..=high {
            if !is_listed_suite_id(suite_id) {
                continue;
            }
            let plain = assemble_mode_a_outer_plaintext(suite_id, inner).unwrap();
            let wire = seal_mode_a_outer(&k_outer, &nonce, &plain).unwrap();
            let back = open_mode_a_outer(&k_outer, &wire).unwrap();
            let (id, blob) = parse_mode_a_outer_plaintext(&back).unwrap();
            assert_eq!(id, suite_id);
            assert_eq!(blob, inner.as_slice());
        }
    }
}

#[test]
fn rfc8439_chacha20_poly1305_kat_empty_aad() {
    let key_bytes = hex::decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
    let nonce_bytes = hex::decode("070000004041424344454647").unwrap();
    let pt = hex::decode(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
         202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
    )
    .unwrap();
    let expected_ct = hex::decode(
        "9f7aeb5e05f846bd1deb85f03a8c04a1d1d19a2c1d1478c9c593ca9c499f1dba6ebfe91b88ab780c90f39824d6f67cc74535805d8a5c5b78589dbff42d852566d30306a99c3f066fd64b5d0622fb0fe5",
    )
    .unwrap();
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key_bytes.as_slice()));
    let got = cipher
        .encrypt(Nonce::from_slice(nonce_bytes.as_slice()), pt.as_slice())
        .unwrap();
    assert_eq!(got.as_slice(), expected_ct.as_slice());
    let back = cipher
        .decrypt(Nonce::from_slice(nonce_bytes.as_slice()), got.as_slice())
        .unwrap();
    assert_eq!(back, pt);
}

#[test]
fn tamper_outer_nonce_ciphertext_tag_all_yield_same_aead_error() {
    let k_outer = [0x55u8; 32];
    let nonce = [0x66u8; 12];
    let plain = assemble_mode_a_outer_plaintext(0x0001, b"x").unwrap();
    let wire = seal_mode_a_outer(&k_outer, &nonce, &plain).unwrap();
    let err_nonce = {
        let mut w = wire.clone();
        w[0] ^= 1;
        open_mode_a_outer(&k_outer, &w).unwrap_err()
    };
    let err_mid = {
        let mut w = wire.clone();
        w[20] ^= 1;
        open_mode_a_outer(&k_outer, &w).unwrap_err()
    };
    let err_tag = {
        let mut w = wire.clone();
        let last = w.len() - 1;
        w[last] ^= 1;
        open_mode_a_outer(&k_outer, &w).unwrap_err()
    };
    assert_eq!(err_nonce, CessCryptoError::AeadDecrypt);
    assert_eq!(err_mid, CessCryptoError::AeadDecrypt);
    assert_eq!(err_tag, CessCryptoError::AeadDecrypt);
}

#[test]
fn unlisted_suite_id_after_outer_decrypt_is_wire_error_not_aead_error() {
    let k_outer = [0x77u8; 32];
    let nonce = [0u8; 12];
    let forged_plain = [0x00u8, 0x31, b'p', b'q'];
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&k_outer));
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), forged_plain.as_slice())
        .unwrap();
    let mut wire = Vec::with_capacity(12 + ct.len());
    wire.extend_from_slice(&nonce);
    wire.extend_from_slice(&ct);
    let opened = open_mode_a_outer(&k_outer, &wire).unwrap();
    assert_eq!(opened, forged_plain.as_slice());
    let e = parse_mode_a_outer_plaintext(&opened).unwrap_err();
    assert_eq!(e, CessWireError::UnlistedSuiteId);
}

#[test]
fn spec_gap_full_wire_includes_97_byte_pubkey_prefix() {
    let n = 0usize;
    let p = ClassicalProfile::UnsignedNoBlake3;
    let spec_full = SPEC_OUTER_WRAPPER_OVERHEAD + n + p.inner_overhead();
    let cess_only = cess_mode_a_wire_len(n, p);
    assert_eq!(spec_full - cess_only, 113 - CESS_OUTER_AEAD_OVERHEAD);
}
