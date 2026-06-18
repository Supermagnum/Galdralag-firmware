//! CESS v0.2 alignment helpers ([`spec/CESS-v0.2.md`](https://github.com/Supermagnum/CESS/blob/main/spec/CESS-v0.2.md)).
//!
//! This crate provides **HKDF-BLAKE3** (`derive_k_outer`, `hkdf_blake3`), **ChaCha20-Poly1305** outer
//! seal/open (`seal_mode_a_outer`, `open_mode_a_outer`), and **wire layout** for **Mode A** outer
//! plaintext **`suite_id` (16-bit BE) || `inner_blob`** (Section 6.6, Section 8.3). See
//! [`docs/CESS_CONFORMANCE.md`](../../docs/CESS_CONFORMANCE.md).
//!
//! **Conformance:** This crate alone does not establish CESS-CORE certification; see the
//! conformance document for the deviation register (AES/SHA-2 retained elsewhere in the workspace).

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

mod hkdf_blake3;
mod inner_info;
mod mode_a;
mod registry_ids;
mod wire;

#[cfg(test)]
mod spec_tests;

pub use hkdf_blake3::{derive_k_outer, hkdf_blake3, hmac_blake3};
pub use inner_info::{
    cess_blake3_integrity_gap_info, cess_blake3_integrity_info, cess_inner_cascade_etm64_info,
    cess_inner_cascade_layer_key_info, cess_inner_cascade_layer_nonce_info, CessInnerEtM64Cipher,
};
pub use mode_a::{open_mode_a_outer, seal_mode_a_outer, CessCryptoError};
pub use registry_ids::{is_listed_suite_id, LISTED_SUITE_ID_RANGES};
pub use wire::{
    assemble_mode_a_outer_plaintext, parse_mode_a_outer_plaintext, CessWireError, SuiteId,
};

/// UTF-8 `info` string for HKDF-BLAKE3 when deriving **`K_outer`** (CESS §6.6).
pub const CESS_OUTER_ENVELOPE_INFO_UTF8: &str = "cess-outer-envelope-v1";

/// Reserved `suite_id` value; outer plaintext carrying this value must be **rejected** (CESS §14.2).
pub const SUITE_ID_RESERVED: u16 = 0;

/// Wire byte for **BrainpoolP384r1** in the ephemeral session handshake (`SessionCurve` in
/// `ephemeral-session`). Mode A outer ECDH **must** use this curve only for the IKM feeding
/// `K_outer` (CESS §6.1.1).
pub const WIRE_CURVE_BRAINPOOL_P384: u8 = 0x02;

/// Canonical **`suite_id`** values from the CESS [**Cipher suite identifier lookup
/// table**](https://github.com/Supermagnum/CESS/blob/main/ALGORITHM-REGISTRY.md#cipher-suite-identifier-lookup-table).
/// Per CESS Section 8.5, the **lookup table** is **authoritative**; informative bit-field layouts in
/// the registry **must not** override a table row.
///
/// Built-in Galdralag profile names map to these rows so Mode A outer `suite_id` matches the registry.
pub mod registry {
    /// `0x0001` — default **CESS-CORE** inner profile: ChaCha20-Poly1305 (BrainpoolP384r1 classical KEM per table).
    pub const CESS_CORE_DEFAULT_CHACHA: u16 = 0x0001;
    /// `0x0003` — cascade ChaCha inner, Serpent outer (BrainpoolP384r1 classical KEM per table).
    pub const CASCADE_CHACHA_INNER_SERPENT_OUTER_P384: u16 = 0x0003;
    /// `0x0012` — cascade ChaCha inner, Serpent outer (BrainpoolP512r1 classical KEM per table).
    pub const CASCADE_CHACHA_INNER_SERPENT_OUTER_P512: u16 = 0x0012;
}

/// Map a **built-in** [`cipher-profile`](https://github.com/Supermagnum/Galdralag-firmware/tree/main/crates/cipher-profile)
/// name to the CESS registry **`suite_id`** for Mode A outer plaintext (`suite_id || inner_blob`).
/// Only IDs listed in the upstream lookup table are emitted; see registry for **unknown `suite_id`**
/// handling and **Ed25519**-signed rows (`0x0200`–…).
///
/// Custom profiles are not listed in the built-in map; host tools that wrap with Mode A require a
/// registry-backed or deployment-specific assignment.
pub fn suite_id_for_profile_name(name: &str) -> Option<u16> {
    match name {
        "standard" => Some(registry::CESS_CORE_DEFAULT_CHACHA),
        "conservative" | "conservative-shamir" => {
            Some(registry::CASCADE_CHACHA_INNER_SERPENT_OUTER_P384)
        }
        "high-assurance" => Some(registry::CASCADE_CHACHA_INNER_SERPENT_OUTER_P512),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_outer_plaintext() {
        let inner = [1u8, 2, 3, 4, 5];
        let packed = assemble_mode_a_outer_plaintext(0x0001, &inner).unwrap();
        let (id, blob) = parse_mode_a_outer_plaintext(&packed).unwrap();
        assert_eq!(id, 0x0001);
        assert_eq!(blob, inner.as_slice());
    }

    #[test]
    fn reserved_suite_rejected() {
        assert!(assemble_mode_a_outer_plaintext(SUITE_ID_RESERVED, &[0]).is_err());
    }

    #[test]
    fn builtin_profile_maps_to_registry_table() {
        for name in [
            "standard",
            "conservative",
            "conservative-shamir",
            "high-assurance",
        ] {
            let id = suite_id_for_profile_name(name).expect("builtin profile");
            assert!(
                is_listed_suite_id(id),
                "profile {name} maps to {id:#06x}, must be in ALGORITHM-REGISTRY lookup table"
            );
        }
        assert_eq!(
            suite_id_for_profile_name("standard"),
            Some(registry::CESS_CORE_DEFAULT_CHACHA)
        );
        assert_eq!(
            suite_id_for_profile_name("conservative"),
            Some(registry::CASCADE_CHACHA_INNER_SERPENT_OUTER_P384)
        );
        assert_eq!(
            suite_id_for_profile_name("conservative-shamir"),
            Some(registry::CASCADE_CHACHA_INNER_SERPENT_OUTER_P384)
        );
        assert_eq!(
            suite_id_for_profile_name("high-assurance"),
            Some(registry::CASCADE_CHACHA_INNER_SERPENT_OUTER_P512)
        );
    }

    #[test]
    fn registry_constants_match_listed_table() {
        assert!(is_listed_suite_id(registry::CESS_CORE_DEFAULT_CHACHA));
        assert!(is_listed_suite_id(registry::CASCADE_CHACHA_INNER_SERPENT_OUTER_P384));
        assert!(is_listed_suite_id(registry::CASCADE_CHACHA_INNER_SERPENT_OUTER_P512));
    }

    #[test]
    fn gaps_in_table_are_unlisted() {
        assert!(!is_listed_suite_id(0x0000));
        assert!(!is_listed_suite_id(0x0031));
        assert!(!is_listed_suite_id(0x0103));
        assert!(!is_listed_suite_id(0xFFFF));
    }
}
