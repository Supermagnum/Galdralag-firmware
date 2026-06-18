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
mod mode_a;
mod wire;

pub use hkdf_blake3::{derive_k_outer, hkdf_blake3, hmac_blake3};
pub use mode_a::{open_mode_a_outer, seal_mode_a_outer, CessCryptoError};
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

/// Provisional **16-bit** suite identifiers for built-in Galdralag profile names.
///
/// Values live in the **private-use** range until allocated in the CESS
/// [ALGORITHM-REGISTRY](https://github.com/Supermagnum/CESS/blob/main/ALGORITHM-REGISTRY.md).
/// **Do not** treat these as stable across releases until registered upstream.
pub mod provisional {
    /// `standard` profile (`cipher-profile` built-in).
    pub const GALDRALAG_STANDARD: u16 = 0xE001;
    /// `conservative` profile.
    pub const GALDRALAG_CONSERVATIVE: u16 = 0xE002;
    /// `conservative-shamir` profile.
    pub const GALDRALAG_CONSERVATIVE_SHAMIR: u16 = 0xE003;
    /// `high-assurance` profile.
    pub const GALDRALAG_HIGH_ASSURANCE: u16 = 0xE004;

    /// Map a built-in profile name to a provisional suite id, if known.
    pub fn suite_id_for_profile_name(name: &str) -> Option<u16> {
        match name {
            "standard" => Some(GALDRALAG_STANDARD),
            "conservative" => Some(GALDRALAG_CONSERVATIVE),
            "conservative-shamir" => Some(GALDRALAG_CONSERVATIVE_SHAMIR),
            "high-assurance" => Some(GALDRALAG_HIGH_ASSURANCE),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_outer_plaintext() {
        let inner = [1u8, 2, 3, 4, 5];
        let packed = assemble_mode_a_outer_plaintext(0xE001, &inner).unwrap();
        let (id, blob) = parse_mode_a_outer_plaintext(&packed).unwrap();
        assert_eq!(id, 0xE001);
        assert_eq!(blob, inner.as_slice());
    }

    #[test]
    fn reserved_suite_rejected() {
        assert!(assemble_mode_a_outer_plaintext(SUITE_ID_RESERVED, &[0]).is_err());
    }

    #[test]
    fn provisional_names() {
        assert_eq!(
            provisional::suite_id_for_profile_name("standard"),
            Some(provisional::GALDRALAG_STANDARD)
        );
    }
}
