//! HKDF domain separation: every operational key **must** use a distinct `info` label (RFC 5869).
//!
//! Production code uses [`hkdf`] with [`sha2::Sha512`] for SHA-512-backed derivation; `info`
//! strings are fixed per [`KeyPurpose`]. When ComboHash accelerates SHA-512, keep the same
//! byte-level `info` values after validation.

use crate::GaldrError;
use hkdf::Hkdf;
use sha2::Sha512;

/// Key derivation purposes for vault operations. Each maps to a unique `info` octet string.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum KeyPurpose {
    /// Root unwrap for vault header and slot directory integrity.
    VaultRootUnwrap,
    /// AEAD keys for RRAM blob payloads.
    RramBlobWrap,
    /// Long-term storage sealing outside individual blobs.
    StorageSeal,
    /// USB session keys after successful unlock (ephemeral subtree).
    UsbSession,
    /// PIN verifier and related gating keys.
    PinVerifier,
    /// OpenPGP-aligned signing subtree (profile-gated).
    OpenPgpSigning,
    /// X25519 / ECDH agreement material (profile-gated).
    KeyAgreement,
    /// Shamir recovery root expansion (profile-gated; uses `vsss-rs` at rest, HKDF after combine).
    ShamirRecovery,
    /// Serpent-256 AEAD key (Encrypt-then-MAC in `serpent_cipher`).
    SerpentStorage,
    /// Twofish-256 AEAD key (Encrypt-then-MAC in `twofish_cipher`).
    TwofishStorage,
    /// AEAD key used to wrap RSA private key material before RRAM storage (`rsa_vault`).
    RsaKeyWrap,
}

impl KeyPurpose {
    /// HKDF `info` parameter; **must** stay unique per variant for the lifetime of `galdr-v1`.
    pub fn info(self) -> &'static [u8] {
        match self {
            KeyPurpose::VaultRootUnwrap => b"galdr-v1/vault/root-unwrap",
            KeyPurpose::RramBlobWrap => b"galdr-v1/vault/rram-blob-wrap",
            KeyPurpose::StorageSeal => b"galdr-v1/vault/storage-seal",
            KeyPurpose::UsbSession => b"galdr-v1/vault/usb-session",
            KeyPurpose::PinVerifier => b"galdr-v1/vault/pin-verifier",
            KeyPurpose::OpenPgpSigning => b"galdr-v1/vault/openpgp-signing",
            KeyPurpose::KeyAgreement => b"galdr-v1/vault/key-agreement",
            KeyPurpose::ShamirRecovery => b"galdr-v1/vault/shamir-recovery",
            KeyPurpose::SerpentStorage => b"galdralag/serpent/storage/v1",
            KeyPurpose::TwofishStorage => b"galdralag/twofish/storage/v1",
            KeyPurpose::RsaKeyWrap => b"galdralag/rsa/key-wrap/v1",
        }
    }
}

/// HKDF-SHA512 per RFC 5869: HKDF-Extract(`salt`, `ikm`) then HKDF-Expand(PRK, `purpose.info()`, L).
///
/// Domain separation is entirely in [`KeyPurpose::info`]; callers supply only IKM and salt.
///
/// # Arguments
///
/// * `ikm` — input keying material for Extract (often a pseudorandom key or shared secret).
/// * `salt` — optional salt; use `&[]` when no salt is used (still passed as `Some` internally).
/// * `purpose` — selects the static `info` octets for Expand.
/// * `out` — output buffer of length L; must not exceed **16320** bytes (255 × SHA-512 digest size).
///
/// # Errors
///
/// [`GaldrError::KeyDerivation`] when Expand fails (for example `out.len()` above the RFC limit).
pub fn derive_subkey_sha512(
    ikm: &[u8],
    salt: &[u8],
    purpose: KeyPurpose,
    out: &mut [u8],
) -> Result<(), GaldrError> {
    let hk = Hkdf::<Sha512>::new(Some(salt), ikm);
    hk.expand(purpose.info(), out)
        .map_err(|_| GaldrError::KeyDerivation)
}
