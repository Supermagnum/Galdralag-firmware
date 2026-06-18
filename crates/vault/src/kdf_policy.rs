//! HKDF domain separation: every operational key **must** use a distinct `info` label (RFC 5869).
//!
//! **TODO (developer):** Firmware must call `hkdf` + `sha2` only (no hand-rolled KDF). When
//! ComboHash accelerates SHA-512, feed the same byte-level `info` strings after validation.

use crate::GaldrError;

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
            KeyPurpose::RsaKeyWrap => b"galdralag/rsa/key-wrap/v1",
        }
    }
}

/// Stub: production must call HKDF-SHA512 with `purpose.info()` and validated IKM/salt.
pub fn derive_subkey_sha512_stub(
    _ikm: &[u8],
    _salt: &[u8],
    _purpose: KeyPurpose,
    _out: &mut [u8],
) -> Result<(), GaldrError> {
    Err(GaldrError::NotImplemented)
}
