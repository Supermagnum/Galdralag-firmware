//! RRAM vault: sealed blob layout, HKDF **policy strings**, and sensitive material wrappers.
//!
//! **Security role:** this crate is the only long-term key store path; USB and PIN layers must not
//! persist raw IKMs. Align layout with Baochip-1x **4 MiB RRAM** and measured-boot policy from the
//! [platform README](https://github.com/Supermagnum/Baochip-1x-firmware).
//!
//! **`alloc`:** the `rsa` workspace dependency performs heap-backed big-integer arithmetic; RSA APIs
//! in this crate use [`alloc::vec::Vec`] for ciphertexts and DER blobs while the rest of the vault
//! stays `heapless`-oriented where possible.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

#[macro_use]
extern crate alloc;

pub mod brainpool;
pub mod brainpool384;
mod brainpool_common;
pub mod camellia_cipher;
pub mod chacha_aead;
pub mod ecdsa_brainpool;
pub mod kdf_policy;
pub mod key_material;
pub mod layout;
pub mod public_key_vault;
pub mod rsa_keys;
pub mod rsa_vault;
pub mod sealed_key;
pub mod serpent_cipher;
pub mod service;
pub mod session;
pub mod session_long_term_signing;
pub mod shamir;
pub mod twofish_cipher;
pub mod vault_pin_policy;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod wycheproof_aes_gcm;
#[cfg(test)]
mod wycheproof_brainpool256;
#[cfg(test)]
mod wycheproof_brainpool384;
#[cfg(test)]
mod wycheproof_chacha;
#[cfg(test)]
mod wycheproof_ecdsa_brainpool256;
#[cfg(test)]
mod wycheproof_ed25519;
#[cfg(test)]
mod wycheproof_hkdf_sha256;
#[cfg(test)]
mod wycheproof_hkdf_sha512;
#[cfg(test)]
mod wycheproof_hmac_sha256;
#[cfg(test)]
mod wycheproof_hmac_sha512;
#[cfg(test)]
mod wycheproof_rsa;
#[cfg(test)]
mod wycheproof_x25519;

pub use galdr_core::GaldrError;
pub use kdf_policy::{derive_subkey_sha512, KeyPurpose};
pub use key_material::{EphemeralEcdhSecretMaterial, VaultKey256};
pub use layout::{
    SEALED_AUT_OFFSET, SEALED_BLOB_BYTES, SEALED_DEC_OFFSET, SEALED_KEY_REGION_END,
    SEALED_SIG_OFFSET,
};
pub use public_key_vault::{
    vault_delete_public_key, vault_load_public_key_der, vault_store_public_key_der, PublicKeySlot,
    PublicKeyVaultError, PUBLIC_KEY_REGION_BASE, PUBLIC_KEY_SLOT_BYTES,
};
pub use sealed_key::{SealedKeyBlob, SealedKeyError};
pub use service::{VaultRequest, VaultService};
pub use session::VaultSessionState;
pub use session_long_term_signing::{
    vault_load_session_long_term_signing_key, vault_store_session_long_term_signing_key,
    SessionLongTermSigningKey, SessionLongTermSigningVaultError,
};
pub use vault_pin_policy::{
    provisioned_attempts_range, vault_read_pin_policy, vault_write_pin_policy, VaultPinPolicyError,
    VaultPinPolicyRecord, VAULT_PIN_POLICY_RECORD_BYTES,
};
