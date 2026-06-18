//! RRAM vault: sealed blob layout, HKDF **policy strings**, and sensitive material wrappers.
//!
//! **Security role:** this crate is the only long-term key store path; USB and PIN layers must not
//! persist raw IKMs. Align layout with Baochip-1x **4 MiB RRAM** and measured-boot policy from the
//! [platform README](https://raw.githubusercontent.com/Supermagnum/Baochip-1x-firmware/refs/heads/main/README.md).
//!
//! **`alloc`:** the `rsa` workspace dependency performs heap-backed big-integer arithmetic; RSA APIs
//! in this crate use [`alloc::vec::Vec`] for ciphertexts and DER blobs while the rest of the vault
//! stays `heapless`-oriented where possible.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

#[macro_use]
extern crate alloc;

mod brainpool_common;
pub mod brainpool;
pub mod chacha_aead;
pub mod ecdsa_brainpool;
pub mod kdf_policy;
pub mod key_material;
pub mod service;
pub mod session;
pub mod shamir;
pub mod brainpool384;
pub mod brainpool512;
pub mod serpent_cipher;
pub mod rsa_keys;
pub mod rsa_vault;
pub mod public_key_vault;
pub mod vault_pin_policy;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod wycheproof_chacha;
#[cfg(test)]
mod wycheproof_brainpool384;
#[cfg(test)]
mod wycheproof_brainpool512;
#[cfg(test)]
mod wycheproof_rsa;

pub use galdr_core::GaldrError;
pub use kdf_policy::{derive_subkey_sha512_stub, KeyPurpose};
pub use key_material::{EphemeralEcdhSecretMaterial, VaultKey256};
pub use service::{VaultRequest, VaultService};
pub use session::VaultSessionState;
pub use public_key_vault::{
    vault_delete_public_key, vault_load_public_key_der, vault_store_public_key_der, PublicKeySlot,
    PublicKeyVaultError, PUBLIC_KEY_REGION_BASE, PUBLIC_KEY_SLOT_BYTES,
};
pub use vault_pin_policy::{
    vault_read_pin_policy, vault_write_pin_policy, provisioned_attempts_range, VaultPinPolicyError,
    VaultPinPolicyRecord, VAULT_PIN_POLICY_RECORD_BYTES,
};
