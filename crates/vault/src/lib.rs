//! RRAM vault: sealed blob layout, HKDF **policy strings**, and sensitive material wrappers.
//!
//! **Security role:** this crate is the only long-term key store path; USB and PIN layers must not
//! persist raw IKMs. Align layout with Baochip-1x **4 MiB RRAM** and measured-boot policy from the
//! [platform README](https://raw.githubusercontent.com/Supermagnum/Baochip-1x-firmware/refs/heads/main/README.md).

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

pub mod kdf_policy;
pub mod key_material;
pub mod service;
pub mod session;

#[cfg(test)]
mod tests;

pub use galdr_core::GaldrError;
pub use kdf_policy::{derive_subkey_sha512_stub, KeyPurpose};
pub use key_material::{EphemeralEcdhSecretMaterial, VaultKey256};
pub use service::{VaultRequest, VaultService};
pub use session::VaultSessionState;
