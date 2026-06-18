//! Named cipher profiles: ECDHE curve, symmetric cascade, and Shamir metadata.
//!
//! Profiles are immutable once built. Cascade keying: **built-in** names that map to a CESS
//! `suite_id` use **HKDF-BLAKE3** over the **classical ECDH** shared secret
//! ([`ephemeral_session::SessionKeys::cess_inner_cascade_ikm`]); **custom** profiles use
//! **HKDF-SHA256** over a 32-byte PRK ([`ephemeral_session::SessionKeys::profile_prk`]).

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

mod audit;
mod cascade;
mod domain;
mod error;
mod layer;
mod profile;
mod registry;
mod shamir_cfg;

pub use audit::{curve_audit_str, layer_audit_name, ProfileAuditRecord};
pub use cascade::{cascade_decrypt, cascade_encrypt, CascadeCiphertext, CascadePlaintext};
pub use domain::{layer_key_info, layer_nonce_info, MAX_CASCADE_PLAINTEXT};
pub use error::CipherProfileError;
pub use layer::CipherLayer;
pub use profile::{CipherProfile, CipherProfileBuilder};
pub use registry::ProfileRegistry;
pub use shamir_cfg::ShamirConfig;
