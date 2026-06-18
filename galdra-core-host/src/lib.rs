//! Host-side business logic for the Galdra token management tool.
//!
//! All user-facing binaries (`galdra`, `galdrad`, GUI) should call into this crate instead of
//! duplicating policy or database access.

pub mod audit;
pub use cipher_profile;
pub mod cipher_envelope;
pub mod config;
pub mod contacts;
pub mod db;
pub mod device;
pub mod encrypt;
pub mod ephemeral_offers;
pub mod error;
pub mod galdra_fingerprint;
pub mod openpgp_pcsc;
pub mod groups;
pub mod keyserver;
pub mod ldap;
pub mod profiles;
pub mod shamir_ops;
pub mod sign;
pub mod sync;

pub use error::GaldraError;
pub use galdra_fingerprint::{GaldraFingerprint, GaldraFingerprintParseError};
pub use sync::SyncImportMode;
