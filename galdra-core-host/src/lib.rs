//! Host-side business logic for the Galdra token management tool.
//!
//! All user-facing binaries (`galdra`, `galdrad`, GUI) should call into this crate instead of
//! duplicating policy or database access.

pub mod audit;
pub mod config;
pub mod contacts;
pub mod db;
pub mod device;
pub mod encrypt;
pub mod error;
pub mod groups;
pub mod keyserver;
pub mod ldap;
pub mod sign;
pub mod sync;

pub use error::GaldraError;
pub use sync::SyncImportMode;
