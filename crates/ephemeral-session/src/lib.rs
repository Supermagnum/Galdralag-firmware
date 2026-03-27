//! Authenticated ephemeral ECDH session protocol (Brainpool curves, HKDF-SHA256 session keys).
//!
//! Provides cryptographic forward secrecy: long-term signing keys authenticate ephemeral offers;
//! session keys depend on fresh ephemeral ECDH shared secrets.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

#[cfg(not(test))]
extern crate alloc;

mod curve_select;
mod error;
mod handshake;
mod hkdf_labels;
mod keys;
mod protocol;
mod trust;

pub use curve_select::SessionCurve;
pub use hkdf_labels::domain;
pub use error::EphemeralSessionError;
pub use handshake::{InitMessage, ResponseMessage, INIT_PROTOCOL_VERSION, MAX_HANDSHAKE_BYTES, MAX_SIG_BYTES, RESP_PROTOCOL_VERSION};
pub use keys::{EphemeralKeyPair, SessionKeys};
pub use protocol::{InitiatorSession, ResponderSession, SessionRole};
pub use trust::{InMemoryTrustStore, LongTermCert, TrustStore, MAX_SEC1};
