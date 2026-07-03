//! Authenticated ephemeral ECDH session protocol (Brainpool curves, HKDF-SHA256 session keys).
//!
//! Provides cryptographic forward secrecy: long-term signing keys authenticate ephemeral offers;
//! session keys depend on fresh ephemeral ECDH shared secrets.
//!
//! **CESS Mode A:** [`EphemeralSharedSecret::cess_k_outer_mode_a`] derives **`K_outer`** (HKDF-BLAKE3,
//! `cess-outer-envelope-v1`) from the raw ECDH IKM. Use **BrainpoolP384r1** for the handshake when
//! feeding the CESS outer layer (CESS §6.1.1). Seal/open helpers are in the **`cess`** crate
//! (`seal_mode_a_outer`, `open_mode_a_outer`).

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

pub use curve_select::{SessionCurve, SessionCurveWireError};
pub use error::EphemeralSessionError;
pub use handshake::{
    InitMessage, ResponseMessage, INIT_PROTOCOL_VERSION, MAX_HANDSHAKE_BYTES, MAX_SIG_BYTES,
    RESP_PROTOCOL_VERSION,
};
pub use hkdf_labels::domain;
pub use keys::{EphemeralKeyPair, EphemeralSharedSecret, SessionKeys};
pub use protocol::{InitiatorSession, ResponderSession, SessionRole};
pub use trust::{InMemoryTrustStore, LongTermCert, TrustStore, MAX_SEC1};
