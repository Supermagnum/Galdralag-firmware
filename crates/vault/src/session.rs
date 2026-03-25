//! Session key lifecycle: ephemeral ECDH material must not outlive HKDF output installation.
//!
//! **Security role:** enforces **forward secrecy** posture from the Baochip README (authenticated
//! ephemeral ECDH); this module only documents state — real zeroisation hooks into `zeroize` +
//! `ZeroiseController`.

/// Tracks whether ephemeral agreement material may still exist in RAM.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VaultSessionState {
    /// No ephemeral secret present.
    Idle,
    /// Ephemeral private scalar held pending HKDF.
    EphemeralPending,
    /// Session keys installed; ephemeral material must have been zeroised.
    SessionActive,
}
