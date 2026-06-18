//! Error type for the ephemeral session protocol.

use galdr_core::HalError;

/// Failure modes for authenticated ephemeral ECDH sessions.
#[derive(Debug, Eq, PartialEq)]
pub enum EphemeralSessionError {
    /// The ephemeral key pair could not be generated (TRNG failure).
    KeyGeneration,

    /// The peer's ephemeral public key is not a valid point on the curve.
    InvalidPeerPublicKey,

    /// The peer's long-term signature over the ephemeral public key is invalid.
    /// This indicates an impersonation attempt or message corruption.
    InvalidPeerSignature,

    /// The ECDH operation failed (for example point at infinity).
    EcdhFailed,

    /// The session has already been completed. Ephemeral keys have been
    /// destroyed and cannot be reused.
    SessionAlreadyCompleted,

    /// The session has already been initialised. Call `complete()` not `init()`.
    SessionAlreadyInitialised,

    /// Handshake message is malformed or truncated.
    MalformedHandshake,

    /// The curve specified in the peer's message does not match the
    /// negotiated curve.
    CurveMismatch,

    /// The long-term key loaded from the vault does not match the expected
    /// fingerprint in the handshake.
    FingerprintMismatch,

    /// Vault storage error.
    Storage,

    /// Underlying Brainpool error (from vault crate).
    Brainpool,

    /// In-memory trust store has no free slots.
    TrustStoreFull,
}

impl From<HalError> for EphemeralSessionError {
    fn from(_: HalError) -> Self {
        EphemeralSessionError::Storage
    }
}

impl From<galdr_vault::brainpool::BrainpoolError> for EphemeralSessionError {
    fn from(_: galdr_vault::brainpool::BrainpoolError) -> Self {
        EphemeralSessionError::Brainpool
    }
}

impl From<galdr_vault::session_long_term_signing::SessionLongTermSigningVaultError>
    for EphemeralSessionError
{
    fn from(e: galdr_vault::session_long_term_signing::SessionLongTermSigningVaultError) -> Self {
        match e {
            galdr_vault::session_long_term_signing::SessionLongTermSigningVaultError::StorageError => {
                EphemeralSessionError::Storage
            }
            _ => EphemeralSessionError::MalformedHandshake,
        }
    }
}
