//! Shared error type for Brainpool curve operations (P-256r1, P-384r1, P-512r1).
//!
//! One enum keeps cross-curve error handling uniform and avoids duplicate `PartialEq` surfaces.

/// Errors from Brainpool scalar, point, ECDH, and ECDSA operations across supported curves.
#[derive(Debug, Eq, PartialEq)]
pub enum BrainpoolError {
    /// The encoded point is not on the curve or is malformed.
    InvalidPoint,
    /// The scalar encoding is invalid or out of range.
    InvalidScalar,
    /// The hardware TRNG could not supply entropy.
    TrngFailure,
    /// The peer public key is the point at infinity (ECDH is undefined).
    PointAtInfinity,
    /// ECDSA verification failed or the signature encoding is invalid.
    InvalidSignature,
}
