//! ECDSA over brainpoolP512r1.

pub use super::BrainpoolP512r1;

/// ECDSA signature (fixed-size coordinates).
pub type Signature = ecdsa::Signature<BrainpoolP512r1>;

/// ASN.1 DER-encoded ECDSA signature.
pub type DerSignature = ecdsa::der::Signature<BrainpoolP512r1>;

impl ecdsa::EcdsaCurve for BrainpoolP512r1 {
    const NORMALIZE_S: bool = false;
}

#[cfg(feature = "sha512")]
impl ecdsa::hazmat::DigestAlgorithm for BrainpoolP512r1 {
    type Digest = sha2::Sha512;
}
