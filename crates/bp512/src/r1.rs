//! brainpoolP512r1 elliptic curve (RFC 5639 Section 3.7).

#[cfg(feature = "ecdsa")]
pub mod ecdsa;

#[cfg(feature = "arithmetic")]
mod arithmetic;

#[cfg(feature = "arithmetic")]
pub use {
    self::arithmetic::{AffinePoint, NonZeroScalar, ProjectivePoint, ScalarValue},
    crate::Scalar,
};

use crate::ORDER;
use elliptic_curve::{
    bigint::{Odd, U512},
    consts::U64,
    FieldBytesEncoding,
};

#[cfg(feature = "pkcs8")]
use crate::pkcs8;

/// brainpoolP512r1: verifiably pseudo-random Weierstrass curve (RFC 5639).
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, PartialOrd, Ord)]
pub struct BrainpoolP512r1;

impl elliptic_curve::Curve for BrainpoolP512r1 {
    type FieldBytesSize = U64;

    type Uint = U512;

    const ORDER: Odd<U512> = ORDER;
}

impl elliptic_curve::PrimeCurve for BrainpoolP512r1 {}

impl elliptic_curve::point::PointCompression for BrainpoolP512r1 {
    const COMPRESS_POINTS: bool = false;
}

#[cfg(feature = "pkcs8")]
impl pkcs8::AssociatedOid for BrainpoolP512r1 {
    const OID: pkcs8::ObjectIdentifier =
        pkcs8::ObjectIdentifier::new_unwrap("1.3.36.3.3.2.8.1.1.13");
}

/// SEC1-encoded point.
pub type Sec1Point = elliptic_curve::sec1::Sec1Point<BrainpoolP512r1>;

/// Serialized field element bytes (base field or scalar).
pub type FieldBytes = elliptic_curve::FieldBytes<BrainpoolP512r1>;

impl FieldBytesEncoding<BrainpoolP512r1> for U512 {
    fn decode_field_bytes(field_bytes: &FieldBytes) -> Self {
        crate::decode_field_bytes(field_bytes)
    }

    fn encode_field_bytes(&self) -> FieldBytes {
        crate::encode_field_bytes(self)
    }
}

/// Secret key scalar.
pub type SecretKey = elliptic_curve::SecretKey<BrainpoolP512r1>;

#[cfg(not(feature = "arithmetic"))]
impl elliptic_curve::sec1::ValidatePublicKey for BrainpoolP512r1 {}
