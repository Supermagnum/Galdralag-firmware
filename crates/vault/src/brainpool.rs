//! Brainpool P-256r1 ECDH and SEC1 encoding using the audited `bp256` / `elliptic-curve` stack.
//!
//! **Security role:** software group law on VexRiscv until PKE hardware binding is wired; domain
//! parameters are fixed by `bp256::BrainpoolP256r1` (RFC 5639).

use bp256::elliptic_curve::pkcs8::DecodePublicKey;
use bp256::elliptic_curve::sec1::{FromSec1Point, Sec1Point, ToSec1Point};
use bp256::elliptic_curve::{PublicKey, SecretKey};
use bp256::BrainpoolP256r1;
use elliptic_curve::ecdh::diffie_hellman;
use galdr_core::hal::HardwareTrng;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Rejection-sampling attempts when drawing a uniform scalar from the TRNG (must be in-range mod n).
const SCALAR_SAMPLE_TRIES: usize = 128;

pub use crate::brainpool_common::BrainpoolError;

/// A scalar value on BrainpoolP256r1. Holds a private key or ephemeral secret.
/// Zeroizes on drop. No Clone, no Copy.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct BrainpoolScalar(zeroize::Zeroizing<[u8; 32]>);

/// A compressed or uncompressed public key point on BrainpoolP256r1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrainpoolPublicKey(PublicKey<BrainpoolP256r1>);

/// An ECDH shared secret derived from a BrainpoolP256r1 key exchange.
/// Zeroizes on drop. No Clone, no Copy.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct BrainpoolSharedSecret(zeroize::Zeroizing<[u8; 32]>);

impl BrainpoolScalar {
    fn secret_key(&self) -> Result<SecretKey<BrainpoolP256r1>, BrainpoolError> {
        SecretKey::from_slice(self.0.as_ref()).map_err(|_| BrainpoolError::InvalidScalar)
    }

    /// Generate a random scalar using the provided TRNG source.
    pub fn generate<T: HardwareTrng>(trng: &mut T) -> Result<Self, BrainpoolError> {
        for _ in 0..SCALAR_SAMPLE_TRIES {
            let mut raw = [0u8; 32];
            trng.try_fill_bytes(&mut raw)
                .map_err(|_| BrainpoolError::TrngFailure)?;
            if let Ok(sk) = SecretKey::<BrainpoolP256r1>::from_slice(&raw) {
                raw.zeroize();
                let fb = sk.to_bytes();
                let mut arr = [0u8; 32];
                arr.copy_from_slice(fb.as_slice());
                return Ok(Self(zeroize::Zeroizing::new(arr)));
            }
            raw.zeroize();
        }
        Err(BrainpoolError::TrngFailure)
    }

    /// Derive the corresponding public key.
    pub fn public_key(&self) -> Result<BrainpoolPublicKey, BrainpoolError> {
        let pk = self.secret_key()?.public_key();
        Ok(BrainpoolPublicKey(pk))
    }

    /// Perform ECDH with a peer's public key.
    pub fn diffie_hellman(
        &self,
        peer: &BrainpoolPublicKey,
    ) -> Result<BrainpoolSharedSecret, BrainpoolError> {
        let affine = peer.0.as_affine();
        if bool::from(affine.is_identity()) {
            return Err(BrainpoolError::PointAtInfinity);
        }
        let shared = diffie_hellman(self.secret_key()?.to_nonzero_scalar(), peer.0.as_affine());
        let raw = shared.raw_secret_bytes();
        let mut out = [0u8; 32];
        if raw.as_slice().len() != out.len() {
            return Err(BrainpoolError::InvalidPoint);
        }
        out.copy_from_slice(raw.as_slice());
        Ok(BrainpoolSharedSecret(zeroize::Zeroizing::new(out)))
    }

    /// Deserialize a scalar from raw secret key bytes (interoperability and test vectors).
    pub fn from_secret_key_bytes_for_test(bytes: &[u8]) -> Result<Self, BrainpoolError> {
        let sk = SecretKey::<BrainpoolP256r1>::from_slice(bytes)
            .map_err(|_| BrainpoolError::InvalidScalar)?;
        let fb = sk.to_bytes();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(fb.as_slice());
        Ok(Self(zeroize::Zeroizing::new(arr)))
    }

    /// Serialise scalar bytes for persistence and test hooks (vault integration tests).
    pub fn to_secret_bytes_for_test(&self) -> [u8; 32] {
        let s = self.0.as_ref();
        let mut out = [0u8; 32];
        out.copy_from_slice(s);
        out
    }
}

impl BrainpoolPublicKey {
    /// Deserialise an X.509 / SPKI `SubjectPublicKeyInfo` DER blob (as in Wycheproof `encoding: asn`).
    pub fn from_public_key_der(bytes: &[u8]) -> Result<Self, BrainpoolError> {
        let pk = PublicKey::from_public_key_der(bytes).map_err(|_| BrainpoolError::InvalidPoint)?;
        Ok(BrainpoolPublicKey(pk))
    }

    /// Serialise to uncompressed SEC1 form (65 bytes: 0x04 || x || y).
    pub fn to_sec1_uncompressed(&self) -> [u8; 65] {
        let enc = self.0.to_sec1_point(false);
        let mut out = [0u8; 65];
        let b = enc.as_bytes();
        out.copy_from_slice(b);
        out
    }

    /// Deserialise from SEC1 form (compressed or uncompressed).
    /// Returns Err if the point is not on the curve or is the point at infinity.
    pub fn from_sec1(bytes: &[u8]) -> Result<Self, BrainpoolError> {
        let point = Sec1Point::<BrainpoolP256r1>::from_bytes(bytes)
            .map_err(|_| BrainpoolError::InvalidPoint)?;
        if point.is_identity() {
            return Err(BrainpoolError::PointAtInfinity);
        }
        let pk = PublicKey::from_sec1_point(&point)
            .into_option()
            .ok_or(BrainpoolError::InvalidPoint)?;
        Ok(BrainpoolPublicKey(pk))
    }
}

impl BrainpoolSharedSecret {
    /// Constant-time equality of raw shared secret bytes.
    pub fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.as_bytes().ct_eq(other.as_bytes())
    }

    /// Raw shared secret bytes (for tests and higher-level KDFs).
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }
}

#[cfg(test)]
impl BrainpoolPublicKey {
    /// Test-only construction from a `PublicKey` (e.g. identity handling checks).
    pub fn from_public_key_for_test(pk: PublicKey<BrainpoolP256r1>) -> Self {
        Self(pk)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bp256::elliptic_curve::sec1::Sec1Point;
    use galdr_core::fake_hal::FakeTrng;
    use subtle::ConstantTimeEq;

    /// RFC 5639 generator in uncompressed SEC1 (hex: 04 || Gx || Gy).
    const G_SEC1: [u8; 65] = [
        0x04, 0x8b, 0xd2, 0xae, 0xb9, 0xcb, 0x7e, 0x57, 0xcb, 0x2c, 0x4b, 0x48, 0x2f, 0xfc, 0x81,
        0xb7, 0xaf, 0xb9, 0xde, 0x27, 0xe1, 0xe3, 0xbd, 0x23, 0xc2, 0x3a, 0x44, 0x53, 0xbd, 0x9a,
        0xce, 0x32, 0x62, 0x54, 0x7e, 0xf8, 0x35, 0xc3, 0xda, 0xc4, 0xfd, 0x97, 0xf8, 0x46, 0x1a,
        0x14, 0x61, 0x1d, 0xc9, 0xc2, 0x77, 0x45, 0x13, 0x2d, 0xed, 0x8e, 0x54, 0x5c, 0x1d, 0x54,
        0xc7, 0x2f, 0x04, 0x69, 0x97,
    ];

    #[test]
    fn generator_point_on_curve() {
        let pk = BrainpoolPublicKey::from_sec1(&G_SEC1);
        assert!(pk.is_ok(), "generator must parse as valid SEC1 point");
    }

    #[test]
    fn key_generation_round_trip() {
        let mut trng = FakeTrng::from_seed(0xC0FFEE);
        let sk = BrainpoolScalar::generate(&mut trng).expect("scalar");
        let pk1 = sk.public_key().expect("pk1");
        let pk2 = sk.public_key().expect("pk2");
        assert_eq!(pk1.to_sec1_uncompressed(), pk2.to_sec1_uncompressed());
    }

    #[test]
    fn ecdh_commutativity() {
        let mut ta = FakeTrng::from_seed(1);
        let mut tb = FakeTrng::from_seed(2);
        let a = BrainpoolScalar::generate(&mut ta).expect("a");
        let b = BrainpoolScalar::generate(&mut tb).expect("b");
        let pa = a.public_key().expect("pa");
        let pb = b.public_key().expect("pb");
        let sa = a.diffie_hellman(&pb).expect("sa");
        let sb = b.diffie_hellman(&pa).expect("sb");
        assert!(bool::from(sa.ct_eq(&sb)));
    }

    #[test]
    fn sec1_round_trip_uncompressed() {
        let mut trng = FakeTrng::from_seed(4);
        let sk = BrainpoolScalar::generate(&mut trng).expect("sk");
        let pk = sk.public_key().expect("pk");
        let bytes = pk.to_sec1_uncompressed();
        let back = BrainpoolPublicKey::from_sec1(&bytes).expect("parse");
        assert_eq!(pk.to_sec1_uncompressed(), back.to_sec1_uncompressed());
    }

    #[test]
    fn sec1_rejects_point_not_on_curve() {
        let mut bad = [0u8; 65];
        bad[0] = 0x04;
        bad[1..].fill(0x7f);
        let r = BrainpoolPublicKey::from_sec1(&bad);
        assert_eq!(r, Err(BrainpoolError::InvalidPoint));
    }

    #[test]
    fn shared_secret_compare_constant_time() {
        let mut t = FakeTrng::from_seed(5);
        let a = BrainpoolScalar::generate(&mut t).expect("a");
        let b = BrainpoolScalar::generate(&mut t).expect("b");
        let pa = a.public_key().expect("pa");
        let pb = b.public_key().expect("pb");
        let sa = a.diffie_hellman(&pb).expect("sa");
        let sb = b.diffie_hellman(&pa).expect("sb");
        assert!(bool::from(sa.as_bytes().ct_eq(sb.as_bytes())));
    }

    #[test]
    fn encoded_identity_rejected_by_from_sec1() {
        let enc = Sec1Point::<BrainpoolP256r1>::identity();
        let r = BrainpoolPublicKey::from_sec1(enc.as_bytes());
        assert_eq!(r, Err(BrainpoolError::PointAtInfinity));
    }
}
