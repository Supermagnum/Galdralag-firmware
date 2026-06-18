//! Brainpool P-512r1 (`brainpoolP512r1`) ECDH, SEC1 encoding, and ECDSA with SHA-512.
//!
//! # Implementation note
//!
//! RFC 5639 domain parameters for this curve are **not** duplicated here. They are fixed by the
//! audited RustCrypto [`bp512::BrainpoolP512r1`] type (Weierstrass curve over a 512-bit prime field).
//! The `bp512` crate uses the same `elliptic-curve` / `ecdsa` stack as `bp256` (Session 1).
//!
//! ECDSA digests: **SHA-512** (not SHA-256), matching the field size and Wycheproof vectors.

use crate::brainpool_common::BrainpoolError;
use bp512::BrainpoolP512r1;
use bp512::elliptic_curve::ecdh::diffie_hellman;
use bp512::elliptic_curve::pkcs8::DecodePublicKey;
use bp512::elliptic_curve::sec1::{FromSec1Point, Sec1Point, ToSec1Point};
use bp512::elliptic_curve::{PublicKey, SecretKey};
use ecdsa::der;
use ecdsa::signature::{Signer, Verifier};
use ecdsa::{SigningKey, VerifyingKey};
use galdr_core::hal::HardwareTrng;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Rejection-sampling attempts when drawing a uniform scalar from the TRNG (must be in-range mod n).
const SCALAR_SAMPLE_TRIES: usize = 128;

/// Maximum DER-encoded ECDSA signature size for P-512 (r/s INTEGERs plus SEQUENCE overhead).
pub const MAX_DER_SIG_P512: usize = 200;

/// A non-zero scalar on BrainpoolP512r1. Zeroizes on drop. No Clone, no Copy.
#[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct BrainpoolP512Scalar(zeroize::Zeroizing<[u8; 64]>);

/// Uncompressed or compressed public key on BrainpoolP512r1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrainpoolP512PublicKey(PublicKey<BrainpoolP512r1>);

/// ECDH shared secret (x-coordinate bytes). Zeroizes on drop. No Clone, no Copy.
#[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct BrainpoolP512SharedSecret(zeroize::Zeroizing<[u8; 64]>);

/// ECDSA signing key. Zeroizes on drop. No Clone, no Copy.
pub struct BrainpoolP512SigningKey(SigningKey<BrainpoolP512r1>);

/// ECDSA verifying key (public).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrainpoolP512VerifyingKey(VerifyingKey<BrainpoolP512r1>);

/// DER-encoded ECDSA signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrainpoolP512Signature {
    der: heapless::Vec<u8, MAX_DER_SIG_P512>,
}

#[cfg(test)]
impl BrainpoolP512Signature {
    pub(crate) fn from_der_bytes_for_test(bytes: &[u8]) -> Result<Self, BrainpoolError> {
        let mut der = heapless::Vec::new();
        for b in bytes {
            der.push(*b).map_err(|_| BrainpoolError::InvalidSignature)?;
        }
        Ok(BrainpoolP512Signature { der })
    }

    pub(crate) fn xor_first_byte_for_test(&mut self) {
        if let Some(b) = self.der.get_mut(0) {
            *b ^= 0x01;
        }
    }
}

impl BrainpoolP512Scalar {
    fn secret_key(&self) -> Result<SecretKey<BrainpoolP512r1>, BrainpoolError> {
        SecretKey::from_slice(self.0.as_ref()).map_err(|_| BrainpoolError::InvalidScalar)
    }

    /// Generate a random scalar using the provided TRNG source.
    pub fn generate<T: HardwareTrng>(trng: &mut T) -> Result<Self, BrainpoolError> {
        for _ in 0..SCALAR_SAMPLE_TRIES {
            let mut raw = [0u8; 64];
            trng
                .try_fill_bytes(&mut raw)
                .map_err(|_| BrainpoolError::TrngFailure)?;
            if let Ok(sk) = SecretKey::<BrainpoolP512r1>::from_slice(&raw) {
                raw.zeroize();
                let fb = sk.to_bytes();
                let mut arr = [0u8; 64];
                arr.copy_from_slice(fb.as_slice());
                return Ok(Self(zeroize::Zeroizing::new(arr)));
            }
            raw.zeroize();
        }
        Err(BrainpoolError::TrngFailure)
    }

    /// Derive the corresponding public key.
    pub fn public_key(&self) -> Result<BrainpoolP512PublicKey, BrainpoolError> {
        let pk = self.secret_key()?.public_key();
        Ok(BrainpoolP512PublicKey(pk))
    }

    /// Perform ECDH with a peer's public key.
    pub fn diffie_hellman(
        &self,
        peer: &BrainpoolP512PublicKey,
    ) -> Result<BrainpoolP512SharedSecret, BrainpoolError> {
        let affine = peer.0.as_affine();
        if bool::from(affine.is_identity()) {
            return Err(BrainpoolError::PointAtInfinity);
        }
        let shared = diffie_hellman(self.secret_key()?.to_nonzero_scalar(), peer.0.as_affine());
        let raw = shared.raw_secret_bytes();
        let mut out = [0u8; 64];
        if raw.as_slice().len() != out.len() {
            return Err(BrainpoolError::InvalidPoint);
        }
        out.copy_from_slice(raw.as_slice());
        Ok(BrainpoolP512SharedSecret(zeroize::Zeroizing::new(out)))
    }

    /// Build a scalar from raw secret key bytes (Wycheproof / interoperability).
    pub fn from_secret_key_bytes_for_test(bytes: &[u8]) -> Result<Self, BrainpoolError> {
        let sk = SecretKey::<BrainpoolP512r1>::from_slice(bytes)
            .map_err(|_| BrainpoolError::InvalidScalar)?;
        let fb = sk.to_bytes();
        let mut arr = [0u8; 64];
        arr.copy_from_slice(fb.as_slice());
        Ok(Self(zeroize::Zeroizing::new(arr)))
    }

    pub fn to_secret_bytes_for_test(&self) -> [u8; 64] {
        let s = self.0.as_ref();
        let mut out = [0u8; 64];
        out.copy_from_slice(s);
        out
    }
}

impl BrainpoolP512PublicKey {
    /// Deserialise an X.509 / SPKI `SubjectPublicKeyInfo` DER blob (as in Wycheproof `encoding: asn`).
    pub fn from_public_key_der(bytes: &[u8]) -> Result<Self, BrainpoolError> {
        let pk = PublicKey::from_public_key_der(bytes).map_err(|_| BrainpoolError::InvalidPoint)?;
        Ok(BrainpoolP512PublicKey(pk))
    }

    /// Serialise to uncompressed SEC1 form (129 bytes: `0x04` || x || y).
    pub fn to_sec1_uncompressed(&self) -> [u8; 129] {
        let enc = self.0.to_sec1_point(false);
        let mut out = [0u8; 129];
        let b = enc.as_bytes();
        out.copy_from_slice(b);
        out
    }

    /// Deserialise from SEC1 (compressed or uncompressed). Rejects infinity and invalid points.
    pub fn from_sec1(bytes: &[u8]) -> Result<Self, BrainpoolError> {
        let point = Sec1Point::<BrainpoolP512r1>::from_bytes(bytes)
            .map_err(|_| BrainpoolError::InvalidPoint)?;
        if point.is_identity() {
            return Err(BrainpoolError::PointAtInfinity);
        }
        let pk = PublicKey::from_sec1_point(&point)
            .into_option()
            .ok_or(BrainpoolError::InvalidPoint)?;
        Ok(BrainpoolP512PublicKey(pk))
    }
}

impl BrainpoolP512SharedSecret {
    /// Constant-time equality of raw shared secret bytes.
    pub fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.as_bytes().ct_eq(other.as_bytes())
    }

    /// Raw shared secret bytes (for KDFs and tests).
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl BrainpoolP512SigningKey {
    /// Generate a new signing key using the TRNG.
    pub fn generate<T: HardwareTrng>(trng: &mut T) -> Result<Self, BrainpoolError> {
        for _ in 0..SCALAR_SAMPLE_TRIES {
            let mut raw = [0u8; 64];
            trng
                .try_fill_bytes(&mut raw)
                .map_err(|_| BrainpoolError::TrngFailure)?;
            if let Ok(sk) = SigningKey::<BrainpoolP512r1>::from_slice(&raw) {
                raw.zeroize();
                return Ok(Self(sk));
            }
            raw.zeroize();
        }
        Err(BrainpoolError::TrngFailure)
    }

    /// Return the corresponding verifying key.
    pub fn verifying_key(&self) -> BrainpoolP512VerifyingKey {
        BrainpoolP512VerifyingKey(*self.0.verifying_key())
    }

    /// Sign a message using ECDSA with SHA-512 (digest computed internally).
    ///
    /// The TRNG is required for API symmetry with other vault signing entry points; the `ecdsa`
    /// crate uses deterministic ECDSA (RFC 6979) with SHA-512 for this curve.
    pub fn sign<T: HardwareTrng>(
        &self,
        message: &[u8],
        #[allow(unused_variables)] trng: &mut T,
    ) -> Result<BrainpoolP512Signature, BrainpoolError> {
        let sig: der::Signature<BrainpoolP512r1> = self
            .0
            .try_sign(message)
            .map_err(|_| BrainpoolError::InvalidSignature)?;
        let mut v = heapless::Vec::new();
        for b in sig.as_bytes() {
            v.push(*b).map_err(|_| BrainpoolError::InvalidSignature)?;
        }
        Ok(BrainpoolP512Signature { der: v })
    }

    #[doc(hidden)]
    pub fn to_scalar_bytes_for_test(&self) -> [u8; 64] {
        let fb = self.0.to_bytes();
        let mut a = [0u8; 64];
        a.copy_from_slice(fb.as_slice());
        a
    }

    #[doc(hidden)]
    pub fn from_scalar_bytes_for_test(bytes: &[u8; 64]) -> Result<Self, BrainpoolError> {
        let sk = SigningKey::from_slice(bytes.as_slice()).map_err(|_| BrainpoolError::InvalidScalar)?;
        Ok(Self(sk))
    }
}

impl BrainpoolP512VerifyingKey {
    /// Deserialise a verifying key from X.509 / SPKI `SubjectPublicKeyInfo` DER (Wycheproof `publicKeyDer`).
    pub fn from_public_key_der(bytes: &[u8]) -> Result<Self, BrainpoolError> {
        let vk =
            VerifyingKey::from_public_key_der(bytes).map_err(|_| BrainpoolError::InvalidPoint)?;
        Ok(BrainpoolP512VerifyingKey(vk))
    }

    /// Verify an ECDSA-SHA512 signature over `message`.
    pub fn verify(
        &self,
        message: &[u8],
        signature: &BrainpoolP512Signature,
    ) -> Result<(), BrainpoolError> {
        let sig = der::Signature::from_bytes(signature.der.as_slice())
            .map_err(|_| BrainpoolError::InvalidSignature)?;
        self.0
            .verify(message, &sig)
            .map_err(|_| BrainpoolError::InvalidSignature)
    }

    /// Serialise to uncompressed SEC1 (129 bytes).
    pub fn to_sec1_uncompressed(&self) -> [u8; 129] {
        let enc = self.0.to_sec1_point(false);
        let mut out = [0u8; 129];
        let b = enc.as_bytes();
        out.copy_from_slice(b);
        out
    }

    /// Deserialise verifying key from SEC1 (compressed or uncompressed).
    pub fn from_sec1(bytes: &[u8]) -> Result<Self, BrainpoolError> {
        let vk = VerifyingKey::from_sec1_bytes(bytes).map_err(|_| BrainpoolError::InvalidPoint)?;
        Ok(BrainpoolP512VerifyingKey(vk))
    }
}

#[cfg(test)]
impl BrainpoolP512PublicKey {
    /// Test-only construction from a `PublicKey` (e.g. identity handling checks).
    pub fn from_public_key_for_test(pk: PublicKey<BrainpoolP512r1>) -> Self {
        Self(pk)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::brainpool::{BrainpoolPublicKey, BrainpoolSharedSecret};
    use crate::brainpool384::{BrainpoolP384PublicKey, BrainpoolP384SharedSecret};
    use bp512::elliptic_curve::sec1::Sec1Point;
    use galdr_core::fake_hal::FakeTrng;
    use std::any::TypeId;

    /// RFC 5639 Section 3.7 generator for brainpoolP512r1, uncompressed SEC1 (`0x04` || Gx || Gy).
    const G_SEC1: [u8; 129] = [
        0x04,
        0x81, 0xae, 0xe4, 0xbd, 0xd8, 0x2e, 0xd9, 0x64, 0x5a, 0x21, 0x32, 0x2e, 0x9c, 0x4c, 0x6a, 0x93,
        0x85, 0xed, 0x9f, 0x70, 0xb5, 0xd9, 0x16, 0xc1, 0xb4, 0x3b, 0x62, 0xee, 0xf4, 0xd0, 0x09, 0x8e,
        0xff, 0x3b, 0x1f, 0x78, 0xe2, 0xd0, 0xd4, 0x8d, 0x50, 0xd1, 0x68, 0x7b, 0x93, 0xb9, 0x7d, 0x5f,
        0x7c, 0x6d, 0x50, 0x47, 0x40, 0x6a, 0x5e, 0x68, 0x8b, 0x35, 0x22, 0x09, 0xbc, 0xb9, 0xf8, 0x22,
        0x7d, 0xde, 0x38, 0x5d, 0x56, 0x63, 0x32, 0xec, 0xc0, 0xea, 0xbf, 0xa9, 0xcf, 0x78, 0x22, 0xfd,
        0xf2, 0x09, 0xf7, 0x00, 0x24, 0xa5, 0x7b, 0x1a, 0xa0, 0x00, 0xc5, 0x5b, 0x88, 0x1f, 0x81, 0x11,
        0xb2, 0xdc, 0xde, 0x49, 0x4a, 0x5f, 0x48, 0x5e, 0x5b, 0xca, 0x4b, 0xd8, 0x8a, 0x27, 0x63, 0xae,
        0xd1, 0xca, 0x2b, 0x2f, 0xa8, 0xf0, 0x54, 0x06, 0x78, 0xcd, 0x1e, 0x0f, 0x3a, 0xd8, 0x08, 0x92,
    ];

    #[test]
    fn generator_point_on_curve() {
        let pk = BrainpoolP512PublicKey::from_sec1(&G_SEC1);
        assert!(pk.is_ok(), "generator must parse as valid SEC1 point");
    }

    #[test]
    fn key_generation_round_trip() {
        let mut trng = FakeTrng::from_seed(0xC0FFEE);
        let sk = BrainpoolP512Scalar::generate(&mut trng).expect("scalar");
        let pk1 = sk.public_key().expect("pk1");
        let pk2 = sk.public_key().expect("pk2");
        assert_eq!(pk1.to_sec1_uncompressed(), pk2.to_sec1_uncompressed());
    }

    #[test]
    fn ecdh_commutativity() {
        let mut ta = FakeTrng::from_seed(1);
        let mut tb = FakeTrng::from_seed(2);
        let a = BrainpoolP512Scalar::generate(&mut ta).expect("a");
        let b = BrainpoolP512Scalar::generate(&mut tb).expect("b");
        let pa = a.public_key().expect("pa");
        let pb = b.public_key().expect("pb");
        let sa = a.diffie_hellman(&pb).expect("sa");
        let sb = b.diffie_hellman(&pa).expect("sb");
        assert!(bool::from(sa.ct_eq(&sb)));
    }

    #[test]
    fn sec1_round_trip_uncompressed() {
        let mut trng = FakeTrng::from_seed(4);
        let sk = BrainpoolP512Scalar::generate(&mut trng).expect("sk");
        let pk = sk.public_key().expect("pk");
        let bytes = pk.to_sec1_uncompressed();
        let back = BrainpoolP512PublicKey::from_sec1(&bytes).expect("parse");
        assert_eq!(pk.to_sec1_uncompressed(), back.to_sec1_uncompressed());
    }

    #[test]
    fn sec1_rejects_point_not_on_curve() {
        let mut bad = [0u8; 129];
        bad[0] = 0x04;
        bad[1..].fill(0x7f);
        let r = BrainpoolP512PublicKey::from_sec1(&bad);
        assert_eq!(r, Err(BrainpoolError::InvalidPoint));
    }

    #[test]
    fn shared_secret_compare_constant_time() {
        let mut t = FakeTrng::from_seed(5);
        let a = BrainpoolP512Scalar::generate(&mut t).expect("a");
        let b = BrainpoolP512Scalar::generate(&mut t).expect("b");
        let pa = a.public_key().expect("pa");
        let pb = b.public_key().expect("pb");
        let sa = a.diffie_hellman(&pb).expect("sa");
        let sb = b.diffie_hellman(&pa).expect("sb");
        assert!(bool::from(sa.as_bytes().ct_eq(sb.as_bytes())));
    }

    #[test]
    fn encoded_identity_rejected_by_from_sec1() {
        let enc = Sec1Point::<BrainpoolP512r1>::identity();
        let r = BrainpoolP512PublicKey::from_sec1(enc.as_bytes());
        assert_eq!(r, Err(BrainpoolError::PointAtInfinity));
    }

    #[test]
    fn ecdsa_sign_verify_round_trip() {
        let mut trng = FakeTrng::from_seed(0xA11CE);
        let sk = BrainpoolP512SigningKey::generate(&mut trng).expect("sk");
        let vk = sk.verifying_key();
        let msg = b"galdr brainpool p512 ecdsa vector";
        let sig = sk.sign(msg, &mut trng).expect("sign");
        assert!(vk.verify(msg, &sig).is_ok());
    }

    #[test]
    fn ecdsa_reject_wrong_key() {
        let mut t1 = FakeTrng::from_seed(1);
        let mut t2 = FakeTrng::from_seed(2);
        let sk_a = BrainpoolP512SigningKey::generate(&mut t1).expect("a");
        let sk_b = BrainpoolP512SigningKey::generate(&mut t2).expect("b");
        let vk_b = sk_b.verifying_key();
        let msg = b"same message";
        let sig = sk_a.sign(msg, &mut t1).expect("sign");
        assert_eq!(
            vk_b.verify(msg, &sig),
            Err(BrainpoolError::InvalidSignature)
        );
    }

    #[test]
    fn ecdsa_reject_tampered_message() {
        let mut trng = FakeTrng::from_seed(3);
        let sk = BrainpoolP512SigningKey::generate(&mut trng).expect("sk");
        let vk = sk.verifying_key();
        let mut msg = b"original".to_vec();
        let sig = sk.sign(&msg, &mut trng).expect("sign");
        msg[0] ^= 0x01;
        assert_eq!(
            vk.verify(&msg, &sig),
            Err(BrainpoolError::InvalidSignature)
        );
    }

    #[test]
    fn ecdsa_reject_tampered_signature() {
        let mut trng = FakeTrng::from_seed(4);
        let sk = BrainpoolP512SigningKey::generate(&mut trng).expect("sk");
        let vk = sk.verifying_key();
        let msg = b"fixed message";
        let mut sig = sk.sign(msg, &mut trng).expect("sign");
        sig.xor_first_byte_for_test();
        assert_eq!(
            vk.verify(msg, &sig),
            Err(BrainpoolError::InvalidSignature)
        );
    }

    #[test]
    fn verifying_key_sec1_round_trip() {
        let mut trng = FakeTrng::from_seed(5);
        let sk = BrainpoolP512SigningKey::generate(&mut trng).expect("sk");
        let vk = sk.verifying_key();
        let bytes = vk.to_sec1_uncompressed();
        let back = BrainpoolP512VerifyingKey::from_sec1(&bytes).expect("parse");
        assert_eq!(vk.to_sec1_uncompressed(), back.to_sec1_uncompressed());
    }

    #[test]
    fn cross_curve_p512_public_key_not_p256() {
        assert_ne!(
            TypeId::of::<BrainpoolPublicKey>(),
            TypeId::of::<BrainpoolP512PublicKey>()
        );
    }

    #[test]
    fn cross_curve_p512_shared_secret_not_p256() {
        assert_ne!(
            TypeId::of::<BrainpoolSharedSecret>(),
            TypeId::of::<BrainpoolP512SharedSecret>()
        );
    }

    #[test]
    fn cross_curve_p512_public_key_not_p384() {
        assert_ne!(
            TypeId::of::<BrainpoolP384PublicKey>(),
            TypeId::of::<BrainpoolP512PublicKey>()
        );
    }

    #[test]
    fn cross_curve_p512_shared_secret_not_p384() {
        assert_ne!(
            TypeId::of::<BrainpoolP384SharedSecret>(),
            TypeId::of::<BrainpoolP512SharedSecret>()
        );
    }
}
