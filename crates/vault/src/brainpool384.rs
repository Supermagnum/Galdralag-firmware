//! Brainpool P-384r1 (`brainpoolP384r1`) ECDH, SEC1 encoding, and ECDSA with SHA-384.
//!
//! # Implementation note
//!
//! RFC 5639 domain parameters for this curve are **not** duplicated here. They are fixed by the
//! audited RustCrypto [`bp384::BrainpoolP384r1`] type (Weierstrass curve over a 384-bit prime field).
//! The `bp384` crate uses the same `elliptic-curve` / `ecdsa` stack as `bp256` (Session 1).
//!
//! ECDSA digests: **SHA-384** (not SHA-256), matching the field size and Wycheproof vectors.

use crate::brainpool_common::BrainpoolError;
use bp384::BrainpoolP384r1;
use bp384::elliptic_curve::ecdh::diffie_hellman;
use bp384::elliptic_curve::pkcs8::DecodePublicKey;
use bp384::elliptic_curve::sec1::{FromSec1Point, Sec1Point, ToSec1Point};
use bp384::elliptic_curve::{PublicKey, SecretKey};
use ecdsa::der;
use ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use ecdsa::signature::{Signer, Verifier};
use ecdsa::{SigningKey, VerifyingKey};
use galdr_core::hal::HardwareTrng;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Rejection-sampling attempts when drawing a uniform scalar from the TRNG (must be in-range mod n).
const SCALAR_SAMPLE_TRIES: usize = 128;

/// Maximum DER-encoded ECDSA signature size for P-384 (r/s INTEGERs plus SEQUENCE overhead).
pub const MAX_DER_SIG_P384: usize = 150;

/// A non-zero scalar on BrainpoolP384r1. Zeroizes on drop. No Clone, no Copy.
#[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct BrainpoolP384Scalar(zeroize::Zeroizing<[u8; 48]>);

/// Uncompressed or compressed public key on BrainpoolP384r1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrainpoolP384PublicKey(PublicKey<BrainpoolP384r1>);

/// ECDH shared secret (x-coordinate bytes). Zeroizes on drop. No Clone, no Copy.
#[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct BrainpoolP384SharedSecret(zeroize::Zeroizing<[u8; 48]>);

/// ECDSA signing key. Zeroizes on drop. No Clone, no Copy.
pub struct BrainpoolP384SigningKey(SigningKey<BrainpoolP384r1>);

/// ECDSA verifying key (public).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrainpoolP384VerifyingKey(VerifyingKey<BrainpoolP384r1>);

/// DER-encoded ECDSA signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrainpoolP384Signature {
    der: heapless::Vec<u8, MAX_DER_SIG_P384>,
}

impl BrainpoolP384Signature {
    /// DER-encoded signature bytes.
    pub fn from_der_bytes(bytes: &[u8]) -> Result<Self, BrainpoolError> {
        let mut der = heapless::Vec::new();
        for b in bytes {
            der.push(*b).map_err(|_| BrainpoolError::InvalidSignature)?;
        }
        Ok(BrainpoolP384Signature { der })
    }

    /// Borrow the DER-encoded signature.
    pub fn der_bytes(&self) -> &[u8] {
        self.der.as_slice()
    }
}

#[cfg(test)]
impl BrainpoolP384Signature {
    pub(crate) fn from_der_bytes_for_test(bytes: &[u8]) -> Result<Self, BrainpoolError> {
        let mut der = heapless::Vec::new();
        for b in bytes {
            der.push(*b).map_err(|_| BrainpoolError::InvalidSignature)?;
        }
        Ok(BrainpoolP384Signature { der })
    }

    pub(crate) fn xor_first_byte_for_test(&mut self) {
        if let Some(b) = self.der.get_mut(0) {
            *b ^= 0x01;
        }
    }
}

impl BrainpoolP384Scalar {
    fn secret_key(&self) -> Result<SecretKey<BrainpoolP384r1>, BrainpoolError> {
        SecretKey::from_slice(self.0.as_ref()).map_err(|_| BrainpoolError::InvalidScalar)
    }

    /// Generate a random scalar using the provided TRNG source.
    pub fn generate<T: HardwareTrng>(trng: &mut T) -> Result<Self, BrainpoolError> {
        for _ in 0..SCALAR_SAMPLE_TRIES {
            let mut raw = [0u8; 48];
            trng
                .try_fill_bytes(&mut raw)
                .map_err(|_| BrainpoolError::TrngFailure)?;
            if let Ok(sk) = SecretKey::<BrainpoolP384r1>::from_slice(&raw) {
                raw.zeroize();
                let fb = sk.to_bytes();
                let mut arr = [0u8; 48];
                arr.copy_from_slice(fb.as_slice());
                return Ok(Self(zeroize::Zeroizing::new(arr)));
            }
            raw.zeroize();
        }
        Err(BrainpoolError::TrngFailure)
    }

    /// Derive the corresponding public key.
    pub fn public_key(&self) -> Result<BrainpoolP384PublicKey, BrainpoolError> {
        let pk = self.secret_key()?.public_key();
        Ok(BrainpoolP384PublicKey(pk))
    }

    /// Perform ECDH with a peer's public key.
    pub fn diffie_hellman(
        &self,
        peer: &BrainpoolP384PublicKey,
    ) -> Result<BrainpoolP384SharedSecret, BrainpoolError> {
        let affine = peer.0.as_affine();
        if bool::from(affine.is_identity()) {
            return Err(BrainpoolError::PointAtInfinity);
        }
        let shared = diffie_hellman(self.secret_key()?.to_nonzero_scalar(), peer.0.as_affine());
        let raw = shared.raw_secret_bytes();
        let mut out = [0u8; 48];
        if raw.as_slice().len() != out.len() {
            return Err(BrainpoolError::InvalidPoint);
        }
        out.copy_from_slice(raw.as_slice());
        Ok(BrainpoolP384SharedSecret(zeroize::Zeroizing::new(out)))
    }

    /// Build a scalar from raw secret key bytes (Wycheproof / interoperability).
    pub fn from_secret_key_bytes_for_test(bytes: &[u8]) -> Result<Self, BrainpoolError> {
        let sk = SecretKey::<BrainpoolP384r1>::from_slice(bytes)
            .map_err(|_| BrainpoolError::InvalidScalar)?;
        let fb = sk.to_bytes();
        let mut arr = [0u8; 48];
        arr.copy_from_slice(fb.as_slice());
        Ok(Self(zeroize::Zeroizing::new(arr)))
    }

    pub fn to_secret_bytes_for_test(&self) -> [u8; 48] {
        let s = self.0.as_ref();
        let mut out = [0u8; 48];
        out.copy_from_slice(s);
        out
    }
}

impl BrainpoolP384PublicKey {
    /// Deserialise an X.509 / SPKI `SubjectPublicKeyInfo` DER blob (as in Wycheproof `encoding: asn`).
    pub fn from_public_key_der(bytes: &[u8]) -> Result<Self, BrainpoolError> {
        let pk = PublicKey::from_public_key_der(bytes).map_err(|_| BrainpoolError::InvalidPoint)?;
        Ok(BrainpoolP384PublicKey(pk))
    }

    /// Serialise to uncompressed SEC1 form (97 bytes: `0x04` || x || y).
    pub fn to_sec1_uncompressed(&self) -> [u8; 97] {
        let enc = self.0.to_sec1_point(false);
        let mut out = [0u8; 97];
        let b = enc.as_bytes();
        out.copy_from_slice(b);
        out
    }

    /// Deserialise from SEC1 (compressed or uncompressed). Rejects infinity and invalid points.
    pub fn from_sec1(bytes: &[u8]) -> Result<Self, BrainpoolError> {
        let point = Sec1Point::<BrainpoolP384r1>::from_bytes(bytes)
            .map_err(|_| BrainpoolError::InvalidPoint)?;
        if point.is_identity() {
            return Err(BrainpoolError::PointAtInfinity);
        }
        let pk = PublicKey::from_sec1_point(&point)
            .into_option()
            .ok_or(BrainpoolError::InvalidPoint)?;
        Ok(BrainpoolP384PublicKey(pk))
    }
}

impl BrainpoolP384SharedSecret {
    /// Constant-time equality of raw shared secret bytes.
    pub fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.as_bytes().ct_eq(other.as_bytes())
    }

    /// Raw shared secret bytes (for KDFs and tests).
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl BrainpoolP384SigningKey {
    /// Generate a new signing key using the TRNG.
    pub fn generate<T: HardwareTrng>(trng: &mut T) -> Result<Self, BrainpoolError> {
        for _ in 0..SCALAR_SAMPLE_TRIES {
            let mut raw = [0u8; 48];
            trng
                .try_fill_bytes(&mut raw)
                .map_err(|_| BrainpoolError::TrngFailure)?;
            if let Ok(sk) = SigningKey::<BrainpoolP384r1>::from_slice(&raw) {
                raw.zeroize();
                return Ok(Self(sk));
            }
            raw.zeroize();
        }
        Err(BrainpoolError::TrngFailure)
    }

    /// Return the corresponding verifying key.
    pub fn verifying_key(&self) -> BrainpoolP384VerifyingKey {
        BrainpoolP384VerifyingKey(*self.0.verifying_key())
    }

    /// Sign a message using ECDSA with SHA-384 (digest computed internally).
    ///
    /// The TRNG is required for API symmetry with other vault signing entry points; the `ecdsa`
    /// crate uses deterministic ECDSA (RFC 6979) with SHA-384 for this curve.
    pub fn sign<T: HardwareTrng>(
        &self,
        message: &[u8],
        #[allow(unused_variables)] trng: &mut T,
    ) -> Result<BrainpoolP384Signature, BrainpoolError> {
        let sig: der::Signature<BrainpoolP384r1> = self
            .0
            .try_sign(message)
            .map_err(|_| BrainpoolError::InvalidSignature)?;
        let mut v = heapless::Vec::new();
        for b in sig.as_bytes() {
            v.push(*b).map_err(|_| BrainpoolError::InvalidSignature)?;
        }
        Ok(BrainpoolP384Signature { der: v })
    }

    /// Sign `SHA256(preimage)` using ECDSA prehash signing (RFC 6979 over the digest bytes).
    pub fn sign_handshake_sha256_prehash<T: HardwareTrng>(
        &self,
        preimage: &[u8],
        #[allow(unused_variables)] trng: &mut T,
    ) -> Result<BrainpoolP384Signature, BrainpoolError> {
        let digest = Sha256::digest(preimage);
        let sig: der::Signature<BrainpoolP384r1> = self
            .0
            .sign_prehash(digest.as_slice())
            .map_err(|_| BrainpoolError::InvalidSignature)?;
        let mut v = heapless::Vec::new();
        for b in sig.as_bytes() {
            v.push(*b).map_err(|_| BrainpoolError::InvalidSignature)?;
        }
        Ok(BrainpoolP384Signature { der: v })
    }

    #[doc(hidden)]
    pub fn to_scalar_bytes_for_test(&self) -> [u8; 48] {
        let fb = self.0.to_bytes();
        let mut a = [0u8; 48];
        a.copy_from_slice(fb.as_slice());
        a
    }

    #[doc(hidden)]
    pub fn from_scalar_bytes_for_test(bytes: &[u8; 48]) -> Result<Self, BrainpoolError> {
        let sk = SigningKey::from_slice(bytes.as_slice()).map_err(|_| BrainpoolError::InvalidScalar)?;
        Ok(Self(sk))
    }
}

impl BrainpoolP384VerifyingKey {
    /// Deserialise a verifying key from X.509 / SPKI `SubjectPublicKeyInfo` DER (Wycheproof `publicKeyDer`).
    pub fn from_public_key_der(bytes: &[u8]) -> Result<Self, BrainpoolError> {
        let vk =
            VerifyingKey::from_public_key_der(bytes).map_err(|_| BrainpoolError::InvalidPoint)?;
        Ok(BrainpoolP384VerifyingKey(vk))
    }

    /// Verify an ECDSA-SHA384 signature over `message`.
    pub fn verify(
        &self,
        message: &[u8],
        signature: &BrainpoolP384Signature,
    ) -> Result<(), BrainpoolError> {
        let sig = der::Signature::from_bytes(signature.der.as_slice())
            .map_err(|_| BrainpoolError::InvalidSignature)?;
        self.0
            .verify(message, &sig)
            .map_err(|_| BrainpoolError::InvalidSignature)
    }

    /// Verify a signature over `SHA256(preimage)` (paired with [`BrainpoolP384SigningKey::sign_handshake_sha256_prehash`]).
    pub fn verify_handshake_sha256_prehash(
        &self,
        preimage: &[u8],
        signature: &BrainpoolP384Signature,
    ) -> Result<(), BrainpoolError> {
        let digest = Sha256::digest(preimage);
        let sig = der::Signature::from_bytes(signature.der.as_slice())
            .map_err(|_| BrainpoolError::InvalidSignature)?;
        self.0
            .verify_prehash(digest.as_slice(), &sig)
            .map_err(|_| BrainpoolError::InvalidSignature)
    }

    /// Serialise to uncompressed SEC1 (97 bytes).
    pub fn to_sec1_uncompressed(&self) -> [u8; 97] {
        let enc = self.0.to_sec1_point(false);
        let mut out = [0u8; 97];
        let b = enc.as_bytes();
        out.copy_from_slice(b);
        out
    }

    /// Deserialise verifying key from SEC1 (compressed or uncompressed).
    pub fn from_sec1(bytes: &[u8]) -> Result<Self, BrainpoolError> {
        let vk = VerifyingKey::from_sec1_bytes(bytes).map_err(|_| BrainpoolError::InvalidPoint)?;
        Ok(BrainpoolP384VerifyingKey(vk))
    }
}

#[cfg(test)]
impl BrainpoolP384PublicKey {
    /// Test-only construction from a `PublicKey` (e.g. identity handling checks).
    pub fn from_public_key_for_test(pk: PublicKey<BrainpoolP384r1>) -> Self {
        Self(pk)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::brainpool::{BrainpoolPublicKey, BrainpoolSharedSecret};
    use bp384::elliptic_curve::sec1::Sec1Point;
    use galdr_core::fake_hal::FakeTrng;
    use std::any::TypeId;

    /// RFC 5639 generator for brainpoolP384r1, uncompressed SEC1 (`0x04` || Gx || Gy).
    const G_SEC1: [u8; 97] = [
        0x04,
        0x1d, 0x1c, 0x64, 0xf0, 0x68, 0xcf, 0x45, 0xff, 0xa2, 0xa6, 0x3a, 0x81, 0xb7, 0xc1,
        0x3f, 0x6b, 0x88, 0x47, 0xa3, 0xe7, 0x7e, 0xf1, 0x4f, 0xe3, 0xdb, 0x7f, 0xca, 0xfe,
        0x0c, 0xbd, 0x10, 0xe8, 0xe8, 0x26, 0xe0, 0x34, 0x36, 0xd6, 0x46, 0xaa, 0xef, 0x87,
        0xb2, 0xe2, 0x47, 0xd4, 0xaf, 0x1e,
        0x8a, 0xbe, 0x1d, 0x75, 0x20, 0xf9, 0xc2, 0xa4, 0x5c, 0xb1, 0xeb, 0x8e, 0x95, 0xcf,
        0xd5, 0x52, 0x62, 0xb7, 0x0b, 0x29, 0xfe, 0xec, 0x58, 0x64, 0xe1, 0x9c, 0x05, 0x4f,
        0xf9, 0x91, 0x29, 0x28, 0x0e, 0x46, 0x46, 0x21, 0x77, 0x91, 0x81, 0x11, 0x42, 0x82,
        0x03, 0x41, 0x26, 0x3c, 0x53, 0x15,
    ];

    #[test]
    fn generator_point_on_curve() {
        let pk = BrainpoolP384PublicKey::from_sec1(&G_SEC1);
        assert!(pk.is_ok(), "generator must parse as valid SEC1 point");
    }

    #[test]
    fn key_generation_round_trip() {
        let mut trng = FakeTrng::from_seed(0xC0FFEE);
        let sk = BrainpoolP384Scalar::generate(&mut trng).expect("scalar");
        let pk1 = sk.public_key().expect("pk1");
        let pk2 = sk.public_key().expect("pk2");
        assert_eq!(pk1.to_sec1_uncompressed(), pk2.to_sec1_uncompressed());
    }

    #[test]
    fn ecdh_commutativity() {
        let mut ta = FakeTrng::from_seed(1);
        let mut tb = FakeTrng::from_seed(2);
        let a = BrainpoolP384Scalar::generate(&mut ta).expect("a");
        let b = BrainpoolP384Scalar::generate(&mut tb).expect("b");
        let pa = a.public_key().expect("pa");
        let pb = b.public_key().expect("pb");
        let sa = a.diffie_hellman(&pb).expect("sa");
        let sb = b.diffie_hellman(&pa).expect("sb");
        assert!(bool::from(sa.ct_eq(&sb)));
    }

    #[test]
    fn sec1_round_trip_uncompressed() {
        let mut trng = FakeTrng::from_seed(4);
        let sk = BrainpoolP384Scalar::generate(&mut trng).expect("sk");
        let pk = sk.public_key().expect("pk");
        let bytes = pk.to_sec1_uncompressed();
        let back = BrainpoolP384PublicKey::from_sec1(&bytes).expect("parse");
        assert_eq!(pk.to_sec1_uncompressed(), back.to_sec1_uncompressed());
    }

    #[test]
    fn sec1_rejects_point_not_on_curve() {
        let mut bad = [0u8; 97];
        bad[0] = 0x04;
        bad[1..].fill(0x7f);
        let r = BrainpoolP384PublicKey::from_sec1(&bad);
        assert_eq!(r, Err(BrainpoolError::InvalidPoint));
    }

    #[test]
    fn shared_secret_compare_constant_time() {
        let mut t = FakeTrng::from_seed(5);
        let a = BrainpoolP384Scalar::generate(&mut t).expect("a");
        let b = BrainpoolP384Scalar::generate(&mut t).expect("b");
        let pa = a.public_key().expect("pa");
        let pb = b.public_key().expect("pb");
        let sa = a.diffie_hellman(&pb).expect("sa");
        let sb = b.diffie_hellman(&pa).expect("sb");
        assert!(bool::from(sa.as_bytes().ct_eq(sb.as_bytes())));
    }

    #[test]
    fn encoded_identity_rejected_by_from_sec1() {
        let enc = Sec1Point::<BrainpoolP384r1>::identity();
        let r = BrainpoolP384PublicKey::from_sec1(enc.as_bytes());
        assert_eq!(r, Err(BrainpoolError::PointAtInfinity));
    }

    #[test]
    fn ecdsa_sign_verify_round_trip() {
        let mut trng = FakeTrng::from_seed(0xA11CE);
        let sk = BrainpoolP384SigningKey::generate(&mut trng).expect("sk");
        let vk = sk.verifying_key();
        let msg = b"galdr brainpool p384 ecdsa vector";
        let sig = sk.sign(msg, &mut trng).expect("sign");
        assert!(vk.verify(msg, &sig).is_ok());
    }

    #[test]
    fn ecdsa_reject_wrong_key() {
        let mut t1 = FakeTrng::from_seed(1);
        let mut t2 = FakeTrng::from_seed(2);
        let sk_a = BrainpoolP384SigningKey::generate(&mut t1).expect("a");
        let sk_b = BrainpoolP384SigningKey::generate(&mut t2).expect("b");
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
        let sk = BrainpoolP384SigningKey::generate(&mut trng).expect("sk");
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
        let sk = BrainpoolP384SigningKey::generate(&mut trng).expect("sk");
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
        let sk = BrainpoolP384SigningKey::generate(&mut trng).expect("sk");
        let vk = sk.verifying_key();
        let bytes = vk.to_sec1_uncompressed();
        let back = BrainpoolP384VerifyingKey::from_sec1(&bytes).expect("parse");
        assert_eq!(vk.to_sec1_uncompressed(), back.to_sec1_uncompressed());
    }

    #[test]
    fn cross_curve_p384_public_key_not_p256() {
        assert_ne!(
            TypeId::of::<BrainpoolPublicKey>(),
            TypeId::of::<BrainpoolP384PublicKey>()
        );
    }

    #[test]
    fn cross_curve_p384_shared_secret_not_p256() {
        assert_ne!(
            TypeId::of::<BrainpoolSharedSecret>(),
            TypeId::of::<BrainpoolP384SharedSecret>()
        );
    }
}
