//! ECDSA over Brainpool P-256r1 with SHA-256 (audited `bp256` / `ecdsa` stack).

use crate::brainpool_common::BrainpoolError;
use bp256::BrainpoolP256r1;
use bp256::elliptic_curve::pkcs8::DecodePublicKey;
use ecdsa::der;
use ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use ecdsa::signature::{Signer, Verifier};
use ecdsa::{SigningKey, VerifyingKey};
use galdr_core::hal::HardwareTrng;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

/// Rejection-sampling attempts when drawing a signing scalar from the TRNG (must be in-range mod n).
const SCALAR_SAMPLE_TRIES: usize = 128;

/// Maximum DER-encoded ECDSA signature size for P-256 (brainpool uses the same coordinate sizes).
const MAX_DER_SIG: usize = 72;

/// A BrainpoolP256r1 ECDSA signing key. Zeroizes on drop. No Clone, no Copy.
///
/// The inner [`SigningKey`] implements [`ZeroizeOnDrop`]; dropping this wrapper zeroizes the scalar.
pub struct BrainpoolSigningKey(SigningKey<BrainpoolP256r1>);

/// A BrainpoolP256r1 ECDSA verifying key (public).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrainpoolVerifyingKey(VerifyingKey<BrainpoolP256r1>);

/// A DER-encoded ECDSA signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrainpoolSignature {
    der: heapless::Vec<u8, MAX_DER_SIG>,
}

impl BrainpoolSignature {
    /// DER-encoded signature bytes (RFC 5480 / ECDSA-Sig-Value).
    pub fn from_der_bytes(bytes: &[u8]) -> Result<Self, BrainpoolError> {
        let mut der = heapless::Vec::new();
        for b in bytes {
            der.push(*b).map_err(|_| BrainpoolError::InvalidSignature)?;
        }
        Ok(BrainpoolSignature { der })
    }

    /// Borrow the DER-encoded signature.
    pub fn der_bytes(&self) -> &[u8] {
        self.der.as_slice()
    }
}

#[cfg(test)]
impl BrainpoolSignature {
    pub(crate) fn from_der_bytes_for_test(bytes: &[u8]) -> Result<Self, BrainpoolError> {
        let mut der = heapless::Vec::new();
        for b in bytes {
            der.push(*b).map_err(|_| BrainpoolError::InvalidSignature)?;
        }
        Ok(BrainpoolSignature { der })
    }

    pub(crate) fn xor_first_byte_for_test(&mut self) {
        if let Some(b) = self.der.get_mut(0) {
            *b ^= 0x01;
        }
    }
}

impl BrainpoolSigningKey {
    /// Generate a new signing key using the TRNG.
    pub fn generate<T: HardwareTrng>(trng: &mut T) -> Result<Self, BrainpoolError> {
        for _ in 0..SCALAR_SAMPLE_TRIES {
            let mut raw = [0u8; 32];
            trng
                .try_fill_bytes(&mut raw)
                .map_err(|_| BrainpoolError::TrngFailure)?;
            if let Ok(sk) = SigningKey::<BrainpoolP256r1>::from_slice(&raw) {
                raw.zeroize();
                return Ok(Self(sk));
            }
            raw.zeroize();
        }
        Err(BrainpoolError::TrngFailure)
    }

    /// Return the corresponding verifying key.
    pub fn verifying_key(&self) -> BrainpoolVerifyingKey {
        BrainpoolVerifyingKey(*self.0.verifying_key())
    }

    /// Sign a message. The digest (SHA-256) is computed internally.
    ///
    /// The TRNG is required by the vault API for protocol symmetry; signing uses deterministic
    /// ECDSA (RFC 6979) over SHA-256 via the `ecdsa` crate, so the TRNG is not mixed into `k`.
    pub fn sign<T: HardwareTrng>(
        &self,
        message: &[u8],
        #[allow(unused_variables)] trng: &mut T,
    ) -> Result<BrainpoolSignature, BrainpoolError> {
        let sig: der::Signature<BrainpoolP256r1> = self
            .0
            .try_sign(message)
            .map_err(|_| BrainpoolError::InvalidSignature)?;
        let mut v = heapless::Vec::new();
        for b in sig.as_bytes() {
            v.push(*b).map_err(|_| BrainpoolError::InvalidSignature)?;
        }
        Ok(BrainpoolSignature { der: v })
    }

    /// Sign `SHA256(preimage)` using ECDSA prehash signing (RFC 6979 over the digest bytes).
    ///
    /// Used by the authenticated ephemeral ECDH handshake so all Brainpool curves hash the
    /// transcript with SHA-256 before ECDSA, while the curve-specific ECDSA group still applies.
    pub fn sign_handshake_sha256_prehash<T: HardwareTrng>(
        &self,
        preimage: &[u8],
        #[allow(unused_variables)] trng: &mut T,
    ) -> Result<BrainpoolSignature, BrainpoolError> {
        let digest = Sha256::digest(preimage);
        let sig: der::Signature<BrainpoolP256r1> = self
            .0
            .sign_prehash(digest.as_slice())
            .map_err(|_| BrainpoolError::InvalidSignature)?;
        let mut v = heapless::Vec::new();
        for b in sig.as_bytes() {
            v.push(*b).map_err(|_| BrainpoolError::InvalidSignature)?;
        }
        Ok(BrainpoolSignature { der: v })
    }

    #[doc(hidden)]
    pub fn to_scalar_bytes_for_test(&self) -> [u8; 32] {
        let fb = self.0.to_bytes();
        let mut a = [0u8; 32];
        a.copy_from_slice(fb.as_slice());
        a
    }

    #[doc(hidden)]
    pub fn from_scalar_bytes_for_test(bytes: &[u8; 32]) -> Result<Self, BrainpoolError> {
        let sk = SigningKey::from_slice(bytes.as_slice()).map_err(|_| BrainpoolError::InvalidScalar)?;
        Ok(Self(sk))
    }
}

impl BrainpoolVerifyingKey {
    /// Deserialise a verifying key from X.509 / SPKI `SubjectPublicKeyInfo` DER (Wycheproof `publicKeyDer`).
    pub fn from_public_key_der(bytes: &[u8]) -> Result<Self, BrainpoolError> {
        let vk =
            VerifyingKey::from_public_key_der(bytes).map_err(|_| BrainpoolError::InvalidPoint)?;
        Ok(BrainpoolVerifyingKey(vk))
    }

    /// Verify a signature over a message.
    pub fn verify(
        &self,
        message: &[u8],
        signature: &BrainpoolSignature,
    ) -> Result<(), BrainpoolError> {
        let sig = der::Signature::from_bytes(signature.der.as_slice())
            .map_err(|_| BrainpoolError::InvalidSignature)?;
        self.0
            .verify(message, &sig)
            .map_err(|_| BrainpoolError::InvalidSignature)
    }

    /// Verify a signature over `SHA256(preimage)` (paired with [`BrainpoolSigningKey::sign_handshake_sha256_prehash`]).
    pub fn verify_handshake_sha256_prehash(
        &self,
        preimage: &[u8],
        signature: &BrainpoolSignature,
    ) -> Result<(), BrainpoolError> {
        let digest = Sha256::digest(preimage);
        let sig = der::Signature::from_bytes(signature.der.as_slice())
            .map_err(|_| BrainpoolError::InvalidSignature)?;
        self.0
            .verify_prehash(digest.as_slice(), &sig)
            .map_err(|_| BrainpoolError::InvalidSignature)
    }

    /// Serialise to uncompressed SEC1 (65 bytes).
    pub fn to_sec1_uncompressed(&self) -> [u8; 65] {
        let enc = self.0.to_sec1_point(false);
        let mut out = [0u8; 65];
        let b = enc.as_bytes();
        if b.len() == 65 {
            out.copy_from_slice(b);
        }
        out
    }

    /// Deserialise verifying key from SEC1 (compressed or uncompressed).
    pub fn from_sec1(bytes: &[u8]) -> Result<Self, BrainpoolError> {
        let vk = VerifyingKey::from_sec1_bytes(bytes).map_err(|_| BrainpoolError::InvalidPoint)?;
        Ok(BrainpoolVerifyingKey(vk))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use galdr_core::fake_hal::FakeTrng;

    #[test]
    fn ecdsa_sign_verify_round_trip() {
        let mut trng = FakeTrng::from_seed(0xA11CE);
        let sk = BrainpoolSigningKey::generate(&mut trng).expect("sk");
        let vk = sk.verifying_key();
        let msg = b"galdr brainpool ecdsa vector";
        let sig = sk.sign(msg, &mut trng).expect("sign");
        assert!(vk.verify(msg, &sig).is_ok());
    }

    #[test]
    fn ecdsa_reject_wrong_key() {
        let mut t1 = FakeTrng::from_seed(1);
        let mut t2 = FakeTrng::from_seed(2);
        let sk_a = BrainpoolSigningKey::generate(&mut t1).expect("a");
        let sk_b = BrainpoolSigningKey::generate(&mut t2).expect("b");
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
        let sk = BrainpoolSigningKey::generate(&mut trng).expect("sk");
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
        let sk = BrainpoolSigningKey::generate(&mut trng).expect("sk");
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
        let sk = BrainpoolSigningKey::generate(&mut trng).expect("sk");
        let vk = sk.verifying_key();
        let bytes = vk.to_sec1_uncompressed();
        let back = BrainpoolVerifyingKey::from_sec1(&bytes).expect("parse");
        assert_eq!(vk.to_sec1_uncompressed(), back.to_sec1_uncompressed());
    }
}
