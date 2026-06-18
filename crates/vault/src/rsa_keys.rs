//! RSA (software): OAEP-SHA256 encryption, RSASSA-PSS (SHA-256 / SHA-512), and RSASSA-PKCS1-v1_5-SHA256
//! for OpenPGP legacy interoperability.
//!
//! Private keys use the audited [`rsa`](https://docs.rs/rsa) crate (`zeroize` on drop for internal
//! CRT material per upstream version 0.9.9). The firmware supplies entropy through
//! [`galdr_core::hal::HardwareTrng`]; `getrandom` is not enabled on the `rsa` dependency.

use alloc::vec::Vec;
use core::fmt;

use galdr_core::hal::HardwareTrng;
use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::pss::{Pss, VerifyingKey};
use rsa::sha2::{Digest, Sha256, Sha512};
use rsa::signature::Verifier;
use rsa::traits::PublicKeyParts;
use rsa::{
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey},
    pss::Signature as PssSignatureInner,
};
use rsa::{Oaep, RsaPrivateKey as RsaPrivInner, RsaPublicKey as RsaPubInner};
use zeroize::Zeroize;

/// Minimum RSA modulus size accepted by this API (bits).
pub const RSA_MIN_MODULUS_BITS: usize = 2048;

/// Largest ciphertext size handled here (4096-bit modulus, bytes).
pub const RSA_MAX_CIPHERTEXT_BYTES: usize = 512;

/// Marker type. Callers must name [`Pkcs1v15`] to use PKCS#1 v1.5 signing or verification, so
/// accidental use in new protocols is visible in review.
///
/// For OpenPGP legacy interoperability only. Do not use in new protocol designs.
pub struct Pkcs1v15;

/// Errors from RSA operations, encoding, and key policy enforcement.
#[derive(Debug, Eq, PartialEq)]
pub enum RsaError {
    /// Modulus smaller than [`RSA_MIN_MODULUS_BITS`].
    KeyTooSmall {
        /// Observed modulus size in bits.
        bits: usize,
    },
    /// RSAES-OAEP decryption failed (including label mismatch).
    DecryptionFailed,
    /// Signing operation failed.
    SignatureFailed,
    /// Signature verification failed.
    VerificationFailed,
    /// DER/SPKI/PKCS#8 parse failure or non-UTF8 OAEP label when UTF-8 is required by the `rsa` OAEP helper.
    InvalidEncoding,
    /// Randomness required for encryption or signing was not available.
    TrngFailure,
    /// Key generation failed (embedded or host provisioning).
    KeyGeneration,
    /// Key generation `bits` is not one of the supported sizes for `generate` (2048, 3072, 4096).
    UnsupportedKeySize {
        /// Requested size in bits.
        bits: usize,
    },
}

impl fmt::Display for RsaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RsaError::KeyTooSmall { bits } => write!(f, "RSA modulus too small: {bits} bits"),
            RsaError::DecryptionFailed => write!(f, "RSA-OAEP decryption failed"),
            RsaError::SignatureFailed => write!(f, "RSA signing failed"),
            RsaError::VerificationFailed => write!(f, "RSA signature verification failed"),
            RsaError::InvalidEncoding => write!(f, "invalid RSA key encoding"),
            RsaError::TrngFailure => write!(f, "TRNG failure"),
            RsaError::KeyGeneration => write!(f, "RSA key generation failed"),
            RsaError::UnsupportedKeySize { bits } => {
                write!(f, "unsupported RSA key size for generation: {bits} bits")
            }
        }
    }
}

fn map_rsa_err(e: rsa::Error) -> RsaError {
    match e {
        rsa::Error::Pkcs8(e) => {
            let _ = e;
            RsaError::InvalidEncoding
        }
        rsa::Error::Decryption => RsaError::DecryptionFailed,
        rsa::Error::Verification => RsaError::VerificationFailed,
        _ => RsaError::InvalidEncoding,
    }
}

fn ensure_min_public_bits(pk: &RsaPubInner) -> Result<(), RsaError> {
    let bits = pk.n().bits();
    if bits < RSA_MIN_MODULUS_BITS {
        return Err(RsaError::KeyTooSmall { bits });
    }
    Ok(())
}

fn oaep_sha256(label: &[u8]) -> Result<Oaep, RsaError> {
    if label.is_empty() {
        return Ok(Oaep::new::<Sha256>());
    }
    let s = core::str::from_utf8(label).map_err(|_| RsaError::InvalidEncoding)?;
    Ok(Oaep::new_with_label::<Sha256, _>(s))
}

/// RSA private key. Minimum modulus 2048 bits. No `Clone` / `Copy`.
pub struct RsaPrivateKey {
    inner: RsaPrivInner,
}

/// RSA public key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RsaPublicKey {
    inner: RsaPubInner,
}

/// RSAES-OAEP / SHA-256 ciphertext (length equals modulus size in bytes).
pub struct RsaOaepCiphertext {
    buf: Vec<u8>,
}

/// RSASSA-PSS signature bytes (length equals modulus size in bytes for common exponents).
pub struct RsaPssSignature {
    buf: Vec<u8>,
}

/// RSASSA-PKCS1-v1_5 signature bytes.
pub struct RsaPkcs1Signature {
    buf: Vec<u8>,
}

/// Plaintext returned from RSA-OAEP decryption; zeroises on drop.
pub struct RsaPlaintext {
    buf: Vec<u8>,
}

/// PKCS#8 DER export of a private key; zeroises on drop.
pub struct RsaDerBytes {
    buf: zeroize::Zeroizing<Vec<u8>>,
}

impl RsaOaepCiphertext {
    /// Borrow raw ciphertext bytes.
    pub fn as_slice(&self) -> &[u8] {
        self.buf.as_slice()
    }

    /// Test/fuzz helper: build from untrusted bytes without validating length.
    #[doc(hidden)]
    pub fn from_bytes_fuzz(data: &[u8]) -> Self {
        Self { buf: data.to_vec() }
    }
}

impl RsaPssSignature {
    /// Borrow raw signature bytes.
    pub fn as_slice(&self) -> &[u8] {
        self.buf.as_slice()
    }

    #[doc(hidden)]
    pub fn from_bytes_fuzz(data: &[u8]) -> Self {
        Self { buf: data.to_vec() }
    }

    #[cfg(test)]
    fn flip_first_byte_for_test(&mut self) {
        if let Some(b) = self.buf.first_mut() {
            *b ^= 0x01;
        }
    }
}

impl RsaPkcs1Signature {
    /// Borrow raw signature bytes.
    pub fn as_slice(&self) -> &[u8] {
        self.buf.as_slice()
    }

    #[doc(hidden)]
    pub fn from_bytes_fuzz(data: &[u8]) -> Self {
        Self { buf: data.to_vec() }
    }
}

impl RsaPlaintext {
    /// Borrow decrypted bytes.
    pub fn as_slice(&self) -> &[u8] {
        self.buf.as_slice()
    }

    #[cfg(test)]
    pub(crate) fn as_mut_slice_for_test(&mut self) -> &mut [u8] {
        self.buf.as_mut_slice()
    }
}

impl zeroize::Zeroize for RsaPlaintext {
    fn zeroize(&mut self) {
        self.buf.zeroize();
    }
}

impl Drop for RsaPlaintext {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl RsaDerBytes {
    /// Borrow PKCS#8 DER bytes.
    pub fn as_slice(&self) -> &[u8] {
        self.buf.as_slice()
    }
}

impl Drop for RsaDerBytes {
    fn drop(&mut self) {
        self.buf.zeroize();
    }
}

impl RsaPrivateKey {
    /// Generate a new RSA key of `bits` (2048, 3072, or 4096). Slower on embedded hardware;
    /// prefer importing a provisioned key for devices.
    pub fn generate<T: HardwareTrng>(trng: &mut T, bits: usize) -> Result<Self, RsaError> {
        if bits != 2048 && bits != 3072 && bits != 4096 {
            return Err(RsaError::UnsupportedKeySize { bits });
        }
        if bits < RSA_MIN_MODULUS_BITS {
            return Err(RsaError::KeyTooSmall { bits });
        }
        let inner = RsaPrivInner::new(trng, bits).map_err(|_| RsaError::KeyGeneration)?;
        ensure_min_public_bits(inner.as_ref())?;
        Ok(Self { inner })
    }

    /// Import a private key from PKCS#8 DER. Rejects moduli under 2048 bits.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, RsaError> {
        let inner = RsaPrivInner::from_pkcs8_der(der).map_err(|_| RsaError::InvalidEncoding)?;
        ensure_min_public_bits(inner.as_ref())?;
        Ok(Self { inner })
    }

    /// Public half of this key pair.
    pub fn public_key(&self) -> RsaPublicKey {
        RsaPublicKey {
            inner: RsaPubInner::from(&self.inner),
        }
    }

    /// Decrypt using RSAES-OAEP with SHA-256 (and SHA-256 MGF1). `label` must be UTF-8 unless empty
    /// (empty label uses the standard empty-string OAEP label).
    pub fn decrypt_oaep(
        &self,
        ciphertext: &RsaOaepCiphertext,
        label: &[u8],
    ) -> Result<RsaPlaintext, RsaError> {
        ensure_min_public_bits(self.inner.as_ref())?;
        let padding = oaep_sha256(label)?;
        let pt = self
            .inner
            .decrypt(padding, ciphertext.as_slice())
            .map_err(map_rsa_err)?;
        Ok(RsaPlaintext { buf: pt })
    }

    /// Sign with RSASSA-PSS / SHA-256.
    pub fn sign_pss_sha256<T: HardwareTrng>(
        &self,
        message: &[u8],
        trng: &mut T,
    ) -> Result<RsaPssSignature, RsaError> {
        ensure_min_public_bits(self.inner.as_ref())?;
        let digest = Sha256::digest(message);
        let padding = Pss::new::<Sha256>();
        let sig = self
            .inner
            .sign_with_rng(trng, padding, digest.as_slice())
            .map_err(|_| RsaError::SignatureFailed)?;
        Ok(RsaPssSignature { buf: sig })
    }

    /// Sign with RSASSA-PSS / SHA-512.
    pub fn sign_pss_sha512<T: HardwareTrng>(
        &self,
        message: &[u8],
        trng: &mut T,
    ) -> Result<RsaPssSignature, RsaError> {
        ensure_min_public_bits(self.inner.as_ref())?;
        let digest = Sha512::digest(message);
        let padding = Pss::new::<Sha512>();
        let sig = self
            .inner
            .sign_with_rng(trng, padding, digest.as_slice())
            .map_err(|_| RsaError::SignatureFailed)?;
        Ok(RsaPssSignature { buf: sig })
    }

    /// Sign with RSASSA-PKCS1-v1_5 / SHA-256.
    ///
    /// For OpenPGP legacy interoperability only. Do not use in new protocol designs.
    pub fn sign_pkcs1_sha256(
        &self,
        _marker: Pkcs1v15,
        message: &[u8],
    ) -> Result<RsaPkcs1Signature, RsaError> {
        let _ = _marker;
        ensure_min_public_bits(self.inner.as_ref())?;
        let digest = Sha256::digest(message);
        let padding = Pkcs1v15Sign::new::<Sha256>();
        let sig = self
            .inner
            .sign(padding, digest.as_slice())
            .map_err(|_| RsaError::SignatureFailed)?;
        Ok(RsaPkcs1Signature { buf: sig })
    }

    /// Export PKCS#8 DER (sensitive; [`RsaDerBytes`] zeroises on drop).
    pub fn to_pkcs8_der(&self) -> Result<RsaDerBytes, RsaError> {
        let doc = self
            .inner
            .to_pkcs8_der()
            .map_err(|_| RsaError::InvalidEncoding)?;
        Ok(RsaDerBytes {
            buf: zeroize::Zeroizing::new(doc.as_bytes().to_vec()),
        })
    }
}

impl RsaPublicKey {
    /// Import SPKI / SubjectPublicKeyInfo DER. Rejects moduli under 2048 bits.
    pub fn from_spki_der(der: &[u8]) -> Result<Self, RsaError> {
        let inner = RsaPubInner::from_public_key_der(der).map_err(|_| RsaError::InvalidEncoding)?;
        ensure_min_public_bits(&inner)?;
        Ok(Self { inner })
    }

    /// Export SubjectPublicKeyInfo DER.
    pub fn to_spki_der(&self) -> Result<Vec<u8>, RsaError> {
        let doc = self
            .inner
            .to_public_key_der()
            .map_err(|_| RsaError::InvalidEncoding)?;
        Ok(doc.as_bytes().to_vec())
    }

    /// RSAES-OAEP encrypt with SHA-256.
    pub fn encrypt_oaep<T: HardwareTrng>(
        &self,
        plaintext: &[u8],
        label: &[u8],
        trng: &mut T,
    ) -> Result<RsaOaepCiphertext, RsaError> {
        ensure_min_public_bits(&self.inner)?;
        let padding = oaep_sha256(label)?;
        let ct = self
            .inner
            .encrypt(trng, padding, plaintext)
            .map_err(map_rsa_err)?;
        Ok(RsaOaepCiphertext { buf: ct })
    }

    /// Verify PSS / SHA-256.
    pub fn verify_pss_sha256(
        &self,
        message: &[u8],
        signature: &RsaPssSignature,
    ) -> Result<(), RsaError> {
        ensure_min_public_bits(&self.inner)?;
        let vk = VerifyingKey::<Sha256>::new(self.inner.clone());
        let sig = PssSignatureInner::try_from(signature.as_slice())
            .map_err(|_| RsaError::VerificationFailed)?;
        vk.verify(message, &sig)
            .map_err(|_| RsaError::VerificationFailed)
    }

    /// Verify PSS / SHA-512.
    pub fn verify_pss_sha512(
        &self,
        message: &[u8],
        signature: &RsaPssSignature,
    ) -> Result<(), RsaError> {
        ensure_min_public_bits(&self.inner)?;
        let vk = VerifyingKey::<Sha512>::new(self.inner.clone());
        let sig = PssSignatureInner::try_from(signature.as_slice())
            .map_err(|_| RsaError::VerificationFailed)?;
        vk.verify(message, &sig)
            .map_err(|_| RsaError::VerificationFailed)
    }

    /// Verify PKCS#1 v1.5 / SHA-256.
    ///
    /// For OpenPGP legacy interoperability only. Do not use in new protocol designs.
    pub fn verify_pkcs1_sha256(
        &self,
        _marker: Pkcs1v15,
        message: &[u8],
        signature: &RsaPkcs1Signature,
    ) -> Result<(), RsaError> {
        let _ = _marker;
        ensure_min_public_bits(&self.inner)?;
        use rsa::pkcs1v15::Signature as SigPkcs1;
        use rsa::pkcs1v15::VerifyingKey as VkPkcs1;
        let vk = VkPkcs1::<Sha256>::new(self.inner.clone());
        let sig =
            SigPkcs1::try_from(signature.as_slice()).map_err(|_| RsaError::VerificationFailed)?;
        vk.verify(message, &sig)
            .map_err(|_| RsaError::VerificationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use galdr_core::fake_hal::FakeTrng;

    #[test]
    #[ignore]
    fn test_rsa_keygen_2048() {
        let mut trng = FakeTrng::from_seed(0xC0FFEE);
        let k = RsaPrivateKey::generate(&mut trng, 2048).expect("gen");
        let _ = k.public_key();
    }

    /// Software baseline (median of 100 runs each); run with
    /// `cargo test -p vault rsa_perf_baseline -- --ignored --nocapture` and record in `docs/PERFORMANCE.md`.
    #[test]
    #[ignore]
    fn rsa_perf_baseline() {
        use core::time::Duration;
        let mut trng = FakeTrng::from_seed(0xBEEF);
        let key = RsaPrivateKey::generate(&mut trng, 2048).expect("gen");
        let pk = key.public_key();
        let mut tdec = std::vec::Vec::new();
        let mut tsign = std::vec::Vec::new();
        let mut tver = std::vec::Vec::new();
        let mut tr = FakeTrng::from_seed(1);
        let ct = pk.encrypt_oaep(b"bench-plain", b"", &mut tr).expect("enc");
        for _ in 0..100 {
            let i = std::time::Instant::now();
            let _ = key.decrypt_oaep(&ct, b"").expect("dec");
            tdec.push(i.elapsed());
        }
        let mut tr2 = FakeTrng::from_seed(2);
        for _ in 0..100 {
            let i = std::time::Instant::now();
            let _ = key.sign_pss_sha256(b"bench-msg", &mut tr2).expect("sign");
            tsign.push(i.elapsed());
        }
        let sig = key
            .sign_pss_sha256(b"bench-msg", &mut FakeTrng::from_seed(3))
            .expect("sig");
        for _ in 0..100 {
            let i = std::time::Instant::now();
            let _ = pk.verify_pss_sha256(b"bench-msg", &sig);
            tver.push(i.elapsed());
        }
        fn median(mut v: std::vec::Vec<Duration>) -> Duration {
            v.sort();
            v[v.len() / 2]
        }
        eprintln!(
            "RSA 2048 software baseline (median 100 runs): decrypt {:?} sign {:?} verify {:?}",
            median(tdec),
            median(tsign),
            median(tver)
        );
    }

    #[test]
    fn import_pkcs8_round_trip() -> Result<(), RsaError> {
        let mut trng = FakeTrng::from_seed(0xA11);
        let k = RsaPrivateKey::generate(&mut trng, 2048)?;
        let der = k.to_pkcs8_der()?;
        let k2 = RsaPrivateKey::from_pkcs8_der(der.as_slice())?;
        assert_eq!(
            k.public_key().to_spki_der()?,
            k2.public_key().to_spki_der()?
        );
        Ok(())
    }

    #[test]
    fn import_1024_rejected() {
        let der = include_bytes!("../tests/data/rsa_1024_priv.pk8");
        let r = RsaPrivateKey::from_pkcs8_der(der);
        assert!(matches!(r, Err(RsaError::KeyTooSmall { bits: 1024 })));
    }

    #[test]
    fn oaep_round_trip() -> Result<(), RsaError> {
        let mut trng = FakeTrng::from_seed(0x51);
        let k = RsaPrivateKey::generate(&mut trng, 2048)?;
        let pk = k.public_key();
        let label = b"ctx";
        let pt = b"hello-rsa";
        let mut trng2 = FakeTrng::from_seed(0x52);
        let ct = pk.encrypt_oaep(pt, label, &mut trng2)?;
        let out = k.decrypt_oaep(&ct, label)?;
        assert_eq!(out.as_slice(), pt);
        Ok(())
    }

    #[test]
    fn oaep_label_binding() -> Result<(), RsaError> {
        let mut trng = FakeTrng::from_seed(0x61);
        let k = RsaPrivateKey::generate(&mut trng, 2048)?;
        let pk = k.public_key();
        let mut trng2 = FakeTrng::from_seed(0x62);
        let ct = pk.encrypt_oaep(b"m", b"context-a", &mut trng2)?;
        let r = k.decrypt_oaep(&ct, b"context-b");
        assert!(matches!(r, Err(RsaError::DecryptionFailed)));
        Ok(())
    }

    #[test]
    fn pss_sha256_round_trip() -> Result<(), RsaError> {
        let mut trng = FakeTrng::from_seed(0x71);
        let k = RsaPrivateKey::generate(&mut trng, 2048)?;
        let pk = k.public_key();
        let msg = b"sign-me";
        let mut trng2 = FakeTrng::from_seed(0x72);
        let sig = k.sign_pss_sha256(msg, &mut trng2)?;
        pk.verify_pss_sha256(msg, &sig)?;
        Ok(())
    }

    #[test]
    fn pss_sha512_round_trip() -> Result<(), RsaError> {
        let mut trng = FakeTrng::from_seed(0x81);
        let k = RsaPrivateKey::generate(&mut trng, 2048)?;
        let pk = k.public_key();
        let msg = b"sign-me-sha512";
        let mut trng2 = FakeTrng::from_seed(0x82);
        let sig = k.sign_pss_sha512(msg, &mut trng2)?;
        pk.verify_pss_sha512(msg, &sig)?;
        Ok(())
    }

    #[test]
    fn pss_wrong_key_fails() -> Result<(), RsaError> {
        let mut t = FakeTrng::from_seed(1);
        let a = RsaPrivateKey::generate(&mut t, 2048)?;
        let mut t2 = FakeTrng::from_seed(2);
        let b = RsaPrivateKey::generate(&mut t2, 2048)?;
        let pk_b = b.public_key();
        let mut t3 = FakeTrng::from_seed(3);
        let sig = a.sign_pss_sha256(b"msg", &mut t3)?;
        let r = pk_b.verify_pss_sha256(b"msg", &sig);
        assert_eq!(r, Err(RsaError::VerificationFailed));
        Ok(())
    }

    #[test]
    fn pss_tampered_message_fails() -> Result<(), RsaError> {
        let mut t = FakeTrng::from_seed(4);
        let k = RsaPrivateKey::generate(&mut t, 2048)?;
        let pk = k.public_key();
        let mut t2 = FakeTrng::from_seed(5);
        let sig = k.sign_pss_sha256(b"msg", &mut t2)?;
        let r = pk.verify_pss_sha256(b"ms!", &sig);
        assert_eq!(r, Err(RsaError::VerificationFailed));
        Ok(())
    }

    #[test]
    fn pss_tampered_sig_fails() -> Result<(), RsaError> {
        let mut t = FakeTrng::from_seed(6);
        let k = RsaPrivateKey::generate(&mut t, 2048)?;
        let pk = k.public_key();
        let mut t2 = FakeTrng::from_seed(7);
        let mut sig = k.sign_pss_sha256(b"msg", &mut t2)?;
        sig.flip_first_byte_for_test();
        let r = pk.verify_pss_sha256(b"msg", &sig);
        assert_eq!(r, Err(RsaError::VerificationFailed));
        Ok(())
    }

    #[test]
    fn pkcs1_legacy_round_trip() -> Result<(), RsaError> {
        let mut t = FakeTrng::from_seed(8);
        let k = RsaPrivateKey::generate(&mut t, 2048)?;
        let pk = k.public_key();
        let sig = k.sign_pkcs1_sha256(Pkcs1v15, b"legacy")?;
        pk.verify_pkcs1_sha256(Pkcs1v15, b"legacy", &sig)?;
        Ok(())
    }

    #[test]
    fn rsa_plaintext_zeroize_on_drop() -> Result<(), RsaError> {
        let mut t = FakeTrng::from_seed(10);
        let k = RsaPrivateKey::generate(&mut t, 2048)?;
        let pk = k.public_key();
        let mut t2 = FakeTrng::from_seed(11);
        let ct = pk.encrypt_oaep(b"x", b"", &mut t2)?;
        let mut plain = k.decrypt_oaep(&ct, b"")?;
        plain.as_mut_slice_for_test().fill(0xAB);
        plain.zeroize();
        assert!(plain.as_slice().iter().all(|b| *b == 0));
        Ok(())
    }

    #[test]
    fn key_size_boundaries_generate() {
        let mut t = FakeTrng::from_seed(0);
        assert!(matches!(
            RsaPrivateKey::generate(&mut t, 1024),
            Err(RsaError::UnsupportedKeySize { bits: 1024 })
        ));
        let mut t = FakeTrng::from_seed(0);
        assert!(RsaPrivateKey::generate(&mut t, 2048).is_ok());
        let mut t = FakeTrng::from_seed(0);
        assert!(RsaPrivateKey::generate(&mut t, 2049).is_err());
    }
}
