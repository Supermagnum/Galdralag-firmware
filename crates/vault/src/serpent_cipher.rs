//! Serpent-256 authenticated encryption (Encrypt-then-MAC) and CTR helper.
//!
//! # AEAD choice: Serpent-EtM (HMAC-SHA256)
//!
//! Serpent-GCM (GHASH over Serpent-CTR) is not used here because the workspace does not ship a
//! generic GCM composition for non-AES block ciphers, and duplicating GHMAC wiring would add
//! review surface without a clear gain over a well-understood EtM construction.
//!
//! This module implements **Encrypt-then-MAC**:
//! - Ciphertext = Serpent-CTR(key_cipher, nonce, plaintext)
//! - Tag = HMAC-SHA256(key_mac, `aad` || `nonce` || ciphertext_body)
//! - On decrypt, HMAC is verified before any plaintext is released.
//!
//! Keys are derived with HKDF-SHA256: 64 bytes expanded from the PRK, split into two 256-bit keys
//! (cipher + MAC). The Serpent block cipher implementation is the audited RustCrypto `serpent`
//! crate (`BlockCipher` / `KeyInit` from `cipher`).
//!
//! **Security invariants**
//! - Tag verification uses `hmac::Mac::verify` (constant-time comparison).
//! - Authentication failures zeroise the working plaintext buffer before `Err` is returned.
//! - Unauthenticated CTR (`serpent_ctr_unauthenticated`) must only be used when a higher layer
//!   provides integrity; it is `#[doc(hidden)]` for protocol compositions.

use crate::kdf_policy::KeyPurpose;
use galdr_core::hal::HardwareTrng;
use hkdf::Hkdf;
use hmac::digest::KeyInit as HmacKeyInit;
use hmac::{Hmac, Mac};
use subtle::ConstantTimeEq;
use serpent::cipher::array::Array;
use serpent::cipher::consts::U16;
use serpent::cipher::{BlockCipherEncrypt, KeyInit as CipherKeyInit};
use serpent::Serpent;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// HMAC-SHA256 tag length (EtM).
pub const SERPENT_TAG_LEN: usize = 32;

/// Maximum plaintext length for this vault profile (matches ChaCha20-Poly1305 bound).
pub const MAX_SERPENT_PLAINTEXT: usize = 8192;

/// Maximum stored ciphertext: plaintext + tag.
pub const MAX_SERPENT_CIPHERTEXT: usize = MAX_SERPENT_PLAINTEXT + SERPENT_TAG_LEN;

type HmacSha256 = Hmac<Sha256>;

/// Errors from Serpent key derivation, CTR, and EtM operations.
#[derive(Debug, Eq, PartialEq)]
pub enum SerpentError {
    /// HMAC tag verification failed or ciphertext was truncated.
    AuthenticationFailed,
    /// HKDF expand failed or label construction failed.
    KeyDerivation,
    /// TRNG could not supply nonce bytes.
    TrngFailure,
    /// Plaintext or ciphertext length exceeds the vault buffer bound.
    InvalidLength,
    /// Block cipher or HMAC operation failed (e.g. invalid key length).
    CipherError,
}

/// A Serpent-256 key schedule plus independent HMAC key (both from HKDF). Zeroizes on drop.
/// No `Clone`, no `Copy`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SerpentKey {
    cipher_key: zeroize::Zeroizing<[u8; 32]>,
    mac_key: zeroize::Zeroizing<[u8; 32]>,
}

/// A 128-bit (16-byte) IV for Serpent-CTR and EtM (used as the initial counter block).
#[derive(Clone, Eq, PartialEq)]
pub struct SerpentNonce([u8; 16]);

/// Authenticated ciphertext: body + appended HMAC-SHA256 tag.
#[derive(Clone, Eq, PartialEq)]
pub struct SerpentCiphertext {
    buf: heapless::Vec<u8, MAX_SERPENT_CIPHERTEXT>,
}

/// Decrypted plaintext; zeroizes on drop.
pub struct SerpentPlaintext {
    buf: heapless::Vec<u8, MAX_SERPENT_PLAINTEXT>,
}

impl SerpentKey {
    /// Derive cipher and MAC keys from HKDF-SHA256 for the given `KeyPurpose` and extra `info`.
    pub fn derive(prk: &[u8], purpose: KeyPurpose, info: &[u8]) -> Result<Self, SerpentError> {
        let mut inf = heapless::Vec::<u8, 256>::new();
        for b in purpose.info() {
            inf.push(*b).map_err(|_| SerpentError::KeyDerivation)?;
        }
        for b in info {
            inf.push(*b).map_err(|_| SerpentError::KeyDerivation)?;
        }
        let hk = Hkdf::<Sha256>::from_prk(prk).map_err(|_| SerpentError::KeyDerivation)?;
        let mut okm = [0u8; 64];
        hk.expand(inf.as_slice(), &mut okm)
            .map_err(|_| SerpentError::KeyDerivation)?;
        let mut cipher_key = [0u8; 32];
        let mut mac_key = [0u8; 32];
        cipher_key.copy_from_slice(&okm[..32]);
        mac_key.copy_from_slice(&okm[32..]);
        okm.zeroize();
        Ok(Self {
            cipher_key: zeroize::Zeroizing::new(cipher_key),
            mac_key: zeroize::Zeroizing::new(mac_key),
        })
    }

    fn serpent(&self) -> Result<Serpent, SerpentError> {
        Serpent::new_from_slice(self.cipher_key.as_ref()).map_err(|_| SerpentError::CipherError)
    }

    fn mac_key(&self) -> Result<HmacSha256, SerpentError> {
        <HmacSha256 as HmacKeyInit>::new_from_slice(self.mac_key.as_ref())
            .map_err(|_| SerpentError::CipherError)
    }

    #[doc(hidden)]
    pub fn from_raw_cipher_mac_for_test(cipher: [u8; 32], mac: [u8; 32]) -> Self {
        Self {
            cipher_key: zeroize::Zeroizing::new(cipher),
            mac_key: zeroize::Zeroizing::new(mac),
        }
    }

    #[doc(hidden)]
    pub fn raw_64_for_test(&self) -> [u8; 64] {
        let mut o = [0u8; 64];
        o[..32].copy_from_slice(self.cipher_key.as_ref());
        o[32..].copy_from_slice(self.mac_key.as_ref());
        o
    }
}

impl SerpentNonce {
    /// Generate a random nonce from the TRNG (128 bits).
    pub fn generate<T: HardwareTrng>(trng: &mut T) -> Result<Self, SerpentError> {
        let mut n = [0u8; 16];
        trng.try_fill_bytes(&mut n)
            .map_err(|_| SerpentError::TrngFailure)?;
        Ok(Self(n))
    }

    /// Build nonce from a 128-bit counter (big-endian). Caller must prevent reuse under one key.
    pub fn from_counter(counter: u128) -> Self {
        Self(counter.to_be_bytes())
    }

    /// Expose nonce bytes for framing and MAC input.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl SerpentCiphertext {
    /// Borrow raw bytes (body || tag).
    pub fn as_slice(&self) -> &[u8] {
        self.buf.as_slice()
    }

    /// Build ciphertext view for fuzzing; not a security boundary (caller supplies bytes).
    #[doc(hidden)]
    pub fn from_bytes_fuzz(buf: &[u8]) -> Result<Self, SerpentError> {
        let mut v = heapless::Vec::new();
        for b in buf {
            v.push(*b).map_err(|_| SerpentError::InvalidLength)?;
        }
        Ok(Self { buf: v })
    }

    #[cfg(test)]
    pub(crate) fn flip_last_byte_for_test(&mut self) {
        if let Some(b) = self.buf.last_mut() {
            *b ^= 0x01;
        }
    }

    #[cfg(test)]
    pub(crate) fn flip_first_body_byte_for_test(&mut self) {
        if !self.buf.is_empty() && self.buf.len() > SERPENT_TAG_LEN {
            self.buf[0] ^= 0x01;
        }
    }
}

impl SerpentPlaintext {
    /// Borrow decrypted bytes.
    pub fn as_slice(&self) -> &[u8] {
        self.buf.as_slice()
    }

    #[cfg(test)]
    pub(crate) fn as_mut_slice_for_test(&mut self) -> &mut [u8] {
        self.buf.as_mut_slice()
    }
}

impl Zeroize for SerpentPlaintext {
    fn zeroize(&mut self) {
        self.buf.as_mut_slice().zeroize();
    }
}

impl Drop for SerpentPlaintext {
    fn drop(&mut self) {
        self.zeroize();
    }
}

fn ctr_xor(serpent: &Serpent, nonce: &SerpentNonce, buf: &mut [u8]) -> Result<(), SerpentError> {
    let mut ctr = *nonce.as_bytes();
    let mut off = 0usize;
    while off < buf.len() {
        let block_in: Array<u8, U16> = ctr.into();
        let mut block_out = Array::<u8, U16>::default();
        serpent.encrypt_block_b2b(&block_in, &mut block_out);
        let chunk = core::cmp::min(16, buf.len() - off);
        for i in 0..chunk {
            buf[off + i] ^= block_out[i];
        }
        off += chunk;
        increment_ctr(&mut ctr);
    }
    Ok(())
}

fn increment_ctr(ctr: &mut [u8; 16]) {
    let mut v = u128::from_be_bytes(*ctr);
    v = v.wrapping_add(1);
    *ctr = v.to_be_bytes();
}

fn compute_tag(mac_key: &HmacSha256, aad: &[u8], nonce: &SerpentNonce, body: &[u8]) -> [u8; 32] {
    let mut mac = mac_key.clone();
    mac.update(aad);
    mac.update(nonce.as_bytes());
    mac.update(body);
    let tag = mac.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.into_bytes().as_slice());
    out
}

/// Encrypt `plaintext` with EtM (Serpent-CTR + HMAC-SHA256).
pub fn serpent_encrypt(
    key: &SerpentKey,
    nonce: &SerpentNonce,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<SerpentCiphertext, SerpentError> {
    if plaintext.len() > MAX_SERPENT_PLAINTEXT {
        return Err(SerpentError::InvalidLength);
    }
    let serpent = key.serpent()?;
    let mac = key.mac_key()?;
    let mut buf = heapless::Vec::<u8, MAX_SERPENT_CIPHERTEXT>::new();
    for b in plaintext {
        buf.push(*b).map_err(|_| SerpentError::InvalidLength)?;
    }
    ctr_xor(&serpent, nonce, buf.as_mut_slice())?;
    let tag = compute_tag(&mac, aad, nonce, buf.as_slice());
    for b in tag {
        buf.push(b).map_err(|_| SerpentError::InvalidLength)?;
    }
    Ok(SerpentCiphertext { buf })
}

/// Decrypt and authenticate EtM ciphertext (tag appended).
pub fn serpent_decrypt(
    key: &SerpentKey,
    nonce: &SerpentNonce,
    aad: &[u8],
    ciphertext: &SerpentCiphertext,
) -> Result<SerpentPlaintext, SerpentError> {
    let ct = ciphertext.buf.as_slice();
    if ct.len() < SERPENT_TAG_LEN {
        return Err(SerpentError::AuthenticationFailed);
    }
    let (body, tag) = ct.split_at(ct.len() - SERPENT_TAG_LEN);
    if body.len() > MAX_SERPENT_PLAINTEXT {
        return Err(SerpentError::InvalidLength);
    }
    let mac = key.mac_key()?;
    let mut expected = compute_tag(&mac, aad, nonce, body);
    let ok = tag.len() == expected.len() && bool::from(expected.as_slice().ct_eq(tag));
    expected.zeroize();
    if !ok {
        return Err(SerpentError::AuthenticationFailed);
    }
    let serpent = key.serpent()?;
    let mut buf = heapless::Vec::<u8, MAX_SERPENT_PLAINTEXT>::new();
    for b in body {
        buf.push(*b).map_err(|_| SerpentError::InvalidLength)?;
    }
    match ctr_xor(&serpent, nonce, buf.as_mut_slice()) {
        Ok(()) => Ok(SerpentPlaintext { buf }),
        Err(e) => {
            buf.as_mut_slice().zeroize();
            Err(e)
        }
    }
}

/// Serpent-CTR without authentication. Caller must authenticate elsewhere.
#[doc(hidden)]
pub fn serpent_ctr_unauthenticated(
    key: &SerpentKey,
    nonce: &SerpentNonce,
    buf: &mut [u8],
) -> Result<(), SerpentError> {
    let serpent = key.serpent()?;
    ctr_xor(&serpent, nonce, buf)
}

/// Single-block ECB encrypt for KAT tests (not exposed for production protocols).
#[cfg(test)]
pub(crate) fn serpent_ecb_encrypt_block(key: &[u8], plaintext: &[u8; 16]) -> Result<[u8; 16], SerpentError> {
    let serpent = Serpent::new_from_slice(key).map_err(|_| SerpentError::CipherError)?;
    let block_in: Array<u8, U16> = (*plaintext).into();
    let mut block_out = Array::<u8, U16>::default();
    serpent.encrypt_block_b2b(&block_in, &mut block_out);
    let mut out = [0u8; 16];
    out.copy_from_slice(block_out.as_slice());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use galdr_core::fake_hal::FakeTrng;
    use serde_json::Value;
    use std::collections::HashSet;

    #[test]
    fn serpent_vectors_json_kat() -> Result<(), SerpentError> {
        let data = include_str!("../tests/serpent_vectors.json");
        let parsed: Value =
            serde_json::from_str(data).map_err(|_| SerpentError::CipherError)?;
        let arr = parsed.as_array().ok_or(SerpentError::CipherError)?;
        for entry in arr {
            let key = hex::decode(entry["key"].as_str().ok_or(SerpentError::CipherError)?)
                .map_err(|_| SerpentError::CipherError)?;
            let pt = hex::decode(entry["plaintext"].as_str().ok_or(SerpentError::CipherError)?)
                .map_err(|_| SerpentError::CipherError)?;
            let exp = hex::decode(entry["ciphertext"].as_str().ok_or(SerpentError::CipherError)?)
                .map_err(|_| SerpentError::CipherError)?;
            if pt.len() != 16 || exp.len() != 16 {
                return Err(SerpentError::CipherError);
            }
            let mut pta = [0u8; 16];
            pta.copy_from_slice(&pt);
            let got = serpent_ecb_encrypt_block(&key, &pta)?;
            if got.as_slice() != exp.as_slice() {
                return Err(SerpentError::CipherError);
            }
        }
        Ok(())
    }

    #[test]
    fn aead_round_trip() -> Result<(), SerpentError> {
        let prk = [0x11u8; 32];
        let key = SerpentKey::derive(&prk, KeyPurpose::SerpentStorage, b"")?;
        let mut trng = FakeTrng::from_seed(0x51);
        let nonce = SerpentNonce::generate(&mut trng)?;
        let aad = b"galdr-serpent-aad";
        let pt = b"payload";
        let ct = serpent_encrypt(&key, &nonce, aad, pt)?;
        let out = serpent_decrypt(&key, &nonce, aad, &ct)?;
        assert_eq!(out.as_slice(), pt);
        Ok(())
    }

    #[test]
    fn aad_binding_fails() -> Result<(), SerpentError> {
        let prk = [0x22u8; 32];
        let key = SerpentKey::derive(&prk, KeyPurpose::SerpentStorage, b"")?;
        let mut trng = FakeTrng::from_seed(0x52);
        let nonce = SerpentNonce::generate(&mut trng)?;
        let ct = serpent_encrypt(&key, &nonce, b"context-a", b"data")?;
        let r = serpent_decrypt(&key, &nonce, b"context-b", &ct);
        assert!(matches!(r, Err(SerpentError::AuthenticationFailed)));
        Ok(())
    }

    #[test]
    fn tag_corruption_fails() -> Result<(), SerpentError> {
        let prk = [0x33u8; 32];
        let key = SerpentKey::derive(&prk, KeyPurpose::SerpentStorage, b"")?;
        let mut trng = FakeTrng::from_seed(0x53);
        let nonce = SerpentNonce::generate(&mut trng)?;
        let mut ct = serpent_encrypt(&key, &nonce, b"a", b"m")?;
        ct.flip_last_byte_for_test();
        let r = serpent_decrypt(&key, &nonce, b"a", &ct);
        assert!(matches!(r, Err(SerpentError::AuthenticationFailed)));
        Ok(())
    }

    #[test]
    fn ciphertext_body_corruption_fails() -> Result<(), SerpentError> {
        let prk = [0x44u8; 32];
        let key = SerpentKey::derive(&prk, KeyPurpose::SerpentStorage, b"")?;
        let mut trng = FakeTrng::from_seed(0x54);
        let nonce = SerpentNonce::generate(&mut trng)?;
        let mut ct = serpent_encrypt(&key, &nonce, b"", b"body")?;
        ct.flip_first_body_byte_for_test();
        let r = serpent_decrypt(&key, &nonce, b"", &ct);
        assert!(matches!(r, Err(SerpentError::AuthenticationFailed)));
        Ok(())
    }

    #[test]
    fn plaintext_zeroize_on_drop() -> Result<(), SerpentError> {
        let prk = [0x55u8; 32];
        let key = SerpentKey::derive(&prk, KeyPurpose::SerpentStorage, b"")?;
        let mut trng = FakeTrng::from_seed(0x55);
        let nonce = SerpentNonce::generate(&mut trng)?;
        let ct = serpent_encrypt(&key, &nonce, b"", b"zero-me")?;
        let mut plain = serpent_decrypt(&key, &nonce, b"", &ct)?;
        plain.as_mut_slice_for_test().fill(0xAB);
        plain.zeroize();
        assert!(plain.as_slice().iter().all(|b| *b == 0));
        Ok(())
    }

    #[test]
    fn nonce_uniqueness_fake_trng() -> Result<(), SerpentError> {
        let mut trng = FakeTrng::from_seed(0x1234);
        let mut set = HashSet::new();
        for _ in 0..1000 {
            let n = SerpentNonce::generate(&mut trng)?;
            assert!(set.insert(*n.as_bytes()));
        }
        Ok(())
    }

    #[test]
    fn key_purpose_domain_separation() -> Result<(), SerpentError> {
        let prk = [0x42u8; 32];
        let k1 = SerpentKey::derive(&prk, KeyPurpose::SerpentStorage, b"extra")?;
        let k2 = SerpentKey::derive(&prk, KeyPurpose::RsaKeyWrap, b"extra")?;
        assert_ne!(k1.cipher_key.as_ref(), k2.cipher_key.as_ref());
        assert_ne!(k1.mac_key.as_ref(), k2.mac_key.as_ref());
        Ok(())
    }

    #[test]
    fn ctr_unauthenticated_round_trip() -> Result<(), SerpentError> {
        let prk = [0x66u8; 32];
        let key = SerpentKey::derive(&prk, KeyPurpose::SerpentStorage, b"")?;
        let nonce = SerpentNonce::from_counter(1);
        let mut buf = *b"1234567890123456";
        serpent_ctr_unauthenticated(&key, &nonce, &mut buf)?;
        serpent_ctr_unauthenticated(&key, &nonce, &mut buf)?;
        assert_eq!(&buf, b"1234567890123456");
        Ok(())
    }
}
