//! Camellia-256 authenticated encryption (Encrypt-then-MAC) and CTR helper.
//!
//! # Crate evaluation (Camellia block cipher backend)
//!
//! The block cipher implementation is the **`camellia`** crate from the
//! [RustCrypto block-ciphers](https://github.com/RustCrypto/block-ciphers) repository:
//!
//! 1. **RustSec advisories:** Run `cargo audit` in the workspace; no advisory specific to `camellia`
//!    was present at integration time (re-check before releases).
//! 2. **`no_std`:** `default-features = false` in the workspace dependency.
//! 3. **Traits:** `KeyInit` and `BlockCipherEncrypt` / `BlockCipherDecrypt` from the `cipher` crate.
//! 4. **Audit status:** No formal third-party audit. Same status as the `serpent` and `twofish` crates
//!    in this workspace. Compensating controls: RFC 3713 KAT vectors, dudect tag-check harness, and
//!    camellia_aead fuzz target.
//! 5. **Zeroize:** `features = ["zeroize"]` enables `cipher/zeroize`, which adds `ZeroizeOnDrop` to
//!    the expanded key schedule in `Camellia256`. This is not a stub; it zeroes the internal subkeys
//!    on drop, matching the behaviour of the `serpent` crate under the same feature flag.
//!
//! # AEAD choice: Camellia-EtM (HMAC-SHA256)
//!
//! This module implements **Encrypt-then-MAC**:
//! - Ciphertext = Camellia-CTR(key_cipher, nonce, plaintext)
//! - Tag = HMAC-SHA256(key_mac, `aad` || `nonce` || ciphertext_body)
//! - On decrypt, HMAC is verified before any plaintext is released.
//!
//! Keys are derived with HKDF-SHA256: 64 bytes expanded from the PRK, split into two 256-bit keys
//! (cipher + MAC).
//!
//! **Security invariants**
//! - Tag verification uses `subtle::ConstantTimeEq` (constant-time comparison).
//! - Authentication failures zeroise the working plaintext buffer before `Err` is returned.
//! - Unauthenticated CTR (`camellia_ctr_unauthenticated`) must only be used when a higher layer
//!   provides integrity; it is `#[doc(hidden)]` for protocol compositions.

use crate::kdf_policy::KeyPurpose;
use camellia::cipher::array::Array;
use camellia::cipher::consts::U16;
use camellia::cipher::{BlockCipherEncrypt, KeyInit as CipherKeyInit};
use camellia::Camellia256;
use galdr_core::hal::HardwareTrng;
use hkdf::Hkdf;
use hmac::digest::KeyInit as HmacKeyInit;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// HMAC-SHA256 tag length (EtM).
pub const CAMELLIA_TAG_LEN: usize = 32;

/// Maximum plaintext length for this vault profile (matches ChaCha20-Poly1305 bound).
pub const MAX_CAMELLIA_PLAINTEXT: usize = 8192;

/// Maximum stored ciphertext: plaintext + tag.
pub const MAX_CAMELLIA_CIPHERTEXT: usize = MAX_CAMELLIA_PLAINTEXT + CAMELLIA_TAG_LEN;

type HmacSha256 = Hmac<Sha256>;

/// Errors from Camellia key derivation, CTR, and EtM operations.
#[derive(Debug, Eq, PartialEq)]
pub enum CamelliaError {
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

/// A Camellia-256 key schedule plus independent HMAC key (both from HKDF). Zeroizes on drop.
/// No `Clone`, no `Copy`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct CamelliaKey {
    cipher_key: zeroize::Zeroizing<[u8; 32]>,
    mac_key: zeroize::Zeroizing<[u8; 32]>,
}

/// A 128-bit (16-byte) nonce/IV for Camellia-CTR and EtM (initial counter block).
#[derive(Clone, Eq, PartialEq)]
pub struct CamelliaNonce([u8; 16]);

/// Authenticated ciphertext: body + appended HMAC-SHA256 tag.
#[derive(Clone, Eq, PartialEq)]
pub struct CamelliaCiphertext {
    buf: heapless::Vec<u8, MAX_CAMELLIA_CIPHERTEXT>,
}

/// Decrypted plaintext; zeroizes on drop.
pub struct CamelliaPlaintext {
    buf: heapless::Vec<u8, MAX_CAMELLIA_PLAINTEXT>,
}

impl CamelliaKey {
    /// Derive cipher and MAC keys from HKDF-SHA256 using `info` as the sole HKDF label (no [`KeyPurpose`] prefix).
    pub fn derive_from_prk_label(prk: &[u8], info: &[u8]) -> Result<Self, CamelliaError> {
        let hk = Hkdf::<Sha256>::from_prk(prk).map_err(|_| CamelliaError::KeyDerivation)?;
        let mut okm = [0u8; 64];
        hk.expand(info, &mut okm)
            .map_err(|_| CamelliaError::KeyDerivation)?;
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

    /// Derive cipher and MAC keys from HKDF-SHA256 for the given `KeyPurpose` and extra `info`.
    pub fn derive(prk: &[u8], purpose: KeyPurpose, info: &[u8]) -> Result<Self, CamelliaError> {
        let mut inf = heapless::Vec::<u8, 256>::new();
        for b in purpose.info() {
            inf.push(*b).map_err(|_| CamelliaError::KeyDerivation)?;
        }
        for b in info {
            inf.push(*b).map_err(|_| CamelliaError::KeyDerivation)?;
        }
        let hk = Hkdf::<Sha256>::from_prk(prk).map_err(|_| CamelliaError::KeyDerivation)?;
        let mut okm = [0u8; 64];
        hk.expand(inf.as_slice(), &mut okm)
            .map_err(|_| CamelliaError::KeyDerivation)?;
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

    /// Build from 32+32 octet cipher and MAC keys (e.g. HKDF-BLAKE3 64-byte expand for CESS inner).
    pub fn from_cipher_mac_keys(cipher: [u8; 32], mac: [u8; 32]) -> Self {
        Self {
            cipher_key: zeroize::Zeroizing::new(cipher),
            mac_key: zeroize::Zeroizing::new(mac),
        }
    }

    /// Build from 64 octets of OKM (cipher || MAC), e.g. HKDF-BLAKE3 for CESS inner.
    pub fn from_okm64(okm: &[u8; 64]) -> Self {
        let mut c = [0u8; 32];
        let mut m = [0u8; 32];
        c.copy_from_slice(&okm[..32]);
        m.copy_from_slice(&okm[32..]);
        Self::from_cipher_mac_keys(c, m)
    }

    #[doc(hidden)]
    pub fn from_raw_cipher_mac_for_test(cipher: [u8; 32], mac: [u8; 32]) -> Self {
        Self::from_cipher_mac_keys(cipher, mac)
    }

    #[doc(hidden)]
    pub fn raw_64_for_test(&self) -> [u8; 64] {
        let mut o = [0u8; 64];
        o[..32].copy_from_slice(self.cipher_key.as_ref());
        o[32..].copy_from_slice(self.mac_key.as_ref());
        o
    }

    fn camellia(&self) -> Result<Camellia256, CamelliaError> {
        Camellia256::new_from_slice(self.cipher_key.as_ref())
            .map_err(|_| CamelliaError::CipherError)
    }

    fn mac_key(&self) -> Result<HmacSha256, CamelliaError> {
        <HmacSha256 as HmacKeyInit>::new_from_slice(self.mac_key.as_ref())
            .map_err(|_| CamelliaError::CipherError)
    }
}

impl CamelliaNonce {
    /// Derive a 128-bit nonce from HKDF-SHA256 using `info` as the sole label; uses the first 16 bytes of a 32-byte expand.
    pub fn derive_from_prk_label(prk: &[u8], info: &[u8]) -> Result<Self, CamelliaError> {
        let hk = Hkdf::<Sha256>::from_prk(prk).map_err(|_| CamelliaError::KeyDerivation)?;
        let mut okm = [0u8; 32];
        hk.expand(info, &mut okm)
            .map_err(|_| CamelliaError::KeyDerivation)?;
        let mut n = [0u8; 16];
        n.copy_from_slice(&okm[..16]);
        Ok(Self(n))
    }

    /// First 16 octets of a 32-byte OKM (e.g. HKDF-BLAKE3 expand for deterministic nonce).
    pub fn from_okm32_prefix(okm: &[u8; 32]) -> Self {
        let mut n = [0u8; 16];
        n.copy_from_slice(&okm[..16]);
        Self(n)
    }

    /// Generate a random nonce from the TRNG (128 bits).
    pub fn generate<T: HardwareTrng>(trng: &mut T) -> Result<Self, CamelliaError> {
        let mut n = [0u8; 16];
        trng.try_fill_bytes(&mut n)
            .map_err(|_| CamelliaError::TrngFailure)?;
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

impl CamelliaCiphertext {
    /// Borrow raw bytes (body || tag).
    pub fn as_slice(&self) -> &[u8] {
        self.buf.as_slice()
    }

    /// Build ciphertext view for fuzzing; not a security boundary (caller supplies bytes).
    #[doc(hidden)]
    pub fn from_bytes_fuzz(buf: &[u8]) -> Result<Self, CamelliaError> {
        let mut v = heapless::Vec::new();
        for b in buf {
            v.push(*b).map_err(|_| CamelliaError::InvalidLength)?;
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
        if !self.buf.is_empty() && self.buf.len() > CAMELLIA_TAG_LEN {
            self.buf[0] ^= 0x01;
        }
    }
}

impl CamelliaPlaintext {
    /// Borrow decrypted bytes.
    pub fn as_slice(&self) -> &[u8] {
        self.buf.as_slice()
    }

    #[cfg(test)]
    pub(crate) fn as_mut_slice_for_test(&mut self) -> &mut [u8] {
        self.buf.as_mut_slice()
    }
}

impl Zeroize for CamelliaPlaintext {
    fn zeroize(&mut self) {
        self.buf.as_mut_slice().zeroize();
    }
}

impl Drop for CamelliaPlaintext {
    fn drop(&mut self) {
        self.zeroize();
    }
}

fn ctr_xor(cam: &Camellia256, nonce: &CamelliaNonce, buf: &mut [u8]) -> Result<(), CamelliaError> {
    let mut ctr = *nonce.as_bytes();
    let mut off = 0usize;
    while off < buf.len() {
        let block_in: Array<u8, U16> = ctr.into();
        let mut block_out = Array::<u8, U16>::default();
        cam.encrypt_block_b2b(&block_in, &mut block_out);
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

fn compute_tag(mac_key: &HmacSha256, aad: &[u8], nonce: &CamelliaNonce, body: &[u8]) -> [u8; 32] {
    let mut mac = mac_key.clone();
    mac.update(aad);
    mac.update(nonce.as_bytes());
    mac.update(body);
    let tag = mac.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.into_bytes().as_slice());
    out
}

/// Encrypt `plaintext` with EtM (Camellia-CTR + HMAC-SHA256).
pub fn camellia_encrypt(
    key: &CamelliaKey,
    nonce: &CamelliaNonce,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<CamelliaCiphertext, CamelliaError> {
    if plaintext.len() > MAX_CAMELLIA_PLAINTEXT {
        return Err(CamelliaError::InvalidLength);
    }
    let cam = key.camellia()?;
    let mac = key.mac_key()?;
    let mut buf = heapless::Vec::<u8, MAX_CAMELLIA_CIPHERTEXT>::new();
    for b in plaintext {
        buf.push(*b).map_err(|_| CamelliaError::InvalidLength)?;
    }
    ctr_xor(&cam, nonce, buf.as_mut_slice())?;
    let tag = compute_tag(&mac, aad, nonce, buf.as_slice());
    for b in tag {
        buf.push(b).map_err(|_| CamelliaError::InvalidLength)?;
    }
    Ok(CamelliaCiphertext { buf })
}

/// Decrypt and authenticate EtM ciphertext (tag appended).
pub fn camellia_decrypt(
    key: &CamelliaKey,
    nonce: &CamelliaNonce,
    aad: &[u8],
    ciphertext: &CamelliaCiphertext,
) -> Result<CamelliaPlaintext, CamelliaError> {
    let ct = ciphertext.buf.as_slice();
    if ct.len() < CAMELLIA_TAG_LEN {
        return Err(CamelliaError::AuthenticationFailed);
    }
    let (body, tag) = ct.split_at(ct.len() - CAMELLIA_TAG_LEN);
    if body.len() > MAX_CAMELLIA_PLAINTEXT {
        return Err(CamelliaError::InvalidLength);
    }
    let mac = key.mac_key()?;
    let mut expected = compute_tag(&mac, aad, nonce, body);
    let ok = tag.len() == expected.len() && bool::from(expected.as_slice().ct_eq(tag));
    expected.zeroize();
    if !ok {
        return Err(CamelliaError::AuthenticationFailed);
    }
    let cam = key.camellia()?;
    let mut buf = heapless::Vec::<u8, MAX_CAMELLIA_PLAINTEXT>::new();
    for b in body {
        buf.push(*b).map_err(|_| CamelliaError::InvalidLength)?;
    }
    match ctr_xor(&cam, nonce, buf.as_mut_slice()) {
        Ok(()) => Ok(CamelliaPlaintext { buf }),
        Err(e) => {
            buf.as_mut_slice().zeroize();
            Err(e)
        }
    }
}

/// Camellia-CTR without authentication. Caller must authenticate elsewhere.
#[doc(hidden)]
pub fn camellia_ctr_unauthenticated(
    key: &CamelliaKey,
    nonce: &CamelliaNonce,
    buf: &mut [u8],
) -> Result<(), CamelliaError> {
    let cam = key.camellia()?;
    ctr_xor(&cam, nonce, buf)
}

/// Single-block ECB encrypt for KAT tests (not exposed for production protocols).
#[cfg(test)]
pub(crate) fn camellia_ecb_encrypt_block(
    key: &[u8],
    plaintext: &[u8; 16],
) -> Result<[u8; 16], CamelliaError> {
    let cam = Camellia256::new_from_slice(key).map_err(|_| CamelliaError::CipherError)?;
    let block_in: Array<u8, U16> = (*plaintext).into();
    let mut block_out = Array::<u8, U16>::default();
    cam.encrypt_block_b2b(&block_in, &mut block_out);
    let mut out = [0u8; 16];
    out.copy_from_slice(block_out.as_slice());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use galdr_core::fake_hal::FakeTrng;
    use std::collections::HashSet;

    #[test]
    fn camellia_vectors_json_kat() -> Result<(), CamelliaError> {
        let data = include_str!("../tests/camellia_vectors.json");
        let parsed: serde_json::Value =
            serde_json::from_str(data).map_err(|_| CamelliaError::CipherError)?;
        let arr = parsed.as_array().ok_or(CamelliaError::CipherError)?;
        for entry in arr {
            let key = hex::decode(entry["key"].as_str().ok_or(CamelliaError::CipherError)?)
                .map_err(|_| CamelliaError::CipherError)?;
            let pt = hex::decode(
                entry["plaintext"]
                    .as_str()
                    .ok_or(CamelliaError::CipherError)?,
            )
            .map_err(|_| CamelliaError::CipherError)?;
            let exp = hex::decode(
                entry["ciphertext"]
                    .as_str()
                    .ok_or(CamelliaError::CipherError)?,
            )
            .map_err(|_| CamelliaError::CipherError)?;
            if key.len() != 32 || pt.len() != 16 || exp.len() != 16 {
                return Err(CamelliaError::CipherError);
            }
            let mut pta = [0u8; 16];
            pta.copy_from_slice(&pt);
            let got = camellia_ecb_encrypt_block(&key, &pta)?;
            if got.as_slice() != exp.as_slice() {
                return Err(CamelliaError::CipherError);
            }
        }
        Ok(())
    }

    #[test]
    fn aead_round_trip() -> Result<(), CamelliaError> {
        let prk = [0x11u8; 32];
        let key = CamelliaKey::derive(&prk, KeyPurpose::CamelliaStorage, b"")?;
        let mut trng = FakeTrng::from_seed(0x51);
        let nonce = CamelliaNonce::generate(&mut trng)?;
        let aad = b"galdr-camellia-aad";
        let pt = b"payload";
        let ct = camellia_encrypt(&key, &nonce, aad, pt)?;
        let out = camellia_decrypt(&key, &nonce, aad, &ct)?;
        assert_eq!(out.as_slice(), pt);
        Ok(())
    }

    #[test]
    fn aad_binding_fails() -> Result<(), CamelliaError> {
        let prk = [0x22u8; 32];
        let key = CamelliaKey::derive(&prk, KeyPurpose::CamelliaStorage, b"")?;
        let mut trng = FakeTrng::from_seed(0x52);
        let nonce = CamelliaNonce::generate(&mut trng)?;
        let ct = camellia_encrypt(&key, &nonce, b"context-a", b"data")?;
        let r = camellia_decrypt(&key, &nonce, b"context-b", &ct);
        assert!(matches!(r, Err(CamelliaError::AuthenticationFailed)));
        Ok(())
    }

    #[test]
    fn tag_corruption_fails() -> Result<(), CamelliaError> {
        let prk = [0x33u8; 32];
        let key = CamelliaKey::derive(&prk, KeyPurpose::CamelliaStorage, b"")?;
        let mut trng = FakeTrng::from_seed(0x53);
        let nonce = CamelliaNonce::generate(&mut trng)?;
        let mut ct = camellia_encrypt(&key, &nonce, b"a", b"m")?;
        ct.flip_last_byte_for_test();
        let r = camellia_decrypt(&key, &nonce, b"a", &ct);
        assert!(matches!(r, Err(CamelliaError::AuthenticationFailed)));
        Ok(())
    }

    #[test]
    fn ciphertext_body_corruption_fails() -> Result<(), CamelliaError> {
        let prk = [0x44u8; 32];
        let key = CamelliaKey::derive(&prk, KeyPurpose::CamelliaStorage, b"")?;
        let mut trng = FakeTrng::from_seed(0x54);
        let nonce = CamelliaNonce::generate(&mut trng)?;
        let mut ct = camellia_encrypt(&key, &nonce, b"", b"body")?;
        ct.flip_first_body_byte_for_test();
        let r = camellia_decrypt(&key, &nonce, b"", &ct);
        assert!(matches!(r, Err(CamelliaError::AuthenticationFailed)));
        Ok(())
    }

    #[test]
    fn plaintext_zeroize_on_drop() -> Result<(), CamelliaError> {
        let prk = [0x55u8; 32];
        let key = CamelliaKey::derive(&prk, KeyPurpose::CamelliaStorage, b"")?;
        let mut trng = FakeTrng::from_seed(0x55);
        let nonce = CamelliaNonce::generate(&mut trng)?;
        let ct = camellia_encrypt(&key, &nonce, b"", b"zero-me")?;
        let mut plain = camellia_decrypt(&key, &nonce, b"", &ct)?;
        plain.as_mut_slice_for_test().fill(0xAB);
        plain.zeroize();
        assert!(plain.as_slice().iter().all(|b| *b == 0));
        Ok(())
    }

    #[test]
    fn nonce_uniqueness_fake_trng() -> Result<(), CamelliaError> {
        let mut trng = FakeTrng::from_seed(0x1234);
        let mut set = HashSet::new();
        for _ in 0..1000 {
            let n = CamelliaNonce::generate(&mut trng)?;
            assert!(set.insert(*n.as_bytes()));
        }
        Ok(())
    }

    #[test]
    fn keypurpose_domain_separation() -> Result<(), CamelliaError> {
        let prk = [0x42u8; 32];
        let k1 = CamelliaKey::derive(&prk, KeyPurpose::CamelliaStorage, b"extra")?;
        let k2 = CamelliaKey::derive(&prk, KeyPurpose::SerpentStorage, b"extra")?;
        assert_ne!(k1.cipher_key.as_ref(), k2.cipher_key.as_ref());
        assert_ne!(k1.mac_key.as_ref(), k2.mac_key.as_ref());
        Ok(())
    }

    #[test]
    fn ctr_unauthenticated_round_trip() -> Result<(), CamelliaError> {
        let prk = [0x66u8; 32];
        let key = CamelliaKey::derive(&prk, KeyPurpose::CamelliaStorage, b"")?;
        let nonce = CamelliaNonce::from_counter(1);
        let mut buf = *b"1234567890123456";
        camellia_ctr_unauthenticated(&key, &nonce, &mut buf)?;
        camellia_ctr_unauthenticated(&key, &nonce, &mut buf)?;
        assert_eq!(&buf, b"1234567890123456");
        Ok(())
    }
}
