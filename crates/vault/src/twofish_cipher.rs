//! Twofish-256 authenticated encryption (Encrypt-then-MAC) and CTR helper.
//!
//! # Crate evaluation (Twofish block cipher backend)
//!
//! The block cipher implementation is the **`twofish`** crate from the
//! [RustCrypto block-ciphers](https://github.com/RustCrypto/block-ciphers) repository:
//!
//! 1. **RustSec advisories:** Run `cargo audit` in the workspace; no advisory specific to `twofish`
//!    was present at integration time (re-check before releases).
//! 2. **`no_std`:** `default-features = false` in the workspace dependency.
//! 3. **Traits:** `KeyInit` and `BlockEncrypt` / `BlockDecrypt` from the `cipher` crate (via
//!    `BlockCipher` in the `cipher` 0.4 ecosystem).
//! 4. **Maintenance:** Actively maintained within RustCrypto; release series aligned with other
//!    block ciphers in this workspace (e.g. `serpent`).
//!
//! # AEAD choice: Twofish-EtM (HMAC-SHA256)
//!
//! Twofish-GCM (GHASH over Twofish-CTR) is not used here for the same reasons as Serpent: the
//! workspace does not ship a generic GCM composition for arbitrary 128-bit block ciphers, and
//! EtM with HMAC-SHA256 is well understood.
//!
//! This module implements **Encrypt-then-MAC**:
//! - Ciphertext = Twofish-CTR(key_cipher, nonce, plaintext)
//! - Tag = HMAC-SHA256(key_mac, `aad` || `nonce` || ciphertext_body)
//! - On decrypt, HMAC is verified before any plaintext is released.
//!
//! Keys are derived with HKDF-SHA256: 64 bytes expanded from the PRK, split into two 256-bit keys
//! (cipher + MAC).
//!
//! **Security invariants**
//! - Tag verification uses `hmac::Mac::verify` (constant-time comparison).
//! - Authentication failures zeroise the working plaintext buffer before `Err` is returned.
//! - Unauthenticated CTR (`twofish_ctr_unauthenticated`) must only be used when a higher layer
//!   provides integrity; it is `#[doc(hidden)]` for protocol compositions.

use crate::kdf_policy::KeyPurpose;
use galdr_core::hal::HardwareTrng;
use hkdf::Hkdf;
use hmac::digest::KeyInit as HmacKeyInit;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use twofish::cipher::array::Array;
use twofish::cipher::consts::U16;
use twofish::cipher::{BlockCipherEncrypt, KeyInit as CipherKeyInit};
use twofish::Twofish;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// HMAC-SHA256 tag length (EtM).
pub const TWOFISH_TAG_LEN: usize = 32;

/// Maximum plaintext length for this vault profile (matches ChaCha20-Poly1305 bound).
pub const MAX_TWOFISH_PLAINTEXT: usize = 8192;

/// Maximum stored ciphertext: plaintext + tag.
pub const MAX_TWOFISH_CIPHERTEXT: usize = MAX_TWOFISH_PLAINTEXT + TWOFISH_TAG_LEN;

type HmacSha256 = Hmac<Sha256>;

/// Errors from Twofish key derivation, CTR, and EtM operations.
#[derive(Debug, Eq, PartialEq)]
pub enum TwofishError {
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

/// A Twofish-256 key schedule plus independent HMAC key (both from HKDF). Zeroizes on drop.
/// No `Clone`, no `Copy`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct TwofishKey {
    cipher_key: zeroize::Zeroizing<[u8; 32]>,
    mac_key: zeroize::Zeroizing<[u8; 32]>,
}

/// A 128-bit (16-byte) nonce/IV for Twofish-CTR and EtM (initial counter block).
#[derive(Clone, Eq, PartialEq)]
pub struct TwofishNonce([u8; 16]);

/// Authenticated ciphertext: body + appended HMAC-SHA256 tag.
#[derive(Clone, Eq, PartialEq)]
pub struct TwofishCiphertext {
    buf: heapless::Vec<u8, MAX_TWOFISH_CIPHERTEXT>,
}

/// Decrypted plaintext; zeroizes on drop.
pub struct TwofishPlaintext {
    buf: heapless::Vec<u8, MAX_TWOFISH_PLAINTEXT>,
}

impl TwofishKey {
    /// Derive cipher and MAC keys from HKDF-SHA256 for the given `KeyPurpose` and extra `info`.
    pub fn derive(prk: &[u8], purpose: KeyPurpose, info: &[u8]) -> Result<Self, TwofishError> {
        let mut inf = heapless::Vec::<u8, 256>::new();
        for b in purpose.info() {
            inf.push(*b).map_err(|_| TwofishError::KeyDerivation)?;
        }
        for b in info {
            inf.push(*b).map_err(|_| TwofishError::KeyDerivation)?;
        }
        let hk = Hkdf::<Sha256>::from_prk(prk).map_err(|_| TwofishError::KeyDerivation)?;
        let mut okm = [0u8; 64];
        hk.expand(inf.as_slice(), &mut okm)
            .map_err(|_| TwofishError::KeyDerivation)?;
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

    fn twofish(&self) -> Result<Twofish, TwofishError> {
        Twofish::new_from_slice(self.cipher_key.as_ref()).map_err(|_| TwofishError::CipherError)
    }

    fn mac_key(&self) -> Result<HmacSha256, TwofishError> {
        <HmacSha256 as HmacKeyInit>::new_from_slice(self.mac_key.as_ref())
            .map_err(|_| TwofishError::CipherError)
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

impl TwofishNonce {
    /// Generate a random nonce from the TRNG (128 bits).
    pub fn generate<T: HardwareTrng>(trng: &mut T) -> Result<Self, TwofishError> {
        let mut n = [0u8; 16];
        trng.try_fill_bytes(&mut n)
            .map_err(|_| TwofishError::TrngFailure)?;
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

impl TwofishCiphertext {
    /// Borrow raw bytes (body || tag).
    pub fn as_slice(&self) -> &[u8] {
        self.buf.as_slice()
    }

    /// Build ciphertext view for fuzzing; not a security boundary (caller supplies bytes).
    #[doc(hidden)]
    pub fn from_bytes_fuzz(buf: &[u8]) -> Result<Self, TwofishError> {
        let mut v = heapless::Vec::new();
        for b in buf {
            v.push(*b).map_err(|_| TwofishError::InvalidLength)?;
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
        if !self.buf.is_empty() && self.buf.len() > TWOFISH_TAG_LEN {
            self.buf[0] ^= 0x01;
        }
    }
}

impl TwofishPlaintext {
    /// Borrow decrypted bytes.
    pub fn as_slice(&self) -> &[u8] {
        self.buf.as_slice()
    }

    #[cfg(test)]
    pub(crate) fn as_mut_slice_for_test(&mut self) -> &mut [u8] {
        self.buf.as_mut_slice()
    }
}

impl Zeroize for TwofishPlaintext {
    fn zeroize(&mut self) {
        self.buf.as_mut_slice().zeroize();
    }
}

impl Drop for TwofishPlaintext {
    fn drop(&mut self) {
        self.zeroize();
    }
}

fn ctr_xor(tf: &Twofish, nonce: &TwofishNonce, buf: &mut [u8]) -> Result<(), TwofishError> {
    let mut ctr = *nonce.as_bytes();
    let mut off = 0usize;
    while off < buf.len() {
        let block_in: Array<u8, U16> = ctr.into();
        let mut block_out = Array::<u8, U16>::default();
        tf.encrypt_block_b2b(&block_in, &mut block_out);
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

fn compute_tag(mac_key: &HmacSha256, aad: &[u8], nonce: &TwofishNonce, body: &[u8]) -> [u8; 32] {
    let mut mac = mac_key.clone();
    mac.update(aad);
    mac.update(nonce.as_bytes());
    mac.update(body);
    let tag = mac.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.into_bytes().as_slice());
    out
}

/// Encrypt `plaintext` with EtM (Twofish-CTR + HMAC-SHA256).
pub fn twofish_encrypt(
    key: &TwofishKey,
    nonce: &TwofishNonce,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<TwofishCiphertext, TwofishError> {
    if plaintext.len() > MAX_TWOFISH_PLAINTEXT {
        return Err(TwofishError::InvalidLength);
    }
    let tf = key.twofish()?;
    let mac = key.mac_key()?;
    let mut buf = heapless::Vec::<u8, MAX_TWOFISH_CIPHERTEXT>::new();
    for b in plaintext {
        buf.push(*b).map_err(|_| TwofishError::InvalidLength)?;
    }
    ctr_xor(&tf, nonce, buf.as_mut_slice())?;
    let tag = compute_tag(&mac, aad, nonce, buf.as_slice());
    for b in tag {
        buf.push(b).map_err(|_| TwofishError::InvalidLength)?;
    }
    Ok(TwofishCiphertext { buf })
}

/// Decrypt and authenticate EtM ciphertext (tag appended).
pub fn twofish_decrypt(
    key: &TwofishKey,
    nonce: &TwofishNonce,
    aad: &[u8],
    ciphertext: &TwofishCiphertext,
) -> Result<TwofishPlaintext, TwofishError> {
    let ct = ciphertext.buf.as_slice();
    if ct.len() < TWOFISH_TAG_LEN {
        return Err(TwofishError::AuthenticationFailed);
    }
    let (body, tag) = ct.split_at(ct.len() - TWOFISH_TAG_LEN);
    if body.len() > MAX_TWOFISH_PLAINTEXT {
        return Err(TwofishError::InvalidLength);
    }
    let mac = key.mac_key()?;
    let mut expected = compute_tag(&mac, aad, nonce, body);
    let ok = tag.len() == expected.len() && bool::from(expected.as_slice().ct_eq(tag));
    expected.zeroize();
    if !ok {
        return Err(TwofishError::AuthenticationFailed);
    }
    let tf = key.twofish()?;
    let mut buf = heapless::Vec::<u8, MAX_TWOFISH_PLAINTEXT>::new();
    for b in body {
        buf.push(*b).map_err(|_| TwofishError::InvalidLength)?;
    }
    match ctr_xor(&tf, nonce, buf.as_mut_slice()) {
        Ok(()) => Ok(TwofishPlaintext { buf }),
        Err(e) => {
            buf.as_mut_slice().zeroize();
            Err(e)
        }
    }
}

/// Twofish-CTR without authentication. Caller must authenticate elsewhere.
#[doc(hidden)]
pub fn twofish_ctr_unauthenticated(
    key: &TwofishKey,
    nonce: &TwofishNonce,
    buf: &mut [u8],
) -> Result<(), TwofishError> {
    let tf = key.twofish()?;
    ctr_xor(&tf, nonce, buf)
}

/// Single-block ECB encrypt for KAT tests (not exposed for production protocols).
#[cfg(test)]
pub(crate) fn twofish_ecb_encrypt_block(key: &[u8], plaintext: &[u8; 16]) -> Result<[u8; 16], TwofishError> {
    let tf = Twofish::new_from_slice(key).map_err(|_| TwofishError::CipherError)?;
    let block_in: Array<u8, U16> = (*plaintext).into();
    let mut block_out = Array::<u8, U16>::default();
    tf.encrypt_block_b2b(&block_in, &mut block_out);
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
    fn twofish_vectors_json_kat() -> Result<(), TwofishError> {
        let data = include_str!("../tests/twofish_vectors.json");
        let parsed: Value =
            serde_json::from_str(data).map_err(|_| TwofishError::CipherError)?;
        let arr = parsed
            .get("vectors")
            .and_then(|v| v.as_array())
            .ok_or(TwofishError::CipherError)?;
        for entry in arr {
            let key_bits = entry
                .get("key_bits")
                .and_then(|v| v.as_u64())
                .ok_or(TwofishError::CipherError)?;
            let key = hex::decode(
                entry
                    .get("key")
                    .and_then(|v| v.as_str())
                    .ok_or(TwofishError::CipherError)?,
            )
            .map_err(|_| TwofishError::CipherError)?;
            let pt = hex::decode(
                entry
                    .get("plaintext")
                    .and_then(|v| v.as_str())
                    .ok_or(TwofishError::CipherError)?,
            )
            .map_err(|_| TwofishError::CipherError)?;
            let exp = hex::decode(
                entry
                    .get("ciphertext")
                    .and_then(|v| v.as_str())
                    .ok_or(TwofishError::CipherError)?,
            )
            .map_err(|_| TwofishError::CipherError)?;
            if key_bits != 128 && key_bits != 192 && key_bits != 256 {
                return Err(TwofishError::CipherError);
            }
            let kb = key_bits as usize / 8;
            if key.len() != kb || pt.len() != 16 || exp.len() != 16 {
                return Err(TwofishError::CipherError);
            }
            let mut pta = [0u8; 16];
            pta.copy_from_slice(&pt);
            let got = twofish_ecb_encrypt_block(&key, &pta)?;
            if got.as_slice() != exp.as_slice() {
                return Err(TwofishError::CipherError);
            }
        }
        Ok(())
    }

    #[test]
    fn twofish_aead_roundtrip() -> Result<(), TwofishError> {
        let prk = [0x11u8; 32];
        let key = TwofishKey::derive(&prk, KeyPurpose::TwofishStorage, b"")?;
        let mut trng = FakeTrng::from_seed(0x51);
        let nonce = TwofishNonce::generate(&mut trng)?;
        let aad = b"galdr-twofish-aad";
        let pt = b"payload";
        let ct = twofish_encrypt(&key, &nonce, aad, pt)?;
        let out = twofish_decrypt(&key, &nonce, aad, &ct)?;
        assert_eq!(out.as_slice(), pt);
        Ok(())
    }

    #[test]
    fn twofish_aad_binding_fails() -> Result<(), TwofishError> {
        let prk = [0x22u8; 32];
        let key = TwofishKey::derive(&prk, KeyPurpose::TwofishStorage, b"")?;
        let mut trng = FakeTrng::from_seed(0x52);
        let nonce = TwofishNonce::generate(&mut trng)?;
        let ct = twofish_encrypt(&key, &nonce, b"context-a", b"data")?;
        let r = twofish_decrypt(&key, &nonce, b"context-b", &ct);
        assert!(matches!(r, Err(TwofishError::AuthenticationFailed)));
        Ok(())
    }

    #[test]
    fn twofish_tag_corruption_fails() -> Result<(), TwofishError> {
        let prk = [0x33u8; 32];
        let key = TwofishKey::derive(&prk, KeyPurpose::TwofishStorage, b"")?;
        let mut trng = FakeTrng::from_seed(0x53);
        let nonce = TwofishNonce::generate(&mut trng)?;
        let mut ct = twofish_encrypt(&key, &nonce, b"a", b"m")?;
        ct.flip_last_byte_for_test();
        let r = twofish_decrypt(&key, &nonce, b"a", &ct);
        assert!(matches!(r, Err(TwofishError::AuthenticationFailed)));
        Ok(())
    }

    #[test]
    fn twofish_ciphertext_body_corruption_fails() -> Result<(), TwofishError> {
        let prk = [0x44u8; 32];
        let key = TwofishKey::derive(&prk, KeyPurpose::TwofishStorage, b"")?;
        let mut trng = FakeTrng::from_seed(0x54);
        let nonce = TwofishNonce::generate(&mut trng)?;
        let mut ct = twofish_encrypt(&key, &nonce, b"", b"body")?;
        ct.flip_first_body_byte_for_test();
        let r = twofish_decrypt(&key, &nonce, b"", &ct);
        assert!(matches!(r, Err(TwofishError::AuthenticationFailed)));
        Ok(())
    }

    #[test]
    fn twofish_plaintext_zeroize_on_drop() -> Result<(), TwofishError> {
        let prk = [0x55u8; 32];
        let key = TwofishKey::derive(&prk, KeyPurpose::TwofishStorage, b"")?;
        let mut trng = FakeTrng::from_seed(0x55);
        let nonce = TwofishNonce::generate(&mut trng)?;
        let ct = twofish_encrypt(&key, &nonce, b"", b"zero-me")?;
        let mut plain = twofish_decrypt(&key, &nonce, b"", &ct)?;
        plain.as_mut_slice_for_test().fill(0xAB);
        plain.zeroize();
        assert!(plain.as_slice().iter().all(|b| *b == 0));
        Ok(())
    }

    #[test]
    fn twofish_nonce_uniqueness_fake_trng() -> Result<(), TwofishError> {
        let mut trng = FakeTrng::from_seed(0x1234);
        let mut set = HashSet::new();
        for _ in 0..1000 {
            let n = TwofishNonce::generate(&mut trng)?;
            assert!(set.insert(*n.as_bytes()));
        }
        Ok(())
    }

    #[test]
    fn twofish_keypurpose_domain_separation() -> Result<(), TwofishError> {
        let prk = [0x42u8; 32];
        let k1 = TwofishKey::derive(&prk, KeyPurpose::TwofishStorage, b"extra")?;
        let k2 = TwofishKey::derive(&prk, KeyPurpose::SerpentStorage, b"extra")?;
        assert_ne!(k1.cipher_key.as_ref(), k2.cipher_key.as_ref());
        assert_ne!(k1.mac_key.as_ref(), k2.mac_key.as_ref());
        Ok(())
    }

    #[test]
    fn twofish_ctr_unauthenticated_round_trip() -> Result<(), TwofishError> {
        let prk = [0x66u8; 32];
        let key = TwofishKey::derive(&prk, KeyPurpose::TwofishStorage, b"")?;
        let nonce = TwofishNonce::from_counter(1);
        let mut buf = *b"1234567890123456";
        twofish_ctr_unauthenticated(&key, &nonce, &mut buf)?;
        twofish_ctr_unauthenticated(&key, &nonce, &mut buf)?;
        assert_eq!(&buf, b"1234567890123456");
        Ok(())
    }

    #[test]
    fn twofish_kat_zero_key_128() -> Result<(), TwofishError> {
        let key = [0u8; 16];
        let pt = [0u8; 16];
        let got = twofish_ecb_encrypt_block(&key, &pt)?;
        let exp = hex::decode("9F589F5CF6122C32B6BFEC2F2AE8C35A").map_err(|_| TwofishError::CipherError)?;
        assert_eq!(got.as_slice(), exp.as_slice());
        Ok(())
    }

    #[test]
    fn twofish_kat_zero_key_192() -> Result<(), TwofishError> {
        let key = [0u8; 24];
        let pt = [0u8; 16];
        let got = twofish_ecb_encrypt_block(&key, &pt)?;
        let exp = hex::decode("EFA71F788965BD4453F860178FC19101").map_err(|_| TwofishError::CipherError)?;
        assert_eq!(got.as_slice(), exp.as_slice());
        Ok(())
    }

    #[test]
    fn twofish_kat_zero_key_256() -> Result<(), TwofishError> {
        let key = [0u8; 32];
        let pt = [0u8; 16];
        let got = twofish_ecb_encrypt_block(&key, &pt)?;
        let exp = hex::decode("57FF739D4DC92C1BD7FC01700CC8216F").map_err(|_| TwofishError::CipherError)?;
        assert_eq!(got.as_slice(), exp.as_slice());
        Ok(())
    }

    #[test]
    fn twofish_monte_carlo_json_matches() -> Result<(), TwofishError> {
        use serde_json::Value;
        let data = include_str!("../tests/twofish_vectors.json");
        let parsed: Value = serde_json::from_str(data).map_err(|_| TwofishError::CipherError)?;
        let exp_hex = parsed
            .get("monte_carlo_256_final_ciphertext_hex")
            .and_then(|v| v.as_str())
            .ok_or(TwofishError::CipherError)?;
        use twofish::cipher::array::Array;
        use twofish::cipher::consts::U16;
        use twofish::cipher::{BlockCipherEncrypt, KeyInit};
        use twofish::Twofish;
        let mut key = [0u8; 32];
        let mut plain = Array::<u8, U16>::default();
        for _ in 1..=10_000 {
            let plain_in = plain;
            let tf = Twofish::new_from_slice(&key).map_err(|_| TwofishError::CipherError)?;
            let block_in: Array<u8, U16> = plain_in.into();
            let mut block_out = Array::<u8, U16>::default();
            tf.encrypt_block_b2b(&block_in, &mut block_out);
            let cipher = block_out;
            let (l, r) = key.split_at_mut(16);
            r.copy_from_slice(&l[..16]);
            l.copy_from_slice(plain_in.as_slice());
            plain = cipher;
        }
        let got_hex = hex::encode(plain.as_slice());
        assert_eq!(got_hex, exp_hex);
        Ok(())
    }
}
