//! ChaCha20-Poly1305 AEAD with HKDF-derived keys and typed nonces (RFC 8439 via `chacha20poly1305`).

use crate::kdf_policy::KeyPurpose;
use aead::inout::InOutBuf;
use aead::{AeadInOut, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};
use galdr_core::hal::HardwareTrng;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

/// Maximum plaintext size for this profile (firmware token throughput).
pub const MAX_CHACHA_PLAINTEXT: usize = 8192;

/// Maximum ciphertext buffer (plaintext + 16-byte tag).
pub const MAX_CHACHA_CIPHERTEXT: usize = MAX_CHACHA_PLAINTEXT + 16;

/// Errors from ChaCha20-Poly1305 key derivation and AEAD operations.
#[derive(Debug, Eq, PartialEq)]
pub enum ChaChaError {
    /// Poly1305 tag verification failed or ciphertext was truncated.
    AuthenticationFailed,
    /// HKDF expand failed or output length was invalid.
    KeyDerivation,
    /// TRNG could not supply a nonce or key material.
    TrngFailure,
    /// Input length exceeds the vault buffer bound.
    InvalidLength,
}

/// A ChaCha20-Poly1305 key. 256 bits. Zeroizes on drop. No Clone, no Copy.
#[derive(Zeroize)]
pub struct ChaChaKey([u8; 32]);

impl Drop for ChaChaKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// A ChaCha20-Poly1305 nonce. 96 bits (12 bytes).
/// Constructed only from TRNG output or explicit derivation; never from
/// a caller-supplied integer that might be reused.
#[derive(Clone, Eq, PartialEq)]
pub struct ChaChaNonce([u8; 12]);

/// An authenticated ciphertext with appended 128-bit Poly1305 tag.
/// The plaintext length can be recovered as `ciphertext.len() - 16`.
#[derive(Clone, Eq, PartialEq)]
pub struct ChaChaCiphertext {
    buf: heapless::Vec<u8, MAX_CHACHA_CIPHERTEXT>,
}

/// Decrypted plaintext buffer; zeroizes on drop.
pub struct ChaChaPlaintext {
    buf: heapless::Vec<u8, MAX_CHACHA_PLAINTEXT>,
}

impl Zeroize for ChaChaPlaintext {
    fn zeroize(&mut self) {
        self.buf.as_mut_slice().zeroize();
    }
}

impl Drop for ChaChaPlaintext {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ChaChaKey {
    /// Derive a 256-bit key with HKDF-SHA256 using `info` as the sole label (no [`KeyPurpose`] prefix).
    ///
    /// Intended for cipher-profile cascades where the full domain string is supplied by the caller.
    pub fn derive_from_prk_label(prk: &[u8], info: &[u8]) -> Result<Self, ChaChaError> {
        let hk = Hkdf::<Sha256>::from_prk(prk).map_err(|_| ChaChaError::KeyDerivation)?;
        let mut okm = [0u8; 32];
        hk.expand(info, &mut okm)
            .map_err(|_| ChaChaError::KeyDerivation)?;
        Ok(Self(okm))
    }

    /// Derive a key from HKDF output for the given purpose.
    /// The `info` bytes provide additional domain separation beyond KeyPurpose.
    pub fn derive(prk: &[u8], purpose: KeyPurpose, info: &[u8]) -> Result<Self, ChaChaError> {
        let mut okm = [0u8; 32];
        let mut inf = heapless::Vec::<u8, 256>::new();
        for b in purpose.info() {
            inf.push(*b).map_err(|_| ChaChaError::KeyDerivation)?;
        }
        for b in info {
            inf.push(*b).map_err(|_| ChaChaError::KeyDerivation)?;
        }
        let hk = Hkdf::<Sha256>::from_prk(prk).map_err(|_| ChaChaError::KeyDerivation)?;
        hk.expand(inf.as_slice(), &mut okm)
            .map_err(|_| ChaChaError::KeyDerivation)?;
        Ok(Self(okm))
    }

    fn chacha_key(&self) -> Key {
        Key::from(self.0)
    }

    /// Raw key bytes for Wycheproof / test vectors (not used in production paths).
    #[doc(hidden)]
    pub fn from_raw_key_bytes_for_test(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Build from 32 octets of key material (e.g. HKDF-BLAKE3 expand output for CESS §8.3 inner).
    pub fn from_symmetric_key_material(key: [u8; 32]) -> Self {
        Self(key)
    }

    /// Test-only inspection of raw key bytes (integration tests).
    #[doc(hidden)]
    pub fn as_raw_bytes_for_test(&self) -> [u8; 32] {
        self.0
    }
}

impl ChaChaNonce {
    /// Derive a 96-bit nonce with HKDF-SHA256 using `info` as the sole label; uses the first 12 bytes of the expand output.
    pub fn derive_from_prk_label(prk: &[u8], info: &[u8]) -> Result<Self, ChaChaError> {
        let hk = Hkdf::<Sha256>::from_prk(prk).map_err(|_| ChaChaError::KeyDerivation)?;
        let mut okm = [0u8; 32];
        hk.expand(info, &mut okm)
            .map_err(|_| ChaChaError::KeyDerivation)?;
        let mut n = [0u8; 12];
        n.copy_from_slice(&okm[..12]);
        Ok(Self(n))
    }

    /// First 12 octets of a 32-byte OKM (e.g. HKDF-BLAKE3 expand used for deterministic nonce).
    pub fn from_okm32_prefix(okm: &[u8; 32]) -> Self {
        let mut n = [0u8; 12];
        n.copy_from_slice(&okm[..12]);
        Self(n)
    }

    /// Generate a random nonce from the TRNG. Preferred construction.
    pub fn generate<T: HardwareTrng>(trng: &mut T) -> Result<Self, ChaChaError> {
        let mut n = [0u8; 12];
        trng.try_fill_bytes(&mut n)
            .map_err(|_| ChaChaError::TrngFailure)?;
        Ok(Self(n))
    }

    /// Construct a nonce deterministically from a 96-bit counter value.
    ///
    /// The caller is responsible for ensuring the counter is never reused
    /// under the same key. Document the counter management policy at the
    /// call site.
    pub fn from_counter(counter: u128) -> Self {
        let c = counter & ((1u128 << 96) - 1);
        let mut n = [0u8; 12];
        let b = c.to_be_bytes();
        n.copy_from_slice(&b[4..16]);
        Self(n)
    }

    fn nonce(&self) -> Nonce {
        Nonce::from(self.0)
    }

    /// Copy nonce bytes (the nonce is not secret; exposed for protocol framing).
    pub fn to_bytes(&self) -> [u8; 12] {
        self.0
    }

    /// Reconstruct a nonce from stored framing bytes (nonce is not secret).
    pub fn from_stored_bytes(bytes: [u8; 12]) -> Self {
        Self(bytes)
    }

    #[cfg(test)]
    pub(crate) fn from_bytes_for_test(bytes: [u8; 12]) -> Self {
        Self(bytes)
    }
}

impl ChaChaCiphertext {
    /// Raw ciphertext bytes (body || tag).
    pub fn as_slice(&self) -> &[u8] {
        self.buf.as_slice()
    }

    /// Decode ciphertext bytes (body || Poly1305 tag) for cascade and framing callers.
    pub fn try_from_slice(buf: &[u8]) -> Result<Self, ChaChaError> {
        if buf.len() > MAX_CHACHA_CIPHERTEXT {
            return Err(ChaChaError::InvalidLength);
        }
        let mut v = heapless::Vec::new();
        for b in buf {
            v.push(*b).map_err(|_| ChaChaError::InvalidLength)?;
        }
        Ok(Self { buf: v })
    }

    pub(crate) fn from_heapless_vec(buf: heapless::Vec<u8, MAX_CHACHA_CIPHERTEXT>) -> Self {
        Self { buf }
    }
}

#[cfg(test)]
impl ChaChaCiphertext {
    pub(crate) fn from_vec_for_test(buf: heapless::Vec<u8, MAX_CHACHA_CIPHERTEXT>) -> Self {
        Self { buf }
    }

    pub(crate) fn as_slice_for_test(&self) -> &[u8] {
        self.buf.as_slice()
    }
}

impl ChaChaPlaintext {
    /// Borrow decrypted bytes.
    pub fn as_slice(&self) -> &[u8] {
        self.buf.as_slice()
    }

    #[cfg(test)]
    pub(crate) fn as_mut_slice_for_test(&mut self) -> &mut [u8] {
        self.buf.as_mut_slice()
    }
}

/// Encrypt `plaintext` with additional authenticated data `aad`.
/// Returns the ciphertext with the Poly1305 tag appended.
pub fn chacha_encrypt(
    key: &ChaChaKey,
    nonce: &ChaChaNonce,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<ChaChaCiphertext, ChaChaError> {
    if plaintext.len() > MAX_CHACHA_PLAINTEXT {
        return Err(ChaChaError::InvalidLength);
    }
    let cipher = ChaCha20Poly1305::new(&key.chacha_key());
    let mut buf = heapless::Vec::<u8, MAX_CHACHA_CIPHERTEXT>::new();
    for b in plaintext {
        buf.push(*b).map_err(|_| ChaChaError::InvalidLength)?;
    }
    let tag: Tag = cipher
        .encrypt_inout_detached(
            &nonce.nonce(),
            aad,
            InOutBuf::from(buf.as_mut_slice()),
        )
        .map_err(|_| ChaChaError::AuthenticationFailed)?;
    for b in tag.as_slice() {
        buf.push(*b).map_err(|_| ChaChaError::InvalidLength)?;
    }
    Ok(ChaChaCiphertext { buf })
}

/// Decrypt and authenticate `ciphertext` (tag must be appended).
/// Returns the plaintext only if the tag verifies. The plaintext buffer
/// is zeroised before returning Err on authentication failure.
pub fn chacha_decrypt(
    key: &ChaChaKey,
    nonce: &ChaChaNonce,
    aad: &[u8],
    ciphertext: &ChaChaCiphertext,
) -> Result<ChaChaPlaintext, ChaChaError> {
    let ct = ciphertext.buf.as_slice();
    if ct.len() < 16 {
        return Err(ChaChaError::AuthenticationFailed);
    }
    let (body, tag) = ct.split_at(ct.len() - 16);
    if body.len() > MAX_CHACHA_PLAINTEXT {
        return Err(ChaChaError::InvalidLength);
    }
    let cipher = ChaCha20Poly1305::new(&key.chacha_key());
    let mut buf = heapless::Vec::<u8, MAX_CHACHA_PLAINTEXT>::new();
    for b in body {
        buf.push(*b).map_err(|_| ChaChaError::InvalidLength)?;
    }
    let tag = Tag::try_from(tag).map_err(|_| ChaChaError::AuthenticationFailed)?;
    match cipher.decrypt_inout_detached(
        &nonce.nonce(),
        aad,
        InOutBuf::from(buf.as_mut_slice()),
        &tag,
    ) {
        Ok(()) => Ok(ChaChaPlaintext { buf }),
        Err(_e) => {
            buf.as_mut_slice().zeroize();
            Err(ChaChaError::AuthenticationFailed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use galdr_core::fake_hal::FakeTrng;
    use hex;
    use rand_core::RngCore;
    use std::collections::HashSet;

    /// RFC 8439 section 2.8.2 AAD example (combined ciphertext + tag from test vector).
    #[test]
    fn rfc8439_section_2_8_2_known_answer() -> Result<(), ChaChaError> {
        let key_bytes =
            hex::decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
                .map_err(|_| ChaChaError::InvalidLength)?;
        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&key_bytes);
        let key = ChaChaKey(key_arr);
        let mut nb = [0u8; 12];
        nb.copy_from_slice(
            &hex::decode("070000004041424344454647").map_err(|_| ChaChaError::InvalidLength)?,
        );
        let nonce = ChaChaNonce::from_bytes_for_test(nb);
        let aad =
            hex::decode("50515253c0c1c2c3c4c5c6c7").map_err(|_| ChaChaError::InvalidLength)?;
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let ct = chacha_encrypt(&key, &nonce, &aad, plaintext)?;
        let expected_ct = hex::decode(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116",
        )
        .map_err(|_| ChaChaError::InvalidLength)?;
        let expected_tag = hex::decode("1ae10b594f09e26a7e902ecbd0600691")
            .map_err(|_| ChaChaError::InvalidLength)?;
        let mut exp = heapless::Vec::<u8, MAX_CHACHA_CIPHERTEXT>::new();
        for b in expected_ct.iter().chain(expected_tag.iter()) {
            exp.push(*b).map_err(|_| ChaChaError::InvalidLength)?;
        }
        assert_eq!(ct.buf.as_slice(), exp.as_slice());
        Ok(())
    }

    #[test]
    fn round_trip() -> Result<(), ChaChaError> {
        let mut trng = FakeTrng::from_seed(0xBEE);
        let mut key = [0u8; 32];
        trng.fill_bytes(&mut key);
        let k = ChaChaKey(key);
        let n = ChaChaNonce::generate(&mut trng)?;
        let aad = b"galdr-aad";
        let pt = b"secret payload";
        let ct = chacha_encrypt(&k, &n, aad, pt)?;
        let out = chacha_decrypt(&k, &n, aad, &ct)?;
        assert_eq!(out.as_slice(), pt);
        Ok(())
    }

    #[test]
    fn aad_binding_fails() -> Result<(), ChaChaError> {
        let mut trng = FakeTrng::from_seed(0xC0DE);
        let mut key = [0u8; 32];
        trng.fill_bytes(&mut key);
        let k = ChaChaKey(key);
        let n = ChaChaNonce::generate(&mut trng)?;
        let ct = chacha_encrypt(&k, &n, b"context-a", b"data")?;
        let r = chacha_decrypt(&k, &n, b"context-b", &ct);
        assert!(matches!(r, Err(ChaChaError::AuthenticationFailed)));
        Ok(())
    }

    #[test]
    fn tag_truncation_fails() -> Result<(), ChaChaError> {
        let mut trng = FakeTrng::from_seed(0xD);
        let mut key = [0u8; 32];
        trng.fill_bytes(&mut key);
        let k = ChaChaKey(key);
        let n = ChaChaNonce::generate(&mut trng)?;
        let mut ct = chacha_encrypt(&k, &n, b"", b"x")?;
        ct.buf.pop();
        let r = chacha_decrypt(&k, &n, b"", &ct);
        assert!(matches!(r, Err(ChaChaError::AuthenticationFailed)));
        Ok(())
    }

    #[test]
    fn tag_corruption_fails() -> Result<(), ChaChaError> {
        let mut trng = FakeTrng::from_seed(0xE);
        let mut key = [0u8; 32];
        trng.fill_bytes(&mut key);
        let k = ChaChaKey(key);
        let n = ChaChaNonce::generate(&mut trng)?;
        let mut ct = chacha_encrypt(&k, &n, b"aad", b"msg")?;
        if let Some(b) = ct.buf.last_mut() {
            *b ^= 0x01;
        }
        let r = chacha_decrypt(&k, &n, b"aad", &ct);
        assert!(matches!(r, Err(ChaChaError::AuthenticationFailed)));
        Ok(())
    }

    #[test]
    fn ciphertext_body_corruption_fails() -> Result<(), ChaChaError> {
        let mut trng = FakeTrng::from_seed(0xF);
        let mut key = [0u8; 32];
        trng.fill_bytes(&mut key);
        let k = ChaChaKey(key);
        let n = ChaChaNonce::generate(&mut trng)?;
        let mut ct = chacha_encrypt(&k, &n, b"", b"body")?;
        if !ct.buf.is_empty() {
            ct.buf[0] ^= 0x01;
        }
        let r = chacha_decrypt(&k, &n, b"", &ct);
        assert!(matches!(r, Err(ChaChaError::AuthenticationFailed)));
        Ok(())
    }

    #[test]
    fn plaintext_zeroize_on_drop() -> Result<(), ChaChaError> {
        let mut trng = FakeTrng::from_seed(0x10);
        let mut key = [0u8; 32];
        trng.fill_bytes(&mut key);
        let k = ChaChaKey(key);
        let n = ChaChaNonce::generate(&mut trng)?;
        let ct = chacha_encrypt(&k, &n, b"", b"zero-me")?;
        let mut plain = chacha_decrypt(&k, &n, b"", &ct)?;
        plain.as_mut_slice_for_test().fill(0xAB);
        plain.zeroize();
        assert!(plain.as_slice().iter().all(|b| *b == 0));
        Ok(())
    }

    #[test]
    fn nonce_uniqueness_fake_trng() -> Result<(), ChaChaError> {
        let mut trng = FakeTrng::from_seed(0x1234);
        let mut set = HashSet::new();
        for _ in 0..1000 {
            let n = ChaChaNonce::generate(&mut trng)?;
            let a = n.to_bytes();
            assert!(set.insert(a));
        }
        Ok(())
    }

    #[test]
    fn key_purpose_domain_separation() -> Result<(), ChaChaError> {
        let prk = [0x42u8; 32];
        let k1 = ChaChaKey::derive(&prk, KeyPurpose::RramBlobWrap, b"extra")?;
        let k2 = ChaChaKey::derive(&prk, KeyPurpose::StorageSeal, b"extra")?;
        assert_ne!(k1.0, k2.0);
        Ok(())
    }
}
