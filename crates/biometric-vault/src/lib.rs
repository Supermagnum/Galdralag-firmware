//! On-token biometric template AES-256-GCM encryption and session HMAC verification.
#![no_std]
extern crate alloc;

use alloc::vec::Vec;

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::KeyInit as _;
use aes_gcm::{Aes256Gcm, Key, Nonce};
use biometric_api::Modality;
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Digest;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Total on-chip RRAM (bytes), per `docs/RRAM_LAYOUT.md` / `docs/BIOMETRIC_API.md`.
pub const RRAM_TOTAL_BYTES: usize = 4_194_304;

pub const BIOMETRIC_REGION_OFFSET: usize = 0x010000;

/// Maximum byte span from [`BIOMETRIC_REGION_OFFSET`] through the end of RRAM.
/// `docs/BIOMETRIC_API.md` cites ~4035 KiB of template budget; this is the exact 4 MiB-bound slice.
pub const BIOMETRIC_REGION_SIZE: usize = RRAM_TOTAL_BYTES - BIOMETRIC_REGION_OFFSET;

pub const MAX_TEMPLATE_SIZE_BYTES: usize = 16 * 1024;

pub const MAX_ENROLLED_PERSONS: usize = 260;

pub const SAMPLES_PER_ENROLLMENT: usize = 3;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum VaultError {
    Crypto,
    TemplateTooLarge,
    DecryptFailed,
    TokenMismatch,
    TimeWindow,
}

fn derive_slot_key(
    master_key: &[u8; 32],
    user_id: &[u8; 16],
    modality: Modality,
) -> Result<[u8; 32], VaultError> {
    let mut salt = [0u8; 17];
    salt[0] = modality as u8;
    salt[1..].copy_from_slice(user_id);
    let hk = Hkdf::<Sha256>::new(Some(salt.as_slice()), master_key.as_slice());
    let mut key = [0u8; 32];
    hk.expand(b"galdrag-bio-slot-v1", &mut key)
        .map_err(|_| VaultError::Crypto)?;
    Ok(key)
}

/// Deterministic AES-GCM nonce derived from vault binding material and plaintext (unique per template bytes).
fn nonce_for_plaintext(
    master_key: &[u8; 32],
    user_id: &[u8; 16],
    modality: Modality,
    raw_template: &[u8],
) -> [u8; 12] {
    let mut h = Sha256::new();
    h.update(master_key);
    h.update(user_id);
    h.update([modality as u8]);
    h.update((raw_template.len() as u64).to_le_bytes());
    h.update(raw_template);
    let d = h.finalize();
    let mut n = [0u8; 12];
    n.copy_from_slice(&d[..12]);
    n
}

/// Encrypt a raw template for storage in RRAM (AES-256-GCM; per-slot key from HKDF).
pub fn encrypt_template(
    master_key: &[u8; 32],
    user_id: &[u8; 16],
    modality: Modality,
    raw_template: &[u8],
) -> Result<Vec<u8>, VaultError> {
    if raw_template.len() > MAX_TEMPLATE_SIZE_BYTES {
        return Err(VaultError::TemplateTooLarge);
    }
    let key = derive_slot_key(master_key, user_id, modality)?;
    let nonce = nonce_for_plaintext(master_key, user_id, modality, raw_template);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_slice()));
    let ga_nonce = Nonce::from_slice(nonce.as_slice());
    let ct = cipher
        .encrypt(
            ga_nonce,
            Payload {
                msg: raw_template,
                aad: b"",
            },
        )
        .map_err(|_| VaultError::Crypto)?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(ct.as_slice());
    Ok(out)
}

/// Decrypted template bytes; zeroized on drop.
pub type ZeroizingVec = Zeroizing<Vec<u8>>;

/// Decrypt a template blob. Plaintext is zeroized when the return value is dropped.
pub fn decrypt_template(
    master_key: &[u8; 32],
    user_id: &[u8; 16],
    modality: Modality,
    encrypted_blob: &[u8],
) -> Result<ZeroizingVec, VaultError> {
    if encrypted_blob.len() < 12 + 16 {
        return Err(VaultError::DecryptFailed);
    }
    let (nonce_b, ct) = encrypted_blob.split_at(12);
    let key = derive_slot_key(master_key, user_id, modality)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_slice()));
    let ga_nonce = Nonce::from_slice(nonce_b);
    let pt = cipher
        .decrypt(ga_nonce, Payload { msg: ct, aad: b"" })
        .map_err(|_| VaultError::DecryptFailed)?;
    let expected = nonce_for_plaintext(master_key, user_id, modality, pt.as_slice());
    if expected.as_slice().ct_ne(nonce_b).into() {
        return Err(VaultError::DecryptFailed);
    }
    Ok(Zeroizing::new(pt))
}

/// HMAC-SHA256(vault_biometric_hmac_key, nonce || device_id || timestamp_be).
pub fn generate_session_token(
    hmac_key: &[u8; 32],
    nonce: &[u8; 32],
    device_id: &[u8; 16],
    timestamp: u64,
) -> [u8; 32] {
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(hmac_key.as_slice()).expect("HMAC key length");
    mac.update(nonce.as_slice());
    mac.update(device_id);
    mac.update(timestamp.to_be_bytes().as_slice());
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_slice());
    out
}

/// Verify a session token (`subtle` compare on the MAC tag).
pub fn verify_session_token(
    hmac_key: &[u8; 32],
    nonce: &[u8; 32],
    device_id: &[u8; 16],
    timestamp: u64,
    token: &[u8; 32],
    max_age_secs: u64,
    now_secs: u64,
) -> Result<(), VaultError> {
    if now_secs.saturating_sub(timestamp) > max_age_secs {
        return Err(VaultError::TimeWindow);
    }
    let expected = generate_session_token(hmac_key, nonce, device_id, timestamp);
    if expected.as_slice().ct_ne(token.as_slice()).into() {
        return Err(VaultError::TokenMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use biometric_api::Modality;

    #[test]
    fn encrypt_decrypt_roundtrip_smoke() {
        let mk = [9u8; 32];
        let uid = [3u8; 16];
        let raw = b"template-bytes";
        let ct = encrypt_template(&mk, &uid, Modality::FingerVein, raw).unwrap();
        let pt = decrypt_template(&mk, &uid, Modality::FingerVein, ct.as_slice()).unwrap();
        assert_eq!(pt.as_slice(), raw.as_slice());
    }
}
