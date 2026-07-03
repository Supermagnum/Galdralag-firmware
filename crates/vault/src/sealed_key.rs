//! AEAD-sealed private key scalars for OpenPGP slots (RRAM persistence).

#![deny(unsafe_code)]

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use galdr_core::hal::HardwareTrng;
use heapless::Vec;
use hkdf::Hkdf;
use sha2::Sha256;

use crate::kdf_policy::KeyPurpose;
use crate::layout::SEALED_BLOB_BYTES;

/// HKDF `info` prefix for per-slot wrapping keys (distinct from [`KeyPurpose::info`] labels).
const WRAP_INFO_PREFIX: &[u8] = b"galdralag/sealed-key/wrap/v1";

/// Sealed blob: `purpose` (1) || `nonce` (12) || AES-GCM ciphertext (n) || tag (16), `n` = scalar length.
///
/// Total length: `29 + n` bytes, `n` in `1..=64`.
pub struct SealedKeyBlob(Vec<u8, 93>);

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SealedKeyError {
    /// AEAD tag verification failed (tampering, wrong key, or empty cell).
    AuthenticationFailed,
    /// Stored purpose byte does not match the expected slot.
    PurposeMismatch,
    /// TRNG failure when sampling a nonce.
    TrngError,
    /// Encoding, length, or internal buffer error.
    StorageError,
}

fn purpose_wire_id(purpose: KeyPurpose) -> Result<u8, SealedKeyError> {
    match purpose {
        KeyPurpose::OpenPgpSig => Ok(1),
        KeyPurpose::OpenPgpDec => Ok(2),
        KeyPurpose::OpenPgpAut => Ok(3),
        _ => Err(SealedKeyError::StorageError),
    }
}

fn derive_wrapping_key(
    master_key: &[u8; 32],
    purpose_byte: u8,
) -> Result<[u8; 32], SealedKeyError> {
    let mut info = Vec::<u8, 64>::new();
    for b in WRAP_INFO_PREFIX {
        info.push(*b).map_err(|_| SealedKeyError::StorageError)?;
    }
    info.push(purpose_byte)
        .map_err(|_| SealedKeyError::StorageError)?;
    let hk = Hkdf::<Sha256>::new(Some(&[]), master_key);
    let mut okm = [0u8; 32];
    hk.expand(info.as_slice(), &mut okm)
        .map_err(|_| SealedKeyError::StorageError)?;
    Ok(okm)
}

fn build_aad(purpose_byte: u8, nonce: &[u8; 12]) -> Result<Vec<u8, 13>, SealedKeyError> {
    let mut a = Vec::<u8, 13>::new();
    a.push(purpose_byte)
        .map_err(|_| SealedKeyError::StorageError)?;
    for b in nonce {
        a.push(*b).map_err(|_| SealedKeyError::StorageError)?;
    }
    Ok(a)
}

impl SealedKeyBlob {
    /// Seal a private key scalar under the vault master key.
    pub fn seal<T: HardwareTrng>(
        master_key: &[u8; 32],
        purpose: KeyPurpose,
        scalar_bytes: &[u8],
        trng: &mut T,
    ) -> Result<Self, SealedKeyError> {
        if scalar_bytes.is_empty() || scalar_bytes.len() > 64 {
            return Err(SealedKeyError::StorageError);
        }
        let purpose_byte = purpose_wire_id(purpose)?;
        let mut nonce = [0u8; 12];
        trng.try_fill_bytes(&mut nonce)
            .map_err(|_| SealedKeyError::TrngError)?;
        let aad = build_aad(purpose_byte, &nonce)?;
        let wrapping_key = derive_wrapping_key(master_key, purpose_byte)?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&wrapping_key));
        let nonce_ga = Nonce::from_slice(&nonce);
        let combined = cipher
            .encrypt(
                nonce_ga,
                Payload {
                    msg: scalar_bytes,
                    aad: aad.as_slice(),
                },
            )
            .map_err(|_| SealedKeyError::StorageError)?;
        if combined.len() != scalar_bytes.len().saturating_add(16) {
            return Err(SealedKeyError::StorageError);
        }
        let mut out = Vec::<u8, 93>::new();
        out.push(purpose_byte)
            .map_err(|_| SealedKeyError::StorageError)?;
        for b in nonce {
            out.push(b).map_err(|_| SealedKeyError::StorageError)?;
        }
        for b in combined {
            out.push(b).map_err(|_| SealedKeyError::StorageError)?;
        }
        Ok(Self(out))
    }

    /// Unseal this blob. Verifies the tag; returns scalar bytes on success.
    pub fn unseal(
        &self,
        master_key: &[u8; 32],
        expected_purpose: KeyPurpose,
    ) -> Result<Vec<u8, 64>, SealedKeyError> {
        let expected_wire = purpose_wire_id(expected_purpose)?;
        Self::unseal_inner(&self.0, master_key, expected_wire)
    }

    fn unseal_inner(
        raw: &Vec<u8, 93>,
        master_key: &[u8; 32],
        expected_wire: u8,
    ) -> Result<Vec<u8, 64>, SealedKeyError> {
        let sl = raw.len();
        if !(29..=93).contains(&sl) {
            return Err(SealedKeyError::AuthenticationFailed);
        }
        if raw.iter().all(|&b| b == 0) {
            return Err(SealedKeyError::AuthenticationFailed);
        }
        let purpose_byte = raw[0];
        if purpose_byte != expected_wire {
            if matches!(purpose_byte, 1..=3) {
                return Err(SealedKeyError::PurposeMismatch);
            }
            return Err(SealedKeyError::AuthenticationFailed);
        }
        let nonce: [u8; 12] = raw[1..13]
            .try_into()
            .map_err(|_| SealedKeyError::AuthenticationFailed)?;
        let combined = &raw[13..];
        if combined.len() < 17 {
            return Err(SealedKeyError::AuthenticationFailed);
        }
        let aad = build_aad(purpose_byte, &nonce)?;
        let wrapping_key = derive_wrapping_key(master_key, purpose_byte)?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&wrapping_key));
        let nonce_ga = Nonce::from_slice(&nonce);
        let pt = cipher
            .decrypt(
                nonce_ga,
                Payload {
                    msg: combined,
                    aad: aad.as_slice(),
                },
            )
            .map_err(|_| SealedKeyError::AuthenticationFailed)?;
        let mut v = Vec::<u8, 64>::new();
        for b in pt {
            v.push(b).map_err(|_| SealedKeyError::StorageError)?;
        }
        Ok(v)
    }

    /// Try to unseal a fixed-size RRAM cell (may be zero-padded after the blob).
    pub fn unseal_from_storage_cell(
        cell: &[u8; SEALED_BLOB_BYTES],
        master_key: &[u8; 32],
        expected_purpose: KeyPurpose,
    ) -> Result<Vec<u8, 64>, SealedKeyError> {
        let expected_wire = purpose_wire_id(expected_purpose)?;
        if cell.iter().all(|&b| b == 0) {
            return Err(SealedKeyError::AuthenticationFailed);
        }
        for n in (1..=64).rev() {
            let len = 29usize.saturating_add(n);
            if len > SEALED_BLOB_BYTES {
                continue;
            }
            if len < SEALED_BLOB_BYTES && cell[len..].iter().any(|&b| b != 0) {
                continue;
            }
            let mut v = Vec::<u8, 93>::new();
            for b in cell[..len].iter() {
                if v.push(*b).is_err() {
                    return Err(SealedKeyError::StorageError);
                }
            }
            match Self::unseal_inner(&v, master_key, expected_wire) {
                Ok(s) => return Ok(s),
                Err(SealedKeyError::PurposeMismatch) => {
                    return Err(SealedKeyError::PurposeMismatch);
                }
                Err(SealedKeyError::AuthenticationFailed) => continue,
                Err(e) => return Err(e),
            }
        }
        Err(SealedKeyError::AuthenticationFailed)
    }

    /// Raw blob bytes for [`galdr_core::hal::VaultStorage::write`].
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Length of this blob (29..=93).
    pub fn blob_len(&self) -> usize {
        self.0.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use galdr_core::fake_hal::FakeTrng;

    const MASTER: [u8; 32] = [0x7Eu8; 32];

    #[test]
    fn seal_unseal_roundtrip() {
        let mut trng = FakeTrng::from_seed(0xC0DE);
        let scalar = [0x3Bu8; 32];
        let blob =
            SealedKeyBlob::seal(&MASTER, KeyPurpose::OpenPgpSig, &scalar, &mut trng).expect("seal");
        let out = blob
            .unseal(&MASTER, KeyPurpose::OpenPgpSig)
            .expect("unseal");
        assert_eq!(out.as_slice(), scalar.as_slice());
    }

    #[test]
    fn tamper_tag() {
        let mut trng = FakeTrng::from_seed(1);
        let scalar = [0x22u8; 32];
        let blob =
            SealedKeyBlob::seal(&MASTER, KeyPurpose::OpenPgpAut, &scalar, &mut trng).expect("seal");
        let mut raw = alloc::vec::Vec::from(blob.as_slice());
        let last = raw.len().saturating_sub(1);
        raw[last] ^= 0x01;
        let mut inner = Vec::<u8, 93>::new();
        for b in raw {
            inner.push(b).unwrap();
        }
        let bad = SealedKeyBlob(inner);
        let r = bad.unseal(&MASTER, KeyPurpose::OpenPgpAut);
        assert_eq!(r, Err(SealedKeyError::AuthenticationFailed));
    }

    #[test]
    fn tamper_purpose() {
        let mut trng = FakeTrng::from_seed(2);
        let scalar = [0x11u8; 32];
        let blob =
            SealedKeyBlob::seal(&MASTER, KeyPurpose::OpenPgpSig, &scalar, &mut trng).expect("seal");
        let r = blob.unseal(&MASTER, KeyPurpose::OpenPgpDec);
        assert_eq!(r, Err(SealedKeyError::PurposeMismatch));
    }

    #[test]
    fn empty_cell() {
        let cell = [0u8; SEALED_BLOB_BYTES];
        let r = SealedKeyBlob::unseal_from_storage_cell(&cell, &MASTER, KeyPurpose::OpenPgpSig);
        assert_eq!(r, Err(SealedKeyError::AuthenticationFailed));
    }
}
