//! Store RSA private keys in RRAM-backed [`VaultStorage`] with ChaCha20-Poly1305 wrapping.
//!
//! Wrapped blobs use [`crate::chacha_aead`] with [`crate::kdf_policy::KeyPurpose::RsaKeyWrap`].
//! Callers supply the vault master PRK (never stored in plaintext in the slot).
//!
//! Use [`RsaVaultStoreContext`] to bundle HAL storage, PRK, and TRNG, then call
//! [`vault_store_rsa_key`] with the slot, key, and overwrite flag only.

use alloc::vec::Vec;

use galdr_core::hal::{HardwareTrng, VaultStorage};

use crate::chacha_aead::{chacha_decrypt, chacha_encrypt, ChaChaCiphertext, ChaChaKey, ChaChaNonce};
use crate::kdf_policy::KeyPurpose;
use crate::rsa_keys::{RsaDerBytes, RsaPrivateKey};

/// Bundles [`VaultStorage`], the vault master PRK (for HKDF-RsaKeyWrap), and a TRNG for the
/// ChaCha nonce. Keeps provisioning inputs together at the type level so store paths do not drop
/// entropy or domain separation by accident.
pub struct RsaVaultStoreContext<'a, S: VaultStorage, T: HardwareTrng> {
    /// RRAM (or test) backing store.
    pub storage: &'a mut S,
    /// Master PRK; never written to the slot.
    pub vault_master_prk: &'a [u8],
    /// Entropy for [`ChaChaNonce::generate`].
    pub trng: &'a mut T,
}

impl<'a, S, T> RsaVaultStoreContext<'a, S, T>
where
    S: VaultStorage,
    T: HardwareTrng,
{
    /// Construct a store context for one or more [`vault_store_rsa_key`] calls.
    pub fn new(storage: &'a mut S, vault_master_prk: &'a [u8], trng: &'a mut T) -> Self {
        Self {
            storage,
            vault_master_prk,
            trng,
        }
    }
}

/// Slot identifier for persisted RSA keys (index into the vault layout).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct KeySlot(pub u32);

/// Errors from vault RSA persistence.
#[derive(Debug, Eq, PartialEq)]
pub enum RsaVaultError {
    /// Underlying RSA error.
    Rsa(crate::rsa_keys::RsaError),
    /// ChaCha AEAD or derivation failure.
    Wrap(crate::chacha_aead::ChaChaError),
    /// Slot already contains a key and `overwrite` was false.
    SlotOccupied,
    /// Slot is empty or unreadable.
    SlotEmpty,
    /// Slot metadata invalid (magic / length).
    SlotInvalid,
    /// HAL storage error.
    StorageError,
}

const RSA_VAULT_MAGIC: &[u8; 4] = b"G3R1";
/// Bytes reserved per RSA slot (wrapped PKCS#8 + header).
const RSA_SLOT_BYTES: usize = 8192;
/// Header: magic 4 + ct_len 4 + nonce 12 = 20.
const RSA_HEADER_LEN: usize = 20;
/// AAD for ChaCha wrapping (versioned string).
const RSA_WRAP_AAD: &[u8] = b"galdralag/rsa/vault-wrap/v1";

fn slot_offset(slot: &KeySlot) -> u64 {
    u64::from(slot.0).saturating_mul(RSA_SLOT_BYTES as u64)
}

fn derive_wrap_key(vault_master_prk: &[u8], slot: &KeySlot) -> Result<ChaChaKey, RsaVaultError> {
    let mut info = heapless::Vec::<u8, 32>::new();
    for b in slot.0.to_be_bytes() {
        info.push(b).map_err(|_| RsaVaultError::SlotInvalid)?;
    }
    ChaChaKey::derive(vault_master_prk, KeyPurpose::RsaKeyWrap, info.as_slice())
        .map_err(RsaVaultError::Wrap)
}

/// Store `key` wrapped under HKDF(`vault_master_prk`, [`KeyPurpose::RsaKeyWrap`], slot id).
/// The ChaCha nonce comes from `ctx.trng`.
pub fn vault_store_rsa_key<S, T>(
    ctx: &mut RsaVaultStoreContext<'_, S, T>,
    slot: &KeySlot,
    key: &RsaPrivateKey,
    overwrite: bool,
) -> Result<(), RsaVaultError>
where
    S: VaultStorage,
    T: HardwareTrng,
{
    let off = slot_offset(slot);
    let mut probe = [0u8; 4];
    ctx.storage
        .read(off, &mut probe)
        .map_err(|_| RsaVaultError::StorageError)?;
    if probe == *RSA_VAULT_MAGIC && !overwrite {
        return Err(RsaVaultError::SlotOccupied);
    }
    let der: RsaDerBytes = key.to_pkcs8_der().map_err(RsaVaultError::Rsa)?;
    let wrap_key = derive_wrap_key(ctx.vault_master_prk, slot)?;
    let nonce = ChaChaNonce::generate(ctx.trng).map_err(RsaVaultError::Wrap)?;
    let ct = chacha_encrypt(&wrap_key, &nonce, RSA_WRAP_AAD, der.as_slice())
        .map_err(RsaVaultError::Wrap)?;
    let ct_bytes = ct.as_slice();
    let ct_len: u32 = u32::try_from(ct_bytes.len()).map_err(|_| RsaVaultError::SlotInvalid)?;
    if RSA_HEADER_LEN + ct_bytes.len() > RSA_SLOT_BYTES {
        return Err(RsaVaultError::SlotInvalid);
    }
    let mut buf = Vec::with_capacity(RSA_HEADER_LEN + ct_bytes.len());
    buf.extend_from_slice(RSA_VAULT_MAGIC);
    buf.extend_from_slice(&ct_len.to_le_bytes());
    buf.extend_from_slice(&nonce.to_bytes());
    buf.extend_from_slice(ct_bytes);
    let mut slot_buf = alloc::vec![0u8; RSA_SLOT_BYTES];
    slot_buf[..buf.len()].copy_from_slice(&buf);
    ctx.storage
        .write(off, &slot_buf)
        .map_err(|_| RsaVaultError::StorageError)?;
    Ok(())
}

/// Load a wrapped RSA private key.
pub fn vault_load_rsa_key(
    storage: &mut impl VaultStorage,
    vault_master_prk: &[u8],
    slot: &KeySlot,
) -> Result<RsaPrivateKey, RsaVaultError> {
    let off = slot_offset(slot);
    let mut slot_buf = alloc::vec![0u8; RSA_SLOT_BYTES];
    storage
        .read(off, &mut slot_buf)
        .map_err(|_| RsaVaultError::StorageError)?;
    if slot_buf.len() < RSA_HEADER_LEN || &slot_buf[..4] != RSA_VAULT_MAGIC {
        return Err(RsaVaultError::SlotEmpty);
    }
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&slot_buf[4..8]);
    let ct_len = u32::from_le_bytes(len_bytes) as usize;
    if ct_len < 16 || RSA_HEADER_LEN.saturating_add(ct_len) > RSA_SLOT_BYTES {
        return Err(RsaVaultError::SlotInvalid);
    }
    let mut nb = [0u8; 12];
    nb.copy_from_slice(&slot_buf[8..20]);
    let nonce = ChaChaNonce::from_stored_bytes(nb);
    let ct_slice = &slot_buf[20..20 + ct_len];
    let mut v = heapless::Vec::new();
    for b in ct_slice.iter() {
        v.push(*b).map_err(|_| RsaVaultError::SlotInvalid)?;
    }
    let ct = ChaChaCiphertext::from_heapless_vec(v);
    let wrap_key = derive_wrap_key(vault_master_prk, slot)?;
    let plain = chacha_decrypt(&wrap_key, &nonce, RSA_WRAP_AAD, &ct).map_err(RsaVaultError::Wrap)?;
    let pkcs8 = plain.as_slice();
    RsaPrivateKey::from_pkcs8_der(pkcs8).map_err(RsaVaultError::Rsa)
}

/// Zero-fill the slot.
pub fn vault_delete_rsa_key(
    storage: &mut impl VaultStorage,
    slot: &KeySlot,
) -> Result<(), RsaVaultError> {
    let off = slot_offset(slot);
    let z = alloc::vec![0u8; RSA_SLOT_BYTES];
    storage
        .write(off, &z)
        .map_err(|_| RsaVaultError::StorageError)?;
    Ok(())
}

impl From<crate::rsa_keys::RsaError> for RsaVaultError {
    fn from(e: crate::rsa_keys::RsaError) -> Self {
        RsaVaultError::Rsa(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use galdr_core::fake_hal::{FakeTrng, FakeVaultStorage};

    #[test]
    fn vault_round_trip() -> Result<(), RsaVaultError> {
        let mut mem = FakeVaultStorage::new(RSA_SLOT_BYTES * 4);
        let prk = [0x55u8; 32];
        let slot = KeySlot(1);
        let mut trng = FakeTrng::from_seed(0x71);
        let key = RsaPrivateKey::generate(&mut trng, 2048).map_err(RsaVaultError::Rsa)?;
        let mut trng2 = FakeTrng::from_seed(0x72);
        let mut store = RsaVaultStoreContext::new(&mut mem, &prk, &mut trng2);
        vault_store_rsa_key(&mut store, &slot, &key, true)?;
        let loaded = vault_load_rsa_key(&mut mem, &prk, &slot)?;
        assert_eq!(
            key.public_key().to_spki_der().map_err(RsaVaultError::Rsa)?,
            loaded.public_key().to_spki_der().map_err(RsaVaultError::Rsa)?
        );
        Ok(())
    }

    #[test]
    fn vault_overwrite_protection() -> Result<(), RsaVaultError> {
        let mut mem = FakeVaultStorage::new(RSA_SLOT_BYTES * 2);
        let prk = [0x33u8; 32];
        let slot = KeySlot(0);
        let mut trng = FakeTrng::from_seed(1);
        let key = RsaPrivateKey::generate(&mut trng, 2048).map_err(RsaVaultError::Rsa)?;
        let mut trng2 = FakeTrng::from_seed(2);
        {
            let mut store = RsaVaultStoreContext::new(&mut mem, &prk, &mut trng2);
            vault_store_rsa_key(&mut store, &slot, &key, true)?;
        }
        let mut trng3 = FakeTrng::from_seed(3);
        let mut store2 = RsaVaultStoreContext::new(&mut mem, &prk, &mut trng3);
        let r = vault_store_rsa_key(&mut store2, &slot, &key, false);
        assert_eq!(r, Err(RsaVaultError::SlotOccupied));
        Ok(())
    }

    #[test]
    fn vault_delete() -> Result<(), RsaVaultError> {
        let mut mem = FakeVaultStorage::new(RSA_SLOT_BYTES * 2);
        let prk = [0x44u8; 32];
        let slot = KeySlot(0);
        let mut trng = FakeTrng::from_seed(4);
        let key = RsaPrivateKey::generate(&mut trng, 2048).map_err(RsaVaultError::Rsa)?;
        let mut trng2 = FakeTrng::from_seed(5);
        let mut store = RsaVaultStoreContext::new(&mut mem, &prk, &mut trng2);
        vault_store_rsa_key(&mut store, &slot, &key, true)?;
        vault_delete_rsa_key(&mut mem, &slot)?;
        let r = vault_load_rsa_key(&mut mem, &prk, &slot);
        assert!(matches!(r, Err(RsaVaultError::SlotEmpty)));
        Ok(())
    }
}
