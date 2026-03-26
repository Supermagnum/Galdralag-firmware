//! Non-secret public keys (e.g. OpenPGP subkeys, TLS peer SPKI) in the RRAM vault.
//!
//! Payloads are stored **unencrypted** (public material). Callers authenticate or bind keys at a
//! higher layer. Layout: magic, little-endian length, DER bytes.

use alloc::vec::Vec;

use galdr_core::hal::VaultStorage;

/// Slot index for [`vault_store_public_key_der`] / [`vault_load_public_key_der`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct PublicKeySlot(pub u32);

#[derive(Debug, Eq, PartialEq)]
pub enum PublicKeyVaultError {
    SlotOccupied,
    SlotEmpty,
    DerTooLarge,
    SlotInvalid,
    StorageError,
}

const PUBLIC_KEY_MAGIC: &[u8; 4] = b"GPK1";
/// Bytes reserved per public-key slot (DER + header).
pub const PUBLIC_KEY_SLOT_BYTES: usize = 2048;
const HEADER_LEN: usize = 8;

/// Region base offset for the public-key table (after a policy header); layout-specific.
pub const PUBLIC_KEY_REGION_BASE: u64 = 256;

fn slot_offset(slot: &PublicKeySlot) -> u64 {
    PUBLIC_KEY_REGION_BASE + u64::from(slot.0) * (PUBLIC_KEY_SLOT_BYTES as u64)
}

/// Store SPKI / SubjectPublicKeyInfo DER (or other public blob) at `slot`.
pub fn vault_store_public_key_der<S: VaultStorage>(
    storage: &mut S,
    slot: &PublicKeySlot,
    der: &[u8],
    overwrite: bool,
) -> Result<(), PublicKeyVaultError> {
    if HEADER_LEN + der.len() > PUBLIC_KEY_SLOT_BYTES {
        return Err(PublicKeyVaultError::DerTooLarge);
    }
    let off = slot_offset(slot);
    let mut probe = [0u8; 4];
    storage
        .read(off, &mut probe)
        .map_err(|_| PublicKeyVaultError::StorageError)?;
    if probe == *PUBLIC_KEY_MAGIC && !overwrite {
        return Err(PublicKeyVaultError::SlotOccupied);
    }
    let mut buf = vec![0u8; PUBLIC_KEY_SLOT_BYTES];
    buf[0..4].copy_from_slice(PUBLIC_KEY_MAGIC);
    let len = u32::try_from(der.len()).map_err(|_| PublicKeyVaultError::DerTooLarge)?;
    buf[4..8].copy_from_slice(&len.to_le_bytes());
    buf[HEADER_LEN..HEADER_LEN + der.len()].copy_from_slice(der);
    storage
        .write(off, &buf)
        .map_err(|_| PublicKeyVaultError::StorageError)?;
    Ok(())
}

/// Load DER from `slot`.
pub fn vault_load_public_key_der<S: VaultStorage>(
    storage: &S,
    slot: &PublicKeySlot,
) -> Result<Vec<u8>, PublicKeyVaultError> {
    let off = slot_offset(slot);
    let mut buf = vec![0u8; PUBLIC_KEY_SLOT_BYTES];
    storage
        .read(off, &mut buf)
        .map_err(|_| PublicKeyVaultError::StorageError)?;
    if buf[0..4] != *PUBLIC_KEY_MAGIC {
        return Err(PublicKeyVaultError::SlotEmpty);
    }
    let len = u32::from_le_bytes(buf[4..8].try_into().unwrap()) as usize;
    if len > PUBLIC_KEY_SLOT_BYTES - HEADER_LEN {
        return Err(PublicKeyVaultError::SlotInvalid);
    }
    Ok(buf[HEADER_LEN..HEADER_LEN + len].to_vec())
}

/// Clear `slot` (all bytes zero).
pub fn vault_delete_public_key<S: VaultStorage>(
    storage: &mut S,
    slot: &PublicKeySlot,
) -> Result<(), PublicKeyVaultError> {
    let off = slot_offset(slot);
    let zeros = vec![0u8; PUBLIC_KEY_SLOT_BYTES];
    storage
        .write(off, &zeros)
        .map_err(|_| PublicKeyVaultError::StorageError)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use galdr_core::fake_hal::FakeVaultStorage;

    #[test]
    fn store_load_delete_roundtrip() {
        let mut mem = FakeVaultStorage::new(65536);
        let slot = PublicKeySlot(0);
        let der = [0x30u8, 0x03, 0x01, 0x02, 0x03];
        vault_store_public_key_der(&mut mem, &slot, &der, true).unwrap();
        let got = vault_load_public_key_der(&mem, &slot).unwrap();
        assert_eq!(got, der);
        vault_delete_public_key(&mut mem, &slot).unwrap();
        assert_eq!(
            vault_load_public_key_der(&mem, &slot),
            Err(PublicKeyVaultError::SlotEmpty)
        );
    }

    #[test]
    fn second_store_without_overwrite_fails() {
        let mut mem = FakeVaultStorage::new(65536);
        let slot = PublicKeySlot(1);
        vault_store_public_key_der(&mut mem, &slot, &[1, 2], true).unwrap();
        let r = vault_store_public_key_der(&mut mem, &slot, &[3, 4], false);
        assert_eq!(r, Err(PublicKeyVaultError::SlotOccupied));
    }
}
