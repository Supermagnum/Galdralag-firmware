//! Bump-allocated public-key material region in RRAM.

use crate::error::ContactStoreError;
use crate::layout::{KEY_REGION_BYTES, KEY_REGION_OFFSET, MAX_PUBLIC_KEY_BYTES};
use crate::record::ContactRecord;
use galdr_core::hal::VaultStorage;

const COMPACT_SCRATCH_BYTES: usize = MAX_PUBLIC_KEY_BYTES;

/// Bump allocator state for public-key blobs.
#[derive(Default)]
pub struct KeyMaterialRegion {
    bump: u32,
}

impl KeyMaterialRegion {
    /// New region with bump at zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Current bump offset.
    pub fn bump_offset(&self) -> u32 {
        self.bump
    }

    /// Restore bump after boot scan.
    pub fn set_bump(&mut self, bump: u32) {
        self.bump = bump.min(KEY_REGION_BYTES);
    }

    /// Write key bytes; returns `(offset, len)` within the region.
    pub fn alloc<S: VaultStorage>(
        &mut self,
        storage: &mut S,
        key_bytes: &[u8],
    ) -> Result<(u32, u16), ContactStoreError> {
        if key_bytes.len() > MAX_PUBLIC_KEY_BYTES {
            return Err(ContactStoreError::KeyTooLarge);
        }
        let len = key_bytes.len() as u16;
        let need = u64::from(self.bump) + u64::from(len);
        if need > u64::from(KEY_REGION_BYTES) {
            return Err(ContactStoreError::HeapFull);
        }
        let off = KEY_REGION_OFFSET + u64::from(self.bump);
        storage
            .write(off, key_bytes)
            .map_err(|_| ContactStoreError::StorageWrite)?;
        let offset = self.bump;
        self.bump = self.bump.saturating_add(u32::from(len));
        Ok((offset, len))
    }

    /// Read key bytes into `buf`.
    pub fn read<S: VaultStorage>(
        &self,
        storage: &S,
        offset: u32,
        len: u16,
        buf: &mut [u8],
    ) -> Result<(), ContactStoreError> {
        if len == 0 {
            return Ok(());
        }
        if buf.len() < usize::from(len) {
            return Err(ContactStoreError::KeyTooLarge);
        }
        let end = u64::from(offset) + u64::from(len);
        if end > u64::from(KEY_REGION_BYTES) {
            return Err(ContactStoreError::CorruptRecord);
        }
        let off = KEY_REGION_OFFSET + u64::from(offset);
        storage
            .read(off, &mut buf[..usize::from(len)])
            .map_err(|_| ContactStoreError::StorageRead)?;
        Ok(())
    }

    /// Remaining bytes.
    pub fn free_space(&self) -> u32 {
        KEY_REGION_BYTES.saturating_sub(self.bump)
    }

    /// Compact live key blobs and rewrite offsets on active records.
    pub fn compact<S: VaultStorage>(
        &mut self,
        storage: &mut S,
        records: &mut [ContactRecord; 54],
    ) -> Result<(), ContactStoreError> {
        let mut scratch = [0u8; COMPACT_SCRATCH_BYTES];
        let mut new_bump = 0u32;
        for rec in records.iter_mut() {
            if !rec.is_active() || rec.key_len == 0 {
                continue;
            }
            let len = usize::from(rec.key_len);
            if len > scratch.len() {
                return Err(ContactStoreError::KeyTooLarge);
            }
            self.read(storage, rec.key_offset, rec.key_len, &mut scratch[..len])?;
            let need = u64::from(new_bump) + u64::from(rec.key_len);
            if need > u64::from(KEY_REGION_BYTES) {
                return Err(ContactStoreError::HeapFull);
            }
            let off = KEY_REGION_OFFSET + u64::from(new_bump);
            storage
                .write(off, &scratch[..len])
                .map_err(|_| ContactStoreError::StorageWrite)?;
            rec.key_offset = new_bump;
            new_bump = new_bump.saturating_add(u32::from(rec.key_len));
        }
        self.bump = new_bump;
        Ok(())
    }
}
