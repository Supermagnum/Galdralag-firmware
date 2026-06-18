//! Bump-allocated string heap in RRAM (64 KiB).

use crate::error::ContactStoreError;
use crate::layout::{STRING_HEAP_BYTES, STRING_HEAP_OFFSET};
use crate::record::{ContactRecord, StringRef};
use galdr_core::hal::VaultStorage;

/// Maximum live string bytes held in SRAM during compaction (`54 * 256` sketch bound).
const COMPACT_SCRATCH_BYTES: usize = 54 * 256;

/// Bump allocator state for heap-backed UTF-8 strings.
#[derive(Default)]
pub struct StringHeap {
    bump: u32,
}

impl StringHeap {
    /// New heap with bump at zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Current bump offset in RRAM.
    pub fn bump_offset(&self) -> u32 {
        self.bump
    }

    /// Restore bump after scanning live refs on boot.
    pub fn set_bump(&mut self, bump: u32) {
        self.bump = bump.min(STRING_HEAP_BYTES);
    }

    /// Write `bytes` at the bump pointer and advance.
    pub fn alloc<S: VaultStorage>(
        &mut self,
        storage: &mut S,
        bytes: &[u8],
    ) -> Result<StringRef, ContactStoreError> {
        if bytes.len() > u32::MAX as usize {
            return Err(ContactStoreError::StringTooLong);
        }
        let len = bytes.len() as u16;
        let need = u64::from(self.bump) + u64::from(len);
        if need > u64::from(STRING_HEAP_BYTES) {
            return Err(ContactStoreError::HeapFull);
        }
        let off = STRING_HEAP_OFFSET + u64::from(self.bump);
        storage
            .write(off, bytes)
            .map_err(|_| ContactStoreError::StorageWrite)?;
        let r = StringRef {
            offset: self.bump,
            len,
        };
        self.bump = self.bump.saturating_add(u32::from(len));
        Ok(r)
    }

    /// Read string bytes into `buf`.
    pub fn read<S: VaultStorage>(
        &self,
        storage: &S,
        r: StringRef,
        buf: &mut [u8],
    ) -> Result<(), ContactStoreError> {
        if r.is_empty() {
            return Ok(());
        }
        if buf.len() < usize::from(r.len) {
            return Err(ContactStoreError::StringTooLong);
        }
        let end = u64::from(r.offset) + u64::from(r.len);
        if end > u64::from(STRING_HEAP_BYTES) {
            return Err(ContactStoreError::CorruptRecord);
        }
        let off = STRING_HEAP_OFFSET + u64::from(r.offset);
        storage
            .read(off, &mut buf[..usize::from(r.len)])
            .map_err(|_| ContactStoreError::StorageRead)?;
        Ok(())
    }

    /// Remaining bytes in the heap.
    pub fn free_space(&self) -> u32 {
        STRING_HEAP_BYTES.saturating_sub(self.bump)
    }

    /// Rebuild the heap, rewriting live [`StringRef`] fields in `records`.
    pub fn compact<S: VaultStorage>(
        &mut self,
        storage: &mut S,
        records: &mut [ContactRecord; 54],
    ) -> Result<(), ContactStoreError> {
        let mut scratch = [0u8; COMPACT_SCRATCH_BYTES];
        let mut new_bump = 0u32;
        for rec in records.iter_mut() {
            if !rec.is_active() {
                continue;
            }
            let refs = [
                &mut rec.email,
                &mut rec.display_name,
                &mut rec.badge_number,
                &mut rec.organisation,
                &mut rec.department,
                &mut rec.role,
                &mut rec.note,
                &mut rec.radio_affiliation,
                &mut rec.street,
                &mut rec.country,
                &mut rec.postal_code,
                &mut rec.region,
                &mut rec.fluxer_id,
                &mut rec.discord_id,
                &mut rec.irc_id,
            ];
            for sr in refs {
                if sr.is_empty() {
                    continue;
                }
                let len = usize::from(sr.len);
                if len > scratch.len() {
                    return Err(ContactStoreError::HeapFull);
                }
                let old = *sr;
                let off_old = STRING_HEAP_OFFSET + u64::from(old.offset);
                storage
                    .read(off_old, &mut scratch[..len])
                    .map_err(|_| ContactStoreError::StorageRead)?;
                let need = u64::from(new_bump) + u64::from(old.len);
                if need > u64::from(STRING_HEAP_BYTES) {
                    return Err(ContactStoreError::HeapFull);
                }
                let off_new = STRING_HEAP_OFFSET + u64::from(new_bump);
                storage
                    .write(off_new, &scratch[..len])
                    .map_err(|_| ContactStoreError::StorageWrite)?;
                sr.offset = new_bump;
                new_bump = new_bump.saturating_add(u32::from(old.len));
            }
        }
        self.bump = new_bump;
        Ok(())
    }
}
