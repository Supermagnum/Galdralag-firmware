//! AORAM-resident sorted contact index (SRAM).

use crate::error::ContactStoreError;
use crate::record::{ContactFlags, ContactRecord};

/// One hot-index entry (SRAM only).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IndexEntry {
    /// First 16 bytes of the OpenPGP fingerprint.
    pub fingerprint_prefix: [u8; 16],
    /// RRAM slot index (`0..=53`).
    pub slot: u8,
    /// Cached flags (may include session-only bits in upper layers).
    pub flags: u8,
}

/// Sorted fingerprint-prefix index (max 54 entries).
pub struct ContactIndex {
    entries: [IndexEntry; 54],
    len: u8,
}

#[allow(clippy::derivable_impls)]
impl Default for ContactIndex {
    fn default() -> Self {
        Self {
            entries: [IndexEntry::default(); 54],
            len: 0,
        }
    }
}

impl ContactIndex {
    /// Empty index.
    pub fn new() -> Self {
        Self::default()
    }

    fn flags_bits(f: ContactFlags) -> u8 {
        f.bits()
    }

    /// Insert or replace an entry, keeping sorted order by prefix.
    pub fn insert(
        &mut self,
        fp: &[u8; 32],
        slot: u8,
        flags: ContactFlags,
    ) -> Result<(), ContactStoreError> {
        let mut prefix = [0u8; 16];
        prefix.copy_from_slice(&fp[..16]);
        let new_e = IndexEntry {
            fingerprint_prefix: prefix,
            slot,
            flags: Self::flags_bits(flags),
        };
        let n = usize::from(self.len);
        let pos = self.entries[..n]
            .iter()
            .position(|e| e.fingerprint_prefix > prefix)
            .unwrap_or(n);
        if pos < n && self.entries[pos].fingerprint_prefix == prefix {
            self.entries[pos] = new_e;
            return Ok(());
        }
        if n >= 54 {
            return Err(ContactStoreError::RecipientSlotsFull);
        }
        for i in (pos..n).rev() {
            self.entries[i + 1] = self.entries[i];
        }
        self.entries[pos] = new_e;
        self.len += 1;
        Ok(())
    }

    /// Remove all entries for `slot`.
    pub fn remove(&mut self, slot: u8) {
        let mut w = 0usize;
        let n = usize::from(self.len);
        for i in 0..n {
            if self.entries[i].slot != slot {
                if w != i {
                    self.entries[w] = self.entries[i];
                }
                w += 1;
            }
        }
        self.len = w as u8;
    }

    /// Find slot by 16-byte prefix (caller confirms full fingerprint in RRAM).
    pub fn lookup_prefix(&self, fp_prefix: &[u8; 16]) -> Option<u8> {
        let n = usize::from(self.len);
        let mut lo = 0usize;
        let mut hi = n;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let p = &self.entries[mid].fingerprint_prefix;
            if p < fp_prefix {
                lo = mid + 1;
            } else if p > fp_prefix {
                hi = mid;
            } else {
                return Some(self.entries[mid].slot);
            }
        }
        None
    }

    /// Update cached flags for a slot.
    pub fn update_flags(&mut self, slot: u8, flags: ContactFlags) {
        let bits = Self::flags_bits(flags);
        let n = usize::from(self.len);
        for e in &mut self.entries[..n] {
            if e.slot == slot {
                e.flags = bits;
            }
        }
    }

    /// Rebuild from verified active records.
    pub fn rebuild_from_records(&mut self, records: &[ContactRecord; 54]) {
        self.len = 0;
        for (slot, rec) in records.iter().enumerate() {
            if !rec.is_active() {
                continue;
            }
            let _ = self.insert(&rec.fingerprint, slot as u8, rec.contact_flags());
        }
    }

    /// Iterate index entries.
    pub fn iter(&self) -> impl Iterator<Item = &IndexEntry> {
        let n = usize::from(self.len);
        self.entries[..n].iter()
    }
}
