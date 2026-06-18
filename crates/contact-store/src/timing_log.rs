//! Append-only `last_fetched` timing log (16 KiB RRAM).

use crate::crc::crc32c;
use crate::error::ContactStoreError;
use crate::layout::{TIMING_LOG_BYTES, TIMING_LOG_OFFSET};
use crate::record::ContactRecord;
use crate::SlotIndex;
use galdr_core::hal::{MonotonicCounter, VaultStorage};

/// One timing-log entry (16 bytes with padding).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TimingLogEntry {
    /// Contact slot index.
    pub slot: u8,
    pub pad0: [u8; 3],
    /// Updated `last_fetched` value.
    pub last_fetched: u32,
    /// Monotonic sequence number for merge ordering.
    pub seq: u32,
    /// CRC32C over the preceding 12 bytes.
    pub entry_crc: u32,
}

const ENTRY_BYTES: usize = 16;
const MAX_ENTRIES: usize = (TIMING_LOG_BYTES as usize) / ENTRY_BYTES;

impl TimingLogEntry {
    fn as_bytes(&self) -> [u8; ENTRY_BYTES] {
        let mut out = [0u8; ENTRY_BYTES];
        out[0] = self.slot;
        out[4..8].copy_from_slice(&self.last_fetched.to_le_bytes());
        out[8..12].copy_from_slice(&self.seq.to_le_bytes());
        out[12..16].copy_from_slice(&self.entry_crc.to_le_bytes());
        out
    }

    fn body_for_crc(&self) -> [u8; 12] {
        let mut b = [0u8; 12];
        b[0] = self.slot;
        b[4..8].copy_from_slice(&self.last_fetched.to_le_bytes());
        b[8..12].copy_from_slice(&self.seq.to_le_bytes());
        b
    }

    fn recompute_crc(&mut self) {
        self.entry_crc = crc32c(&self.body_for_crc());
    }

    fn from_bytes(bytes: &[u8; ENTRY_BYTES]) -> Result<Self, ContactStoreError> {
        if bytes.iter().all(|&b| b == 0) {
            return Err(ContactStoreError::CorruptLogEntry);
        }
        let slot = bytes[0];
        let last_fetched = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let seq = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let entry_crc = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        let e = Self {
            slot,
            pad0: [0; 3],
            last_fetched,
            seq,
            entry_crc,
        };
        let expect = crc32c(&e.body_for_crc());
        if expect != entry_crc {
            return Err(ContactStoreError::CorruptLogEntry);
        }
        Ok(e)
    }
}

/// Append-only timing log state.
#[derive(Default)]
pub struct TimingLog {
    count: usize,
}

impl TimingLog {
    /// Empty log.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of unmerged entries.
    pub fn pending_count(&self) -> usize {
        self.count
    }

    fn entry_offset(index: usize) -> u64 {
        TIMING_LOG_OFFSET + (index as u64) * ENTRY_BYTES as u64
    }

    /// Read one log entry by index (for tests and host merge tools).
    pub fn read_entry<S: VaultStorage>(
        storage: &S,
        index: usize,
    ) -> Result<TimingLogEntry, ContactStoreError> {
        let mut buf = [0u8; ENTRY_BYTES];
        storage
            .read(Self::entry_offset(index), &mut buf)
            .map_err(|_| ContactStoreError::StorageRead)?;
        TimingLogEntry::from_bytes(&buf)
    }

    fn write_entry<S: VaultStorage>(
        storage: &mut S,
        index: usize,
        entry: &TimingLogEntry,
    ) -> Result<(), ContactStoreError> {
        let bytes = entry.as_bytes();
        storage
            .write(Self::entry_offset(index), &bytes)
            .map_err(|_| ContactStoreError::StorageWrite)
    }

    /// Append a timing update; sequence number comes from `counter.increment()`.
    pub fn append<S: VaultStorage, MC: MonotonicCounter>(
        &mut self,
        storage: &mut S,
        counter: &mut MC,
        slot: SlotIndex,
        last_fetched: u32,
        records: &mut [ContactRecord; 54],
    ) -> Result<(), ContactStoreError> {
        let seq = counter
            .increment()
            .map_err(|_| ContactStoreError::CounterError)?;
        if self.count >= MAX_ENTRIES {
            Self::merge(self, storage, records)?;
        }
        let mut e = TimingLogEntry {
            slot: slot.0,
            pad0: [0; 3],
            last_fetched,
            seq,
            entry_crc: 0,
        };
        e.recompute_crc();
        Self::write_entry(storage, self.count, &e)?;
        self.count += 1;
        Ok(())
    }

    /// Apply highest-sequence updates per slot, then clear the log.
    pub fn merge<S: VaultStorage>(
        &mut self,
        storage: &mut S,
        records: &mut [ContactRecord; 54],
    ) -> Result<(), ContactStoreError> {
        let mut best: [(u32, u32); 54] = [(0, 0); 54];
        for i in 0..self.count {
            let e = Self::read_entry(storage, i)?;
            let slot = usize::from(e.slot);
            if slot >= 54 {
                continue;
            }
            let (seq, _) = best[slot];
            if e.seq >= seq {
                best[slot] = (e.seq, e.last_fetched);
            }
        }
        for (slot, (seq, ts)) in best.iter().enumerate() {
            if *seq == 0 {
                continue;
            }
            if records[slot].is_active() {
                records[slot].last_fetched = *ts;
            }
        }
        Self::clear(self, storage)?;
        Ok(())
    }

    fn clear<S: VaultStorage>(&mut self, storage: &mut S) -> Result<(), ContactStoreError> {
        let zeros = [0u8; ENTRY_BYTES];
        for i in 0..MAX_ENTRIES {
            storage
                .write(Self::entry_offset(i), &zeros)
                .map_err(|_| ContactStoreError::StorageWrite)?;
        }
        self.count = 0;
        Ok(())
    }
}
