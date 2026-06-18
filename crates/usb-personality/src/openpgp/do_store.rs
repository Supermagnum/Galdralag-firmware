//! Persistent OpenPGP data objects in vault RRAM (keyed by DO tag).

#![deny(unsafe_code)]

use galdr_core::hal::VaultStorage;
use galdr_core::HalError;
use heapless::Vec;

/// Magic header for OpenPGP DO blob (`OPGP`).
pub const DO_STORE_MAGIC: [u8; 4] = *b"OPGP";

const VERSION: u8 = 1;
const HEADER_LEN: usize = 8;
/// Per-slot: tag (u16 LE) + len (u8) + payload (max 254).
const SLOT_BYTES: usize = 2 + 1 + 254;
const SLOT_COUNT: usize = 32;

/// Total bytes reserved for one [`DoStore`] region (header + fixed slots).
pub const DO_STORE_REGION_BYTES: usize = HEADER_LEN + SLOT_COUNT * SLOT_BYTES;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum DoStoreError {
    ValueTooLong,
    Full,
    Io(HalError),
}

impl From<HalError> for DoStoreError {
    fn from(e: HalError) -> Self {
        DoStoreError::Io(e)
    }
}

/// Stores DOs in vault RRAM as key-value pairs. Separate region from key material.
pub struct DoStore<S: VaultStorage> {
    storage: S,
    base: u64,
}

impl<S: VaultStorage> DoStore<S> {
    pub fn new(storage: S, base_offset: u64) -> Self {
        Self {
            storage,
            base: base_offset,
        }
    }

    /// Returns true if the region has a valid magic header.
    pub fn probe(&self) -> Result<bool, DoStoreError> {
        let mut hdr = [0u8; HEADER_LEN];
        self.storage
            .read(self.base, &mut hdr)
            .map_err(DoStoreError::from)?;
        Ok(hdr[0..4] == DO_STORE_MAGIC && hdr[4] == VERSION)
    }

    fn init_if_needed(&mut self) -> Result<(), DoStoreError> {
        if self.probe()? {
            return Ok(());
        }
        let mut buf = [0u8; DO_STORE_REGION_BYTES];
        buf[0..4].copy_from_slice(&DO_STORE_MAGIC);
        buf[4] = VERSION;
        self.storage
            .write(self.base, &buf)
            .map_err(DoStoreError::from)?;
        Ok(())
    }

    fn read_slot(&self, index: usize) -> Result<[u8; SLOT_BYTES], DoStoreError> {
        if index >= SLOT_COUNT {
            return Err(DoStoreError::Io(HalError::Denied));
        }
        let mut slot = [0u8; SLOT_BYTES];
        let off = self.base + HEADER_LEN as u64 + (index * SLOT_BYTES) as u64;
        self.storage
            .read(off, &mut slot)
            .map_err(DoStoreError::from)?;
        Ok(slot)
    }

    fn write_slot(&mut self, index: usize, slot: &[u8; SLOT_BYTES]) -> Result<(), DoStoreError> {
        if index >= SLOT_COUNT {
            return Err(DoStoreError::Io(HalError::Denied));
        }
        let off = self.base + HEADER_LEN as u64 + (index * SLOT_BYTES) as u64;
        self.storage.write(off, slot).map_err(DoStoreError::from)?;
        Ok(())
    }

    /// Read a stored DO by tag (empty if missing or store uninitialised).
    pub fn read(&self, tag: u16) -> Option<Vec<u8, 254>> {
        let hdr_ok = self.probe().ok()?;
        if !hdr_ok {
            return None;
        }
        for i in 0..SLOT_COUNT {
            let slot = self.read_slot(i).ok()?;
            let t = u16::from_le_bytes([slot[0], slot[1]]);
            if t != tag {
                continue;
            }
            let len = slot[2] as usize;
            if len > 254 {
                return None;
            }
            let mut out = Vec::new();
            for b in slot[3..3 + len].iter() {
                out.push(*b).ok()?;
            }
            return Some(out);
        }
        None
    }

    /// Write or replace a DO (max 254 bytes).
    pub fn write(&mut self, tag: u16, value: &[u8]) -> Result<(), DoStoreError> {
        if value.len() > 254 {
            return Err(DoStoreError::ValueTooLong);
        }
        self.init_if_needed()?;
        let mut empty_idx: Option<usize> = None;
        let mut existing_idx: Option<usize> = None;
        for i in 0..SLOT_COUNT {
            let slot = self.read_slot(i)?;
            let t = u16::from_le_bytes([slot[0], slot[1]]);
            if t == tag {
                existing_idx = Some(i);
                break;
            }
            if t == 0 && empty_idx.is_none() {
                empty_idx = Some(i);
            }
        }
        let idx = existing_idx.or(empty_idx).ok_or(DoStoreError::Full)?;
        let mut slot = [0u8; SLOT_BYTES];
        slot[0..2].copy_from_slice(&tag.to_le_bytes());
        slot[2] = value.len() as u8;
        slot[3..3 + value.len()].copy_from_slice(value);
        self.write_slot(idx, &slot)
    }

    /// Remove a DO if present.
    pub fn delete(&mut self, tag: u16) -> Result<(), DoStoreError> {
        if !self.probe().unwrap_or(false) {
            return Ok(());
        }
        for i in 0..SLOT_COUNT {
            let mut slot = self.read_slot(i)?;
            let t = u16::from_le_bytes([slot[0], slot[1]]);
            if t == tag {
                slot.fill(0);
                self.write_slot(i, &slot)?;
                break;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use galdr_core::fake_hal::FakeVaultStorage;

    #[test]
    fn write_read_round_trip() {
        let mem = FakeVaultStorage::new(DO_STORE_REGION_BYTES);
        let mut s = DoStore::new(mem, 0);
        s.write(0x5B, b"Alice").unwrap();
        let v = s.read(0x5B).unwrap();
        assert_eq!(v.as_slice(), b"Alice");
    }

    #[test]
    fn uninitialised_read_returns_none() {
        let mem = FakeVaultStorage::new(DO_STORE_REGION_BYTES);
        let s = DoStore::new(mem, 0);
        assert!(s.read(0x5B).is_none());
    }
}
