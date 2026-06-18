//! Test-only HAL doubles. Enable with `galdr-core` feature **`test-hal`** (see crate `dev-dependencies`).
//!
//! **Never enable `test-hal` in production firmware images.**

extern crate alloc;

use crate::hal::{MonotonicCounter, RebootController, VaultStorage, ZeroiseController};
use crate::HalError;
use rand_core::{CryptoRng, RngCore};

/// Deterministic monotonic counter for unit tests (not tamper-resistant).
pub struct FakeMonotonicCounter {
    n: u32,
    fail_next: bool,
}

impl FakeMonotonicCounter {
    pub fn new(start: u32) -> Self {
        Self {
            n: start,
            fail_next: false,
        }
    }

    pub fn set_fail_next(&mut self, v: bool) {
        self.fail_next = v;
    }
}

impl MonotonicCounter for FakeMonotonicCounter {
    fn read(&self) -> Result<u32, HalError> {
        Ok(self.n)
    }

    fn increment(&mut self) -> Result<u32, HalError> {
        if self.fail_next {
            self.fail_next = false;
            return Err(HalError::Bus);
        }
        self.n = self.n.saturating_add(1);
        Ok(self.n)
    }

    fn refund_on_success(&mut self) -> Result<(), HalError> {
        self.n = self.n.saturating_sub(1);
        Ok(())
    }
}

/// Linear congruential **non-cryptographic** RNG for tests only.
#[derive(Clone, Debug)]
pub struct FakeTrng {
    state: u64,
}

impl FakeTrng {
    pub fn from_seed(seed: u64) -> Self {
        Self { state: seed }
    }
}

impl RngCore for FakeTrng {
    fn next_u32(&mut self) -> u32 {
        self.state = self.state.wrapping_mul(6364136223846793005).wrapping_add(1);
        (self.state >> 33) as u32
    }

    fn next_u64(&mut self) -> u64 {
        let hi = self.next_u32() as u64;
        let lo = self.next_u32() as u64;
        (hi << 32) | lo
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            let v = self.next_u64().to_le_bytes();
            for (i, b) in chunk.iter_mut().enumerate() {
                *b = v[i];
            }
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for FakeTrng {}

/// Records zeroisation calls.
pub struct FakeZeroiseController {
    pub regions: alloc::vec::Vec<u32>,
}

impl FakeZeroiseController {
    pub fn new() -> Self {
        Self {
            regions: alloc::vec::Vec::new(),
        }
    }
}

impl Default for FakeZeroiseController {
    fn default() -> Self {
        Self::new()
    }
}

impl ZeroiseController for FakeZeroiseController {
    fn zeroise_region(&mut self, region_id: u32) -> Result<(), HalError> {
        self.regions.push(region_id);
        Ok(())
    }
}

/// Records a call to `enter_update_mode` without performing any hardware action.
///
/// Useful for testing code paths that request a firmware update without having
/// a physical Dabao board attached. The `requested` flag can be inspected after
/// the call to confirm the correct code path was reached.
pub struct FakeRebootController {
    pub requested: bool,
}

impl FakeRebootController {
    pub fn new() -> Self {
        Self { requested: false }
    }
}

impl Default for FakeRebootController {
    fn default() -> Self {
        Self::new()
    }
}

impl RebootController for FakeRebootController {
    fn enter_update_mode(&mut self) -> Result<(), HalError> {
        self.requested = true;
        Ok(())
    }
}

/// In-memory vault backing store.
pub struct FakeVaultStorage {
    mem: alloc::vec::Vec<u8>,
    fail_next_write: bool,
}

impl FakeVaultStorage {
    pub fn new(size: usize) -> Self {
        Self {
            mem: alloc::vec![0u8; size],
            fail_next_write: false,
        }
    }

    /// When set, the next [`VaultStorage::write`] returns [`HalError::EccUncorrectable`] and clears the flag.
    pub fn set_fail_next_write(&mut self, v: bool) {
        self.fail_next_write = v;
    }

    /// Test inspection: entire backing buffer.
    pub fn as_slice(&self) -> &[u8] {
        self.mem.as_slice()
    }

    /// Zero every byte (simulated post-zeroise vault).
    pub fn zero_all(&mut self) {
        self.mem.fill(0);
    }
}

impl VaultStorage for FakeVaultStorage {
    fn read(&self, offset: u64, out: &mut [u8]) -> Result<(), HalError> {
        let o = usize::try_from(offset).map_err(|_| HalError::Denied)?;
        let end = o.checked_add(out.len()).ok_or(HalError::Denied)?;
        if end > self.mem.len() {
            return Err(HalError::Denied);
        }
        out.copy_from_slice(&self.mem[o..end]);
        Ok(())
    }

    fn write(&mut self, offset: u64, data: &[u8]) -> Result<(), HalError> {
        if self.fail_next_write {
            self.fail_next_write = false;
            return Err(HalError::EccUncorrectable);
        }
        let o = usize::try_from(offset).map_err(|_| HalError::Denied)?;
        let end = o.checked_add(data.len()).ok_or(HalError::Denied)?;
        if end > self.mem.len() {
            return Err(HalError::Denied);
        }
        self.mem[o..end].copy_from_slice(data);
        Ok(())
    }
}
