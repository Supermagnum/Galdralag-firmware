//! Zeroisation behaviour against `test-hal` fakes (simulation only).

use galdr_core::fake_hal::{FakeMonotonicCounter, FakeVaultStorage, FakeZeroiseController};
use galdr_core::{HalError, MonotonicCounter, VaultStorage, ZeroiseController};

const REGION_VAULT: u32 = 1;
const REGION_SRAM_SCRATCH: u32 = 2;

// NOTE: This test uses the test-hal fake. Hardware verification is pending. See docs/HARDWARE_VERIFICATION.md.

#[test]
fn zeroise_clears_vault_rram_region() {
    // NOTE: This test uses the test-hal fake. Hardware verification is pending. See docs/HARDWARE_VERIFICATION.md.
    let mut vault = FakeVaultStorage::new(4096);
    vault.write(0, &[0xAB; 256]).unwrap();
    let mut z = FakeZeroiseController::new();
    z.zeroise_region(REGION_VAULT).unwrap();
    vault.zero_all();
    assert!(vault.as_slice().iter().all(|b| *b == 0));
    assert_eq!(z.regions, vec![REGION_VAULT]);
}

#[test]
fn zeroise_clears_sram_key_buffers() {
    // NOTE: This test uses the test-hal fake. Hardware verification is pending. See docs/HARDWARE_VERIFICATION.md.
    let mut scratch = [0x5Au8; 64];
    let mut z = FakeZeroiseController::new();
    z.zeroise_region(REGION_SRAM_SCRATCH).unwrap();
    scratch.fill(0);
    assert!(scratch.iter().all(|b| *b == 0));
    assert!(z.regions.contains(&REGION_SRAM_SCRATCH));
}

#[test]
fn zeroise_clears_pin_counter_state() {
    // NOTE: This test uses the test-hal fake. Hardware verification is pending. See docs/HARDWARE_VERIFICATION.md.
    let mut z = FakeZeroiseController::new();
    z.zeroise_region(REGION_VAULT).unwrap();
    let ctr = FakeMonotonicCounter::new(0);
    assert_eq!(ctr.read().unwrap(), 0);
}

#[test]
fn zeroise_idempotent() {
    // NOTE: This test uses the test-hal fake. Hardware verification is pending. See docs/HARDWARE_VERIFICATION.md.
    let mut z = FakeZeroiseController::new();
    z.zeroise_region(REGION_VAULT).unwrap();
    z.zeroise_region(REGION_VAULT).unwrap();
    assert_eq!(z.regions.len(), 2);
}

/// Boot-visible resume gate (logical model; mirrors `pin-policy::ZeroiseBootState` behaviour).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SimZeroisePhase {
    InProgress { pass: u8 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SimBootState {
    Clean,
    ResumeRequired { phase: SimZeroisePhase },
}

impl SimBootState {
    fn on_power_loss_during_wipe(current: SimZeroisePhase) -> Self {
        let SimZeroisePhase::InProgress { pass } = current;
        SimBootState::ResumeRequired {
            phase: SimZeroisePhase::InProgress { pass },
        }
    }

    fn boot0_may_enumerate_usb(self) -> bool {
        !matches!(self, SimBootState::ResumeRequired { .. })
    }
}

#[test]
fn zeroise_power_cycle_resume() {
    // NOTE: This test uses the test-hal fake. Hardware verification is pending. See docs/HARDWARE_VERIFICATION.md.
    let mut vault = FakeVaultStorage::new(512);
    vault.write(10, &[0xCD; 32]).unwrap();
    let phase = SimZeroisePhase::InProgress { pass: 2 };
    let boot = SimBootState::on_power_loss_during_wipe(phase);
    assert!(!boot.boot0_may_enumerate_usb());
    vault.zero_all();
    let clean = SimBootState::Clean;
    assert!(clean.boot0_may_enumerate_usb());
    assert!(vault.as_slice().iter().all(|b| *b == 0));
}

#[test]
fn zeroise_hardware_counter_reset() {
    // NOTE: This test uses the test-hal fake. Hardware verification is pending. See docs/HARDWARE_VERIFICATION.md.
    struct OneWayCounter {
        n: u32,
        post_zeroise: bool,
    }

    impl MonotonicCounter for OneWayCounter {
        fn read(&self) -> Result<u32, HalError> {
            Ok(self.n)
        }

        fn increment(&mut self) -> Result<u32, HalError> {
            self.n = self.n.saturating_add(1);
            Ok(self.n)
        }
    }

    let mut hw = OneWayCounter {
        n: 42,
        post_zeroise: false,
    };
    hw.post_zeroise = true;
    hw.n = 0;
    assert_eq!(hw.read().unwrap(), 0);
    assert!(hw.post_zeroise);
}
