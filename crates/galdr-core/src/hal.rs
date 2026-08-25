//! Hardware abstraction for Baochip-1x always-on domain, TRNG, RRAM vault, and boot zeroisation.
//!
//! Real drivers live outside this crate; these traits define the **security contract** integrators
//! must satisfy (monotonicity, entropy quality, wipe semantics).

use crate::HalError;
use rand_core::{CryptoRng, RngCore};

/// Hardware-backed attempt counter in the always-on domain (one-way across power cycles).
///
/// **Security role:** bounds PIN and stateful-signature (XMSS/LMS) abuse; must not be rollable from
/// application software on production parts.
pub trait MonotonicCounter {
    fn read(&self) -> Result<u32, HalError>;

    /// Consumes one attempt. **PIN policy must call this before any PIN comparison** for the same
    /// user submission (see `pin-policy` crate tests).
    fn increment(&mut self) -> Result<u32, HalError>;

    /// After a successful PIN verify, refunds the attempt reservation made by [`increment`].
    /// Hardware that cannot roll back the counter returns [`HalError::Denied`]; the policy layer
    /// ignores `Denied` and leaves the counter incremented (see `pin-policy` integration tests).
    fn refund_on_success(&mut self) -> Result<(), HalError> {
        Err(HalError::Denied)
    }
}

/// True random number generator block (ring-oscillator sourced on Baochip-1x).
///
/// **Security role:** seeds key generation and multi-pass zeroisation overwrites; must meet product
/// TRNG validation (e.g. BSI AIS 20/31 procedures on raw output during bring-up).
pub trait HardwareTrng: RngCore + CryptoRng {}

impl<T: RngCore + CryptoRng> HardwareTrng for T {}

mod shamir_split_rng {
    /// Sealed marker: only types explicitly approved in this crate may implement [`super::ShamirSplitRng`].
    pub trait Sealed {}
}

/// Entropy source approved for Shamir polynomial coefficients.
///
/// Production split paths must use OS or hardware TRNG (`OsRng` on host via the `host` feature,
/// platform [`HardwareTrng`] on device). Test doubles ([`crate::fake_hal::FakeTrng`]) implement this
/// only when the `test-hal` feature is enabled.
///
/// **Future firmware Shamir split must use the platform [`HardwareTrng`] service** (ring-oscillator
/// TRNG on Baochip-1x), never a fixed seed or LCG. Add an explicit `ShamirSplitRng` implementation
/// in this crate when on-device split is wired.
pub trait ShamirSplitRng: HardwareTrng + shamir_split_rng::Sealed {}

#[cfg(feature = "test-hal")]
impl shamir_split_rng::Sealed for crate::fake_hal::FakeTrng {}

#[cfg(feature = "test-hal")]
impl ShamirSplitRng for crate::fake_hal::FakeTrng {}

#[cfg(feature = "host")]
mod host_shamir_rng {
    use super::shamir_split_rng;
    use super::ShamirSplitRng;

    impl shamir_split_rng::Sealed for rand::rngs::OsRng {}

    impl ShamirSplitRng for rand::rngs::OsRng {}
}

/// Boot0 / secure controller path that performs TRNG-sourced multi-pass overwrite of sensitive regions.
///
/// **Security role:** ties policy breaches (signature failure, PIN exhaustion extension per Baochip
/// design notes) to the same class of active wipe as immutable boot.
pub trait ZeroiseController {
    /// Schedule or execute wipe of a policy-defined region (vault, AORAM, SRAM scratch, etc.).
    fn zeroise_region(&mut self, region_id: u32) -> Result<(), HalError>;
}

/// Byte-level access to on-chip RRAM vault with ECC awareness.
///
/// **Security role:** all long-lived key material crosses this boundary; upper layers must AEAD-wrap
/// payloads and never store plaintext verification keys without policy review.
pub trait VaultStorage {
    fn read(&self, offset: u64, out: &mut [u8]) -> Result<(), HalError>;
    fn write(&mut self, offset: u64, data: &[u8]) -> Result<(), HalError>;
}

/// Vault storage stub that rejects every access with [`HalError::Unsupported`].
///
/// Used on Dabao bring-up when OpenPGP RRAM mapping fails so the CCID daemon can still start
/// with a non-vault backend for APDUs that do not need persistent storage.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnsupportedVaultStorage;

impl VaultStorage for UnsupportedVaultStorage {
    fn read(&self, _offset: u64, _out: &mut [u8]) -> Result<(), HalError> {
        Err(HalError::Unsupported)
    }

    fn write(&mut self, _offset: u64, _data: &[u8]) -> Result<(), HalError> {
        Err(HalError::Unsupported)
    }
}

/// Programmatic entry into boot1 USB firmware-update mode.
///
/// On Baochip-1x the boot1 stage checks a one-way RRAM counter (`BootWaitCoding`) before
/// calling `try_boot`. When that counter reads `Enable` (odd raw value), boot1 skips the
/// normal boot path and enters the USB mass-storage / serial REPL loop, accepting a `.uf2`
/// firmware image without requiring the operator to press the physical PROG or RESET buttons.
///
/// The sequence is:
/// 1. Advance `BootWaitCoding` to `Enable` by incrementing the counter at ACRAM offset 80
///    until its raw value is odd.
/// 2. Write the magic value `0x55AA` to `SFR_RCURST0` in the sysctrl block to trigger a
///    soft reset. The device reboots; boot1 observes `Enable` and stays in update mode.
///
/// This is the Galdralag firmware's exposure of that mechanism. Calling `enter_update_mode`
/// must be a deliberate, audited operation — it reboots the device and ends the current
/// session. Any in-flight cryptographic operations must be completed or explicitly aborted
/// before this call.
///
/// Implementations on test platforms (see `FakeRebootController`) record the call without
/// rebooting; the hardware implementation in `services/galdralag` performs the real MMIO
/// sequence.
pub trait RebootController {
    /// Signal boot1 to enter firmware-update mode, then trigger a soft reset.
    ///
    /// Returns `Ok(())` on platforms where the call is a no-op stub (tests).
    /// On real hardware this call does not return — the soft reset fires before the
    /// function would ordinarily unwind.
    fn enter_update_mode(&mut self) -> Result<(), HalError>;
}
