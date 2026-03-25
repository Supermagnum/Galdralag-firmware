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
}

/// True random number generator block (ring-oscillator sourced on Baochip-1x).
///
/// **Security role:** seeds key generation and multi-pass zeroisation overwrites; must meet product
/// TRNG validation (e.g. BSI AIS 20/31 procedures on raw output during bring-up).
pub trait HardwareTrng: RngCore + CryptoRng {}

impl<T: RngCore + CryptoRng> HardwareTrng for T {}

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
