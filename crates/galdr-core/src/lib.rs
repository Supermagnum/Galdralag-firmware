//! Galdr core: hardware abstraction traits, shared errors, and security-boundary documentation.
//!
//! Firmware targets **Baochip-1x** (Dabao) under **Xous** on `riscv32imac-unknown-none-elf`.
//! See the [Baochip-1x firmware design README](https://github.com/Supermagnum/Baochip-1x-firmware)
//! for silicon capabilities (RRAM, always-on counters, ComboHash, PKE, TRNG, USB HS).

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

pub mod error;
pub mod hal;

#[cfg(feature = "test-hal")]
pub mod fake_hal;

#[cfg(test)]
mod hal_tests;

#[cfg(test)]
mod crypto_rfc;

#[cfg(test)]
mod property_tests;

#[cfg(test)]
mod scaffold_todos;

pub use error::{GaldrError, HalError};
pub use hal::{HardwareTrng, MonotonicCounter, RebootController, VaultStorage, ZeroiseController};
