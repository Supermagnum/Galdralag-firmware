//! Programmatic firmware-update mode entry for Baochip-1x / Dabao.
//!
//! # How it works
//!
//! The Baochip-1x boot chain (boot1) reads a one-way RRAM counter called
//! `BootWaitCoding` before deciding whether to call `try_boot`. When that
//! counter reads `Enable` (raw value is odd), boot1 skips normal boot and
//! enters the USB mass-storage / serial REPL loop so the operator can send a
//! `.uf2` firmware image — no physical PROG or RESET button press required.
//!
//! `Bao1xRebootController::enter_update_mode` performs exactly the two steps
//! that boot1's own REPL `bootwait enable` + `reset` commands do:
//!
//! 1. Advance the `BootWaitCoding` one-way counter at ACRAM offset 80 until
//!    its raw u32 value is odd (== `Enable`). Because the counter is one-way,
//!    each call may consume one permanent increment of RRAM wear. The maximum
//!    number of increments needed per call is 1 (the counter can only be at
//!    `Disable` (even) or `Enable` (odd) due to the two-state encoding).
//! 2. Write the magic value `0x55AA` to `SFR_RCURST0` in the sysctrl block.
//!    This triggers a soft reset; the device reboots immediately. This function
//!    does not return on hardware.
//!
//! # Hardware addresses (sourced from xous-core utralib / bao1x-hal)
//!
//! | Symbol                   | Address          | Source                                    |
//! |--------------------------|------------------|-------------------------------------------|
//! | `ONEWAY_START`           | `0x603D_A000`    | `bao1x-hal/src/acram.rs`                  |
//! | `BOOT_WAIT_OFFSET`       | 80               | `bao1x-api/src/offsets/common.rs`         |
//! | `COUNTER_STRIDE_U32`     | 8                | `bao1x-hal/src/acram.rs` (32 bytes / 4)   |
//! | `HW_SYSCTRL_BASE`        | `0x4004_0000`    | `utralib/src/generated/bao1x.rs`          |
//! | `SFR_RCURST0` (word idx) | 32               | `utralib/src/generated/bao1x.rs`          |
//!
//! The `BootWaitCoding` counter byte address is:
//! `0x603D_A000 + 80 * 8 * 4 = 0x603D_AA00`
//!
//! The `SFR_RCURST0` byte address is:
//! `0x4004_0000 + 32 * 4 = 0x4004_0080`
//!
//! # Safety rationale
//!
//! The two `unsafe` blocks in this module are MMIO pointer dereferences. There
//! is no safe Rust way to perform volatile reads and writes to fixed hardware
//! register addresses; the workspace `unsafe_code = "forbid"` lint is overridden
//! in this crate's `Cargo.toml` for exactly this reason. Both addresses are
//! sourced directly from the xous-core utralib and bao1x-hal generated files and
//! verified against the Baochip-1x memory map documented in `docs/RRAM_LAYOUT.md`.

use galdr_core::HalError;

/// Opaque authorization for [`Bao1xRebootController::enter_update_mode`].
///
/// This type cannot be constructed by downstream code unless the `privileged-reboot` feature is
/// enabled on `galdralag-service` **and** the caller uses [`Self::for_operator_consent`], which must
/// only be invoked from an explicit operator-consent or boot-policy flow (not yet wired to IPC).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UpdateModeAuthorization(());

impl UpdateModeAuthorization {
    /// Issue authorization after operator consent or boot-policy approval.
    ///
    /// Gated by the `privileged-reboot` Cargo feature (default **off**). **Placeholder:** does not
    /// verify physical input, boot1 serial, Admin PIN, or any other operator-intent signal yet —
    /// it only constructs an opaque token. Real consent logic must be added here (or in a single
    /// caller this function delegates to) once product UX is chosen.
    #[cfg(feature = "privileged-reboot")]
    pub fn for_operator_consent() -> Self {
        Self(())
    }
}

/// Physical base address of the ACRAM one-way counter array.
/// Source: `bao1x-hal/src/acram.rs` `ONEWAY_START`.
const ONEWAY_START: usize = 0x603D_A000;

/// One-way counter array index for `BootWaitCoding`.
/// Source: `bao1x-api/src/offsets/common.rs` `encode_oneway! { #[offset = 80] pub enum BootWaitCoding`.
const BOOT_WAIT_OFFSET: usize = 80;

/// Number of u32 words between consecutive one-way counter entries.
/// Source: `bao1x-hal/src/acram.rs` `COUNTER_STRIDE_U32 = ONEWAY_LEN / size_of::<u32>() = 32 / 4`.
const COUNTER_STRIDE_U32: usize = 8;

/// Physical base address of the sysctrl peripheral.
/// Source: `utralib/src/generated/bao1x.rs` `HW_SYSCTRL_BASE`.
const HW_SYSCTRL_BASE: usize = 0x4004_0000;

/// Word index of `SFR_RCURST0` within the sysctrl register block.
/// Source: `utralib/src/generated/bao1x.rs` `SFR_RCURST0: crate::Register::new(32, ...)`.
const SFR_RCURST0_WORD_IDX: usize = 32;

/// Magic value that triggers a soft reset when written to `SFR_RCURST0`.
/// Source: `bao1x-boot/boot1/src/repl.rs` and `bao1x-boot/boot1/src/main.rs`.
const RCURST_MAGIC: u32 = 0x55AA;

/// The raw u32 value of the `BootWaitCoding` counter that maps to `Enable`.
///
/// `BootWaitCoding` has two variants — `[Disable, Enable]`. The one-way counter
/// is decoded as `value % ALL.len()`, so:
/// - even value → index 0 → `Disable`
/// - odd value  → index 1 → `Enable`
///
/// We check `value & 1 == 1` rather than comparing to a specific integer because
/// the raw counter can be at any absolute value after repeated boot cycles.
#[inline(always)]
fn boot_wait_is_enabled(raw: u32) -> bool {
    raw & 1 == 1
}

/// Hardware implementation of [`RebootController`] for Baochip-1x (Dabao/Baosec).
///
/// This type is only meaningful when the firmware is running on the actual
/// Baochip-1x SoC. On any other target the MMIO addresses are invalid and
/// calling `enter_update_mode` will have undefined behaviour — use
/// `galdr_core::fake_hal::FakeRebootController` in tests and host-side code.
pub struct Bao1xRebootController;

impl Bao1xRebootController {
    pub fn new() -> Self {
        Self
    }

    /// Advance `BootWaitCoding` to `Enable`, then trigger a soft reset.
    ///
    /// Requires [`UpdateModeAuthorization`]. There is no bare `RebootController` implementation
    /// on this type: enabling `privileged-reboot` and calling
    /// [`UpdateModeAuthorization::for_operator_consent`] is the deliberate opt-in path.
    ///
    /// This function does not return on Baochip-1x hardware: the device reboots into boot1 update
    /// mode. Any in-flight operations must be completed or aborted before calling this.
    pub fn enter_update_mode(
        &mut self,
        _auth: UpdateModeAuthorization,
    ) -> Result<(), HalError> {
        // SAFETY: all unsafe blocks below dereference MMIO-mapped addresses that
        // are valid and live for the lifetime of the hardware. This code must only
        // run on a Baochip-1x SoC (Dabao or Baosec board). The `xous-bsp` feature
        // gate on the binary target in Cargo.toml provides the build-time boundary.
        unsafe {
            if !boot_wait_is_enabled(Self::read_boot_wait()) {
                Self::inc_boot_wait();
                if !boot_wait_is_enabled(Self::read_boot_wait()) {
                    return Err(HalError::Bus);
                }
            }
            Self::trigger_soft_reset()
        }
    }

    /// Return a raw pointer to the `BootWaitCoding` counter word in ACRAM.
    ///
    /// Safety contract for callers: only call `read_volatile` / `write_volatile`
    /// through this pointer on Baochip-1x hardware where the address is mapped
    /// as ACRAM. On any other target this pointer is invalid.
    #[inline(always)]
    fn boot_wait_ptr() -> *mut u32 {
        let byte_offset = BOOT_WAIT_OFFSET * COUNTER_STRIDE_U32 * core::mem::size_of::<u32>();
        (ONEWAY_START + byte_offset) as *mut u32
    }

    /// Return a raw pointer to `SFR_RCURST0` in the sysctrl peripheral.
    ///
    /// Safety contract for callers: only call `write_volatile` through this
    /// pointer on Baochip-1x hardware where `HW_SYSCTRL_BASE` is mapped.
    #[inline(always)]
    fn rcurst0_ptr() -> *mut u32 {
        (HW_SYSCTRL_BASE + SFR_RCURST0_WORD_IDX * core::mem::size_of::<u32>()) as *mut u32
    }

    /// Read the current raw value of the `BootWaitCoding` one-way counter.
    ///
    /// # Safety
    ///
    /// The caller must ensure this runs on Baochip-1x hardware.
    unsafe fn read_boot_wait() -> u32 {
        // SAFETY: address is valid ACRAM on Baochip-1x; volatile prevents
        // the compiler from caching or eliding the read.
        unsafe { Self::boot_wait_ptr().read_volatile() }
    }

    /// Increment the `BootWaitCoding` one-way counter by one.
    ///
    /// Writing any value to the counter address causes the hardware to increment
    /// the stored count by one. The value written is ignored.
    ///
    /// # Safety
    ///
    /// The caller must ensure this runs on Baochip-1x hardware. Each call
    /// permanently consumes one RRAM write cycle at this counter location.
    unsafe fn inc_boot_wait() {
        // SAFETY: writing 0 to the ACRAM counter address triggers a hardware
        // increment. This is a one-way operation backed by RRAM.
        unsafe { Self::boot_wait_ptr().write_volatile(0) }
    }

    /// Write the soft-reset magic to `SFR_RCURST0`, rebooting the device.
    ///
    /// # Safety
    ///
    /// The caller must ensure this runs on Baochip-1x hardware. This call does
    /// not return — the CPU is reset before execution continues.
    unsafe fn trigger_soft_reset() -> ! {
        // SAFETY: writing 0x55AA to SFR_RCURST0 triggers an immediate soft
        // reset of the Baochip-1x SoC. The function is marked `!` to signal
        // to the compiler that this code path never returns.
        unsafe { Self::rcurst0_ptr().write_volatile(RCURST_MAGIC) }

        // The soft reset fires synchronously with the write. We should never
        // reach this point on real hardware. The loop prevents the compiler
        // from omitting the write_volatile call on the assumption that the
        // diverging path is reachable.
        loop {
            core::hint::spin_loop();
        }
    }
}

impl Default for Bao1xRebootController {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_wait_enable_detection() {
        // Even values decode to Disable.
        assert!(!boot_wait_is_enabled(0));
        assert!(!boot_wait_is_enabled(2));
        assert!(!boot_wait_is_enabled(100));
        // Odd values decode to Enable.
        assert!(boot_wait_is_enabled(1));
        assert!(boot_wait_is_enabled(3));
        assert!(boot_wait_is_enabled(99));
    }

    #[test]
    fn fake_reboot_controller_records_request() {
        use galdr_core::fake_hal::FakeRebootController;
        use galdr_core::RebootController;
        let mut ctrl = FakeRebootController::new();
        assert!(!ctrl.requested);
        ctrl.enter_update_mode().unwrap();
        assert!(ctrl.requested);
    }

    #[test]
    fn update_mode_requires_authorization_token_type() {
        // Compile-time contract: `enter_update_mode` takes `UpdateModeAuthorization`, not `()`.
        // With default features, `for_operator_consent` is absent so no production call site can
        // obtain a token without enabling `privileged-reboot`.
        let _needs_auth = |auth: UpdateModeAuthorization, ctrl: &mut Bao1xRebootController| {
            let _ = ctrl.enter_update_mode(auth);
        };
        let _ = _needs_auth;
    }

    #[test]
    fn hardware_addresses_are_sane() {
        // Smoke-check that the computed pointer values match the expected addresses
        // from xous-core. These are compile-time constants so the test exercises
        // the constant arithmetic, not memory access.
        let boot_wait_addr = ONEWAY_START
            + BOOT_WAIT_OFFSET * COUNTER_STRIDE_U32 * core::mem::size_of::<u32>();
        assert_eq!(boot_wait_addr, 0x603D_AA00,
            "BootWaitCoding address mismatch (check ONEWAY_START, BOOT_WAIT_OFFSET, COUNTER_STRIDE_U32)");

        let rcurst_addr =
            HW_SYSCTRL_BASE + SFR_RCURST0_WORD_IDX * core::mem::size_of::<u32>();
        assert_eq!(rcurst_addr, 0x4004_0080,
            "SFR_RCURST0 address mismatch (check HW_SYSCTRL_BASE, SFR_RCURST0_WORD_IDX)");
    }
}
