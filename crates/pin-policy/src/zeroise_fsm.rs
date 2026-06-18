//! Power-loss during zeroisation: boot resumes wipe **before USB enumeration** (state machine model).
//!
//! **TODO (developer):** Wire to boot0 flow described in the Baochip README; this enum is only a
//! logical model for tests.

/// Where the device is in an active wipe sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ZeroisePhase {
    Idle,
    /// Multi-pass pass index (opaque).
    InProgress {
        pass: u8,
    },
}

/// Boot-visible state for interrupted zeroisation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ZeroiseBootState {
    Clean,
    /// Must continue zeroisation before exposing USB or vault unlock.
    ResumeRequired {
        phase: ZeroisePhase,
    },
}

impl ZeroiseBootState {
    /// Simulate power loss during wipe; next boot must resume.
    pub fn on_power_loss_during_wipe(current: ZeroisePhase) -> Self {
        match current {
            ZeroisePhase::Idle => ZeroiseBootState::Clean,
            ZeroisePhase::InProgress { pass } => ZeroiseBootState::ResumeRequired {
                phase: ZeroisePhase::InProgress { pass },
            },
        }
    }

    /// Boot0 entry: if resume required, stay non-enumerating until wipe completes.
    pub fn boot0_may_enumerate_usb(self) -> bool {
        !matches!(self, ZeroiseBootState::ResumeRequired { .. })
    }
}
