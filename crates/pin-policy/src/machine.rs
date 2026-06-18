use galdr_core::{HalError, MonotonicCounter};
use subtle::{Choice, ConstantTimeEq};

/// Constant-time PIN equality on equal-length slices. **All PIN checks must use this helper.**
///
/// **Security role:** mitigates timing leaks vs stored verifier; length mismatch returns false
/// without short-circuiting secret-dependent branches beyond the length check (caller should pad
/// or hash to fixed width in production).
pub fn pin_compare(a: &[u8], b: &[u8]) -> Choice {
    if a.len() != b.len() {
        return Choice::from(0u8);
    }
    a.ct_eq(b)
}

/// Callback into vault / boot to perform TRNG-sourced multi-pass wipe.
pub trait ZeroisationTrigger {
    fn trigger_zeroisation(&mut self);
}

/// Default PIN attempt limit for hardware tokens (smartcards, Nitrokey-class devices): three tries
/// before lockout / zeroisation, matching common industry practice.
pub const DEFAULT_MAX_PIN_ATTEMPTS: u32 = 3;

/// Minimum `max_attempts` allowed when **provisioning** policy into the vault (inclusive).
pub const MIN_PROVISIONED_PIN_ATTEMPTS: u32 = 3;

/// Maximum `max_attempts` allowed when **provisioning** policy into the vault (inclusive).
pub const MAX_PROVISIONED_PIN_ATTEMPTS: u32 = 10;

/// Invalid provisioned attempt count (outside [`MIN_PROVISIONED_PIN_ATTEMPTS`]..=[`MAX_PROVISIONED_PIN_ATTEMPTS`]).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PinPolicyProvisionError {
    MaxAttemptsOutOfRange,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PinPolicyConfig {
    pub max_attempts: u32,
}

impl PinPolicyConfig {
    /// Build policy for a **provisioned** token: only values in **3..=10** are accepted.
    ///
    /// The firmware default is [`DEFAULT_MAX_PIN_ATTEMPTS`]. Integrators may raise the limit (up to
    /// 10) at provisioning time if operational needs outweigh marginal brute-force exposure; the value
    /// is persisted in vault policy next to the PIN verifier hash.
    pub fn try_with_max_attempts(max_attempts: u32) -> Result<Self, PinPolicyProvisionError> {
        if !(MIN_PROVISIONED_PIN_ATTEMPTS..=MAX_PROVISIONED_PIN_ATTEMPTS).contains(&max_attempts) {
            return Err(PinPolicyProvisionError::MaxAttemptsOutOfRange);
        }
        Ok(Self { max_attempts })
    }
}

impl Default for PinPolicyConfig {
    fn default() -> Self {
        Self {
            max_attempts: DEFAULT_MAX_PIN_ATTEMPTS,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PinState {
    BootCold,
    LockedIdle,
    AttemptCharge,
    Verifying,
    Unlocked,
    Cooldown,
    Bricked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PinOutcome {
    Success,
    Failed { attempts_used: u32 },
    Breach,
}

pub struct PinPolicyMachine<C, Z> {
    pub config: PinPolicyConfig,
    pub state: PinState,
    counter: C,
    zeroisation: Z,
}

impl<C: MonotonicCounter, Z: ZeroisationTrigger> PinPolicyMachine<C, Z> {
    pub fn new(config: PinPolicyConfig, counter: C, zeroisation: Z) -> Self {
        Self {
            config,
            state: PinState::BootCold,
            counter,
            zeroisation,
        }
    }

    pub fn enter_locked_idle(&mut self) {
        if self.state != PinState::Bricked {
            self.state = PinState::LockedIdle;
        }
    }

    /// **Ordering:** `increment` runs before `verify`. If count exceeds `max_attempts`, zeroises
    /// without calling `verify`.
    pub fn submit_attempt<F>(&mut self, verify: F) -> Result<PinOutcome, HalError>
    where
        F: FnOnce() -> Choice,
    {
        if self.state == PinState::Bricked {
            return Ok(PinOutcome::Breach);
        }
        self.state = PinState::AttemptCharge;
        let count = self.counter.increment()?;
        self.state = PinState::Verifying;
        if count > self.config.max_attempts {
            self.zeroisation.trigger_zeroisation();
            self.state = PinState::Bricked;
            return Ok(PinOutcome::Breach);
        }
        let ok = bool::from(verify());
        if ok {
            let _ = self.counter.refund_on_success();
            self.state = PinState::Unlocked;
            return Ok(PinOutcome::Success);
        }
        self.state = PinState::LockedIdle;
        Ok(PinOutcome::Failed {
            attempts_used: count,
        })
    }

    pub fn into_inner(self) -> (PinPolicyConfig, PinState, C, Z) {
        (self.config, self.state, self.counter, self.zeroisation)
    }
}
