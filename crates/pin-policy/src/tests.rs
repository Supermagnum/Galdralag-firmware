use crate::machine::{
    pin_compare, PinOutcome, PinPolicyConfig, PinPolicyMachine, PinPolicyProvisionError,
    ZeroisationTrigger,
};
use crate::zeroise_fsm::{ZeroiseBootState, ZeroisePhase};
use galdr_core::fake_hal::FakeMonotonicCounter;
use subtle::Choice;

struct FlagZ(bool);

impl ZeroisationTrigger for FlagZ {
    fn trigger_zeroisation(&mut self) {
        self.0 = true;
    }
}

#[test]
fn provisioned_attempt_range() {
    assert_eq!(
        PinPolicyConfig::try_with_max_attempts(2),
        Err(PinPolicyProvisionError::MaxAttemptsOutOfRange)
    );
    assert_eq!(
        PinPolicyConfig::try_with_max_attempts(11),
        Err(PinPolicyProvisionError::MaxAttemptsOutOfRange)
    );
    assert_eq!(
        PinPolicyConfig::try_with_max_attempts(3).unwrap().max_attempts,
        3
    );
    assert_eq!(
        PinPolicyConfig::try_with_max_attempts(10).unwrap().max_attempts,
        10
    );
    assert_eq!(PinPolicyConfig::default().max_attempts, 3);
}

#[test]
fn pin_compare_uses_constant_time_eq() {
    let a = [1u8, 2, 3];
    let b = [1u8, 2, 3];
    assert!(bool::from(pin_compare(&a, &b)));
    let c = [1u8, 2, 4];
    assert!(!bool::from(pin_compare(&a, &c)));
    assert!(!bool::from(pin_compare(&a, &a[..2])));
}

#[test]
fn increment_before_compare_exhausts_attempts() {
    let z = FlagZ(false);
    let mut m = PinPolicyMachine::new(
        PinPolicyConfig { max_attempts: 1 },
        FakeMonotonicCounter::new(0),
        z,
    );
    m.enter_locked_idle();
    let r = m
        .submit_attempt(|| Choice::from(0u8))
        .unwrap();
    assert_eq!(r, PinOutcome::Failed { attempts_used: 1 });
    let r = m.submit_attempt(|| Choice::from(1u8)).unwrap();
    assert_eq!(r, PinOutcome::Breach);
    let (_, _, _, z) = m.into_inner();
    assert!(z.0);
}

#[test]
fn verify_skipped_after_threshold() {
    let z = FlagZ(false);
    let mut m = PinPolicyMachine::new(
        PinPolicyConfig { max_attempts: 0 },
        FakeMonotonicCounter::new(0),
        z,
    );
    m.enter_locked_idle();
    let mut called = false;
    let r = m
        .submit_attempt(|| {
            called = true;
            Choice::from(1u8)
        })
        .unwrap();
    assert_eq!(r, PinOutcome::Breach);
    assert!(!called);
    let (_, _, _, zf) = m.into_inner();
    assert!(zf.0);
}

#[test]
fn zeroise_resumes_after_power_loss() {
    let st = ZeroiseBootState::on_power_loss_during_wipe(ZeroisePhase::InProgress { pass: 2 });
    assert!(!st.boot0_may_enumerate_usb());
    let clean = ZeroiseBootState::on_power_loss_during_wipe(ZeroisePhase::Idle);
    assert!(clean.boot0_may_enumerate_usb());
}
