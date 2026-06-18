//! Full PIN policy integration tests (parser boundary, counter ordering, threshold, challenge path).

use galdr_core::fake_hal::FakeMonotonicCounter;
use galdr_core::GaldrError;
use galdr_core::{MonotonicCounter, VaultStorage};
use pin_policy::{
    parse_challenge_passphrase, parse_unlock_pin, pin_compare, PinOutcome, PinParseError,
    PinPolicyConfig, PinPolicyMachine, PinState, ZeroisationTrigger,
};
use std::cell::RefCell;
use std::rc::Rc;
use subtle::Choice;

struct FlagZ(bool);

impl ZeroisationTrigger for FlagZ {
    fn trigger_zeroisation(&mut self) {
        self.0 = true;
    }
}

#[test]
fn pin_length_4_rejected() {
    let counter = FakeMonotonicCounter::new(0);
    assert_eq!(parse_unlock_pin("1234"), Err(PinParseError::TooShort));
    assert_eq!(counter.read().unwrap(), 0);
}

#[test]
fn pin_length_5_accepted() {
    let parsed = parse_unlock_pin("abcde");
    assert_eq!(parsed, Ok("abcde"));
    let z = FlagZ(false);
    let mut counter = FakeMonotonicCounter::new(0);
    let mut m = PinPolicyMachine::new(
        PinPolicyConfig::try_with_max_attempts(5).expect("provisioned policy"),
        z,
    );
    m.enter_locked_idle();
    let pin = parsed.unwrap().as_bytes();
    let r = m
        .submit_attempt(&mut counter, || pin_compare(pin, pin))
        .unwrap();
    assert_eq!(r, PinOutcome::Success);
}

#[test]
fn pin_length_5_non_alphanumeric_rejected() {
    let counter = FakeMonotonicCounter::new(0);
    assert_eq!(
        parse_unlock_pin("abcd "),
        Err(PinParseError::InvalidCharacter)
    );
    assert_eq!(counter.read().unwrap(), 0);
}

#[test]
fn pin_length_100_accepted() {
    let s: String = (0u8..100).map(|i| (b'a' + (i % 26)) as char).collect();
    let r = parse_unlock_pin(&s);
    assert!(r.is_ok());
    assert_eq!(r.unwrap().chars().count(), 100);
}

#[test]
fn counter_incremented_before_compare_wrong_pin() {
    let mut counter = FakeMonotonicCounter::new(0);
    let mut m = PinPolicyMachine::new(
        PinPolicyConfig::try_with_max_attempts(5).expect("provisioned policy"),
        FlagZ(false),
    );
    m.enter_locked_idle();
    let r = m
        .submit_attempt(&mut counter, || Choice::from(0u8))
        .unwrap();
    assert_eq!(r, PinOutcome::Failed { attempts_used: 1 });
    assert_eq!(counter.read().unwrap(), 1);
}

#[test]
fn correct_pin_no_counter_increment() {
    let mut counter = FakeMonotonicCounter::new(0);
    let mut m = PinPolicyMachine::new(
        PinPolicyConfig::try_with_max_attempts(5).expect("provisioned policy"),
        FlagZ(false),
    );
    m.enter_locked_idle();
    let r = m
        .submit_attempt(&mut counter, || Choice::from(1u8))
        .unwrap();
    assert_eq!(r, PinOutcome::Success);
    assert_eq!(counter.read().unwrap(), 0);
}

/// Counter persisted to RRAM: increment updates cache then writes; failed write returns `Err` but
/// cache reflects the attempted increment (simulated ordering contract).
struct RramPersistedCounter {
    storage: Rc<RefCell<galdr_core::fake_hal::FakeVaultStorage>>,
    offset: u64,
    cache: u32,
}

impl RramPersistedCounter {
    fn new(storage: Rc<RefCell<galdr_core::fake_hal::FakeVaultStorage>>, offset: u64) -> Self {
        let mut buf = [0u8; 4];
        storage
            .borrow()
            .read(offset, &mut buf)
            .expect("read counter slot");
        let cache = u32::from_le_bytes(buf);
        Self {
            storage,
            offset,
            cache,
        }
    }

    pub fn persist(&mut self) -> Result<(), galdr_core::HalError> {
        let mut b = [0u8; 4];
        b.copy_from_slice(&self.cache.to_le_bytes());
        self.storage.borrow_mut().write(self.offset, &b)
    }
}

impl galdr_core::hal::MonotonicCounter for RramPersistedCounter {
    fn read(&self) -> Result<u32, galdr_core::HalError> {
        Ok(self.cache)
    }

    fn increment(&mut self) -> Result<u32, galdr_core::HalError> {
        self.cache = self.cache.saturating_add(1);
        match self.persist() {
            Ok(()) => Ok(self.cache),
            Err(e) => Err(e),
        }
    }

    fn refund_on_success(&mut self) -> Result<(), galdr_core::HalError> {
        self.cache = self.cache.saturating_sub(1);
        self.persist()
    }
}

#[test]
fn counter_incremented_on_rram_flush_failure() {
    let storage = Rc::new(RefCell::new(galdr_core::fake_hal::FakeVaultStorage::new(
        256,
    )));
    storage.borrow_mut().write(0, &0u32.to_le_bytes()).unwrap();

    let mut ctr = RramPersistedCounter::new(Rc::clone(&storage), 0);
    storage.borrow_mut().set_fail_next_write(true);

    let mut m = PinPolicyMachine::new(
        PinPolicyConfig::try_with_max_attempts(5).expect("provisioned policy"),
        FlagZ(false),
    );
    m.enter_locked_idle();
    let r = m.submit_attempt(&mut ctr, || Choice::from(0u8));
    assert!(r.is_err());

    assert_eq!(ctr.read().unwrap(), 1);

    let mut buf = [0u8; 4];
    storage.borrow().read(0, &mut buf).unwrap();
    assert_eq!(u32::from_le_bytes(buf), 0);

    storage.borrow_mut().set_fail_next_write(false);
    ctr.persist().unwrap();
    let mut buf2 = [0u8; 4];
    storage.borrow().read(0, &mut buf2).unwrap();
    assert_eq!(u32::from_le_bytes(buf2), 1);
}

#[test]
fn pin_threshold_minus_one_no_zeroise() {
    let z = FlagZ(false);
    let mut counter = FakeMonotonicCounter::new(2);
    let mut m = PinPolicyMachine::new(PinPolicyConfig::default(), z);
    m.enter_locked_idle();
    let r = m
        .submit_attempt(&mut counter, || Choice::from(0u8))
        .unwrap();
    assert_eq!(r, PinOutcome::Failed { attempts_used: 3 });
    let (_, _, z) = m.into_inner();
    assert!(!z.0);
}

#[test]
fn pin_at_threshold_zeroise_triggered() {
    let z = FlagZ(false);
    let mut counter = FakeMonotonicCounter::new(3);
    let mut m = PinPolicyMachine::new(PinPolicyConfig::default(), z);
    m.enter_locked_idle();
    let r = m
        .submit_attempt(&mut counter, || Choice::from(0u8))
        .unwrap();
    assert_eq!(r, PinOutcome::Breach);
    let (_, state, z) = m.into_inner();
    assert!(z.0);
    assert_eq!(state, PinState::Bricked);
}

#[test]
fn pin_correct_at_threshold_minus_one() {
    let z = FlagZ(false);
    let mut counter = FakeMonotonicCounter::new(2);
    let mut m = PinPolicyMachine::new(PinPolicyConfig::default(), z);
    m.enter_locked_idle();
    let r = m
        .submit_attempt(&mut counter, || Choice::from(1u8))
        .unwrap();
    assert_eq!(r, PinOutcome::Success);
    assert_eq!(counter.read().unwrap(), 2);
    let (_, _, z) = m.into_inner();
    assert!(!z.0);
}

#[test]
fn challenge_response_4_char_rejected() {
    let c = FakeMonotonicCounter::new(0);
    assert_eq!(
        parse_challenge_passphrase("1234"),
        Err(PinParseError::TooShort)
    );
    assert_eq!(c.read().unwrap(), 0);
}

#[test]
fn challenge_response_5_char_accepted() {
    let p = parse_challenge_passphrase("abcde").unwrap();
    assert_eq!(p, "abcde");
}

#[test]
fn bricked_returns_device_zeroised_equivalent() {
    let mut counter = FakeMonotonicCounter::new(0);
    let mut m = PinPolicyMachine::new(
        PinPolicyConfig { max_attempts: 0 },
        FlagZ(false),
    );
    m.enter_locked_idle();
    let r = m
        .submit_attempt(&mut counter, || Choice::from(0u8))
        .unwrap();
    assert_eq!(r, PinOutcome::Breach);
    let r2 = m
        .submit_attempt(&mut counter, || Choice::from(1u8))
        .unwrap();
    assert_eq!(r2, PinOutcome::Breach);
    let (_, st, _) = m.into_inner();
    assert_eq!(st, PinState::Bricked);
}

/// Map policy breach to shared [`GaldrError`] for upper layers (USB stack).
fn outcome_to_galdr(o: PinOutcome) -> Result<(), GaldrError> {
    match o {
        PinOutcome::Success => Ok(()),
        PinOutcome::Failed { .. } => Err(GaldrError::Denied),
        PinOutcome::Breach => Err(GaldrError::DeviceZeroised),
    }
}

#[test]
fn breach_maps_to_device_zeroised() {
    let mut counter = FakeMonotonicCounter::new(0);
    let mut m = PinPolicyMachine::new(
        PinPolicyConfig { max_attempts: 0 },
        FlagZ(false),
    );
    m.enter_locked_idle();
    let r = m
        .submit_attempt(&mut counter, || Choice::from(0u8))
        .unwrap();
    assert_eq!(outcome_to_galdr(r), Err(GaldrError::DeviceZeroised));
}
