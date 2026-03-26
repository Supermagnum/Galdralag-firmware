//! PIN entry policy: **hardware counter increment precedes PIN compare**; threshold triggers active
//! zeroisation (extended boot0 path per Baochip design notes).
//!
//! **Provisioning:** the default attempt ceiling is [`DEFAULT_MAX_PIN_ATTEMPTS`] (3). Values stored
//! on the token must be built with [`PinPolicyConfig::try_with_max_attempts`] in **3..=10** (see
//! [`MIN_PROVISIONED_PIN_ATTEMPTS`] / [`MAX_PROVISIONED_PIN_ATTEMPTS`]).

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

mod machine;
mod pin_input;
mod zeroise_fsm;

pub use machine::{
    pin_compare, PinOutcome, PinPolicyConfig, PinPolicyMachine, PinPolicyProvisionError, PinState,
    ZeroisationTrigger, DEFAULT_MAX_PIN_ATTEMPTS, MAX_PROVISIONED_PIN_ATTEMPTS,
    MIN_PROVISIONED_PIN_ATTEMPTS,
};
pub use pin_input::{parse_challenge_passphrase, parse_unlock_pin, PinParseError};
pub use zeroise_fsm::{ZeroiseBootState, ZeroisePhase};

#[cfg(test)]
mod tests;

#[cfg(test)]
mod property_tests;
