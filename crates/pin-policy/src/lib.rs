//! PIN entry policy: **hardware counter increment precedes PIN compare**; threshold triggers active
//! zeroisation (extended boot0 path per Baochip design notes).

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

mod machine;
mod zeroise_fsm;

pub use machine::{
    pin_compare, PinOutcome, PinPolicyConfig, PinPolicyMachine, PinState, ZeroisationTrigger,
};
pub use zeroise_fsm::{ZeroiseBootState, ZeroisePhase};

#[cfg(test)]
mod tests;

#[cfg(test)]
mod property_tests;
