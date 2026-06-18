//! VERIFY (INS 0x20) — PIN verification (PW1 / PW3).
//!
//! Handled by [`crate::openpgp::dispatch::handle_apdu`]; verification must use [`pin_policy`] before compare.

#![deny(unsafe_code)]
