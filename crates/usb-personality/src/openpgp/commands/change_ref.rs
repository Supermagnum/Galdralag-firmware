//! CHANGE REFERENCE DATA (INS 0x24) — PIN change.
//!
//! Dispatched from [`crate::openpgp::dispatch::handle_apdu`] as `INS_CHANGE_REFERENCE` with
//! `P1=0x00`, `P2=0x81` (PW1) or `P2=0x83` (PW3). PIN field lengths are taken from PW status
//! (DO 0xC4) via [`crate::openpgp::OpenPgpBackend::pw_status_bytes`].

#![deny(unsafe_code)]
