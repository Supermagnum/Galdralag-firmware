//! OpenPGP command handlers (INS dispatch lives in [`crate::openpgp::dispatch`]).

#![deny(unsafe_code)]

pub mod auth;
pub mod change_ref;
pub mod decipher;
pub mod generate_key;
pub mod get_data;
pub mod get_response;
pub mod put_data;
pub mod reset_retry;
pub mod select;
pub mod sign;
pub mod verify;
