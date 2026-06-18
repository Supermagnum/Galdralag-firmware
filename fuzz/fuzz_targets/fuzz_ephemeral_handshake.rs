// INVARIANT: arbitrary bytes must never panic in InitMessage::parse or ResponseMessage::parse.
// Both must return typed errors for all malformed input.

#![no_main]

use ephemeral_session::{InitMessage, ResponseMessage};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = InitMessage::parse(data);
    let _ = ResponseMessage::parse(data);
});
