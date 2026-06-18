#![no_main]

//! Fuzz [`biometric_api::signed_match_from_bytes`] and the host validation path.
//! Must not panic on arbitrary input.

use biometric_api::{
    galdrad_validate_match_result, signed_match_from_bytes, verify_match_payload_signature,
};
use ed25519_dalek::SigningKey;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(sm) = signed_match_from_bytes(data) else {
        return;
    };
    let mut key = [0u8; 32];
    let copy_len = key.len().min(data.len());
    key[..copy_len].copy_from_slice(&data[..copy_len]);
    let sk = SigningKey::from_bytes(&key);
    let vk = sk.verifying_key().clone();
    let _ = verify_match_payload_signature(&sm.payload, &sm.signature, &vk);
    let _ = galdrad_validate_match_result(
        &sm,
        &vk,
        &sm.payload.nonce,
        sm.payload.timestamp.saturating_add(1),
        300,
    );
});
