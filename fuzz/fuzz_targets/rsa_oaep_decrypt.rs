#![no_main]

// INVARIANT: arbitrary ciphertext bytes must never panic in decrypt_oaep.
// Must return Err for invalid ciphertexts, never panic.

use libfuzzer_sys::fuzz_target;
use galdr_vault::rsa_keys::{RsaOaepCiphertext, RsaPrivateKey};

fuzz_target!(|data: &[u8]| {
    static PK8: &[u8] = include_bytes!("../../crates/vault/tests/data/rsa_2048_fuzz.pk8");
    let key = match RsaPrivateKey::from_pkcs8_der(PK8) {
        Ok(k) => k,
        Err(_) => return,
    };
    let ct = RsaOaepCiphertext::from_bytes_fuzz(data);
    let _ = key.decrypt_oaep(&ct, b"");
});
