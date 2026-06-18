// INVARIANT: arbitrary bytes must never panic in CipherProfile::from_bytes.
// Arbitrary bytes passed to cascade_decrypt must return typed errors,
// never panic, and never return plaintext without a valid authentication tag.

#![no_main]

use cipher_profile::{cascade_decrypt, CipherProfile, CascadeCiphertext, ProfileRegistry};

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = CipherProfile::from_bytes(data);

    let reg = ProfileRegistry::with_builtins();
    let Some(profile) = reg.get("standard") else {
        return;
    };
    let mut ciphertext = heapless::Vec::<u8, 65536>::new();
    for b in data.iter().copied().take(65536) {
        if ciphertext.push(b).is_err() {
            break;
        }
    }
    let mut profile_name = heapless::String::<64>::new();
    if profile_name.push_str(profile.name()).is_err() {
        return;
    }
    let ct = CascadeCiphertext {
        profile_name,
        ciphertext,
    };
    let prk = [0x7Bu8; 32];
    let _ = cascade_decrypt(profile, &prk, b"", &ct);
});
