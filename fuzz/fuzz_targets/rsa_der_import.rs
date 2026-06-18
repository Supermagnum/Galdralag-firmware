#![no_main]

// INVARIANT: arbitrary DER bytes must never panic in from_pkcs8_der or from_spki_der.

use libfuzzer_sys::fuzz_target;
use galdr_vault::rsa_keys::{RsaPrivateKey, RsaPublicKey};

fuzz_target!(|data: &[u8]| {
    let _ = RsaPrivateKey::from_pkcs8_der(data);
    let _ = RsaPublicKey::from_spki_der(data);
});
