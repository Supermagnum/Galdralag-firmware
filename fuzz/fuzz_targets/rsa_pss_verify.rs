#![no_main]

// INVARIANT: arbitrary signature bytes must never panic in verify_pss_sha256 / verify_pss_sha512.

use libfuzzer_sys::fuzz_target;
use vault::rsa_keys::{RsaPrivateKey, RsaPssSignature};

fuzz_target!(|data: &[u8]| {
    static PK8: &[u8] = include_bytes!("../../crates/vault/tests/data/rsa_2048_fuzz.pk8");
    let key = match RsaPrivateKey::from_pkcs8_der(PK8) {
        Ok(k) => k,
        Err(_) => return,
    };
    let pk = key.public_key();
    let sig = RsaPssSignature::from_bytes_fuzz(data);
    let _ = pk.verify_pss_sha256(b"fuzz", &sig);
    let _ = pk.verify_pss_sha512(b"fuzz", &sig);
});
