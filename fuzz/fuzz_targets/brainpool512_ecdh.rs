#![no_main]

// INVARIANT: arbitrary SEC1 bytes must never panic in from_sec1.
// ECDH with any parsed-but-valid point must return Ok or typed error.

use galdr_core::fake_hal::FakeTrng;
use libfuzzer_sys::fuzz_target;
use galdr_vault::brainpool512::{BrainpoolP512PublicKey, BrainpoolP512Scalar};

fuzz_target!(|data: &[u8]| {
    let _ = BrainpoolP512PublicKey::from_sec1(data);
    let Ok(pk) = BrainpoolP512PublicKey::from_sec1(data) else {
        return;
    };
    let mut seed_bytes = [0u8; 8];
    let n = data.len().min(8);
    seed_bytes[..n].copy_from_slice(&data[..n]);
    let seed = u64::from_le_bytes(seed_bytes);
    let mut trng = FakeTrng::from_seed(seed);
    let Ok(sk) = BrainpoolP512Scalar::generate(&mut trng) else {
        return;
    };
    let _ = sk.diffie_hellman(&pk);
});
