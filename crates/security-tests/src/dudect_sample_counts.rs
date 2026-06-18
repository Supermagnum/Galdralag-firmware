//! Base sample counts per harness and optional `DUDECT_SAMPLE_MULTIPLIER` (set by `xtask timing-test --full`).

use crate::dudect_stats::{
    DUDECT_SAMPLES, DUDECT_SAMPLES_BRAINPOOL_REDUCED, DUDECT_SAMPLES_BRAINPOOL_SLOW,
    DUDECT_SAMPLES_EPHEMERAL_ECDH, DUDECT_SAMPLES_PBKDF2, DUDECT_SAMPLES_SHA3,
    DUDECT_SAMPLES_SIGNATURE_VERIFY,
};

pub fn dudect_sample_multiplier() -> usize {
    std::env::var("DUDECT_SAMPLE_MULTIPLIER")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|&n| n >= 1)
        .unwrap_or(1)
}

fn base_samples_for_harness(name: &str) -> usize {
    match name {
        "timing_brainpool256_scalar_mult" | "timing_brainpool384_scalar_mult" => {
            DUDECT_SAMPLES_BRAINPOOL_REDUCED
        }
        "timing_brainpool512_scalar_mult" => DUDECT_SAMPLES_BRAINPOOL_SLOW,
        "timing_pbkdf2" => DUDECT_SAMPLES_PBKDF2,
        "timing_sha3_256" | "timing_sha3_512" => DUDECT_SAMPLES_SHA3,
        "timing_ephemeral_ecdh" => DUDECT_SAMPLES_EPHEMERAL_ECDH,
        "timing_signature_verify" => DUDECT_SAMPLES_SIGNATURE_VERIFY,
        _ => DUDECT_SAMPLES,
    }
}

pub fn samples_for_harness(name: &str) -> usize {
    base_samples_for_harness(name)
        .saturating_mul(dudect_sample_multiplier())
        .max(1)
}
