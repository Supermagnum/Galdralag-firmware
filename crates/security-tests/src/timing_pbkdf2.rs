// TIMING HARNESS: PBKDF2-HMAC-SHA256
//
// Measures whether PBKDF2 iteration timing depends on password content.
// A FAIL here would indicate data-dependent timing in HMAC-SHA256 PRF
// which would be an unusual finding given the audited sha2/hmac crates.
// Threshold: |t| > 4.5. Uses DUDECT_SAMPLES_PBKDF2 (100k); each sample is PBKDF2-HMAC-SHA256 with 1000 iterations.
//
// Operational note: timing leakage in PBKDF2 is a lower operational concern than
// AEAD tag checks or ECDH for this firmware; this harness establishes a baseline.

use crate::dudect_sample_counts::samples_for_harness;
use crate::dudect_stats::{update_ct_stats, Class, CtRunner, CtSummary};
use pbkdf2::pbkdf2_hmac;
use rand::prelude::*;
use sha2::Sha256;
use std::hint::black_box;

/// PBKDF2-HMAC-SHA256 with fixed salt and iteration count; two password classes (fixed vs random).
pub fn bench_timing_pbkdf2() -> CtSummary {
    const PW_A: [u8; 16] = *b"AAAAAAAAAAAAAAAA";
    let salt = [0x38u8; 16];
    let n = samples_for_harness("timing_pbkdf2");
    let mut rng = StdRng::seed_from_u64(0x50424B44);
    let mut work = Vec::with_capacity(n);
    for _ in 0..n {
        if rng.gen_bool(0.5) {
            work.push((Class::Left, PW_A));
        } else {
            let mut pw_b = [0u8; 16];
            rng.fill_bytes(&mut pw_b);
            work.push((Class::Right, pw_b));
        }
    }
    let mut runner = CtRunner::default();
    for (c, pw) in work {
        runner.run_one(c, move || {
            let mut out = [0u8; 32];
            pbkdf2_hmac::<Sha256>(black_box(&pw), black_box(&salt), 1000, &mut out);
            black_box(out);
        });
    }
    let (l, r) = runner.left_right();
    update_ct_stats(None, l, r).0
}
