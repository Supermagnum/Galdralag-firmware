// TIMING HARNESS: BLAKE3
//
// Tested with single-chunk inputs (64 bytes) to measure the
// compression function timing rather than the tree-hashing structure.
// Threshold: |t| > 4.5 at 100,000 samples.
//
// Operational note: baseline; less critical than AEAD tag or ECDH.

use crate::dudect_stats::{update_ct_stats, Class, CtRunner, CtSummary, DUDECT_SAMPLES};
use rand::prelude::*;
use std::hint::black_box;

/// BLAKE3 over 64-byte inputs (single chunk).
pub fn bench_timing_blake3() -> CtSummary {
    let mut rng = StdRng::seed_from_u64(0x424C4B3333);
    let mut work = Vec::with_capacity(DUDECT_SAMPLES);
    for _ in 0..DUDECT_SAMPLES {
        if rng.gen_bool(0.5) {
            work.push((Class::Left, [0u8; 64]));
        } else {
            let mut r = [0u8; 64];
            rng.fill_bytes(&mut r);
            work.push((Class::Right, r));
        }
    }
    let mut runner = CtRunner::default();
    for (c, a) in work {
        runner.run_one(c, move || {
            black_box(blake3::hash(black_box(&a)));
        });
    }
    let (l, r) = runner.left_right();
    update_ct_stats(None, l, r).0
}
