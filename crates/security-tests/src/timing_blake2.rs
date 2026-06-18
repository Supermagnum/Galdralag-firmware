// TIMING HARNESS: BLAKE2b and BLAKE2s
//
// BLAKE2 is designed for software efficiency; its internal operations
// involve rotations and XORs with no data-dependent branches in the
// reference implementation. A FAIL would be unexpected.
// Threshold: |t| > 4.5 at 100,000 samples.
//
// Operational note: baseline; less critical than AEAD tag or ECDH.

use crate::dudect_sample_counts::samples_for_harness;
use crate::dudect_stats::{update_ct_stats, Class, CtRunner, CtSummary};
use blake2::digest::consts::U32;
use blake2::{Blake2b, Blake2s256, Digest};
use rand::prelude::*;
use std::hint::black_box;

/// BLAKE2b-256 over 64-byte inputs.
pub fn bench_timing_blake2b() -> CtSummary {
    let n = samples_for_harness("timing_blake2b");
    let mut rng = StdRng::seed_from_u64(0x424C4B3262);
    let mut work = Vec::with_capacity(n);
    for _ in 0..n {
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
            let mut h = Blake2b::<U32>::new();
            h.update(black_box(&a));
            black_box(h.finalize());
        });
    }
    let (l, r) = runner.left_right();
    update_ct_stats(None, l, r).0
}

/// BLAKE2s-256 over 64-byte inputs.
pub fn bench_timing_blake2s() -> CtSummary {
    let n = samples_for_harness("timing_blake2s");
    let mut rng = StdRng::seed_from_u64(0x424C4B3273);
    let mut work = Vec::with_capacity(n);
    for _ in 0..n {
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
            let mut h = Blake2s256::new();
            h.update(black_box(&a));
            black_box(h.finalize());
        });
    }
    let (l, r) = runner.left_right();
    update_ct_stats(None, l, r).0
}
