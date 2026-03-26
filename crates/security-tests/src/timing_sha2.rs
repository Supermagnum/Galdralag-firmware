// TIMING HARNESS: SHA-256 and SHA-512
//
// Measures whether SHA-2 computation time depends on input content.
// SHA-2 is a Merkle-Damgård construction; timing should be input-independent
// for fixed-length inputs. A FAIL would be highly unusual.
// These harnesses establish a baseline; SHA-2 timing leakage in the
// audited sha2 crate would be a significant upstream finding.
// Threshold: |t| > 4.5 at 100,000 samples.
//
// Operational note: hash timing is less critical than AEAD tag or ECDH paths here.

use crate::dudect_stats::{update_ct_stats, Class, CtRunner, CtSummary, DUDECT_SAMPLES};
use rand::prelude::*;
use sha2::{Digest, Sha256, Sha512};
use std::hint::black_box;

/// SHA-256 over 64-byte blocks: class 0 all-zero, class 1 random.
pub fn bench_timing_sha256() -> CtSummary {
    let mut rng = StdRng::seed_from_u64(0x534841323536);
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
            let mut h = Sha256::new();
            h.update(black_box(&a));
            black_box(h.finalize());
        });
    }
    let (l, r) = runner.left_right();
    update_ct_stats(None, l, r).0
}

/// SHA-512 over 64-byte blocks: class 0 all-zero, class 1 random.
pub fn bench_timing_sha512() -> CtSummary {
    let mut rng = StdRng::seed_from_u64(0x534841353132);
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
            let mut h = Sha512::new();
            h.update(black_box(&a));
            black_box(h.finalize());
        });
    }
    let (l, r) = runner.left_right();
    update_ct_stats(None, l, r).0
}
