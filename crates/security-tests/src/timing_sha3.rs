// TIMING HARNESS: SHA3-256 and SHA3-512
//
// Keccak sponge construction. Timing should be input-independent for
// fixed-length inputs processed in a single absorption block. Each harness
// compares two RNG-filled 64-byte blocks (not zeros vs random) so the
// classes differ only by which fixed block is hashed.
// Threshold: |t| > 4.5 (see DUDECT_SAMPLES_SHA3 in dudect_stats — larger N reduces host jitter).
//
// Operational note: baseline only; less critical than AEAD/ECDH timing paths.

use crate::dudect_sample_counts::samples_for_harness;
use crate::dudect_stats::{update_ct_stats, Class, CtRunner, CtSummary};
use rand::prelude::*;
use sha3::{Digest, Sha3_256, Sha3_512};
use std::hint::black_box;

/// SHA3-256 over 64-byte inputs.
pub fn bench_timing_sha3_256() -> CtSummary {
    let mut rng = StdRng::seed_from_u64(0x53484133563235);
    let mut block_a = [0u8; 64];
    let mut block_b = [0u8; 64];
    rng.fill_bytes(&mut block_a);
    rng.fill_bytes(&mut block_b);
    let n = samples_for_harness("timing_sha3_256");
    let mut work = Vec::with_capacity(n);
    for _ in 0..n {
        if rng.gen_bool(0.5) {
            work.push((Class::Left, block_a));
        } else {
            work.push((Class::Right, block_b));
        }
    }
    let mut runner = CtRunner::default();
    for (c, a) in work {
        runner.run_one(c, move || {
            let mut h = Sha3_256::new();
            h.update(black_box(&a));
            black_box(h.finalize());
        });
    }
    let (l, r) = runner.left_right();
    update_ct_stats(None, l, r).0
}

/// SHA3-512 over 64-byte inputs.
pub fn bench_timing_sha3_512() -> CtSummary {
    let mut rng = StdRng::seed_from_u64(0x53484133563531);
    let mut block_a = [0u8; 64];
    let mut block_b = [0u8; 64];
    rng.fill_bytes(&mut block_a);
    rng.fill_bytes(&mut block_b);
    let n = samples_for_harness("timing_sha3_512");
    let mut work = Vec::with_capacity(n);
    for _ in 0..n {
        if rng.gen_bool(0.5) {
            work.push((Class::Left, block_a));
        } else {
            work.push((Class::Right, block_b));
        }
    }
    let mut runner = CtRunner::default();
    for (c, a) in work {
        runner.run_one(c, move || {
            let mut h = Sha3_512::new();
            h.update(black_box(&a));
            black_box(h.finalize());
        });
    }
    let (l, r) = runner.left_right();
    update_ct_stats(None, l, r).0
}
