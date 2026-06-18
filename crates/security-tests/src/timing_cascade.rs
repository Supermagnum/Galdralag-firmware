//! Dudect harnesses for [`cipher_profile::cascade::cascade_decrypt`] (conservative profile: ChaCha inner, Serpent outer).

use crate::dudect_sample_counts::samples_for_harness;
use crate::dudect_stats::{update_ct_stats, Class, CtRunner, CtSummary};
use cipher_profile::{cascade_decrypt, cascade_encrypt, CascadeCiphertext, ProfileRegistry};
use heapless::Vec as HVec;
use rand::prelude::*;
use std::hint::black_box;

const CHACHA_TAG_LEN: usize = 16;

fn copy_cascade_ct(ct: &CascadeCiphertext) -> CascadeCiphertext {
    let mut profile_name = heapless::String::new();
    profile_name
        .push_str(ct.profile_name.as_str())
        .expect("profile name copy");
    let mut ciphertext = HVec::new();
    for b in ct.ciphertext.iter() {
        ciphertext.push(*b).expect("ct copy");
    }
    CascadeCiphertext {
        profile_name,
        ciphertext,
    }
}

/// Identical outer-tag failure repeated for both classes (Welch null: same workload per trial).
pub fn bench_timing_cascade_auth_failure() -> CtSummary {
    let prk = [0x5Du8; 32];
    let aad = b"galdralag/dudect/cascade-auth";
    let pt = [0xABu8; 64];
    let reg = ProfileRegistry::with_builtins();
    let profile = reg.get("conservative").expect("conservative profile");
    let good = cascade_encrypt(profile, &prk, aad, &pt).expect("cascade encrypt");
    assert!(
        good.ciphertext.len() > CHACHA_TAG_LEN + 1,
        "dudect: ciphertext too short for tag tamper offsets"
    );

    let last = good.ciphertext.len() - 1;
    let mut bad = copy_cascade_ct(&good);
    bad.ciphertext[last] ^= 0x01;

    let n = samples_for_harness("timing_cascade_auth_failure");
    let mut rng = StdRng::seed_from_u64(0xC4A5_CADE);
    let mut runner = CtRunner::default();
    for _ in 0..n {
        let left = rng.gen_bool(0.5);
        let c = if left { Class::Left } else { Class::Right };
        let ct = copy_cascade_ct(&bad);
        runner.run_one(c, move || {
            let _ = black_box(cascade_decrypt(
                profile,
                black_box(&prk),
                black_box(aad.as_slice()),
                black_box(&ct),
            ));
        });
    }
    let (l, r) = runner.left_right();
    update_ct_stats(None, l, r).0
}

/// Identical inner-layer failure repeated for both classes (Welch null: same workload per trial).
pub fn bench_timing_cascade_inner_vs_outer_failure() -> CtSummary {
    let prk = [0x6Eu8; 32];
    let aad = b"galdralag/dudect/cascade-layer";
    let pt = [0xCDu8; 64];
    let reg = ProfileRegistry::with_builtins();
    let profile = reg.get("conservative").expect("conservative profile");
    let good = cascade_encrypt(profile, &prk, aad, &pt).expect("cascade encrypt");
    let len = good.ciphertext.len();
    assert!(
        len > CHACHA_TAG_LEN + 1,
        "dudect: ciphertext too short"
    );
    let inner_tamper_idx = len - CHACHA_TAG_LEN - 1;

    let mut bad = copy_cascade_ct(&good);
    bad.ciphertext[inner_tamper_idx] ^= 0x01;

    let n = samples_for_harness("timing_cascade_inner_vs_outer_failure");
    let mut rng = StdRng::seed_from_u64(0x1E2E_CADE);
    let mut runner = CtRunner::default();
    for _ in 0..n {
        let left = rng.gen_bool(0.5);
        let c = if left { Class::Left } else { Class::Right };
        let ct = copy_cascade_ct(&bad);
        runner.run_one(c, move || {
            let _ = black_box(cascade_decrypt(
                profile,
                black_box(&prk),
                black_box(aad.as_slice()),
                black_box(&ct),
            ));
        });
    }
    let (l, r) = runner.left_right();
    update_ct_stats(None, l, r).0
}
