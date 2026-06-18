// Statistical timing analysis adapted from dudect-bencher (Apache-2.0 / MIT).
// See https://crates.io/crates/dudect-bencher

use std::cmp;
use std::hint::black_box;
use std::time::Instant;

#[derive(Copy, Clone, Debug, Default, PartialEq)]
pub struct CtSummary {
    pub max_t: f64,
    pub max_tau: f64,
    /// Subsample size for the percentile test that produced `max_t` (used for tau).
    pub sample_size: usize,
    /// Total timing measurements (left + right); matches harness loop iterations.
    pub total_timings: usize,
}

#[derive(Copy, Clone)]
pub enum Class {
    Left,
    Right,
}

#[derive(Default)]
pub struct CtRunner {
    left: Vec<u64>,
    right: Vec<u64>,
}

impl CtRunner {
    pub fn run_one<T, F>(&mut self, class: Class, f: F)
    where
        F: FnOnce() -> T,
    {
        let start = Instant::now();
        black_box(f());
        let end = Instant::now();
        let dur = end.duration_since(start);
        let ns = dur.as_secs() * 1_000_000_000 + u64::from(dur.subsec_nanos());
        match class {
            Class::Left => self.left.push(ns),
            Class::Right => self.right.push(ns),
        }
    }

    pub fn left_right(&self) -> (&Vec<u64>, &Vec<u64>) {
        (&self.left, &self.right)
    }
}

#[derive(Copy, Clone, Debug, Default)]
struct CtTest {
    means: (f64, f64),
    sq_diffs: (f64, f64),
    sizes: (usize, usize),
}

#[derive(Default)]
pub struct CtCtx {
    tests: Vec<CtTest>,
    percentiles: Vec<f64>,
}

fn local_cmp(x: f64, y: f64) -> cmp::Ordering {
    use cmp::Ordering::{Equal, Greater, Less};
    if y.is_nan() {
        Greater
    } else if x.is_nan() || x < y {
        Less
    } else if x == y {
        Equal
    } else {
        Greater
    }
}

fn percentile_of_sorted(sorted_samples: &[f64], pct: f64) -> f64 {
    assert!(!sorted_samples.is_empty());
    if sorted_samples.len() == 1 {
        return sorted_samples[0];
    }
    assert!((0f64..=100f64).contains(&pct));
    let length = (sorted_samples.len() - 1) as f64;
    let rank = (pct / 100f64) * length;
    let lrank = rank.floor();
    let d = rank - lrank;
    let n = lrank as usize;
    let lo = sorted_samples[n];
    let hi = sorted_samples[n + 1];
    lo + (hi - lo) * d
}

fn prepare_percentiles(durations: &[u64]) -> Vec<f64> {
    let sorted: Vec<f64> = {
        let mut v = durations.to_vec();
        v.sort();
        v.into_iter().map(|d| d as f64).collect()
    };
    (0..100)
        .map(|i| {
            let exp = f64::from(10 * (i + 1)) / 100f64;
            let pct = 1f64 - 0.5f64.powf(exp);
            percentile_of_sorted(&sorted, 100f64 * pct)
        })
        .collect()
}

pub fn update_ct_stats(
    ctx: Option<CtCtx>,
    left_samples: &[u64],
    right_samples: &[u64],
) -> (CtSummary, CtCtx) {
    let (mut tests, percentiles) = match ctx {
        Some(c) => (c.tests, c.percentiles),
        None => {
            let mut all = left_samples.to_vec();
            all.extend_from_slice(right_samples);
            let pcts = prepare_percentiles(&all);
            (vec![CtTest::default(); 101], pcts)
        }
    };

    let left_f: Vec<f64> = left_samples.iter().map(|&n| n as f64).collect();
    let right_f: Vec<f64> = right_samples.iter().map(|&n| n as f64).collect();

    for &s in &left_f {
        update_test_left(&mut tests[0], s);
    }
    for &s in &right_f {
        update_test_right(&mut tests[0], s);
    }

    for (test, &pct) in tests.iter_mut().skip(1).zip(percentiles.iter()) {
        for &left_sample in left_f.iter().filter(|&&x| x < pct) {
            update_test_left(test, left_sample);
        }
        for &right_sample in right_f.iter().filter(|&&x| x < pct) {
            update_test_right(test, right_sample);
        }
    }

    let max_test = tests
        .iter()
        .max_by(|&x, &y| local_cmp(compute_t(x).abs(), compute_t(y).abs()))
        .unwrap();
    let sample_size = max_test.sizes.0 + max_test.sizes.1;
    let total_timings = left_samples.len() + right_samples.len();
    let max_t = compute_t(max_test);
    let max_tau = max_t / (sample_size as f64).sqrt();

    let new_ctx = CtCtx { tests, percentiles };
    let summ = CtSummary {
        max_t,
        max_tau,
        sample_size,
        total_timings,
    };
    (summ, new_ctx)
}

fn compute_t(test: &CtTest) -> f64 {
    let &CtTest {
        means,
        sq_diffs,
        sizes,
    } = test;
    if sizes.0 < 2 || sizes.1 < 2 {
        return 0.0;
    }
    let num = means.0 - means.1;
    let n0 = sizes.0 as f64;
    let n1 = sizes.1 as f64;
    let var0 = sq_diffs.0 / (n0 - 1f64);
    let var1 = sq_diffs.1 / (n1 - 1f64);
    let den = (var0 / n0 + var1 / n1).sqrt();
    if den == 0.0 {
        return 0.0;
    }
    num / den
}

fn update_test_left(test: &mut CtTest, datum: f64) {
    test.sizes.0 += 1;
    let diff = datum - test.means.0;
    test.means.0 += diff / (test.sizes.0 as f64);
    test.sq_diffs.0 += diff * (datum - test.means.0);
}

fn update_test_right(test: &mut CtTest, datum: f64) {
    test.sizes.1 += 1;
    let diff = datum - test.means.1;
    test.means.1 += diff / (test.sizes.1 as f64);
    test.sq_diffs.1 += diff * (datum - test.means.1);
}

pub const DUDECT_THRESHOLD: f64 = 4.5;
pub const DUDECT_SAMPLES: usize = 100_000;

/// PBKDF2: each sample runs 1000 HMAC-SHA256 iterations, so wall time dominates. Use the same N as
/// [`DUDECT_SAMPLES`] so the suite stays practical; Welch threshold is unchanged.
pub const DUDECT_SAMPLES_PBKDF2: usize = 100_000;

/// SHA-3 (Keccak): host noise can push |t| slightly past 4.5 at 100k; larger N tightens the estimate.
/// Slightly higher than default: Keccak rounds are fast and host jitter can borderline-cross |t|>4.5 at 200k.
pub const DUDECT_SAMPLES_SHA3: usize = 350_000;

/// Brainpool P512 ECDH: 100k samples would take excessive wall time. Same Welch threshold; lower N
/// reduces statistical power slightly.
pub const DUDECT_SAMPLES_BRAINPOOL_SLOW: usize = 15_000;

/// Brainpool P256/P384 ECDH: fewer timings than P512 (and than 100k default harnesses).
pub const DUDECT_SAMPLES_BRAINPOOL_REDUCED: usize = 5_000;

/// Ephemeral `EphemeralKeyPair::ecdh` paired samples (10_000 total timings: two ECDH calls per pair).
pub const DUDECT_SAMPLES_EPHEMERAL_ECDH: usize = 10_000;

/// Brainpool ECDSA verify (`timing_signature_verify`): verify is slower per sample than tag checks;
/// 10k timings keep wall time practical; Welch threshold unchanged.
pub const DUDECT_SAMPLES_SIGNATURE_VERIFY: usize = 10_000;
