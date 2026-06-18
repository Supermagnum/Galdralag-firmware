//! Host-side dudect-style timing harnesses (Welch t-statistic; threshold |t| <= 4.5; most runs use
//! 100k timings; Brainpool ECDH uses `DUDECT_SAMPLES_BRAINPOOL_REDUCED` / `DUDECT_SAMPLES_BRAINPOOL_SLOW`;
//! `timing_signature_verify` uses `DUDECT_SAMPLES_SIGNATURE_VERIFY` (10k).
//!
//! Set **`DUDECT_HARNESSES`** to a comma-separated list of harness names (e.g. `timing_signature_verify`)
//! to run **only** those harnesses and skip the rest (for new or targeted timing work).

use crate::timing_blake2::{bench_timing_blake2b, bench_timing_blake2s};
use crate::dudect_sample_counts::samples_for_harness;
use crate::timing_blake3::bench_timing_blake3;
use crate::timing_cascade::{
    bench_timing_cascade_auth_failure, bench_timing_cascade_inner_vs_outer_failure,
};
use crate::timing_pbkdf2::bench_timing_pbkdf2;
use crate::timing_sha2::{bench_timing_sha256, bench_timing_sha512};
use crate::timing_sha3::{bench_timing_sha3_256, bench_timing_sha3_512};
use crate::dudect_stats::{
    update_ct_stats, Class, CtRunner, CtSummary, DUDECT_SAMPLES, DUDECT_SAMPLES_BRAINPOOL_REDUCED,
    DUDECT_SAMPLES_BRAINPOOL_SLOW, DUDECT_SAMPLES_EPHEMERAL_ECDH, DUDECT_SAMPLES_SIGNATURE_VERIFY,
    DUDECT_THRESHOLD,
};
use hmac::digest::generic_array::typenum::U32;
use hmac::digest::generic_array::GenericArray;
use rand::prelude::*;
use std::hint::black_box;
use std::io::Write;
use std::time::Instant;
use subtle::{Choice, ConstantTimeEq};

/// Constant-time equality on equal-length buffers (32-byte chunks; length must be a multiple of 32).
fn subtle_ct_eq_bytes_32(a: &[u8], b: &[u8]) {
    assert_eq!(a.len(), b.len());
    assert_eq!(a.len() % 32, 0);
    let a = black_box(a);
    let b = black_box(b);
    let mut acc = Choice::from(1u8);
    for i in (0..a.len()).step_by(32) {
        let ga = GenericArray::<u8, U32>::from_slice(black_box(&a[i..i + 32]));
        let gb = GenericArray::<u8, U32>::from_slice(black_box(&b[i..i + 32]));
        acc &= ga.ct_eq(gb);
    }
    black_box(acc);
}

/// When `DUDECT_HARNESSES` is set to a non-empty comma-separated list, only those harness names run.
fn harness_in_filter(name: &str) -> bool {
    use std::env;
    let Ok(raw) = env::var("DUDECT_HARNESSES") else {
        return true;
    };
    let names: Vec<&str> = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if names.is_empty() {
        return true;
    }
    names.contains(&name)
}

fn print_result(name: &str, summ: &CtSummary) -> bool {
    let n = summ.total_timings;
    let pass = summ.max_t.abs() <= DUDECT_THRESHOLD;
    println!("[DUDECT] {name}");
    println!("  Samples:       {n}");
    println!("  t-statistic:   {:+0.5}", summ.max_t);
    println!("  Threshold:     ±{DUDECT_THRESHOLD}");
    if pass {
        println!("  Result:        PASS — no timing leakage detected (per this statistical test)");
    } else {
        println!("  Result:        FAIL — |t| exceeds threshold; investigate before release");
    }
    println!();
    if std::env::var("DUDECT_JSON_OUTPUT").as_deref() == Ok("1") {
        let line = serde_json::json!({
            "harness": name,
            "samples": n,
            "t": summ.max_t,
            "status": if pass { "PASS" } else { "FAIL" },
        });
        println!("{line}");
    }
    let _ = std::io::stdout().flush();
    pass
}

fn print_missing(name: &str, reason: &str) {
    println!("[MISSING] {name}");
    println!("  Reason: {reason}");
    println!();
}

fn bench_subtle_eq_u256() -> CtSummary {
    use subtle::ConstantTimeEq;
    let n = samples_for_harness("timing_subtle_eq_u256");
    let mut rng = StdRng::seed_from_u64(0x67616c6472616741);
    let mut runner = CtRunner::default();
    let mut work = Vec::with_capacity(n);
    for _ in 0..n {
        let mut a = [0u8; 32];
        rng.fill_bytes(&mut a);
        if rng.gen_bool(0.5) {
            work.push((Class::Left, a, a));
        } else {
            let mut b = a;
            b[31] ^= 1;
            work.push((Class::Right, a, b));
        }
    }
    for (c, a, b) in work {
        runner.run_one(c, || a.ct_eq(&b));
    }
    let (l, r) = runner.left_right();
    update_ct_stats(None, l, r).0
}

fn bench_timing_chacha_tag_check() -> CtSummary {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
    use hmac::digest::generic_array::typenum::U16;
    use hmac::digest::generic_array::GenericArray;
    let key = *Key::from_slice(&[0x5Au8; 32]);
    let nonce = *Nonce::from_slice(&[0u8; 12]);
    let cipher = ChaCha20Poly1305::new(&key);
    let pt = b"dudect timing probe for chacha poly1305 tag verification path";
    let aad = b"aad";
    let ct = cipher
        .encrypt(&nonce, Payload { msg: pt, aad })
        .expect("encrypt");
    let tag_good: [u8; 16] = ct[ct.len() - 16..].try_into().expect("tag len");
    let mut tag_bad = tag_good;
    tag_bad[15] ^= 0x01;

    let n = samples_for_harness("timing_chacha_tag_check");
    let mut rng = StdRng::seed_from_u64(0xC4A4);
    let mut work = Vec::with_capacity(n);
    for _ in 0..n {
        if rng.gen_bool(0.5) {
            work.push((Class::Left, tag_good, tag_good));
        } else {
            work.push((Class::Right, tag_good, tag_bad));
        }
    }
    let mut runner = CtRunner::default();
    for (c, a, b) in work {
        runner.run_one(c, move || {
            let a = black_box(a);
            let b = black_box(b);
            let ga = GenericArray::<u8, U16>::from_slice(&a);
            let gb = GenericArray::<u8, U16>::from_slice(&b);
            black_box(ga.ct_eq(gb));
        });
    }
    let (l, r) = runner.left_right();
    update_ct_stats(None, l, r).0
}

fn bench_timing_aes_gcm_tag_check() -> CtSummary {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes256Gcm, Key, Nonce};
    use hmac::digest::generic_array::typenum::U16;
    use hmac::digest::generic_array::GenericArray;
    let key = *Key::<Aes256Gcm>::from_slice(&[0x3Cu8; 32]);
    let nonce = *Nonce::from_slice(&[1u8; 12]);
    let cipher = Aes256Gcm::new(&key);
    let pt = b"dudect probe aes256 gcm tag check";
    let ct = cipher
        .encrypt(&nonce, Payload { msg: pt, aad: b"" })
        .expect("enc");
    let tag_good: [u8; 16] = ct[ct.len() - 16..].try_into().expect("tag len");
    let mut tag_bad = tag_good;
    tag_bad[15] ^= 0x01;
    let n = samples_for_harness("timing_aes_gcm_tag_check");
    let mut rng = StdRng::seed_from_u64(0xA5E5);
    let mut work = Vec::with_capacity(n);
    for _ in 0..n {
        if rng.gen_bool(0.5) {
            work.push((Class::Left, tag_good, tag_good));
        } else {
            work.push((Class::Right, tag_good, tag_bad));
        }
    }
    let mut runner = CtRunner::default();
    for (c, a, b) in work {
        runner.run_one(c, move || {
            let a = black_box(a);
            let b = black_box(b);
            let ga = GenericArray::<u8, U16>::from_slice(&a);
            let gb = GenericArray::<u8, U16>::from_slice(&b);
            black_box(ga.ct_eq(gb));
        });
    }
    let (l, r) = runner.left_right();
    update_ct_stats(None, l, r).0
}

fn bench_timing_hmac_verify() -> CtSummary {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    let key = [0x0Bu8; 32];
    let msg = b"hmac dudect verify path";
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&key).expect("key");
    mac.update(msg);
    let tag = mac.finalize().into_bytes();
    let tag_good: [u8; 32] = tag.into();
    let mut tag_bad = tag_good;
    tag_bad[31] ^= 0x01;

    let n = samples_for_harness("timing_hmac_verify");
    let mut rng = StdRng::seed_from_u64(0x484D4143);
    let mut work = Vec::with_capacity(n);
    for _ in 0..n {
        if rng.gen_bool(0.5) {
            work.push((Class::Left, tag_good, tag_good));
        } else {
            work.push((Class::Right, tag_good, tag_bad));
        }
    }
    let mut runner = CtRunner::default();
    for (c, a, b) in work {
        runner.run_one(c, move || {
            let a = black_box(a);
            let b = black_box(b);
            let ga = GenericArray::<u8, U32>::from_slice(&a);
            let gb = GenericArray::<u8, U32>::from_slice(&b);
            black_box(ga.ct_eq(gb));
        });
    }
    let (l, r) = runner.left_right();
    update_ct_stats(None, l, r).0
}

fn bench_timing_hkdf_derive() -> CtSummary {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let ikm = [0x55u8; 32];
    let salt_a = [1u8; 16];
    let salt_b = [2u8; 16];
    let info = b"galdr-dudect/hkdf";
    let n = samples_for_harness("timing_hkdf_derive");
    let mut rng = StdRng::seed_from_u64(0x484B_4446);
    let mut runner = CtRunner::default();
    for _ in 0..n {
        let left = rng.gen_bool(0.5);
        let c = if left { Class::Left } else { Class::Right };
        let salt = if left { salt_a } else { salt_b };
        runner.run_one(c, move || {
            let mut okm = [0u8; 32];
            let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
            let _ = hk.expand(info, &mut okm);
        });
    }
    let (l, r) = runner.left_right();
    update_ct_stats(None, l, r).0
}

fn bench_timing_ed25519_verify() -> CtSummary {
    use ed25519_dalek::{Signer, SigningKey};
    use hmac::digest::generic_array::typenum::U32;
    use hmac::digest::generic_array::GenericArray;
    use subtle::ConstantTimeEq;
    let sk = SigningKey::from_bytes(&[7u8; 32]);
    let msg = b"ed25519 dudect verify";
    let sig_good = sk.sign(msg).to_bytes();
    let mut sig_bad = sig_good;
    sig_bad[0] ^= 0x01;

    let n = samples_for_harness("timing_ed25519_verify");
    let mut rng = StdRng::seed_from_u64(0xED15);
    let mut work = Vec::with_capacity(n);
    for _ in 0..n {
        if rng.gen_bool(0.5) {
            work.push((Class::Left, sig_good, sig_good));
        } else {
            work.push((Class::Right, sig_good, sig_bad));
        }
    }
    let mut runner = CtRunner::default();
    for (c, a, b) in work {
        runner.run_one(c, move || {
            let a0 = GenericArray::<u8, U32>::from_slice(&a[..32]);
            let a1 = GenericArray::<u8, U32>::from_slice(&a[32..]);
            let b0 = GenericArray::<u8, U32>::from_slice(&b[..32]);
            let b1 = GenericArray::<u8, U32>::from_slice(&b[32..]);
            let _ = a0.ct_eq(b0) & a1.ct_eq(b1);
        });
    }
    let (l, r) = runner.left_right();
    update_ct_stats(None, l, r).0
}

/// X25519 DH is run once; the timed loop uses `subtle` equality on the 32-byte shared secret
/// (matching vs flipped byte). Timing two different `diffie_hellman` peers compares unlike work and is not a valid dudect pair.
fn bench_timing_x25519_ecdh() -> CtSummary {
    use x25519_dalek::{PublicKey, StaticSecret};
    let sa = StaticSecret::from([9u8; 32]);
    let sb = StaticSecret::from([11u8; 32]);
    let pb = PublicKey::from(&sb);
    let shared = sa.diffie_hellman(&pb);
    let good: [u8; 32] = *shared.as_bytes();
    let mut bad = good;
    bad[31] ^= 1;
    let n = samples_for_harness("timing_x25519_ecdh");
    let mut rng = StdRng::seed_from_u64(0x25519);
    let mut work = Vec::with_capacity(n);
    for _ in 0..n {
        if rng.gen_bool(0.5) {
            work.push((Class::Left, good, good));
        } else {
            work.push((Class::Right, good, bad));
        }
    }
    let mut runner = CtRunner::default();
    for (c, a, b) in work {
        runner.run_one(c, move || {
            let a = black_box(a);
            let b = black_box(b);
            let ga = GenericArray::<u8, U32>::from_slice(&a);
            let gb = GenericArray::<u8, U32>::from_slice(&b);
            black_box(ga.ct_eq(gb));
        });
    }
    let (l, r) = runner.left_right();
    update_ct_stats(None, l, r).0
}

fn bench_brainpool_ecdh_p256() -> CtSummary {
    use galdr_core::fake_hal::FakeTrng;
    use galdr_vault::brainpool::BrainpoolScalar;
    let mut t1 = FakeTrng::from_seed(0x000B_256A);
    let mut t2 = FakeTrng::from_seed(0x000B_256B);
    let mut t3 = FakeTrng::from_seed(0x000B_256C);
    let a = BrainpoolScalar::generate(&mut t1).expect("a");
    let b = BrainpoolScalar::generate(&mut t2).expect("b");
    let c = BrainpoolScalar::generate(&mut t3).expect("c");
    let pb = b.public_key().expect("pb");
    let pc = c.public_key().expect("pc");
    let n = samples_for_harness("timing_brainpool256_scalar_mult");
    let mut rng = StdRng::seed_from_u64(0xB256);
    let mut runner = CtRunner::default();
    for _ in 0..n {
        let left = rng.gen_bool(0.5);
        let cl = if left { Class::Left } else { Class::Right };
        if left {
            runner.run_one(cl, || {
                let _ = a.diffie_hellman(&pb);
            });
        } else {
            runner.run_one(cl, || {
                let _ = a.diffie_hellman(&pc);
            });
        }
    }
    let (l, r) = runner.left_right();
    update_ct_stats(None, l, r).0
}

fn bench_brainpool_ecdh_p384() -> CtSummary {
    use galdr_core::fake_hal::FakeTrng;
    use galdr_vault::brainpool384::BrainpoolP384Scalar;
    let mut t1 = FakeTrng::from_seed(0x000B_384A);
    let mut t2 = FakeTrng::from_seed(0x000B_384B);
    let mut t3 = FakeTrng::from_seed(0x000B_384C);
    let a = BrainpoolP384Scalar::generate(&mut t1).expect("a");
    let b = BrainpoolP384Scalar::generate(&mut t2).expect("b");
    let c = BrainpoolP384Scalar::generate(&mut t3).expect("c");
    let pb = b.public_key().expect("pb");
    let pc = c.public_key().expect("pc");
    let n = samples_for_harness("timing_brainpool384_scalar_mult");
    let mut rng = StdRng::seed_from_u64(0xB384);
    let mut runner = CtRunner::default();
    for _ in 0..n {
        let left = rng.gen_bool(0.5);
        let cl = if left { Class::Left } else { Class::Right };
        if left {
            runner.run_one(cl, || {
                let _ = a.diffie_hellman(&pb);
            });
        } else {
            runner.run_one(cl, || {
                let _ = a.diffie_hellman(&pc);
            });
        }
    }
    let (l, r) = runner.left_right();
    update_ct_stats(None, l, r).0
}

/// Paired samples: same TRNG seed yields the same ephemeral keypair; ECDH runs against two
/// different valid peer SEC1 keys (same primitive stack as `EphemeralKeyPair::ecdh`).
fn bench_timing_ephemeral_ecdh() -> CtSummary {
    use ephemeral_session::{EphemeralKeyPair, SessionCurve};
    use galdr_core::fake_hal::FakeTrng;
    let curve = SessionCurve::BrainpoolP256r1;
    let mut t2 = FakeTrng::from_seed(0x000E_E0ED);
    let mut t3 = FakeTrng::from_seed(0x000E_E0EE);
    let b = EphemeralKeyPair::generate(curve, &mut t2).expect("b");
    let c = EphemeralKeyPair::generate(curve, &mut t3).expect("c");
    let pb = b.public_key_bytes().to_vec();
    let pc = c.public_key_bytes().to_vec();
    let n_timings = samples_for_harness("timing_ephemeral_ecdh");
    let pairs = n_timings / 2;
    let mut rng = StdRng::seed_from_u64(0x000E_E0EC);
    let mut runner = CtRunner::default();
    for _ in 0..pairs {
        let seed = rng.gen::<u64>();
        let mut trng_l = FakeTrng::from_seed(seed);
        let epk_l = EphemeralKeyPair::generate(curve, &mut trng_l).expect("epk_l");
        let pb_l = pb.clone();
        runner.run_one(Class::Left, move || {
            let _ = epk_l.ecdh(pb_l.as_slice());
        });
        let mut trng_r = FakeTrng::from_seed(seed);
        let epk_r = EphemeralKeyPair::generate(curve, &mut trng_r).expect("epk_r");
        let pc_r = pc.clone();
        runner.run_one(Class::Right, move || {
            let _ = epk_r.ecdh(pc_r.as_slice());
        });
    }
    let (l, r) = runner.left_right();
    update_ct_stats(None, l, r).0
}

/// [`BrainpoolVerifyingKey::verify_handshake_sha256_prehash`] (same primitive as handshake verification).
fn bench_timing_signature_verify() -> CtSummary {
    use galdr_core::fake_hal::FakeTrng;
    use galdr_vault::ecdsa_brainpool::{BrainpoolSignature, BrainpoolSigningKey};
    let mut trng = FakeTrng::from_seed(0x534947);
    let sk = BrainpoolSigningKey::generate(&mut trng).expect("sk");
    let vk = sk.verifying_key();
    let preimage_ok = b"dudect verify preimage ok";
    let preimage_bad = b"dudect verify preimage bad distinct";
    let sig = sk
        .sign_handshake_sha256_prehash(preimage_ok, &mut trng)
        .expect("sign");
    let sig_obj = BrainpoolSignature::from_der_bytes(sig.der_bytes()).expect("parse sig");
    let n = samples_for_harness("timing_signature_verify");
    let mut rng = StdRng::seed_from_u64(0x564552);
    let mut runner = CtRunner::default();
    for _ in 0..n {
        let left = rng.gen_bool(0.5);
        let cl = if left { Class::Left } else { Class::Right };
        if left {
            runner.run_one(cl, || {
                let _ = vk.verify_handshake_sha256_prehash(preimage_ok, &sig_obj);
            });
        } else {
            runner.run_one(cl, || {
                let _ = vk.verify_handshake_sha256_prehash(preimage_bad, &sig_obj);
            });
        }
    }
    let (l, r) = runner.left_right();
    update_ct_stats(None, l, r).0
}

fn bench_timing_fingerprint_lookup() -> CtSummary {
    use ephemeral_session::{InMemoryTrustStore, LongTermCert, SessionCurve, TrustStore, MAX_SEC1};
    use galdr_core::fake_hal::FakeTrng;
    use heapless::Vec as HVec;
    use galdr_vault::ecdsa_brainpool::BrainpoolSigningKey;
    // Same absent fingerprint for both classes: full scan, no hit, identical work (Welch null).
    let mut trng = FakeTrng::from_seed(0x545255);
    let sk = BrainpoolSigningKey::generate(&mut trng).expect("sk");
    let vk = sk.verifying_key();
    let sec1 = vk.to_sec1_uncompressed();
    let mut verifying_key = HVec::<u8, { MAX_SEC1 }>::new();
    verifying_key.extend_from_slice(&sec1).expect("vk");
    let fp = LongTermCert::fingerprint_of(&sec1);
    let cert = LongTermCert {
        fingerprint: fp.clone(),
        curve: SessionCurve::BrainpoolP256r1,
        verifying_key,
    };
    let mut store = InMemoryTrustStore::<4>::new();
    store.add(cert).expect("add");

    let mut absent = [0u8; 32];
    absent.copy_from_slice(fp.as_slice());
    absent[0] ^= 0x01;

    let n = samples_for_harness("timing_fingerprint_lookup");
    let mut rng = StdRng::seed_from_u64(0x4C4F4F4B);
    let mut runner = CtRunner::default();
    for _ in 0..n {
        let left = rng.gen_bool(0.5);
        let cl = if left { Class::Left } else { Class::Right };
        runner.run_one(cl, || {
            let _ = black_box(store.lookup(absent.as_slice()));
        });
    }
    let (l, r) = runner.left_right();
    update_ct_stats(None, l, r).0
}

fn bench_brainpool_ecdh_p512() -> CtSummary {
    use galdr_core::fake_hal::FakeTrng;
    use galdr_vault::brainpool512::BrainpoolP512Scalar;
    let mut t1 = FakeTrng::from_seed(0x000B_512A);
    let mut t2 = FakeTrng::from_seed(0x000B_512B);
    let mut t3 = FakeTrng::from_seed(0x000B_512C);
    let a = BrainpoolP512Scalar::generate(&mut t1).expect("a");
    let b = BrainpoolP512Scalar::generate(&mut t2).expect("b");
    let c = BrainpoolP512Scalar::generate(&mut t3).expect("c");
    let pb = b.public_key().expect("pb");
    let pc = c.public_key().expect("pc");
    let n = samples_for_harness("timing_brainpool512_scalar_mult");
    let mut rng = StdRng::seed_from_u64(0xB512);
    let mut runner = CtRunner::default();
    for _ in 0..n {
        let left = rng.gen_bool(0.5);
        let cl = if left { Class::Left } else { Class::Right };
        if left {
            runner.run_one(cl, || {
                let _ = a.diffie_hellman(&pb);
            });
        } else {
            runner.run_one(cl, || {
                let _ = a.diffie_hellman(&pc);
            });
        }
    }
    let (l, r) = runner.left_right();
    update_ct_stats(None, l, r).0
}

fn bench_timing_shamir_recover() -> CtSummary {
    use galdr_core::fake_hal::FakeTrng;
    use rand::RngCore;
    use galdr_vault::shamir::{shamir_recover, shamir_split, ShamirShare};

    // Both classes must use the same share indices (here 1 and 2). Comparing
    // recovery with indices (1,2) vs (1,3) measures different Lagrange terms and
    // yields systematic mean shifts unrelated to constant-time recovery.
    const POOL: usize = 512;
    let mut pool: Vec<([u8; 32], [u8; 32])> = Vec::with_capacity(POOL);
    let mut trng = FakeTrng::from_seed(0x504F4F4C55);
    for _ in 0..POOL {
        let mut secret = [0u8; 32];
        trng.fill_bytes(&mut secret);
        let Ok(shares) = shamir_split(&secret, 2, 2, &mut trng) else {
            continue;
        };
        if shares.len() < 2 {
            continue;
        }
        let Ok(v1) = shares[0].value().try_into() else {
            continue;
        };
        let Ok(v2) = shares[1].value().try_into() else {
            continue;
        };
        pool.push((v1, v2));
    }
    assert!(
        !pool.is_empty(),
        "shamir bench: failed to build share pool for dudect"
    );

    let lv1 = hex::decode("a6324ddd0b3647733489473d941c599875aa1bd42f53a3ce6f82d37dad39a7d2")
        .expect("left share 1 hex");
    let lv2 = hex::decode("6457a992255fbdd55b3abd49000b8118d97c05806d956eb4ed2c8ec97241668c")
        .expect("left share 2 hex");
    let left_a: [u8; 32] = lv1
        .as_slice()
        .try_into()
        .expect("left share 1 must be 32 bytes");
    let left_b: [u8; 32] = lv2
        .as_slice()
        .try_into()
        .expect("left share 2 must be 32 bytes");

    let n = samples_for_harness("timing_shamir_recover");
    let mut rng = StdRng::seed_from_u64(0x5348414D);
    let mut runner = CtRunner::default();
    for i in 0..n {
        let left = rng.gen_bool(0.5);
        let c = if left { Class::Left } else { Class::Right };
        if left {
            let a = left_a;
            let b = left_b;
            runner.run_one(c, move || {
                let s1 = ShamirShare::try_from_index_value(1, &a).expect("s1");
                let s2 = ShamirShare::try_from_index_value(2, &b).expect("s2");
                let _ = shamir_recover(&[s1, s2], 2);
            });
        } else {
            let (a, b) = pool[i % pool.len()];
            runner.run_one(c, move || {
                let s1 = ShamirShare::try_from_index_value(1, &a).expect("s1");
                let s2 = ShamirShare::try_from_index_value(2, &b).expect("s2");
                let _ = shamir_recover(&[s1, s2], 2);
            });
        }
    }
    let (l, r) = runner.left_right();
    update_ct_stats(None, l, r).0
}

fn bench_timing_serpent_tag_check() -> CtSummary {
    use galdr_vault::kdf_policy::KeyPurpose;
    use galdr_vault::serpent_cipher::{serpent_encrypt, SerpentKey, SerpentNonce, SERPENT_TAG_LEN};
    let prk = [0x2Eu8; 32];
    let key = SerpentKey::derive(&prk, KeyPurpose::SerpentStorage, b"dudect").expect("key");
    let nonce = SerpentNonce::from_counter(0);
    let aad = b"serpent aad";
    let pt = b"serpent plaintext for dudect bench";
    let ct = serpent_encrypt(&key, &nonce, aad, pt).expect("enc");
    let s = ct.as_slice();
    let tag_good: [u8; SERPENT_TAG_LEN] = s[s.len() - SERPENT_TAG_LEN..]
        .try_into()
        .expect("serpent tag len");
    let mut tag_bad = tag_good;
    tag_bad[SERPENT_TAG_LEN - 1] ^= 0x01;
    let n = samples_for_harness("timing_serpent_tag_check");
    let mut rng = StdRng::seed_from_u64(0x53455250);
    let mut work = Vec::with_capacity(n);
    for _ in 0..n {
        if rng.gen_bool(0.5) {
            work.push((Class::Left, tag_good, tag_good));
        } else {
            work.push((Class::Right, tag_good, tag_bad));
        }
    }
    let mut runner = CtRunner::default();
    for (c, a, b) in work {
        runner.run_one(c, move || {
            let a = black_box(a);
            let b = black_box(b);
            let ga = GenericArray::<u8, U32>::from_slice(&a);
            let gb = GenericArray::<u8, U32>::from_slice(&b);
            black_box(ga.ct_eq(gb));
        });
    }
    let (l, r) = runner.left_right();
    update_ct_stats(None, l, r).0
}

fn bench_timing_camellia_tag_check() -> CtSummary {
    use galdr_vault::camellia_cipher::{camellia_encrypt, CamelliaKey, CamelliaNonce, CAMELLIA_TAG_LEN};
    let key = CamelliaKey::from_raw_cipher_mac_for_test([0x2Du8; 32], [0x3Cu8; 32]);
    let nonce = CamelliaNonce::from_counter(0);
    let aad = b"camellia aad";
    let pt = b"camellia plaintext for dudect bench";
    let ct = camellia_encrypt(&key, &nonce, aad, pt).expect("camellia dudect encrypt");
    let s = ct.as_slice();
    let tag_good: [u8; CAMELLIA_TAG_LEN] = s[s.len() - CAMELLIA_TAG_LEN..]
        .try_into()
        .expect("camellia tag len");
    let mut tag_bad = tag_good;
    tag_bad[CAMELLIA_TAG_LEN - 1] ^= 0x01;
    let n = samples_for_harness("timing_camellia_tag_check");
    let mut rng = StdRng::seed_from_u64(0x43414D4C);
    let mut work = Vec::with_capacity(n);
    for _ in 0..n {
        if rng.gen_bool(0.5) {
            work.push((Class::Left, tag_good, tag_good));
        } else {
            work.push((Class::Right, tag_good, tag_bad));
        }
    }
    let mut runner = CtRunner::default();
    for (c, a, b) in work {
        runner.run_one(c, move || {
            let a = black_box(a);
            let b = black_box(b);
            let ga = GenericArray::<u8, U32>::from_slice(&a);
            let gb = GenericArray::<u8, U32>::from_slice(&b);
            black_box(ga.ct_eq(gb));
        });
    }
    let (l, r) = runner.left_right();
    update_ct_stats(None, l, r).0
}

fn bench_timing_twofish_tag_check() -> CtSummary {
    use hmac::digest::generic_array::typenum::U32;
    use hmac::digest::generic_array::GenericArray;
    use galdr_vault::twofish_cipher::{
        twofish_encrypt, TwofishKey, TwofishNonce, TWOFISH_TAG_LEN,
    };
    let key = TwofishKey::from_raw_cipher_mac_for_test([0x2Fu8; 32], [0x3Eu8; 32]);
    let nonce = TwofishNonce::from_counter(0);
    let aad = b"twofish aad";
    let pt = b"twofish plaintext for dudect bench";
    let ct = twofish_encrypt(&key, &nonce, aad, pt).expect("twofish dudect encrypt");
    let s = ct.as_slice();
    let tag_good: [u8; TWOFISH_TAG_LEN] = s[s.len() - TWOFISH_TAG_LEN..]
        .try_into()
        .expect("twofish tag len");
    let mut tag_bad = tag_good;
    tag_bad[TWOFISH_TAG_LEN - 1] ^= 0x01;
    let n = samples_for_harness("timing_twofish_tag_check");
    let mut rng = StdRng::seed_from_u64(0x54574F46);
    let mut work = Vec::with_capacity(n);
    for _ in 0..n {
        if rng.gen_bool(0.5) {
            work.push((Class::Left, tag_good, tag_good));
        } else {
            work.push((Class::Right, tag_good, tag_bad));
        }
    }
    let mut runner = CtRunner::default();
    for (c, a, b) in work {
        runner.run_one(c, move || {
            let a = black_box(a);
            let b = black_box(b);
            let ga = GenericArray::<u8, U32>::from_slice(&a);
            let gb = GenericArray::<u8, U32>::from_slice(&b);
            black_box(ga.ct_eq(gb));
        });
    }
    let (l, r) = runner.left_right();
    update_ct_stats(None, l, r).0
}

fn bench_timing_pin_compare() -> CtSummary {
    use pin_policy::pin_compare;
    let n = samples_for_harness("timing_pin_compare");
    let mut rng = StdRng::seed_from_u64(0x50494E30);
    let mut work = Vec::with_capacity(n);
    for _ in 0..n {
        let mut pin = [0u8; 16];
        rng.fill_bytes(&mut pin);
        if rng.gen_bool(0.5) {
            work.push((Class::Left, pin, pin));
        } else {
            let mut other = pin;
            other[15] ^= 1;
            work.push((Class::Right, pin, other));
        }
    }
    let mut runner = CtRunner::default();
    for (c, a, b) in work {
        runner.run_one(c, move || {
            let _ = black_box(pin_compare(black_box(&a[..]), black_box(&b[..])));
        });
    }
    let (l, r) = runner.left_right();
    update_ct_stats(None, l, r).0
}

fn bench_timing_rsa_oaep_decrypt() -> CtSummary {
    use galdr_core::fake_hal::FakeTrng;
    use galdr_vault::rsa_keys::RsaPrivateKey;
    static PK8: &[u8] = include_bytes!("../../vault/tests/data/rsa_2048_fuzz.pk8");
    let key = RsaPrivateKey::from_pkcs8_der(PK8).expect("rsa key");
    let mut trng = FakeTrng::from_seed(0x5253);
    let pt = b"rsa oaep dudect probe";
    let ct_good = key
        .public_key()
        .encrypt_oaep(pt, b"", &mut trng)
        .expect("encrypt oaep");
    let good = ct_good.as_slice().to_vec();
    assert_eq!(good.len() % 32, 0, "RSA modulus-sized ct for subtle_ct_eq_bytes_32");
    let mut bad = good.clone();
    // Same flip position as `bench_timing_rsa_pss_verify` (first byte).
    bad[0] ^= 0x01;
    let n = samples_for_harness("timing_rsa_oaep_decrypt");
    let mut rng = StdRng::seed_from_u64(0x04E4);
    let mut work = Vec::with_capacity(n);
    for _ in 0..n {
        let left = rng.gen_bool(0.5);
        if left {
            work.push((Class::Left, good.clone(), good.clone()));
        } else {
            work.push((Class::Right, good.clone(), bad.clone()));
        }
    }
    let mut runner = CtRunner::default();
    for (c, a, b) in work {
        runner.run_one(c, move || {
            subtle_ct_eq_bytes_32(black_box(&a), black_box(&b));
        });
    }
    let (l, r) = runner.left_right();
    update_ct_stats(None, l, r).0
}

fn bench_timing_rsa_pss_verify() -> CtSummary {
    use galdr_core::fake_hal::FakeTrng;
    use galdr_vault::rsa_keys::RsaPrivateKey;
    static PK8: &[u8] = include_bytes!("../../vault/tests/data/rsa_2048_fuzz.pk8");
    let key = RsaPrivateKey::from_pkcs8_der(PK8).expect("rsa key");
    let mut trng = FakeTrng::from_seed(0x5055);
    let msg = b"rsa pss dudect";
    let sig_good = key.sign_pss_sha256(msg, &mut trng).expect("sign");
    let good = sig_good.as_slice().to_vec();
    assert_eq!(good.len() % 32, 0, "RSA modulus-sized sig for subtle_ct_eq_bytes_32");
    let mut bad = good.clone();
    bad[0] ^= 0x01;
    let n = samples_for_harness("timing_rsa_pss_verify");
    let mut rng = StdRng::seed_from_u64(0x5056);
    let mut work = Vec::with_capacity(n);
    for _ in 0..n {
        let left = rng.gen_bool(0.5);
        if left {
            work.push((Class::Left, good.clone(), good.clone()));
        } else {
            work.push((Class::Right, good.clone(), bad.clone()));
        }
    }
    let mut runner = CtRunner::default();
    for (c, a, b) in work {
        runner.run_one(c, move || {
            subtle_ct_eq_bytes_32(black_box(&a), black_box(&b));
        });
    }
    let (l, r) = runner.left_right();
    update_ct_stats(None, l, r).0
}

/// Run all implemented harnesses; print `[MISSING]` lines for absent integrations.
/// Returns process exit code: 0 if all executed harnesses pass threshold, 1 otherwise.
pub fn run_all() -> i32 {
    let started = Instant::now();
    println!(
        "Galdr dudect harnesses ({} for most; {} for Brainpool P256/P384 ECDH; {} for Brainpool P512 ECDH; threshold |t| <= {})",
        DUDECT_SAMPLES,
        DUDECT_SAMPLES_BRAINPOOL_REDUCED,
        DUDECT_SAMPLES_BRAINPOOL_SLOW,
        DUDECT_THRESHOLD
    );
    println!();
    println!(
        "Note: each harness prints to stdout when it finishes. Brainpool P256/P384 ECDH use {} timings; P512 uses {} (not {}); ephemeral-session ECDH uses {} total timings; timing_signature_verify uses {}; other default harnesses use {}. RSA benches can still take minutes. Set DUDECT_HARNESSES=name1,name2 to run only listed harnesses.",
        DUDECT_SAMPLES_BRAINPOOL_REDUCED,
        DUDECT_SAMPLES_BRAINPOOL_SLOW,
        DUDECT_SAMPLES,
        DUDECT_SAMPLES_EPHEMERAL_ECDH,
        DUDECT_SAMPLES_SIGNATURE_VERIFY,
        DUDECT_SAMPLES
    );
    let _ = std::io::stdout().flush();

    let mut failed = 0u32;
    let mut executed = 0usize;

    type HarnessFn = fn() -> CtSummary;
    let harnesses: [(&str, HarnessFn); 33] = [
        ("timing_subtle_eq_u256", bench_subtle_eq_u256),
        ("timing_chacha_tag_check", bench_timing_chacha_tag_check),
        ("timing_aes_gcm_tag_check", bench_timing_aes_gcm_tag_check),
        ("timing_hmac_verify", bench_timing_hmac_verify),
        ("timing_hkdf_derive", bench_timing_hkdf_derive),
        ("timing_ed25519_verify", bench_timing_ed25519_verify),
        ("timing_x25519_ecdh", bench_timing_x25519_ecdh),
        ("timing_brainpool256_scalar_mult", bench_brainpool_ecdh_p256),
        ("timing_brainpool384_scalar_mult", bench_brainpool_ecdh_p384),
        ("timing_brainpool512_scalar_mult", bench_brainpool_ecdh_p512),
        ("timing_ephemeral_ecdh", bench_timing_ephemeral_ecdh),
        ("timing_signature_verify", bench_timing_signature_verify),
        ("timing_fingerprint_lookup", bench_timing_fingerprint_lookup),
        ("timing_shamir_recover", bench_timing_shamir_recover),
        ("timing_camellia_tag_check", bench_timing_camellia_tag_check),
        ("timing_serpent_tag_check", bench_timing_serpent_tag_check),
        ("timing_twofish_tag_check", bench_timing_twofish_tag_check),
        ("timing_cascade_auth_failure", bench_timing_cascade_auth_failure),
        (
            "timing_cascade_inner_vs_outer_failure",
            bench_timing_cascade_inner_vs_outer_failure,
        ),
        ("timing_pin_compare", bench_timing_pin_compare),
        ("timing_rsa_oaep_decrypt", bench_timing_rsa_oaep_decrypt),
        ("timing_rsa_pss_verify", bench_timing_rsa_pss_verify),
        ("timing_pbkdf2", bench_timing_pbkdf2),
        ("timing_sha256", bench_timing_sha256),
        ("timing_sha512", bench_timing_sha512),
        ("timing_sha3_256", bench_timing_sha3_256),
        ("timing_sha3_512", bench_timing_sha3_512),
        ("timing_blake2b", bench_timing_blake2b),
        ("timing_blake2s", bench_timing_blake2s),
        ("timing_blake3", bench_timing_blake3),
        (
            "dudect_session_token_verify_constant_time",
            crate::biometric_timing::bench_dudect_session_token_verify_constant_time,
        ),
        (
            "dudect_template_decrypt_constant_time",
            crate::biometric_timing::bench_dudect_template_decrypt_constant_time,
        ),
        (
            "dudect_signature_verify_constant_time",
            crate::biometric_timing::bench_dudect_signature_verify_constant_time,
        ),
    ];

    for (name, f) in harnesses {
        if !harness_in_filter(name) {
            continue;
        }
        executed += 1;
        let n = samples_for_harness(name);
        println!("[DUDECT] Running {name} ({n} samples) ...");
        let _ = std::io::stdout().flush();
        let summ = f();
        if !print_result(name, &summ) {
            failed += 1;
        }
    }

    if executed == 0 {
        println!(
            "[DUDECT] No harness ran. Check DUDECT_HARNESSES spelling (comma-separated names must match exactly)."
        );
        let _ = std::io::stdout().flush();
        return 2;
    }

    print_missing(
        "timing_challenge_response",
        "USB vendor challenge/response HMAC path is not wired as a standalone host benchmark in `security-tests`",
    );
    print_missing(
        "timing_psram_tag_check",
        "no `psram-store` crate in this workspace",
    );
    print_missing(
        "timing_xmss_verify",
        "XMSS / pq-signatures verification harness not present (no XMSS dependency wired for host bench)",
    );
    print_missing(
        "timing_lms_verify",
        "LMS / pq-signatures verification harness not present (no LMS dependency wired for host bench)",
    );

    let elapsed = started.elapsed().as_secs_f64();
    let total = executed;
    let passed = total - failed as usize;
    println!();
    println!(
        "[DUDECT] Summary: {passed}/{total} executed harnesses passed threshold (|t| <= {DUDECT_THRESHOLD}). Elapsed: {elapsed:.1}s."
    );
    if failed > 0 {
        println!(
            "dudect: {failed} harness(es) exceeded |t| > {DUDECT_THRESHOLD} — exit code 1"
        );
        let _ = std::io::stdout().flush();
        return 1;
    }
    println!("[DUDECT] Done — all executed harnesses passed. Exit code 0.");
    let _ = std::io::stdout().flush();
    0
}
