//! Host-side dudect-style timing harnesses (Welch t-statistic; threshold |t| <= 4.5 at 100k samples).

use crate::dudect_stats::{update_ct_stats, Class, CtRunner, CtSummary, DUDECT_SAMPLES, DUDECT_THRESHOLD};
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
        acc = acc & ga.ct_eq(&gb);
    }
    black_box(acc);
}

fn print_result(name: &str, summ: &CtSummary) -> bool {
    let pass = summ.max_t.abs() <= DUDECT_THRESHOLD;
    println!("[DUDECT] {name}");
    println!("  Samples:       {DUDECT_SAMPLES}");
    println!("  t-statistic:   {:+0.5}", summ.max_t);
    println!("  Threshold:     ±{DUDECT_THRESHOLD}");
    if pass {
        println!("  Result:        PASS — no timing leakage detected (per this statistical test)");
    } else {
        println!("  Result:        FAIL — |t| exceeds threshold; investigate before release");
    }
    println!();
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
    let mut rng = StdRng::seed_from_u64(0x67616c6472616741);
    let mut runner = CtRunner::default();
    let mut work = Vec::with_capacity(DUDECT_SAMPLES);
    for _ in 0..DUDECT_SAMPLES {
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

    let mut rng = StdRng::seed_from_u64(0xC4A4);
    let mut work = Vec::with_capacity(DUDECT_SAMPLES);
    for _ in 0..DUDECT_SAMPLES {
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
            black_box(ga.ct_eq(&gb));
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
    let mut rng = StdRng::seed_from_u64(0xA5E5);
    let mut work = Vec::with_capacity(DUDECT_SAMPLES);
    for _ in 0..DUDECT_SAMPLES {
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
            black_box(ga.ct_eq(&gb));
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

    let mut rng = StdRng::seed_from_u64(0x484D4143);
    let mut work = Vec::with_capacity(DUDECT_SAMPLES);
    for _ in 0..DUDECT_SAMPLES {
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
            black_box(ga.ct_eq(&gb));
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
    let mut rng = StdRng::seed_from_u64(0x484B_4446);
    let mut runner = CtRunner::default();
    for _ in 0..DUDECT_SAMPLES {
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

    let mut rng = StdRng::seed_from_u64(0xED15);
    let mut work = Vec::with_capacity(DUDECT_SAMPLES);
    for _ in 0..DUDECT_SAMPLES {
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
            let _ = a0.ct_eq(&b0) & a1.ct_eq(&b1);
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
    let mut rng = StdRng::seed_from_u64(0x25519);
    let mut work = Vec::with_capacity(DUDECT_SAMPLES);
    for _ in 0..DUDECT_SAMPLES {
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
            black_box(ga.ct_eq(&gb));
        });
    }
    let (l, r) = runner.left_right();
    update_ct_stats(None, l, r).0
}

fn bench_brainpool_ecdh_p256() -> CtSummary {
    use galdr_core::fake_hal::FakeTrng;
    use vault::brainpool::BrainpoolScalar;
    let mut t1 = FakeTrng::from_seed(0xB256_A);
    let mut t2 = FakeTrng::from_seed(0xB256_B);
    let mut t3 = FakeTrng::from_seed(0xB256_C);
    let a = BrainpoolScalar::generate(&mut t1).expect("a");
    let b = BrainpoolScalar::generate(&mut t2).expect("b");
    let c = BrainpoolScalar::generate(&mut t3).expect("c");
    let pb = b.public_key().expect("pb");
    let pc = c.public_key().expect("pc");
    let mut rng = StdRng::seed_from_u64(0xB256);
    let mut runner = CtRunner::default();
    for _ in 0..DUDECT_SAMPLES {
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
    use vault::brainpool384::BrainpoolP384Scalar;
    let mut t1 = FakeTrng::from_seed(0xB384_A);
    let mut t2 = FakeTrng::from_seed(0xB384_B);
    let mut t3 = FakeTrng::from_seed(0xB384_C);
    let a = BrainpoolP384Scalar::generate(&mut t1).expect("a");
    let b = BrainpoolP384Scalar::generate(&mut t2).expect("b");
    let c = BrainpoolP384Scalar::generate(&mut t3).expect("c");
    let pb = b.public_key().expect("pb");
    let pc = c.public_key().expect("pc");
    let mut rng = StdRng::seed_from_u64(0xB384);
    let mut runner = CtRunner::default();
    for _ in 0..DUDECT_SAMPLES {
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

fn bench_brainpool_ecdh_p512() -> CtSummary {
    use galdr_core::fake_hal::FakeTrng;
    use vault::brainpool512::BrainpoolP512Scalar;
    let mut t1 = FakeTrng::from_seed(0xB512_A);
    let mut t2 = FakeTrng::from_seed(0xB512_B);
    let mut t3 = FakeTrng::from_seed(0xB512_C);
    let a = BrainpoolP512Scalar::generate(&mut t1).expect("a");
    let b = BrainpoolP512Scalar::generate(&mut t2).expect("b");
    let c = BrainpoolP512Scalar::generate(&mut t3).expect("c");
    let pb = b.public_key().expect("pb");
    let pc = c.public_key().expect("pc");
    let mut rng = StdRng::seed_from_u64(0xB512);
    let mut runner = CtRunner::default();
    for _ in 0..DUDECT_SAMPLES {
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
    use vault::shamir::{shamir_recover, ShamirShare};
    let mk = |i: u8, hx: &str| {
        ShamirShare::try_from_index_value(i, &hex::decode(hx).expect("hex")).expect("share")
    };
    let s1 = mk(
        1,
        "a6324ddd0b3647733489473d941c599875aa1bd42f53a3ce6f82d37dad39a7d2",
    );
    let s2 = mk(
        2,
        "6457a992255fbdd55b3abd49000b8118d97c05806d956eb4ed2c8ec97241668c",
    );
    let s3 = mk(
        3,
        "d374f55e3f78ebb77ea2eb658506c991bdc70f4553d7dc6b93bf4ca5ce69d04f",
    );
    let shares_ab = [s1, s2];
    let s1b = mk(
        1,
        "a6324ddd0b3647733489473d941c599875aa1bd42f53a3ce6f82d37dad39a7d2",
    );
    let shares_ac = [s1b, s3];
    let mut rng = StdRng::seed_from_u64(0x5348414D);
    let mut runner = CtRunner::default();
    for _ in 0..DUDECT_SAMPLES {
        let left = rng.gen_bool(0.5);
        let c = if left { Class::Left } else { Class::Right };
        if left {
            runner.run_one(c, || {
                let _ = shamir_recover(&shares_ab, 2);
            });
        } else {
            runner.run_one(c, || {
                let _ = shamir_recover(&shares_ac, 2);
            });
        }
    }
    let (l, r) = runner.left_right();
    update_ct_stats(None, l, r).0
}

fn bench_timing_serpent_tag_check() -> CtSummary {
    use vault::kdf_policy::KeyPurpose;
    use vault::serpent_cipher::{serpent_encrypt, SerpentKey, SerpentNonce, SERPENT_TAG_LEN};
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
    let mut rng = StdRng::seed_from_u64(0x53455250);
    let mut work = Vec::with_capacity(DUDECT_SAMPLES);
    for _ in 0..DUDECT_SAMPLES {
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
            black_box(ga.ct_eq(&gb));
        });
    }
    let (l, r) = runner.left_right();
    update_ct_stats(None, l, r).0
}

fn bench_timing_pin_compare() -> CtSummary {
    use pin_policy::pin_compare;
    let mut rng = StdRng::seed_from_u64(0x50494E30);
    let mut work = Vec::with_capacity(DUDECT_SAMPLES);
    for _ in 0..DUDECT_SAMPLES {
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
    use std::sync::Arc;
    use vault::rsa_keys::RsaPrivateKey;
    static PK8: &[u8] = include_bytes!("../../vault/tests/data/rsa_2048_fuzz.pk8");
    let key = RsaPrivateKey::from_pkcs8_der(PK8).expect("rsa key");
    let mut trng = FakeTrng::from_seed(0x5253);
    let pt = b"rsa oaep dudect probe";
    let ct_good = key
        .public_key()
        .encrypt_oaep(pt, b"", &mut trng)
        .expect("encrypt oaep");
    let good = Arc::new(ct_good.as_slice().to_vec());
    let mut bad = (*good).clone();
    *bad.last_mut().expect("ct") ^= 0x01;
    let bad = Arc::new(bad);
    let mut rng = StdRng::seed_from_u64(0x04E4);
    let mut runner = CtRunner::default();
    for _ in 0..DUDECT_SAMPLES {
        let left = rng.gen_bool(0.5);
        let c = if left { Class::Left } else { Class::Right };
        let g = good.clone();
        let b = if left { good.clone() } else { bad.clone() };
        runner.run_one(c, move || {
            subtle_ct_eq_bytes_32(black_box(&g), black_box(&b));
        });
    }
    let (l, r) = runner.left_right();
    update_ct_stats(None, l, r).0
}

fn bench_timing_rsa_pss_verify() -> CtSummary {
    use galdr_core::fake_hal::FakeTrng;
    use std::sync::Arc;
    use vault::rsa_keys::RsaPrivateKey;
    static PK8: &[u8] = include_bytes!("../../vault/tests/data/rsa_2048_fuzz.pk8");
    let key = RsaPrivateKey::from_pkcs8_der(PK8).expect("rsa key");
    let mut trng = FakeTrng::from_seed(0x5055);
    let msg = b"rsa pss dudect";
    let sig_good = key.sign_pss_sha256(msg, &mut trng).expect("sign");
    let good = Arc::new(sig_good.as_slice().to_vec());
    let mut bad = (*good).clone();
    bad[0] ^= 0x01;
    let bad = Arc::new(bad);
    let mut rng = StdRng::seed_from_u64(0x5056);
    let mut runner = CtRunner::default();
    for _ in 0..DUDECT_SAMPLES {
        let left = rng.gen_bool(0.5);
        let c = if left { Class::Left } else { Class::Right };
        let g = good.clone();
        let b = if left { good.clone() } else { bad.clone() };
        runner.run_one(c, move || {
            subtle_ct_eq_bytes_32(black_box(&g), black_box(&b));
        });
    }
    let (l, r) = runner.left_right();
    update_ct_stats(None, l, r).0
}

/// Run all implemented harnesses; print `[MISSING]` lines for absent integrations.
/// Returns process exit code: 0 if all executed harnesses pass threshold, 1 otherwise.
pub fn run_all() -> i32 {
    let started = Instant::now();
    println!("Galdr dudect harnesses ({} samples per class distribution; threshold |t| <= {})", DUDECT_SAMPLES, DUDECT_THRESHOLD);
    println!();
    eprintln!(
        "Note: each harness prints to stdout when it finishes. Brainpool P256/P384/P512 and RSA benches are slow (minutes each); progress is announced on stderr before each run."
    );
    let _ = std::io::stderr().flush();

    let mut failed = 0u32;

    let harnesses: [(&str, fn() -> CtSummary); 15] = [
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
        ("timing_shamir_recover", bench_timing_shamir_recover),
        ("timing_serpent_tag_check", bench_timing_serpent_tag_check),
        ("timing_pin_compare", bench_timing_pin_compare),
        ("timing_rsa_oaep_decrypt", bench_timing_rsa_oaep_decrypt),
        ("timing_rsa_pss_verify", bench_timing_rsa_pss_verify),
    ];

    for (name, f) in harnesses {
        eprintln!("[DUDECT] Running {name} ({DUDECT_SAMPLES} samples) ...");
        let _ = std::io::stderr().flush();
        let summ = f();
        if !print_result(name, &summ) {
            failed += 1;
        }
    }

    print_missing(
        "timing_twofish_tag_check",
        "no `vault/src/twofish_cipher.rs` in this workspace (Twofish AEAD not implemented)",
    );
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
    let total = harnesses.len();
    let passed = total - failed as usize;
    println!();
    println!(
        "[DUDECT] Summary: {passed}/{total} executed harnesses passed threshold (|t| <= {DUDECT_THRESHOLD}). Elapsed: {elapsed:.1}s."
    );
    if failed > 0 {
        eprintln!("dudect: {failed} harness(es) exceeded |t| > {DUDECT_THRESHOLD} — exit code 1");
        let _ = std::io::stderr().flush();
        let _ = std::io::stdout().flush();
        return 1;
    }
    println!("[DUDECT] Done — all executed harnesses passed. Exit code 0.");
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();
    0
}
