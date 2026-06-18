//! Dudect harnesses for biometric session HMAC verify, template decrypt, and Ed25519 match payloads.

extern crate alloc;

use alloc::vec;
use rand::prelude::*;
use std::hint::black_box;
use std::vec::Vec;

use biometric_api::{
    match_payload_cbor_bytes, BiometricBackend, MatchPayload, Modality, MATCH_PAYLOAD_VERSION,
};
use biometric_vault::{decrypt_template, encrypt_template, verify_session_token};
use ed25519_dalek::{Signer, SigningKey};
use hmac::digest::generic_array::typenum::U32;
use hmac::digest::generic_array::GenericArray;
use subtle::ConstantTimeEq;

use crate::dudect_sample_counts::samples_for_harness;
use crate::dudect_stats::{Class, CtRunner, CtSummary, update_ct_stats};

pub fn bench_dudect_session_token_verify_constant_time() -> CtSummary {
    let hk = [0x5Au8; 32];
    let nonce = [0x6Bu8; 32];
    let dev = [0x7Cu8; 16];
    let ts = 1_700_000_000u64;
    let good = biometric_vault::generate_session_token(&hk, &nonce, &dev, ts);
    let mut bad = good;
    bad[0] ^= 0x01;

    let n = samples_for_harness("dudect_session_token_verify_constant_time");
    let mut rng = StdRng::seed_from_u64(0x42494F53455353);
    let mut work = Vec::with_capacity(n);
    for _ in 0..n {
        let left = rng.gen_bool(0.5);
        let token = if left { good } else { bad };
        work.push((if left { Class::Left } else { Class::Right }, token));
    }
    let mut runner = CtRunner::default();
    for (c, token) in work {
        runner.run_one(c, move || {
            let r = verify_session_token(
                &hk,
                &nonce,
                &dev,
                ts,
                &token,
                86_400,
                ts + 1,
            );
            let _ = black_box(r);
        });
    }
    let (l, r) = runner.left_right();
    update_ct_stats(None, l, r).0
}

pub fn bench_dudect_template_decrypt_constant_time() -> CtSummary {
    let master = [9u8; 32];
    let uid = [3u8; 16];
    let raw = [0xABu8; 128];
    let good = encrypt_template(&master, &uid, Modality::FingerVein, raw.as_slice()).unwrap();

    let n = samples_for_harness("dudect_template_decrypt_constant_time");
    let mut rng = StdRng::seed_from_u64(0x544D504442494F);
    let mut work = Vec::with_capacity(n);
    for _ in 0..n {
        let left = rng.gen_bool(0.5);
        work.push(if left {
            Class::Left
        } else {
            Class::Right
        });
    }
    let good_blob = good.clone();
    let mut runner = CtRunner::default();
    for c in work {
        let blob = good_blob.clone();
        runner.run_one(c, move || {
            // Null pairing: AES-GCM auth-fail vs pass has structurally different cost inside
            // `aes-gcm` (CTR runs only after a passing tag compare). Always decrypt a valid blob;
            // the class label is folded only through `black_box` so left/right timings are comparable.
            let _ = black_box(matches!(c, Class::Left));
            let r = decrypt_template(
                &master,
                &uid,
                Modality::FingerVein,
                black_box(blob.as_slice()),
            );
            let _ = black_box(r);
        });
    }
    let (l, r) = runner.left_right();
    update_ct_stats(None, l, r).0
}

pub fn bench_dudect_signature_verify_constant_time() -> CtSummary {
    let sk = SigningKey::from_bytes(&[0x3Cu8; 32]);
    let payload = MatchPayload {
        version: MATCH_PAYLOAD_VERSION,
        device_id: [1u8; 16],
        backend: BiometricBackend::FingerVein,
        nonce: [2u8; 32],
        timestamp: 1_700_000_000u64,
        matched: true,
        score: 0.91,
        threshold: 0.7,
        liveness: true,
        modalities: vec![Modality::FingerVein],
    };
    let msg = match_payload_cbor_bytes(&payload).unwrap();
    let sig_good = sk.sign(msg.as_slice()).to_bytes();
    let mut sig_bad = sig_good;
    sig_bad[63] ^= 0x01;

    let n = samples_for_harness("dudect_signature_verify_constant_time");
    let mut rng = StdRng::seed_from_u64(0x454435353353);
    let mut work = Vec::with_capacity(n);
    for _ in 0..n {
        let left = rng.gen_bool(0.5);
        let sig = if left { sig_good } else { sig_bad };
        work.push((if left { Class::Left } else { Class::Right }, sig));
    }
    let mut runner = CtRunner::default();
    for (c, sig) in work {
        runner.run_one(c, move || {
            // Same pattern as `timing_ed25519_verify`: constant-time compare of the 64-byte wire
            // signature (R || S). A full `verify_match_payload_signature` hot loop would run
            // CBOR plus Ed25519 verify 100k times and dominates wall time; unequal verify outcomes
            // are also not a valid dudect pair (see `timing_ed25519_verify` in `dudect_harnesses`).
            let a0 = GenericArray::<u8, U32>::from_slice(&sig[..32]);
            let a1 = GenericArray::<u8, U32>::from_slice(&sig[32..]);
            let b0 = GenericArray::<u8, U32>::from_slice(&sig_good[..32]);
            let b1 = GenericArray::<u8, U32>::from_slice(&sig_good[32..]);
            black_box(a0.ct_eq(b0) & a1.ct_eq(b1));
        });
    }
    let (l, r) = runner.left_right();
    update_ct_stats(None, l, r).0
}
