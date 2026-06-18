use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::StdRng;
use rand::SeedableRng;

use crate::{
    galdrad_validate_match_result, match_payload_cbor_bytes, sign_match_result,
    signed_match_from_bytes, signed_match_to_cbor, verify_match_payload_signature,
    BiometricBackend, BiometricError, MatchPayload, Modality, MATCH_PAYLOAD_VERSION,
};

fn sample_payload() -> MatchPayload {
    MatchPayload {
        version: MATCH_PAYLOAD_VERSION,
        device_id: [1u8; 16],
        backend: BiometricBackend::FingerVein,
        nonce: [2u8; 32],
        timestamp: 1_700_000_000,
        matched: true,
        score: 0.9,
        threshold: 0.7,
        liveness: true,
        modalities: alloc::vec![Modality::FingerVein],
    }
}

fn sample_keypair() -> (SigningKey, VerifyingKey) {
    let mut rng = StdRng::seed_from_u64(0x62696f);
    let sk = SigningKey::generate(&mut rng);
    let vk = sk.verifying_key().clone();
    (sk, vk)
}

fn other_keypair() -> (SigningKey, VerifyingKey) {
    let mut rng = StdRng::seed_from_u64(0x626974);
    let sk = SigningKey::generate(&mut rng);
    let vk = sk.verifying_key().clone();
    (sk, vk)
}

#[test]
fn test_cbor_serialise_match_payload_roundtrip() {
    let p = sample_payload();
    let b = match_payload_cbor_bytes(&p).unwrap();
    let q: MatchPayload = cbor4ii::serde::from_slice(&b).unwrap();
    assert_eq!(p, q);
}

#[test]
fn test_cbor_deserialise_rejects_wrong_version() {
    let mut p = sample_payload();
    p.version = 99;
    let b = match_payload_cbor_bytes(&p).unwrap();
    let q: MatchPayload = cbor4ii::serde::from_slice(&b).unwrap();
    assert_eq!(q.version, 99);
    let (sk, vk) = sample_keypair();
    let sm = sign_match_result(q, &sk).unwrap();
    assert_eq!(sm.payload.version, 99);
    let e = galdrad_validate_match_result(&sm, &vk, &sm.payload.nonce, 1_700_000_100, 300);
    assert_eq!(e, Err(BiometricError::CborError));
}

#[test]
fn test_cbor_deserialise_rejects_missing_fields() {
    let junk = [0xffu8, 0xff, 0x42];
    assert!(cbor4ii::serde::from_slice::<MatchPayload>(&junk).is_err());
}

#[test]
fn test_signature_verify_valid() {
    let (sk, vk) = sample_keypair();
    let p = sample_payload();
    let sm = sign_match_result(p, &sk).unwrap();
    verify_match_payload_signature(&sm.payload, &sm.signature, &vk).unwrap();
}

#[test]
fn test_signature_verify_rejects_tampered_payload() {
    let (sk, vk) = sample_keypair();
    let mut sm = sign_match_result(sample_payload(), &sk).unwrap();
    sm.payload.score = 0.1;
    let e = verify_match_payload_signature(&sm.payload, &sm.signature, &vk);
    assert_eq!(e, Err(BiometricError::SignatureInvalid));
}

#[test]
fn test_signature_verify_rejects_wrong_key() {
    let (sk, _) = sample_keypair();
    let (_, vk2) = other_keypair();
    let sm = sign_match_result(sample_payload(), &sk).unwrap();
    let e = verify_match_payload_signature(&sm.payload, &sm.signature, &vk2);
    assert_eq!(e, Err(BiometricError::SignatureInvalid));
}

#[test]
fn test_liveness_false_rejected_by_galdrad() {
    let (sk, vk) = sample_keypair();
    let mut p = sample_payload();
    p.liveness = false;
    let sm = sign_match_result(p, &sk).unwrap();
    let e =
        galdrad_validate_match_result(&sm, &vk, &sm.payload.nonce, sm.payload.timestamp + 1, 300);
    assert_eq!(e, Err(BiometricError::LivenessCheckFailed));
}

#[test]
fn test_score_below_threshold_rejected() {
    let (sk, vk) = sample_keypair();
    let mut p = sample_payload();
    p.score = 0.5;
    p.threshold = 0.7;
    let sm = sign_match_result(p, &sk).unwrap();
    let e =
        galdrad_validate_match_result(&sm, &vk, &sm.payload.nonce, sm.payload.timestamp + 1, 300);
    assert_eq!(e, Err(BiometricError::MatchFailed));
}

#[test]
fn test_nonce_mismatch_rejected() {
    let (sk, vk) = sample_keypair();
    let sm = sign_match_result(sample_payload(), &sk).unwrap();
    let mut wrong = [0u8; 32];
    wrong[0] = 0xab;
    let e = galdrad_validate_match_result(&sm, &vk, &wrong, sm.payload.timestamp + 1, 300);
    assert_eq!(e, Err(BiometricError::NonceMismatch));
}

#[test]
fn test_signed_match_cbor_round_trip() {
    let (sk, _) = sample_keypair();
    let sm = sign_match_result(sample_payload(), &sk).unwrap();
    let bytes = signed_match_to_cbor(&sm).unwrap();
    let sm2 = signed_match_from_bytes(bytes.as_slice()).unwrap();
    assert_eq!(sm.payload, sm2.payload);
    assert_eq!(sm.signature, sm2.signature);
}

#[test]
fn test_timestamp_expired_rejected() {
    let (sk, vk) = sample_keypair();
    let sm = sign_match_result(sample_payload(), &sk).unwrap();
    let e = galdrad_validate_match_result(&sm, &vk, &sm.payload.nonce, 1_701_000_000, 300);
    assert_eq!(e, Err(BiometricError::TimestampExpired));
}
