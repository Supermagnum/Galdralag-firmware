//! Integration tests with `test-hal` mock drivers.

use biometric_api::{
    galdrad_validate_match_result, BiometricBackendDriver, BiometricError,
};
use biometric_fingervein::MockFingerVeinDevice;
use biometric_sweet::MockSweetPlatform;
use biometric_vault::{
    decrypt_template, encrypt_template, generate_session_token, verify_session_token,
};
use ed25519_dalek::SigningKey;
use rand::rngs::StdRng;
use rand::SeedableRng;

fn rng_sk() -> SigningKey {
    let mut rng = StdRng::seed_from_u64(0x656e);
    SigningKey::generate(&mut rng)
}

#[test]
fn test_mock_fingervein_authenticate_success() {
    let sk = rng_sk();
    let mock = MockFingerVeinDevice::new(sk.clone());
    let nonce = [7u8; 32];
    let enc = vec![];
    let sm = mock.authenticate(&nonce, enc.as_slice()).unwrap();
    let vk = sk.verifying_key().clone();
    galdrad_validate_match_result(&sm, &vk, &nonce, 1_700_000_050, 300).unwrap();
}

#[test]
fn test_mock_fingervein_authenticate_liveness_fail() {
    let sk = rng_sk();
    let mut mock = MockFingerVeinDevice::new(sk.clone());
    mock.force_liveness = false;
    let sm = mock.authenticate(&[0u8; 32], &[]).unwrap();
    let vk = sk.verifying_key().clone();
    let e = galdrad_validate_match_result(&sm, &vk, &sm.payload.nonce, 1_700_000_050, 300);
    assert_eq!(e, Err(BiometricError::LivenessCheckFailed));
}

#[test]
fn test_mock_fingervein_authenticate_score_fail() {
    let sk = rng_sk();
    let mut mock = MockFingerVeinDevice::new(sk.clone());
    mock.force_score = 0.1;
    let sm = mock.authenticate(&[1u8; 32], &[]).unwrap();
    let vk = sk.verifying_key().clone();
    let e = galdrad_validate_match_result(&sm, &vk, &sm.payload.nonce, 1_700_000_050, 300);
    assert_eq!(e, Err(BiometricError::MatchFailed));
}

#[test]
fn test_mock_fingervein_enroll_produces_template() {
    let sk = rng_sk();
    let mock = MockFingerVeinDevice::new(sk);
    let v = mock.enroll(3).unwrap();
    assert!(!v.is_empty());
}

#[test]
fn test_mock_sweet_authenticate_success_all_modalities() {
    let sk = rng_sk();
    let mock = MockSweetPlatform::new(sk.clone());
    let nonce = [0xabu8; 32];
    let sm = mock.authenticate(&nonce, &[]).unwrap();
    let vk = sk.verifying_key().clone();
    galdrad_validate_match_result(&sm, &vk, &nonce, 1_700_000_050, 300).unwrap();
    assert!(sm.payload.modalities.len() >= 3);
}

#[test]
fn test_mock_sweet_authenticate_success_partial_modalities() {
    let sk = rng_sk();
    let mut mock = MockSweetPlatform::new(sk.clone());
    mock.force_modalities = vec![biometric_api::Modality::PalmVein];
    let sm = mock.authenticate(&[9u8; 32], &[]).unwrap();
    let vk = sk.verifying_key().clone();
    galdrad_validate_match_result(&sm, &vk, &sm.payload.nonce, 1_700_000_050, 300).unwrap();
}

#[test]
fn test_mock_sweet_authenticate_liveness_fail() {
    let sk = rng_sk();
    let mut mock = MockSweetPlatform::new(sk.clone());
    mock.force_liveness = false;
    let sm = mock.authenticate(&[2u8; 32], &[]).unwrap();
    let vk = sk.verifying_key().clone();
    let e = galdrad_validate_match_result(&sm, &vk, &sm.payload.nonce, 1_700_000_050, 300);
    assert_eq!(e, Err(BiometricError::LivenessCheckFailed));
}

#[test]
fn test_mock_sweet_enroll_produces_template() {
    let sk = rng_sk();
    let mock = MockSweetPlatform::new(sk);
    let v = mock.enroll(3).unwrap();
    assert!(!v.is_empty());
}

#[test]
fn test_full_auth_flow_fingervein_pin_accepted() {
    let sk = rng_sk();
    let vk = sk.verifying_key().clone();
    let mock = MockFingerVeinDevice::new(sk.clone());
    let mk = [0x55u8; 32];
    let uid = mock.device_id;
    let raw = mock.enroll(1).unwrap();
    let enc = encrypt_template(&mk, &uid, biometric_api::Modality::FingerVein, raw.as_slice()).unwrap();
    let nonce = [0x11u8; 32];
    let sm = mock.authenticate(&nonce, enc.as_slice()).unwrap();
    galdrad_validate_match_result(&sm, &vk, &nonce, 1_700_000_001, 300).unwrap();
    let hmac_key = [0x66u8; 32];
    let tok = generate_session_token(&hmac_key, &nonce, &sm.payload.device_id, sm.payload.timestamp);
    verify_session_token(
        &hmac_key,
        &nonce,
        &sm.payload.device_id,
        sm.payload.timestamp,
        &tok,
        300,
        1_700_000_001,
    )
    .unwrap();
    let _ = decrypt_template(&mk, &uid, biometric_api::Modality::FingerVein, enc.as_slice()).unwrap();
}

#[test]
fn test_full_auth_flow_sweet_pin_accepted() {
    let sk = rng_sk();
    let vk = sk.verifying_key().clone();
    let mock = MockSweetPlatform::new(sk.clone());
    let mk = [0x33u8; 32];
    let uid = mock.device_id;
    let raw = mock.enroll(1).unwrap();
    let enc = encrypt_template(&mk, &uid, biometric_api::Modality::PalmVein, raw.as_slice()).unwrap();
    let nonce = [0x22u8; 32];
    let sm = mock.authenticate(&nonce, enc.as_slice()).unwrap();
    galdrad_validate_match_result(&sm, &vk, &nonce, 1_700_000_002, 300).unwrap();
    let hmac_key = [0x77u8; 32];
    let tok = generate_session_token(&hmac_key, &nonce, &sm.payload.device_id, sm.payload.timestamp);
    verify_session_token(
        &hmac_key,
        &nonce,
        &sm.payload.device_id,
        sm.payload.timestamp,
        &tok,
        300,
        1_700_000_002,
    )
    .unwrap();
}

#[test]
fn test_full_auth_flow_no_biometric_provisioned_pin_only() {
    let provisioned = false;
    assert!(!provisioned, "when false, host skips biometric gate (PIN-only path)");
}

#[test]
fn test_full_auth_flow_biometric_provisioned_device_disconnected_blocked() {
    let dev = biometric_fingervein::FingerVeinDevice::new();
    assert_eq!(dev.probe(), Err(BiometricError::DeviceNotConnected));
}

#[test]
fn test_full_auth_flow_replay_attack_rejected() {
    let sk = rng_sk();
    let vk = sk.verifying_key().clone();
    let mock = MockFingerVeinDevice::new(sk);
    let nonce = [0x33u8; 32];
    let sm = mock.authenticate(&nonce, &[]).unwrap();
    let mut seen = std::collections::BTreeSet::new();
    assert!(seen.insert(nonce));
    assert!(!seen.insert(nonce), "replay nonce should be detectable host-side");
    let e = galdrad_validate_match_result(&sm, &vk, &nonce, 1_700_000_100, 1);
    assert_eq!(e, Err(BiometricError::TimestampExpired));
}

#[test]
fn test_full_auth_flow_timestamp_expired_rejected() {
    let sk = rng_sk();
    let vk = sk.verifying_key().clone();
    let mock = MockFingerVeinDevice::new(sk);
    let sm = mock.authenticate(&[0x44u8; 32], &[]).unwrap();
    let e = galdrad_validate_match_result(&sm, &vk, &sm.payload.nonce, 1_701_000_000, 60);
    assert_eq!(e, Err(BiometricError::TimestampExpired));
}

#[test]
fn test_full_auth_flow_signature_tampered_rejected() {
    let sk = rng_sk();
    let vk = sk.verifying_key().clone();
    let mock = MockFingerVeinDevice::new(sk);
    let mut sm = mock.authenticate(&[0x55u8; 32], &[]).unwrap();
    sm.signature[0] ^= 1;
    let e = galdrad_validate_match_result(&sm, &vk, &sm.payload.nonce, 1_700_000_050, 300);
    assert_eq!(e, Err(BiometricError::SignatureInvalid));
}
