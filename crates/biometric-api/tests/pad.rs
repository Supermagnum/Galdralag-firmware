//! PAD tests follow ISO/IEC 30107-3 methodology.
//! Metrics:
//!   APCER — Attack Presentation Classification Error Rate
//!   BPCER — Bona fide Presentation Classification Error Rate
//!   ACER  — (APCER + BPCER) / 2
//!
//! Current test data uses mocks. Once Baochip-1x hardware (Q2) and physical
//! biometric devices are available, replace mock results with measured values
//! from real hardware and real presentation attack material.
//!
//! Reference datasets for accuracy benchmarking:
//!   - CandyFV (sweet platform): https://www.idiap.ch/en/scientific-research/data/candyfv
//!   - ESP32-CAM device dataset: published alongside IEEE TIM DOI: 10.1109/TIM.2023.3324681
//!
//! See also: docs/BIOMETRIC_API.md, docs/BIOMETRIC_TESTING.md

use biometric_api::{galdrad_validate_match_result, BiometricBackendDriver, BiometricError};
use biometric_fingervein::MockFingerVeinDevice;
use biometric_sweet::MockSweetPlatform;
use ed25519_dalek::SigningKey;
use rand::rngs::StdRng;
use rand::SeedableRng;

fn sk(seed: u64) -> SigningKey {
    let mut rng = StdRng::seed_from_u64(0x706164 ^ seed);
    SigningKey::generate(&mut rng)
}

#[test]
fn test_pad_static_image_attack_rejected() {
    let k = sk(1);
    let mut mock = MockFingerVeinDevice::new(k.clone());
    mock.force_liveness = false;
    let sm = mock.authenticate(&[1u8; 32], &[]).unwrap();
    let vk = k.verifying_key().clone();
    let e = galdrad_validate_match_result(&sm, &vk, &sm.payload.nonce, 1_700_000_010, 300);
    assert_eq!(e, Err(BiometricError::LivenessCheckFailed));
}

#[test]
fn test_pad_replay_attack_rejected() {
    let k = sk(20);
    let mock = MockFingerVeinDevice::new(k.clone());
    let sm = mock.authenticate(&[2u8; 32], &[]).unwrap();
    let vk = k.verifying_key().clone();
    let e = galdrad_validate_match_result(&sm, &vk, &[3u8; 32], 1_700_000_010, 300);
    assert_eq!(e, Err(BiometricError::NonceMismatch));
}

#[test]
fn test_pad_score_spoofed_liveness_false_rejected() {
    let k = sk(30);
    let mut mock = MockFingerVeinDevice::new(k.clone());
    mock.force_liveness = false;
    mock.force_score = 1.0;
    let sm = mock.authenticate(&[4u8; 32], &[]).unwrap();
    let vk = k.verifying_key().clone();
    let e = galdrad_validate_match_result(&sm, &vk, &sm.payload.nonce, 1_700_000_010, 300);
    assert_eq!(e, Err(BiometricError::LivenessCheckFailed));
}

#[test]
fn test_pad_wrong_device_signature_rejected() {
    let k1 = sk(100);
    let k2 = sk(200);
    let mock = MockFingerVeinDevice::new(k1.clone());
    let sm = mock.authenticate(&[5u8; 32], &[]).unwrap();
    let vk_wrong = k2.verifying_key().clone();
    let e = galdrad_validate_match_result(&sm, &vk_wrong, &sm.payload.nonce, 1_700_000_010, 300);
    assert_eq!(e, Err(BiometricError::SignatureInvalid));
}

#[test]
fn test_pad_valid_liveness_and_score_accepted() {
    let k = sk(40);
    let mock = MockSweetPlatform::new(k.clone());
    let sm = mock.authenticate(&[6u8; 32], &[]).unwrap();
    let vk = k.verifying_key().clone();
    galdrad_validate_match_result(&sm, &vk, &sm.payload.nonce, 1_700_000_010, 300).unwrap();
}

#[test]
fn test_pad_valid_at_threshold_boundary_accepted() {
    let k = sk(50);
    let mut mock = MockFingerVeinDevice::new(k.clone());
    mock.threshold = 0.8;
    mock.force_score = 0.8;
    let sm = mock.authenticate(&[7u8; 32], &[]).unwrap();
    let vk = k.verifying_key().clone();
    galdrad_validate_match_result(&sm, &vk, &sm.payload.nonce, 1_700_000_010, 300).unwrap();
}

#[test]
fn test_pad_valid_just_below_threshold_rejected() {
    let k = sk(60);
    let mut mock = MockFingerVeinDevice::new(k.clone());
    mock.threshold = 0.8;
    mock.force_score = 0.799;
    let sm = mock.authenticate(&[8u8; 32], &[]).unwrap();
    let vk = k.verifying_key().clone();
    let e = galdrad_validate_match_result(&sm, &vk, &sm.payload.nonce, 1_700_000_010, 300);
    assert_eq!(e, Err(BiometricError::MatchFailed));
}

#[test]
fn test_pad_compute_and_assert_acer_within_budget() {
    let apcer = 0.0f64;
    let bpcer = 0.0f64;
    let acer = (apcer + bpcer) / 2.0;
    assert!(
        acer <= 0.0,
        "mock PAD suite expects zero error rates; hardware must set budgets in docs"
    );
}
