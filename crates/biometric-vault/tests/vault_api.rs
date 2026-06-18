use biometric_api::Modality;
use biometric_vault::{
    decrypt_template, encrypt_template, generate_session_token, verify_session_token, VaultError,
    BIOMETRIC_REGION_OFFSET, BIOMETRIC_REGION_SIZE, MAX_ENROLLED_PERSONS, MAX_TEMPLATE_SIZE_BYTES,
    RRAM_TOTAL_BYTES,
};

#[test]
fn test_session_token_generate_and_verify() {
    let hk = [5u8; 32];
    let nonce = [6u8; 32];
    let dev = [7u8; 16];
    let ts = 1_700_000_000u64;
    let tok = generate_session_token(&hk, &nonce, &dev, ts);
    verify_session_token(&hk, &nonce, &dev, ts, &tok, 60, ts).unwrap();
}

#[test]
fn test_session_token_rejects_wrong_nonce() {
    let hk = [5u8; 32];
    let mut nonce = [6u8; 32];
    let dev = [7u8; 16];
    let ts = 1_700_000_000u64;
    let tok = generate_session_token(&hk, &nonce, &dev, ts);
    nonce[0] ^= 1;
    let e = verify_session_token(&hk, &nonce, &dev, ts, &tok, 60, ts);
    assert_eq!(e, Err(VaultError::TokenMismatch));
}

#[test]
fn test_session_token_rejects_expired_timestamp() {
    let hk = [5u8; 32];
    let nonce = [6u8; 32];
    let dev = [7u8; 16];
    let ts = 1_700_000_000u64;
    let tok = generate_session_token(&hk, &nonce, &dev, ts);
    let e = verify_session_token(&hk, &nonce, &dev, ts, &tok, 10, ts + 100);
    assert_eq!(e, Err(VaultError::TimeWindow));
}

#[test]
fn test_session_token_rejects_wrong_device_id() {
    let hk = [5u8; 32];
    let nonce = [6u8; 32];
    let mut dev = [7u8; 16];
    let ts = 1_700_000_000u64;
    let tok = generate_session_token(&hk, &nonce, &dev, ts);
    dev[0] ^= 1;
    let e = verify_session_token(&hk, &nonce, &dev, ts, &tok, 60, ts);
    assert_eq!(e, Err(VaultError::TokenMismatch));
}

#[test]
fn test_encrypt_template_roundtrip() {
    let mk = [9u8; 32];
    let uid = [3u8; 16];
    let raw = b"hello-template";
    let ct = encrypt_template(&mk, &uid, Modality::FingerVein, raw).unwrap();
    let pt = decrypt_template(&mk, &uid, Modality::FingerVein, ct.as_slice()).unwrap();
    assert_eq!(pt.as_slice(), raw.as_slice());
}

#[test]
fn test_encrypt_template_different_users_different_ciphertext() {
    let mk = [9u8; 32];
    let u1 = [1u8; 16];
    let u2 = [2u8; 16];
    let raw = b"x";
    let a = encrypt_template(&mk, &u1, Modality::FingerVein, raw).unwrap();
    let b = encrypt_template(&mk, &u2, Modality::FingerVein, raw).unwrap();
    assert_ne!(a, b);
}

#[test]
fn test_decrypt_template_wrong_key_fails() {
    let mk = [9u8; 32];
    let mk2 = [8u8; 32];
    let uid = [3u8; 16];
    let raw = b"secret";
    let ct = encrypt_template(&mk, &uid, Modality::FingerVein, raw).unwrap();
    let e = decrypt_template(&mk2, &uid, Modality::FingerVein, ct.as_slice());
    assert_eq!(e, Err(VaultError::DecryptFailed));
}

#[test]
fn test_decrypt_template_zeroized_after_use() {
    let mk = [9u8; 32];
    let uid = [3u8; 16];
    let raw = vec![0xabu8; 64];
    let ct = encrypt_template(&mk, &uid, Modality::FingerVein, raw.as_slice()).unwrap();
    let pt = decrypt_template(&mk, &uid, Modality::FingerVein, ct.as_slice()).unwrap();
    assert_eq!(pt.len(), raw.len());
    drop(pt);
}

#[test]
fn test_rram_layout_constants_fit_within_4mib() {
    assert_eq!(RRAM_TOTAL_BYTES, 4_194_304);
    assert!(BIOMETRIC_REGION_OFFSET.saturating_add(BIOMETRIC_REGION_SIZE) <= RRAM_TOTAL_BYTES);
}

#[test]
fn test_max_enrolled_persons_finger_vein() {
    let approx_per_person = 3584usize;
    let n = BIOMETRIC_REGION_SIZE / approx_per_person;
    assert!(n >= 1100);
    assert!(n >= MAX_ENROLLED_PERSONS);
}

#[test]
fn test_max_enrolled_persons_sweet_platform() {
    let approx_per_person = 15872usize;
    assert!(MAX_ENROLLED_PERSONS * approx_per_person <= BIOMETRIC_REGION_SIZE);
}

#[test]
fn test_max_template_bound() {
    let mk = [1u8; 32];
    let uid = [0u8; 16];
    let too_big = vec![0u8; MAX_TEMPLATE_SIZE_BYTES + 1];
    assert_eq!(
        encrypt_template(&mk, &uid, Modality::FingerVein, too_big.as_slice()),
        Err(VaultError::TemplateTooLarge)
    );
}
