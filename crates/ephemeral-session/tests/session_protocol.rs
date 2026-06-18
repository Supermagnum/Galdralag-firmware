//! Integration tests for authenticated ephemeral ECDH (all Brainpool curves).

use ephemeral_session::{
    EphemeralSessionError, InitiatorSession, LongTermCert, ResponderSession, SessionCurve,
};
use galdr_core::fake_hal::{FakeTrng, FakeVaultStorage};
use galdr_vault::brainpool384::BrainpoolP384SigningKey;
use galdr_vault::brainpool512::BrainpoolP512SigningKey;
use galdr_vault::ecdsa_brainpool::BrainpoolSigningKey;
use galdr_vault::rsa_vault::KeySlot;
use galdr_vault::session_long_term_signing::{
    vault_store_session_long_term_signing_key, SessionLongTermSigningKey,
};
use subtle::ConstantTimeEq;

const VAULT_SIZE: usize = 0x120_000;

fn p256_cert(sk: &BrainpoolSigningKey) -> LongTermCert {
    let vk = sk.verifying_key();
    let sec1 = vk.to_sec1_uncompressed();
    let mut verifying_key = heapless::Vec::new();
    verifying_key.extend_from_slice(&sec1).expect("sec1");
    LongTermCert {
        fingerprint: LongTermCert::fingerprint_of(&sec1),
        curve: SessionCurve::BrainpoolP256r1,
        verifying_key,
    }
}

fn p384_cert(sk: &BrainpoolP384SigningKey) -> LongTermCert {
    let vk = sk.verifying_key();
    let sec1 = vk.to_sec1_uncompressed();
    let mut verifying_key = heapless::Vec::new();
    verifying_key.extend_from_slice(&sec1).expect("sec1");
    LongTermCert {
        fingerprint: LongTermCert::fingerprint_of(&sec1),
        curve: SessionCurve::BrainpoolP384r1,
        verifying_key,
    }
}

fn p512_cert(sk: &BrainpoolP512SigningKey) -> LongTermCert {
    let vk = sk.verifying_key();
    let sec1 = vk.to_sec1_uncompressed();
    let mut verifying_key = heapless::Vec::new();
    verifying_key.extend_from_slice(&sec1).expect("sec1");
    LongTermCert {
        fingerprint: LongTermCert::fingerprint_of(&sec1),
        curve: SessionCurve::BrainpoolP512r1,
        verifying_key,
    }
}

fn assert_keys_equal(a: &ephemeral_session::SessionKeys, b: &ephemeral_session::SessionKeys) {
    assert!(bool::from(
        a.payload_key_i2r
            .as_slice()
            .ct_eq(b.payload_key_i2r.as_slice())
    ));
    assert!(bool::from(
        a.payload_key_r2i
            .as_slice()
            .ct_eq(b.payload_key_r2i.as_slice())
    ));
    assert!(bool::from(
        a.gdss_mask_key.as_slice().ct_eq(b.gdss_mask_key.as_slice())
    ));
    assert!(bool::from(
        a.gdss_sync_key.as_slice().ct_eq(b.gdss_sync_key.as_slice())
    ));
    assert!(bool::from(
        a.gdss_timing_key
            .as_slice()
            .ct_eq(b.gdss_timing_key.as_slice())
    ));
    assert!(bool::from(a.mac_key.as_slice().ct_eq(b.mac_key.as_slice())));
}

fn full_handshake_p256() {
    let mut trng_i = FakeTrng::from_seed(0xA1);
    let mut trng_r = FakeTrng::from_seed(0xB1);
    let init_sk = BrainpoolSigningKey::generate(&mut trng_i).expect("init sk");
    let resp_sk = BrainpoolSigningKey::generate(&mut trng_r).expect("resp sk");
    let cert_i = p256_cert(&init_sk);
    let cert_r = p256_cert(&resp_sk);
    let mut storage = FakeVaultStorage::new(VAULT_SIZE);
    vault_store_session_long_term_signing_key(
        &mut storage,
        &KeySlot(0),
        &SessionLongTermSigningKey::P256(init_sk),
        true,
    )
    .expect("store");
    vault_store_session_long_term_signing_key(
        &mut storage,
        &KeySlot(1),
        &SessionLongTermSigningKey::P256(resp_sk),
        true,
    )
    .expect("store");
    let curve = SessionCurve::BrainpoolP256r1;
    let mut trng = FakeTrng::from_seed(0xC0);
    let mut initiator = InitiatorSession::new();
    let init_msg = initiator
        .init(curve, &KeySlot(0), &mut trng, &mut storage)
        .expect("init");
    let mut trng2 = FakeTrng::from_seed(0xD0);
    let (resp_msg, r_keys) =
        ResponderSession::respond(&init_msg, &KeySlot(1), &cert_i, &mut trng2, &mut storage)
            .expect("respond");
    let i_keys = initiator.complete(&resp_msg, &cert_r).expect("complete");
    assert_keys_equal(&i_keys, &r_keys);
}

#[test]
fn test_full_handshake_brainpool256r1() {
    full_handshake_p256();
}

#[test]
fn test_full_handshake_brainpool384r1() {
    let mut trng_i = FakeTrng::from_seed(0xA2);
    let mut trng_r = FakeTrng::from_seed(0xB2);
    let init_sk = BrainpoolP384SigningKey::generate(&mut trng_i).expect("init sk");
    let resp_sk = BrainpoolP384SigningKey::generate(&mut trng_r).expect("resp sk");
    let cert_i = p384_cert(&init_sk);
    let cert_r = p384_cert(&resp_sk);
    let mut storage = FakeVaultStorage::new(VAULT_SIZE);
    vault_store_session_long_term_signing_key(
        &mut storage,
        &KeySlot(0),
        &SessionLongTermSigningKey::P384(init_sk),
        true,
    )
    .expect("store");
    vault_store_session_long_term_signing_key(
        &mut storage,
        &KeySlot(1),
        &SessionLongTermSigningKey::P384(resp_sk),
        true,
    )
    .expect("store");
    let curve = SessionCurve::BrainpoolP384r1;
    let mut trng = FakeTrng::from_seed(0xC1);
    let mut initiator = InitiatorSession::new();
    let init_msg = initiator
        .init(curve, &KeySlot(0), &mut trng, &mut storage)
        .expect("init");
    let mut trng2 = FakeTrng::from_seed(0xD1);
    let (resp_msg, r_keys) =
        ResponderSession::respond(&init_msg, &KeySlot(1), &cert_i, &mut trng2, &mut storage)
            .expect("respond");
    let i_keys = initiator.complete(&resp_msg, &cert_r).expect("complete");
    assert_keys_equal(&i_keys, &r_keys);
}

#[test]
fn test_full_handshake_brainpool512r1() {
    let mut trng_i = FakeTrng::from_seed(0xA3);
    let mut trng_r = FakeTrng::from_seed(0xB3);
    let init_sk = BrainpoolP512SigningKey::generate(&mut trng_i).expect("init sk");
    let resp_sk = BrainpoolP512SigningKey::generate(&mut trng_r).expect("resp sk");
    let cert_i = p512_cert(&init_sk);
    let cert_r = p512_cert(&resp_sk);
    let mut storage = FakeVaultStorage::new(VAULT_SIZE);
    vault_store_session_long_term_signing_key(
        &mut storage,
        &KeySlot(0),
        &SessionLongTermSigningKey::P512(init_sk),
        true,
    )
    .expect("store");
    vault_store_session_long_term_signing_key(
        &mut storage,
        &KeySlot(1),
        &SessionLongTermSigningKey::P512(resp_sk),
        true,
    )
    .expect("store");
    let curve = SessionCurve::BrainpoolP512r1;
    let mut trng = FakeTrng::from_seed(0xC2);
    let mut initiator = InitiatorSession::new();
    let init_msg = initiator
        .init(curve, &KeySlot(0), &mut trng, &mut storage)
        .expect("init");
    let mut trng2 = FakeTrng::from_seed(0xD2);
    let (resp_msg, r_keys) =
        ResponderSession::respond(&init_msg, &KeySlot(1), &cert_i, &mut trng2, &mut storage)
            .expect("respond");
    let i_keys = initiator.complete(&resp_msg, &cert_r).expect("complete");
    assert_keys_equal(&i_keys, &r_keys);
}

#[test]
fn test_session_keys_differ_across_sessions() {
    let mut trng_i = FakeTrng::from_seed(0xE1);
    let mut trng_r = FakeTrng::from_seed(0xE2);
    let init_sk = BrainpoolSigningKey::generate(&mut trng_i).expect("init sk");
    let resp_sk = BrainpoolSigningKey::generate(&mut trng_r).expect("resp sk");
    let init_scalar = init_sk.to_scalar_bytes_for_test();
    let resp_scalar = resp_sk.to_scalar_bytes_for_test();
    let cert_i = p256_cert(&init_sk);
    let cert_r = p256_cert(&resp_sk);
    let run = |init_seed: u64, resp_seed: u64| {
        let mut storage = FakeVaultStorage::new(VAULT_SIZE);
        vault_store_session_long_term_signing_key(
            &mut storage,
            &KeySlot(0),
            &SessionLongTermSigningKey::P256(
                BrainpoolSigningKey::from_scalar_bytes_for_test(&init_scalar).expect("init"),
            ),
            true,
        )
        .expect("store");
        vault_store_session_long_term_signing_key(
            &mut storage,
            &KeySlot(1),
            &SessionLongTermSigningKey::P256(
                BrainpoolSigningKey::from_scalar_bytes_for_test(&resp_scalar).expect("resp"),
            ),
            true,
        )
        .expect("store");
        let mut trng = FakeTrng::from_seed(init_seed);
        let mut initiator = InitiatorSession::new();
        let init_msg = initiator
            .init(
                SessionCurve::BrainpoolP256r1,
                &KeySlot(0),
                &mut trng,
                &mut storage,
            )
            .expect("init");
        let mut trng2 = FakeTrng::from_seed(resp_seed);
        let (resp_msg, r_keys) =
            ResponderSession::respond(&init_msg, &KeySlot(1), &cert_i, &mut trng2, &mut storage)
                .expect("respond");
        let i_keys = initiator.complete(&resp_msg, &cert_r).expect("complete");
        (i_keys, r_keys)
    };
    let (k1a, k1b) = run(0xF0, 0xF1);
    let (k2a, k2b) = run(0xF2, 0xF3);
    assert_ne!(
        k1a.payload_key_i2r.as_ref(),
        k2a.payload_key_i2r.as_ref(),
        "keys should differ across sessions"
    );
    assert_ne!(k1b.payload_key_i2r.as_ref(), k2b.payload_key_i2r.as_ref());
}

#[test]
fn test_session_nonreusable() {
    let mut trng_i = FakeTrng::from_seed(0xA1);
    let mut trng_r = FakeTrng::from_seed(0xB1);
    let init_sk = BrainpoolSigningKey::generate(&mut trng_i).expect("init sk");
    let resp_sk = BrainpoolSigningKey::generate(&mut trng_r).expect("resp sk");
    let cert_i = p256_cert(&init_sk);
    let cert_r = p256_cert(&resp_sk);
    let mut storage = FakeVaultStorage::new(VAULT_SIZE);
    vault_store_session_long_term_signing_key(
        &mut storage,
        &KeySlot(0),
        &SessionLongTermSigningKey::P256(init_sk),
        true,
    )
    .expect("store");
    vault_store_session_long_term_signing_key(
        &mut storage,
        &KeySlot(1),
        &SessionLongTermSigningKey::P256(resp_sk),
        true,
    )
    .expect("store");
    let mut trng = FakeTrng::from_seed(0xC0);
    let mut initiator = InitiatorSession::new();
    let init_msg = initiator
        .init(
            SessionCurve::BrainpoolP256r1,
            &KeySlot(0),
            &mut trng,
            &mut storage,
        )
        .expect("init");
    let mut trng2 = FakeTrng::from_seed(0xD0);
    let (resp_msg, _) =
        ResponderSession::respond(&init_msg, &KeySlot(1), &cert_i, &mut trng2, &mut storage)
            .expect("respond");
    let _ = initiator.complete(&resp_msg, &cert_r).expect("complete");
    let r2 = initiator.complete(&resp_msg, &cert_r);
    assert!(matches!(
        r2,
        Err(EphemeralSessionError::SessionAlreadyCompleted)
    ));
}

#[test]
fn test_tampered_init_signature() {
    let mut trng_i = FakeTrng::from_seed(0xA1);
    let mut trng_r = FakeTrng::from_seed(0xB1);
    let init_sk = BrainpoolSigningKey::generate(&mut trng_i).expect("init sk");
    let resp_sk = BrainpoolSigningKey::generate(&mut trng_r).expect("resp sk");
    let cert_i = p256_cert(&init_sk);
    let mut storage = FakeVaultStorage::new(VAULT_SIZE);
    vault_store_session_long_term_signing_key(
        &mut storage,
        &KeySlot(0),
        &SessionLongTermSigningKey::P256(init_sk),
        true,
    )
    .expect("store");
    vault_store_session_long_term_signing_key(
        &mut storage,
        &KeySlot(1),
        &SessionLongTermSigningKey::P256(resp_sk),
        true,
    )
    .expect("store");
    let mut trng = FakeTrng::from_seed(0xC0);
    let mut initiator = InitiatorSession::new();
    let mut init_msg = initiator
        .init(
            SessionCurve::BrainpoolP256r1,
            &KeySlot(0),
            &mut trng,
            &mut storage,
        )
        .expect("init");
    if let Some(b) = init_msg.signature.get_mut(0) {
        *b ^= 0xFF;
    }
    let mut trng2 = FakeTrng::from_seed(0xD0);
    let r = ResponderSession::respond(&init_msg, &KeySlot(1), &cert_i, &mut trng2, &mut storage);
    assert!(matches!(
        r,
        Err(EphemeralSessionError::InvalidPeerSignature)
    ));
}

#[test]
fn test_wrong_long_term_key() {
    let mut trng_i = FakeTrng::from_seed(0xA1);
    let mut trng_r = FakeTrng::from_seed(0xB1);
    let init_sk = BrainpoolSigningKey::generate(&mut trng_i).expect("init sk");
    let resp_sk = BrainpoolSigningKey::generate(&mut trng_r).expect("resp sk");
    let other_sk = BrainpoolSigningKey::generate(&mut FakeTrng::from_seed(0x99)).expect("other");
    let wrong_cert = p256_cert(&other_sk);
    let mut storage = FakeVaultStorage::new(VAULT_SIZE);
    vault_store_session_long_term_signing_key(
        &mut storage,
        &KeySlot(0),
        &SessionLongTermSigningKey::P256(init_sk),
        true,
    )
    .expect("store");
    vault_store_session_long_term_signing_key(
        &mut storage,
        &KeySlot(1),
        &SessionLongTermSigningKey::P256(resp_sk),
        true,
    )
    .expect("store");
    let mut trng = FakeTrng::from_seed(0xC0);
    let mut initiator = InitiatorSession::new();
    let init_msg = initiator
        .init(
            SessionCurve::BrainpoolP256r1,
            &KeySlot(0),
            &mut trng,
            &mut storage,
        )
        .expect("init");
    let mut trng2 = FakeTrng::from_seed(0xD0);
    let r = ResponderSession::respond(
        &init_msg,
        &KeySlot(1),
        &wrong_cert,
        &mut trng2,
        &mut storage,
    );
    assert!(matches!(r, Err(EphemeralSessionError::FingerprintMismatch)));
}

#[test]
fn test_tampered_ephemeral_key() {
    let mut trng_i = FakeTrng::from_seed(0xA1);
    let mut trng_r = FakeTrng::from_seed(0xB1);
    let init_sk = BrainpoolSigningKey::generate(&mut trng_i).expect("init sk");
    let resp_sk = BrainpoolSigningKey::generate(&mut trng_r).expect("resp sk");
    let cert_i = p256_cert(&init_sk);
    let mut storage = FakeVaultStorage::new(VAULT_SIZE);
    vault_store_session_long_term_signing_key(
        &mut storage,
        &KeySlot(0),
        &SessionLongTermSigningKey::P256(init_sk),
        true,
    )
    .expect("store");
    vault_store_session_long_term_signing_key(
        &mut storage,
        &KeySlot(1),
        &SessionLongTermSigningKey::P256(resp_sk),
        true,
    )
    .expect("store");
    let mut trng = FakeTrng::from_seed(0xC0);
    let mut initiator = InitiatorSession::new();
    let mut init_msg = initiator
        .init(
            SessionCurve::BrainpoolP256r1,
            &KeySlot(0),
            &mut trng,
            &mut storage,
        )
        .expect("init");
    if let Some(b) = init_msg.ephemeral_public_key.get_mut(3) {
        *b ^= 0x01;
    }
    let mut trng2 = FakeTrng::from_seed(0xD0);
    let r = ResponderSession::respond(&init_msg, &KeySlot(1), &cert_i, &mut trng2, &mut storage);
    assert!(matches!(
        r,
        Err(EphemeralSessionError::InvalidPeerSignature)
    ));
}

#[test]
fn test_curve_mismatch() {
    let mut trng_i = FakeTrng::from_seed(0xA1);
    let mut trng_r = FakeTrng::from_seed(0xB1);
    let init_sk = BrainpoolSigningKey::generate(&mut trng_i).expect("init sk");
    let resp_sk = BrainpoolSigningKey::generate(&mut trng_r).expect("resp sk");
    let cert_i = p256_cert(&init_sk);
    let mut storage = FakeVaultStorage::new(VAULT_SIZE);
    vault_store_session_long_term_signing_key(
        &mut storage,
        &KeySlot(0),
        &SessionLongTermSigningKey::P256(init_sk),
        true,
    )
    .expect("store");
    vault_store_session_long_term_signing_key(
        &mut storage,
        &KeySlot(1),
        &SessionLongTermSigningKey::P256(resp_sk),
        true,
    )
    .expect("store");
    let mut trng = FakeTrng::from_seed(0xC0);
    let mut initiator = InitiatorSession::new();
    let mut init_msg = initiator
        .init(
            SessionCurve::BrainpoolP256r1,
            &KeySlot(0),
            &mut trng,
            &mut storage,
        )
        .expect("init");
    init_msg.curve = SessionCurve::BrainpoolP384r1;
    let mut trng2 = FakeTrng::from_seed(0xD0);
    let r = ResponderSession::respond(&init_msg, &KeySlot(1), &cert_i, &mut trng2, &mut storage);
    assert!(matches!(
        r,
        Err(EphemeralSessionError::InvalidPeerSignature)
    ));
}

#[test]
fn test_response_initiator_epk_binding() {
    let mut trng_i = FakeTrng::from_seed(0xA1);
    let mut trng_r = FakeTrng::from_seed(0xB1);
    let init_sk = BrainpoolSigningKey::generate(&mut trng_i).expect("init sk");
    let resp_sk = BrainpoolSigningKey::generate(&mut trng_r).expect("resp sk");
    let cert_i = p256_cert(&init_sk);
    let cert_r = p256_cert(&resp_sk);
    let mut storage = FakeVaultStorage::new(VAULT_SIZE);
    vault_store_session_long_term_signing_key(
        &mut storage,
        &KeySlot(0),
        &SessionLongTermSigningKey::P256(init_sk),
        true,
    )
    .expect("store");
    vault_store_session_long_term_signing_key(
        &mut storage,
        &KeySlot(1),
        &SessionLongTermSigningKey::P256(resp_sk),
        true,
    )
    .expect("store");
    let mut trng = FakeTrng::from_seed(0xC0);
    let mut initiator_a = InitiatorSession::new();
    let init_a = initiator_a
        .init(
            SessionCurve::BrainpoolP256r1,
            &KeySlot(0),
            &mut trng,
            &mut storage,
        )
        .expect("init");
    let mut trng2 = FakeTrng::from_seed(0xD0);
    let (resp_msg, _) =
        ResponderSession::respond(&init_a, &KeySlot(1), &cert_i, &mut trng2, &mut storage)
            .expect("respond");
    let mut trng3 = FakeTrng::from_seed(0xC0 + 1);
    let mut initiator_b = InitiatorSession::new();
    let _ = initiator_b
        .init(
            SessionCurve::BrainpoolP256r1,
            &KeySlot(0),
            &mut trng3,
            &mut storage,
        )
        .expect("init");
    let r = initiator_b.complete(&resp_msg, &cert_r);
    assert!(matches!(
        r,
        Err(EphemeralSessionError::InvalidPeerSignature)
    ));
}

#[test]
fn test_as_gdss_keys_lengths_and_distinct() {
    let mut trng_i = FakeTrng::from_seed(0xA1);
    let mut trng_r = FakeTrng::from_seed(0xB1);
    let init_sk = BrainpoolSigningKey::generate(&mut trng_i).expect("init sk");
    let resp_sk = BrainpoolSigningKey::generate(&mut trng_r).expect("resp sk");
    let cert_i = p256_cert(&init_sk);
    let cert_r = p256_cert(&resp_sk);
    let mut storage = FakeVaultStorage::new(VAULT_SIZE);
    vault_store_session_long_term_signing_key(
        &mut storage,
        &KeySlot(0),
        &SessionLongTermSigningKey::P256(init_sk),
        true,
    )
    .expect("store");
    vault_store_session_long_term_signing_key(
        &mut storage,
        &KeySlot(1),
        &SessionLongTermSigningKey::P256(resp_sk),
        true,
    )
    .expect("store");
    let mut trng = FakeTrng::from_seed(0xC0);
    let mut initiator = InitiatorSession::new();
    let init_msg = initiator
        .init(
            SessionCurve::BrainpoolP256r1,
            &KeySlot(0),
            &mut trng,
            &mut storage,
        )
        .expect("init");
    let mut trng2 = FakeTrng::from_seed(0xD0);
    let (resp_msg, keys) =
        ResponderSession::respond(&init_msg, &KeySlot(1), &cert_i, &mut trng2, &mut storage)
            .expect("respond");
    let _ = initiator.complete(&resp_msg, &cert_r).expect("complete");
    let (a, b, c, d) = keys.as_gdss_keys();
    assert_eq!(a.len(), 32);
    assert_eq!(b.len(), 32);
    assert_eq!(c.len(), 32);
    assert_eq!(d.len(), 32);
    assert_ne!(a, b);
    assert_ne!(a, c);
    assert_ne!(a, d);
    assert_ne!(b, c);
}
