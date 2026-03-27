//! Cascade encrypt/decrypt integration checks (built-in profiles).

use cipher_profile::{
    cascade_decrypt, cascade_encrypt, CipherProfileError, ProfileRegistry,
};
use subtle::ConstantTimeEq;

const BUILTIN_NAMES: &[&str] = &[
    "standard",
    "conservative",
    "conservative-shamir",
    "high-assurance",
];

fn tr<T, E: core::fmt::Debug>(r: Result<T, E>) -> T {
    match r {
        Ok(v) => v,
        Err(e) => panic!("{:?}", e),
    }
}

#[test]
fn cascade_roundtrip_all_builtins() {
    let prk = [0x31u8; 32];
    let aad = b"profile||fp||ts";
    let pt = [0x77u8; 64];
    let reg = ProfileRegistry::with_builtins();
    for name in BUILTIN_NAMES {
        let profile = tr(reg.get(name).ok_or("missing builtin"));
        let ct = tr(cascade_encrypt(profile, &prk, aad, &pt));
        let out = tr(cascade_decrypt(profile, &prk, aad, &ct));
        assert!(bool::from(out.as_bytes().ct_eq(pt.as_slice())));
    }
}

#[test]
fn cascade_aad_binding_conservative() {
    let prk = [0x32u8; 32];
    let reg = ProfileRegistry::with_builtins();
    let profile = tr(reg.get("conservative").ok_or("missing"));
    let pt = [0x01u8; 32];
    let ct = tr(cascade_encrypt(profile, &prk, b"context-a", &pt));
    let r = cascade_decrypt(profile, &prk, b"context-b", &ct);
    assert!(matches!(r, Err(CipherProfileError::AuthenticationFailed)));
}

#[test]
fn cascade_ciphertext_tamper_conservative() {
    let prk = [0x33u8; 32];
    let reg = ProfileRegistry::with_builtins();
    let profile = tr(reg.get("conservative").ok_or("missing"));
    let pt = [0x02u8; 48];
    let mut ct = tr(cascade_encrypt(profile, &prk, b"aad", &pt));
    let last = ct.ciphertext.len() - 1;
    ct.ciphertext[last] ^= 0x01;
    let r = cascade_decrypt(profile, &prk, b"aad", &ct);
    assert!(matches!(r, Err(CipherProfileError::AuthenticationFailed)));
}

#[test]
fn cascade_wrong_prk_conservative() {
    let prk_a = [0x44u8; 32];
    let prk_b = [0x55u8; 32];
    let reg = ProfileRegistry::with_builtins();
    let profile = tr(reg.get("conservative").ok_or("missing"));
    let pt = [0x03u8; 16];
    let ct = tr(cascade_encrypt(profile, &prk_a, b"aad", &pt));
    let r = cascade_decrypt(profile, &prk_b, b"aad", &ct);
    assert!(matches!(r, Err(CipherProfileError::AuthenticationFailed)));
}
