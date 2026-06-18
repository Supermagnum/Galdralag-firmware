//! Cascade encrypt/decrypt integration checks (built-in profiles).

use cipher_profile::{
    cascade_decrypt, cascade_encrypt, layer_key_info, layer_nonce_info, CipherLayer,
    CipherProfile, CipherProfileBuilder, CipherProfileError, ProfileRegistry,
};
use ephemeral_session::SessionCurve;
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

/// P(4, 2): ordered distinct two-layer stacks (inner first, outer second).
fn two_layer_ordered_cipher_pairs() -> Vec<(CipherLayer, CipherLayer)> {
    const L: [CipherLayer; 4] = [
        CipherLayer::Aes256Gcm,
        CipherLayer::ChaCha20Poly1305,
        CipherLayer::Twofish256,
        CipherLayer::Serpent256,
    ];
    let mut out = Vec::with_capacity(12);
    for inner in L {
        for outer in L {
            if inner != outer {
                out.push((inner, outer));
            }
        }
    }
    assert_eq!(out.len(), 12, "P(4,2) ordered cipher pairs");
    out
}

/// HKDF-SHA256 `info` bytes for each layer in **encrypt** order (inner first: index 0, 1, ...).
fn hkdf_infos_encrypt_order(profile: &CipherProfile) -> Vec<(Vec<u8>, Vec<u8>)> {
    let name = profile.name();
    let layers = profile.layers();
    let mut out = Vec::with_capacity(layers.len());
    for (i, layer) in layers.iter().enumerate() {
        let k = tr(layer_key_info(name, *layer, i as u8));
        let n = tr(layer_nonce_info(name, *layer, i as u8));
        out.push((k.to_vec(), n.to_vec()));
    }
    out
}

/// HKDF-SHA256 `info` bytes in the **order the decrypt loop processes** layers (outer first).
fn hkdf_infos_decrypt_walk_order(profile: &CipherProfile) -> Vec<(Vec<u8>, Vec<u8>)> {
    let name = profile.name();
    let layers = profile.layers();
    let n = layers.len();
    let mut out = Vec::with_capacity(n);
    for idx in (0..n).rev() {
        let layer = layers[idx];
        let k = tr(layer_key_info(name, layer, idx as u8));
        let nn = tr(layer_nonce_info(name, layer, idx as u8));
        out.push((k.to_vec(), nn.to_vec()));
    }
    out
}

#[test]
fn cascade_hkdf_info_symmetric_encrypt_vs_decrypt_per_layer() {
    let reg = ProfileRegistry::with_builtins();
    for profile_name in BUILTIN_NAMES {
        let profile = tr(reg.get(profile_name).ok_or("missing builtin"));
        let enc = hkdf_infos_encrypt_order(profile);
        let dec_walk = hkdf_infos_decrypt_walk_order(profile);
        assert_eq!(
            enc.len(),
            dec_walk.len(),
            "profile {profile_name}"
        );
        let n = enc.len();
        for i in 0..n {
            assert_eq!(
                enc[i].0,
                dec_walk[n - 1 - i].0,
                "HKDF key info must match for layer index {i} (profile {profile_name})"
            );
            assert_eq!(
                enc[i].1,
                dec_walk[n - 1 - i].1,
                "HKDF nonce info must match for layer index {i} (profile {profile_name})"
            );
        }
        let prk = [0x5Du8; 32];
        let aad = b"hkdf-info-symmetry";
        let pt = [0x6Eu8; 48];
        let ct = tr(cascade_encrypt(profile, &prk, aad, &pt));
        let out = tr(cascade_decrypt(profile, &prk, aad, &ct));
        assert!(
            bool::from(out.as_bytes().ct_eq(pt.as_slice())),
            "round-trip after info check (profile {profile_name})"
        );
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
    // Twelve ordered two-layer stacks (HKDF-SHA256 PRK path; no CESS suite_id): composition only.
    for (idx, (inner, outer)) in two_layer_ordered_cipher_pairs().into_iter().enumerate() {
        let pname = format!("two-{:02}", idx + 1);
        let b = tr(CipherProfileBuilder::new(pname.as_str()));
        let b = b.curve(SessionCurve::BrainpoolP256r1);
        let b = tr(b.layer(inner));
        let b = tr(b.layer(outer));
        let profile = tr(b.build());
        let ct = tr(cascade_encrypt(&profile, &prk, aad, &pt));
        let out = tr(cascade_decrypt(&profile, &prk, aad, &ct));
        assert!(
            bool::from(out.as_bytes().ct_eq(pt.as_slice())),
            "round-trip two-layer pair {idx} {pname} inner={inner:?} outer={outer:?}"
        );
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
fn cascade_corrupted_mid_ciphertext_conservative_fails() {
    let prk = [0xEFu8; 32];
    let reg = ProfileRegistry::with_builtins();
    let profile = tr(reg.get("conservative").ok_or("missing"));
    let pt = [0x77u8; 32];
    let mut ct = tr(cascade_encrypt(profile, &prk, b"aad", &pt));
    let mid = ct.ciphertext.len() / 2;
    ct.ciphertext[mid] ^= 0x5A;
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
