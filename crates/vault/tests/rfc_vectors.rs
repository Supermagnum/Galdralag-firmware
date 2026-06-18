//! RFC JSON vectors under `tests/rfc_vectors/` (loaded at test time).

use galdr_vault::brainpool::BrainpoolPublicKey;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ed25519_dalek::{Signer, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use hkdf::Hkdf;
use pbkdf2::pbkdf2_hmac;
use serde_json::Value;
use sha1::Sha1;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

fn rf(path: &str) -> String {
    let p = format!("{}/tests/rfc_vectors/{path}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {p}: {e}"))
}

#[test]
fn rfc5869_hkdf_sha256_appendix_a() {
    let v: Value = serde_json::from_str(&rf("rfc5869_hkdf_sha256.json")).expect("parse");
    for vec in v["vectors"].as_array().expect("vectors") {
        let ikm = hex::decode(vec["ikm"].as_str().expect("ikm")).expect("ikm hex");
        let salt = hex::decode(vec["salt"].as_str().expect("salt")).expect("salt hex");
        let info = hex::decode(vec["info"].as_str().expect("info")).expect("info hex");
        let n = vec["okm_len"].as_u64().expect("okm_len") as usize;
        let mut okm = vec![0u8; n];
        let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
        hk.expand(&info, &mut okm).expect("expand");
        let exp = hex::decode(vec["okm"].as_str().expect("okm")).expect("okm hex");
        assert_eq!(okm.as_slice(), exp.as_slice());
    }
}

#[test]
fn rfc7748_x25519_section_6_1() {
    let v: Value = serde_json::from_str(&rf("rfc7748_x25519.json")).expect("parse");
    for vec in v["vectors"].as_array().expect("vectors") {
        let a = hex::decode(vec["alice"].as_str().expect("alice")).expect("hex");
        let b = hex::decode(vec["bob"].as_str().expect("bob")).expect("hex");
        let sa = StaticSecret::from(<[u8; 32]>::try_from(a.as_slice()).unwrap());
        let sb = StaticSecret::from(<[u8; 32]>::try_from(b.as_slice()).unwrap());
        let sb_pub = PublicKey::from(&sb);
        let sa_pub = PublicKey::from(&sa);
        let xa = sa.diffie_hellman(&sb_pub);
        let xb = sb.diffie_hellman(&sa_pub);
        assert_eq!(xa.as_bytes(), xb.as_bytes());
    }
}

#[test]
fn rfc8032_ed25519_verify() {
    use ed25519_dalek::SigningKey;
    let v: Value = serde_json::from_str(&rf("rfc8032_ed25519.json")).expect("parse");
    for vec in v["vectors"].as_array().expect("vectors") {
        let sk_b = hex::decode(vec["secret_key"].as_str().expect("sk")).expect("hex");
        let pk = hex::decode(vec["public_key"].as_str().expect("pk")).expect("hex");
        let msg = hex::decode(vec["message"].as_str().unwrap_or("")).unwrap_or_default();
        let sk = SigningKey::from_bytes(&<[u8; 32]>::try_from(sk_b.as_slice()).unwrap());
        assert_eq!(sk.verifying_key().as_bytes().as_slice(), pk.as_slice());
        let sig = sk.sign(&msg);
        let vk = VerifyingKey::from_bytes(&<[u8; 32]>::try_from(pk.as_slice()).unwrap()).unwrap();
        assert!(vk.verify(&msg, &sig).is_ok());
    }
}

#[test]
fn rfc8018_pbkdf2_hmac_sha1() {
    let v: Value = serde_json::from_str(&rf("rfc8018_pbkdf2.json")).expect("parse");
    for vec in v["vectors"].as_array().expect("vectors") {
        let pw = hex::decode(vec["password"].as_str().expect("password")).expect("hex");
        let salt = hex::decode(vec["salt"].as_str().expect("salt")).expect("hex");
        let c = vec["c"].as_u64().expect("c") as u32;
        let dk_len = vec["dk_len"].as_u64().expect("dk_len") as usize;
        let mut dk = vec![0u8; dk_len];
        pbkdf2_hmac::<Sha1>(&pw, &salt, c, &mut dk);
        let exp = hex::decode(vec["dk"].as_str().expect("dk")).expect("hex");
        assert_eq!(dk.as_slice(), exp.as_slice());
    }
}

#[test]
fn rfc2104_hmac_sha1() {
    let v: Value = serde_json::from_str(&rf("rfc2104_hmac.json")).expect("parse");
    for vec in v["vectors"].as_array().expect("vectors") {
        let key = hex::decode(vec["key"].as_str().expect("key")).expect("hex");
        let data = hex::decode(vec["data"].as_str().expect("data")).expect("hex");
        let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(&key).expect("hmac");
        mac.update(&data);
        let out = mac.finalize().into_bytes();
        let exp = hex::decode(vec["hmac_sha1"].as_str().expect("hmac")).expect("hex");
        assert_eq!(out.as_slice(), exp.as_slice());
    }
}

#[test]
fn rfc5639_brainpool_p256_generator_sec1() {
    let v: Value = serde_json::from_str(&rf("rfc5639_brainpool_p256.json")).expect("parse");
    for vec in v["vectors"].as_array().expect("vectors") {
        let g = hex::decode(vec["g_sec1_hex"].as_str().expect("g_sec1_hex")).expect("hex");
        let pk = BrainpoolPublicKey::from_sec1(&g).expect("RFC 5639 G on curve");
        let _ = pk.to_sec1_uncompressed();
    }
}

#[test]
fn rfc8439_chacha20_poly1305_aead() {
    let v: Value = serde_json::from_str(&rf("rfc8439_chacha.json")).expect("parse");
    for vec in v["vectors"].as_array().expect("vectors") {
        let key_bytes = hex::decode(vec["key"].as_str().expect("key")).expect("hex");
        let key = Key::from_slice(&key_bytes);
        let nonce_bytes = hex::decode(vec["nonce"].as_str().expect("nonce")).expect("hex");
        let nonce = Nonce::from_slice(&nonce_bytes);
        let aad = hex::decode(vec["aad"].as_str().expect("aad")).expect("hex");
        let mut ct = hex::decode(vec["ciphertext_hex"].as_str().expect("ct")).expect("hex");
        let tag = hex::decode(vec["tag"].as_str().expect("tag")).expect("hex");
        ct.extend_from_slice(&tag);
        let cipher = ChaCha20Poly1305::new(key);
        let pt = cipher
            .decrypt(nonce, Payload { msg: &ct, aad: &aad })
            .expect("decrypt");
        let expected_pt = hex::decode(vec["plaintext_hex"].as_str().expect("pt")).expect("hex");
        assert_eq!(pt.as_slice(), expected_pt.as_slice());
    }
}
