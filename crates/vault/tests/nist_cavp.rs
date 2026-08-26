//! NIST CAVP-style vectors (subset) loaded from `tests/nist_cavp_vectors/`.

use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sha3::Sha3_256;

fn rf(path: &str) -> String {
    let p = format!(
        "{}/tests/nist_cavp_vectors/{path}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {p}: {e}"))
}

#[test]
fn nist_cavp_sha256_short_msg() {
    let v: Value = serde_json::from_str(&rf("sha256_short_msg.json")).expect("parse");
    for vec in v["vectors"].as_array().expect("vectors") {
        let msg = hex::decode(vec["msg_hex"].as_str().expect("msg_hex")).expect("hex");
        let exp = hex::decode(vec["digest_hex"].as_str().expect("digest_hex")).expect("hex");
        let mut h = Sha256::new();
        h.update(&msg);
        let out = h.finalize();
        assert_eq!(out.as_slice(), exp.as_slice());
    }
}

#[test]
fn nist_cavp_sha3_256_empty() {
    use sha3::Digest as Sha3Digest;
    let v: Value = serde_json::from_str(&rf("sha3_256_short.json")).expect("parse");
    for vec in v["vectors"].as_array().expect("vectors") {
        let msg = hex::decode(vec["msg_hex"].as_str().expect("msg_hex")).expect("hex");
        let exp = hex::decode(vec["digest_hex"].as_str().expect("digest_hex")).expect("hex");
        let mut h = Sha3_256::new();
        Sha3Digest::update(&mut h, &msg);
        let out = Sha3Digest::finalize(h);
        assert_eq!(out.as_slice(), exp.as_slice());
    }
}

#[test]
fn nist_cavp_hmac_sha256_short() {
    let v: Value = serde_json::from_str(&rf("hmac_sha256_short.json")).expect("parse");
    type HmacSha256 = Hmac<Sha256>;
    for vec in v["vectors"].as_array().expect("vectors") {
        let key = hex::decode(vec["key_hex"].as_str().expect("key_hex")).expect("hex");
        let msg = hex::decode(vec["msg_hex"].as_str().expect("msg_hex")).expect("hex");
        let exp = hex::decode(vec["hmac_hex"].as_str().expect("hmac_hex")).expect("hex");
        let mut mac = <HmacSha256 as hmac::digest::KeyInit>::new_from_slice(&key).expect("hmac key");
        mac.update(&msg);
        let out = mac.finalize().into_bytes();
        assert_eq!(out.as_slice(), exp.as_slice());
    }
}
