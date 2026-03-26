//! Known-answer tests (subset) for Blake3, Serpent smoke, Shamir JSON presence.

use galdr_core::fake_hal::FakeTrng;
use serde_json::Value;
use vault::kdf_policy::KeyPurpose;
use vault::serpent_cipher::{serpent_decrypt, serpent_encrypt, SerpentKey, SerpentNonce};

#[test]
fn kat_blake3_empty_from_json() {
    let p = format!("{}/tests/blake3_vectors.json", env!("CARGO_MANIFEST_DIR"));
    let data = std::fs::read_to_string(&p).expect("read blake3_vectors.json");
    let v: Value = serde_json::from_str(&data).expect("parse");
    for vec in v["vectors"].as_array().expect("vectors") {
        let msg = hex::decode(vec["msg_hex"].as_str().unwrap_or("")).unwrap_or_default();
        let exp = hex::decode(vec["hash_hex"].as_str().expect("hash_hex")).expect("hex");
        let h = blake3::hash(&msg);
        assert_eq!(h.as_bytes().as_slice(), exp.as_slice());
    }
}

#[test]
fn kat_serpent_etm_roundtrip_smoke() {
    let sk = SerpentKey::derive(&[0x33u8; 32], KeyPurpose::SerpentStorage, b"kat").unwrap();
    let mut trng = FakeTrng::from_seed(1);
    let n = SerpentNonce::generate(&mut trng).unwrap();
    let ct = serpent_encrypt(&sk, &n, b"aad", b"pt").unwrap();
    let pt = serpent_decrypt(&sk, &n, b"aad", &ct).unwrap();
    assert_eq!(pt.as_slice(), b"pt");
}

#[test]
fn kat_shamir_json_smoke() {
    let data = include_str!("data/shamir_vectors.json");
    let root: Value = serde_json::from_str(data).expect("parse");
    assert!(!root["vectors"].as_array().unwrap().is_empty());
}
