//! Known-answer tests for BLAKE3 (hash, keyed-hash, derive-key), Camellia, Serpent, Twofish smokes, Shamir JSON presence.

use galdr_core::fake_hal::FakeTrng;
use serde_json::Value;
use galdr_vault::camellia_cipher::{camellia_decrypt, camellia_encrypt, CamelliaKey, CamelliaNonce};
use galdr_vault::kdf_policy::KeyPurpose;
use galdr_vault::serpent_cipher::{serpent_decrypt, serpent_encrypt, SerpentKey, SerpentNonce};
use galdr_vault::twofish_cipher::{twofish_decrypt, twofish_encrypt, TwofishKey, TwofishNonce};

#[test]
fn kat_blake3_from_json() {
    let p = format!("{}/tests/blake3_vectors.json", env!("CARGO_MANIFEST_DIR"));
    let data = std::fs::read_to_string(&p).expect("read blake3_vectors.json");
    let v: Value = serde_json::from_str(&data).expect("parse");
    let key_str = v["official_key_ascii"]
        .as_str()
        .expect("official_key_ascii (32-byte keyed-hash test key)");
    assert_eq!(
        key_str.len(),
        32,
        "official keyed-hash key must be exactly 32 bytes"
    );
    let mut keyed = [0u8; 32];
    keyed.copy_from_slice(key_str.as_bytes());
    let context = v["official_context_string"]
        .as_str()
        .expect("official_context_string (derive_key context)");
    for (i, vec) in v["vectors"].as_array().expect("vectors").iter().enumerate() {
        let msg = hex::decode(vec["msg_hex"].as_str().unwrap_or("")).unwrap_or_default();
        let exp_hash = hex::decode(vec["hash_hex"].as_str().expect("hash_hex")).expect("hex");
        let h = blake3::hash(&msg);
        assert_eq!(h.as_bytes(), exp_hash.as_slice(), "hash row {i}");
        let exp_kh =
            hex::decode(vec["keyed_hash_hex"].as_str().expect("keyed_hash_hex")).expect("hex");
        let kh = blake3::keyed_hash(&keyed, &msg);
        assert_eq!(kh.as_bytes(), exp_kh.as_slice(), "keyed_hash row {i}");
        let exp_dk =
            hex::decode(vec["derive_key_hex"].as_str().expect("derive_key_hex")).expect("hex");
        let dk = blake3::derive_key(context, &msg);
        assert_eq!(dk.as_slice(), exp_dk.as_slice(), "derive_key row {i}");
    }
}

#[test]
fn kat_camellia_etm_roundtrip_smoke() {
    let sk = CamelliaKey::derive(&[0x33u8; 32], KeyPurpose::CamelliaStorage, b"kat").unwrap();
    let mut trng = FakeTrng::from_seed(3);
    let n = CamelliaNonce::generate(&mut trng).unwrap();
    let ct = camellia_encrypt(&sk, &n, b"aad", b"pt").unwrap();
    let pt = camellia_decrypt(&sk, &n, b"aad", &ct).unwrap();
    assert_eq!(pt.as_slice(), b"pt");
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
fn kat_twofish_etm_roundtrip_smoke() {
    let sk = TwofishKey::derive(&[0x33u8; 32], KeyPurpose::TwofishStorage, b"kat").unwrap();
    let mut trng = FakeTrng::from_seed(2);
    let n = TwofishNonce::generate(&mut trng).unwrap();
    let ct = twofish_encrypt(&sk, &n, b"aad", b"pt").unwrap();
    let pt = twofish_decrypt(&sk, &n, b"aad", &ct).unwrap();
    assert_eq!(pt.as_slice(), b"pt");
}

#[test]
fn kat_shamir_json_smoke() {
    let data = include_str!("data/shamir_vectors.json");
    let root: Value = serde_json::from_str(data).expect("parse");
    assert!(!root["vectors"].as_array().unwrap().is_empty());
}
