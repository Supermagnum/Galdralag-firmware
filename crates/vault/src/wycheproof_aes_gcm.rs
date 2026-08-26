//! Wycheproof JSON vectors for AES-GCM (`tests/data/wycheproof/aes_gcm_test.json`).
//!
//! **Skipped:** AES-192 keys (`aes-gcm` has no `Aes192Gcm` alias here), empty IV (invalid in GCM),
//! and 2056-bit (257-byte) IVs (no single `typenum` size in the `aes-gcm` API used below).

use aes_gcm::aead::array::Array;
use aes_gcm::aead::consts::{
    U1, U10, U12, U128, U15, U16, U2, U20, U256, U32, U4, U6, U64, U8,
};
use aes_gcm::aead::{Aead, Error as AeadError, KeyInit, Payload};
use aes_gcm::aes::{Aes128, Aes256};
use aes_gcm::{AesGcm, Key};

macro_rules! gcm_decrypt {
    ($aes:ty, $n:ty, $key:expr, $iv:expr, $payload:expr) => {{
        type Ag = AesGcm<$aes, $n>;
        let k = Key::<Ag>::from_slice($key);
        let c = Ag::new(k);
        c.decrypt(Array::from_slice($iv), $payload)
    }};
}

fn aes_gcm_decrypt(key: &[u8], iv: &[u8], payload: Payload<'_, '_>) -> Result<Vec<u8>, AeadError> {
    match (key.len(), iv.len()) {
        (16, 1) => gcm_decrypt!(Aes128, U1, key, iv, payload),
        (16, 2) => gcm_decrypt!(Aes128, U2, key, iv, payload),
        (16, 4) => gcm_decrypt!(Aes128, U4, key, iv, payload),
        (16, 6) => gcm_decrypt!(Aes128, U6, key, iv, payload),
        (16, 8) => gcm_decrypt!(Aes128, U8, key, iv, payload),
        (16, 10) => gcm_decrypt!(Aes128, U10, key, iv, payload),
        (16, 12) => gcm_decrypt!(Aes128, U12, key, iv, payload),
        (16, 15) => gcm_decrypt!(Aes128, U15, key, iv, payload),
        (16, 16) => gcm_decrypt!(Aes128, U16, key, iv, payload),
        (16, 20) => gcm_decrypt!(Aes128, U20, key, iv, payload),
        (16, 32) => gcm_decrypt!(Aes128, U32, key, iv, payload),
        (16, 64) => gcm_decrypt!(Aes128, U64, key, iv, payload),
        (16, 128) => gcm_decrypt!(Aes128, U128, key, iv, payload),
        (16, 256) => gcm_decrypt!(Aes128, U256, key, iv, payload),

        (32, 1) => gcm_decrypt!(Aes256, U1, key, iv, payload),
        (32, 2) => gcm_decrypt!(Aes256, U2, key, iv, payload),
        (32, 4) => gcm_decrypt!(Aes256, U4, key, iv, payload),
        (32, 6) => gcm_decrypt!(Aes256, U6, key, iv, payload),
        (32, 8) => gcm_decrypt!(Aes256, U8, key, iv, payload),
        (32, 10) => gcm_decrypt!(Aes256, U10, key, iv, payload),
        (32, 12) => gcm_decrypt!(Aes256, U12, key, iv, payload),
        (32, 15) => gcm_decrypt!(Aes256, U15, key, iv, payload),
        (32, 16) => gcm_decrypt!(Aes256, U16, key, iv, payload),
        (32, 20) => gcm_decrypt!(Aes256, U20, key, iv, payload),
        (32, 32) => gcm_decrypt!(Aes256, U32, key, iv, payload),
        (32, 64) => gcm_decrypt!(Aes256, U64, key, iv, payload),
        (32, 128) => gcm_decrypt!(Aes256, U128, key, iv, payload),
        (32, 256) => gcm_decrypt!(Aes256, U256, key, iv, payload),

        _ => Err(AeadError),
    }
}

#[test]
fn wycheproof_aes_gcm_json() {
    let data = include_str!("../tests/data/wycheproof/aes_gcm_test.json");
    let root: serde_json::Value = serde_json::from_str(data).expect("wycheproof AES-GCM JSON");
    let groups = root["testGroups"].as_array().expect("testGroups");
    for group in groups {
        if group["type"].as_str() != Some("AeadTest") {
            continue;
        }
        let _iv_size = group["ivSize"].as_u64().expect("ivSize");
        let key_size = group["keySize"].as_u64().expect("keySize");
        let tag_size = group["tagSize"].as_u64().expect("tagSize");
        if tag_size != 128 {
            continue;
        }
        if key_size == 192 {
            continue;
        }
        if key_size != 128 && key_size != 256 {
            continue;
        }

        let tests = group["tests"].as_array().expect("tests");
        for t in tests {
            let tc_id = t["tcId"].as_u64().expect("tcId");
            let key = hex::decode(t["key"].as_str().expect("key")).expect("key hex");
            let iv = hex::decode(t["iv"].as_str().expect("iv")).expect("iv hex");
            let aad = hex::decode(t["aad"].as_str().expect("aad")).expect("aad hex");
            let msg = hex::decode(t["msg"].as_str().expect("msg")).expect("msg hex");
            let ct = hex::decode(t["ct"].as_str().expect("ct")).expect("ct hex");
            let tag = hex::decode(t["tag"].as_str().expect("tag")).expect("tag hex");
            let result = t["result"].as_str().expect("result");

            if iv.is_empty() || iv.len() == 257 {
                continue;
            }

            let mut combined = ct;
            combined.extend_from_slice(&tag);
            let payload = Payload {
                msg: &combined,
                aad: &aad,
            };

            let r = aes_gcm_decrypt(&key, &iv, payload);

            match result {
                "valid" => {
                    let pt = r.unwrap_or_else(|e| panic!("tcId {tc_id} decrypt valid: {e:?}"));
                    assert_eq!(pt.as_slice(), msg.as_slice(), "tcId {tc_id} plaintext");
                }
                "invalid" => {
                    assert!(r.is_err(), "tcId {tc_id} must reject ciphertext");
                }
                other => panic!("tcId {tc_id} unknown result {other:?}"),
            }
        }
    }
}
