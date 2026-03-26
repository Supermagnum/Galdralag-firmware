//! ChaCha20-Poly1305 vectors in Wycheproof-style JSON (see `tests/data/wycheproof_chacha20_poly1305_test.json`).

use crate::chacha_aead::{
    chacha_decrypt, chacha_encrypt, ChaChaCiphertext, ChaChaError, ChaChaKey, ChaChaNonce,
    MAX_CHACHA_CIPHERTEXT,
};

#[test]
fn wycheproof_chacha20_poly1305_json() {
    let data = include_str!("../tests/data/wycheproof_chacha20_poly1305_test.json");
    let root: serde_json::Value =
        serde_json::from_str(data).expect("wycheproof JSON must parse");
    let groups = root["testGroups"]
        .as_array()
        .expect("testGroups array");
    for group in groups {
        let tests = group["tests"].as_array().expect("tests array");
        for t in tests {
            let tc = t["tcId"].as_u64().expect("tcId");
            let key = hex::decode(t["key"].as_str().expect("key"))
                .unwrap_or_else(|e| panic!("tcId {} key hex: {}", tc, e));
            let iv = hex::decode(t["iv"].as_str().expect("iv"))
                .unwrap_or_else(|e| panic!("tcId {} iv hex: {}", tc, e));
            let aad = hex::decode(t["aad"].as_str().expect("aad"))
                .unwrap_or_else(|e| panic!("tcId {} aad hex: {}", tc, e));
            let msg = hex::decode(t["msg"].as_str().expect("msg"))
                .unwrap_or_else(|e| panic!("tcId {} msg hex: {}", tc, e));
            let ct = hex::decode(t["ct"].as_str().expect("ct"))
                .unwrap_or_else(|e| panic!("tcId {} ct hex: {}", tc, e));
            let result = t["result"].as_str().expect("result");
            assert_eq!(key.len(), 32, "tcId {}", tc);
            assert_eq!(iv.len(), 12, "tcId {}", tc);

            let mut key_arr = [0u8; 32];
            key_arr.copy_from_slice(&key);
            let cha_key = ChaChaKey::from_raw_key_bytes_for_test(key_arr);
            let mut nb = [0u8; 12];
            nb.copy_from_slice(&iv);
            let nonce = ChaChaNonce::from_bytes_for_test(nb);

            match result {
                "valid" => {
                    let enc = chacha_encrypt(&cha_key, &nonce, &aad, &msg).unwrap_or_else(|e| {
                        panic!("tcId {} encrypt: {:?}", tc, e);
                    });
                    assert_eq!(
                        enc.as_slice_for_test(),
                        ct.as_slice(),
                        "tcId {} ciphertext mismatch",
                        tc
                    );
                    let dec = chacha_decrypt(&cha_key, &nonce, &aad, &enc).unwrap_or_else(|e| {
                        panic!("tcId {} decrypt own ct: {:?}", tc, e);
                    });
                    assert_eq!(dec.as_slice(), msg.as_slice(), "tcId {}", tc);
                }
                "invalid" => {
                    let mut buf = heapless::Vec::<u8, MAX_CHACHA_CIPHERTEXT>::new();
                    for b in &ct {
                        buf.push(*b).expect("heapless bound");
                    }
                    let blob = ChaChaCiphertext::from_vec_for_test(buf);
                    let r = chacha_decrypt(&cha_key, &nonce, &aad, &blob);
                    assert!(
                        matches!(r, Err(ChaChaError::AuthenticationFailed)),
                        "tcId {} expected auth failure",
                        tc,
                    );
                }
                other => panic!("tcId {} unknown result {:?}", tc, other),
            }
        }
    }
}
