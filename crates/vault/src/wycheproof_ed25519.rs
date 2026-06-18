//! Wycheproof JSON vectors for Ed25519 verify (`tests/data/wycheproof/ed25519_test.json`).

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

fn hex_decode_tc(tc_id: u64, label: &str, s: &str) -> Vec<u8> {
    hex::decode(s).unwrap_or_else(|e| panic!("tcId {tc_id} {label} hex: {e}"))
}

#[test]
fn wycheproof_ed25519_json() {
    let data = include_str!("../tests/data/wycheproof/ed25519_test.json");
    let root: serde_json::Value = serde_json::from_str(data).expect("wycheproof Ed25519 JSON");
    let groups = root["testGroups"].as_array().expect("testGroups");
    for group in groups {
        let pk_hex = group["publicKey"]["pk"].as_str().expect("publicKey.pk");
        let pk_bytes = hex_decode_tc(0, "pk", pk_hex);
        assert_eq!(pk_bytes.len(), 32, "public key length");
        let mut pk_arr = [0u8; 32];
        pk_arr.copy_from_slice(&pk_bytes);
        let vk = VerifyingKey::from_bytes(&pk_arr).expect("verifying key");

        let tests = group["tests"].as_array().expect("tests");
        for t in tests {
            let tc_id = t["tcId"].as_u64().expect("tcId");
            let msg = hex_decode_tc(tc_id, "msg", t["msg"].as_str().expect("msg"));
            let sig_raw = hex_decode_tc(tc_id, "sig", t["sig"].as_str().expect("sig"));
            let result = t["result"].as_str().expect("result");

            let sig = match Signature::from_slice(&sig_raw) {
                Ok(s) => s,
                Err(_) => {
                    assert_eq!(result, "invalid", "tcId {tc_id} bad signature encoding");
                    continue;
                }
            };

            let v = vk.verify(&msg, &sig);
            match result {
                "valid" => assert!(v.is_ok(), "tcId {tc_id} expected valid, got {v:?}"),
                "invalid" => assert!(v.is_err(), "tcId {tc_id} expected verify failure"),
                other => panic!("tcId {tc_id} unknown result {other:?}"),
            }
        }
    }
}
