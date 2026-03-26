//! Wycheproof JSON vectors for Brainpool P-256r1 ECDSA-SHA256 (`tests/data/wycheproof/ecdsa_brainpoolP256r1_sha256_test.json`).

use crate::brainpool_common::BrainpoolError;
use crate::ecdsa_brainpool::{BrainpoolSignature, BrainpoolVerifyingKey};

fn hex_decode_tc(tc_id: u64, label: &str, s: &str) -> Vec<u8> {
    hex::decode(s).unwrap_or_else(|e| panic!("tcId {tc_id} {label} hex: {e}"))
}

fn run_ecdsa_case(
    tc_id: u64,
    vk: &BrainpoolVerifyingKey,
    msg: &[u8],
    sig_raw: &[u8],
    result: &str,
) {
    let sig = match BrainpoolSignature::from_der_bytes_for_test(sig_raw) {
        Ok(s) => s,
        Err(_) => {
            assert_eq!(
                result, "invalid",
                "tcId {tc_id} valid signature must fit DER buffer"
            );
            return;
        }
    };
    match result {
        "valid" => {
            vk.verify(msg, &sig).unwrap_or_else(|e| {
                panic!("tcId {tc_id} expected valid signature, got {e:?}");
            });
        }
        "invalid" => {
            let r = vk.verify(msg, &sig);
            assert_eq!(
                r,
                Err(BrainpoolError::InvalidSignature),
                "tcId {tc_id} expected invalid signature"
            );
        }
        other => panic!("tcId {tc_id} unknown ECDSA result {other:?}"),
    }
}

#[test]
fn wycheproof_brainpool256_ecdsa_sha256_json() {
    let data = include_str!("../tests/data/wycheproof/ecdsa_brainpoolP256r1_sha256_test.json");
    let root: serde_json::Value =
        serde_json::from_str(data).expect("wycheproof ECDSA P256 JSON must parse");
    let groups = root["testGroups"].as_array().expect("testGroups array");
    for group in groups {
        let der = group["publicKeyDer"].as_str().expect("publicKeyDer");
        let der_bytes = hex::decode(der).expect("publicKeyDer hex");
        let vk = BrainpoolVerifyingKey::from_public_key_der(&der_bytes).expect("verifying key");
        let tests = group["tests"].as_array().expect("tests array");
        for t in tests {
            let tc_id = t["tcId"].as_u64().expect("tcId");
            let msg_hex = t["msg"].as_str().expect("msg");
            let sig_hex = t["sig"].as_str().expect("sig");
            let result = t["result"].as_str().expect("result");
            let msg = hex_decode_tc(tc_id, "msg", msg_hex);
            let sig_raw = hex_decode_tc(tc_id, "sig", sig_hex);
            run_ecdsa_case(tc_id, &vk, &msg, &sig_raw, result);
        }
    }
}
