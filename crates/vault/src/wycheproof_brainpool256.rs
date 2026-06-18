//! Wycheproof JSON vectors for Brainpool P-256r1 ECDH (`tests/data/wycheproof/ecdh_brainpoolP256r1_test.json`).

use crate::brainpool::{BrainpoolPublicKey, BrainpoolScalar};
use bp256::elliptic_curve::SecretKey;
use bp256::BrainpoolP256r1;

fn hex_decode_tc(tc_id: u64, label: &str, s: &str) -> Vec<u8> {
    hex::decode(s).unwrap_or_else(|e| panic!("tcId {tc_id} {label} hex: {e}"))
}

fn decode_p256_private_scalar(tc_id: u64, private_hex: &str) -> Vec<u8> {
    let raw = hex_decode_tc(tc_id, "private", private_hex);
    let start = raw.iter().position(|&b| b != 0).unwrap_or(raw.len());
    let mut v = if start >= raw.len() {
        vec![0u8; 32]
    } else {
        raw[start..].to_vec()
    };
    if v.len() > 32 {
        panic!("tcId {tc_id} private scalar longer than 32 bytes after normalization");
    }
    if v.len() < 32 {
        let mut padded = vec![0u8; 32];
        padded[32 - v.len()..].copy_from_slice(&v);
        v = padded;
    }
    v
}

fn run_ecdh_case(tc_id: u64, public_hex: &str, private_hex: &str, shared_hex: &str, result: &str) {
    let private_bytes = decode_p256_private_scalar(tc_id, private_hex);
    let pub_der = hex_decode_tc(tc_id, "public", public_hex);
    let shared_expected = if shared_hex.is_empty() {
        Vec::new()
    } else {
        hex_decode_tc(tc_id, "shared", shared_hex)
    };

    match result {
        "valid" => {
            let pk = BrainpoolPublicKey::from_public_key_der(&pub_der)
                .unwrap_or_else(|e| panic!("tcId {tc_id} valid public DER: {e:?}"));
            let scalar = BrainpoolScalar::from_secret_key_bytes_for_test(&private_bytes)
                .unwrap_or_else(|e| panic!("tcId {tc_id} valid private scalar: {e:?}"));
            let ss = scalar
                .diffie_hellman(&pk)
                .unwrap_or_else(|e| panic!("tcId {tc_id} valid ECDH: {e:?}"));
            assert_eq!(
                ss.as_bytes(),
                shared_expected.as_slice(),
                "tcId {tc_id} ECDH shared secret mismatch"
            );
        }
        "acceptable" => {
            let Ok(pk) = BrainpoolPublicKey::from_public_key_der(&pub_der) else {
                return;
            };
            let Ok(scalar) = BrainpoolScalar::from_secret_key_bytes_for_test(&private_bytes) else {
                return;
            };
            let Ok(ss) = scalar.diffie_hellman(&pk) else {
                return;
            };
            assert_eq!(
                ss.as_bytes(),
                shared_expected.as_slice(),
                "tcId {tc_id} acceptable ECDH mismatch"
            );
        }
        "invalid" => {
            let sk_ok = SecretKey::<BrainpoolP256r1>::from_slice(&private_bytes).ok();
            let pk_ok = BrainpoolPublicKey::from_public_key_der(&pub_der).ok();
            match (sk_ok, pk_ok) {
                (Some(_), Some(pk)) => {
                    let Ok(scalar) =
                        BrainpoolScalar::from_secret_key_bytes_for_test(&private_bytes)
                    else {
                        return;
                    };
                    match scalar.diffie_hellman(&pk) {
                        Err(_) => {}
                        Ok(ss) => {
                            if !shared_expected.is_empty() {
                                assert_ne!(
                                    ss.as_bytes(),
                                    shared_expected.as_slice(),
                                    "tcId {tc_id} invalid ECDH must not match Wycheproof shared"
                                );
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        other => panic!("tcId {tc_id} unknown ECDH result {other:?}"),
    }
}

#[test]
fn wycheproof_brainpool256_ecdh_json() {
    let data = include_str!("../tests/data/wycheproof/ecdh_brainpoolP256r1_test.json");
    let root: serde_json::Value =
        serde_json::from_str(data).expect("wycheproof ECDH P256 JSON must parse");
    let groups = root["testGroups"].as_array().expect("testGroups array");
    for group in groups {
        let tests = group["tests"].as_array().expect("tests array");
        for t in tests {
            let tc_id = t["tcId"].as_u64().expect("tcId");
            let public_hex = t["public"].as_str().expect("public");
            let private_hex = t["private"].as_str().expect("private");
            let shared_hex = t["shared"].as_str().unwrap_or("");
            let result = t["result"].as_str().expect("result");
            run_ecdh_case(tc_id, public_hex, private_hex, shared_hex, result);
        }
    }
}
