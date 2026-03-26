//! Wycheproof JSON vectors for Brainpool P-384r1 ECDH and ECDSA-SHA384 (`tests/data/`).

use crate::brainpool384::{
    BrainpoolP384PublicKey, BrainpoolP384Scalar, BrainpoolP384Signature, BrainpoolP384VerifyingKey,
};
use crate::brainpool_common::BrainpoolError;
use bp384::BrainpoolP384r1;
use bp384::elliptic_curve::SecretKey;

fn hex_decode_tc(tc_id: u64, label: &str, s: &str) -> Vec<u8> {
    hex::decode(s).unwrap_or_else(|e| panic!("tcId {tc_id} {label} hex: {e}"))
}

/// Wycheproof encodes private scalars as minimal hex or with leading zero bytes; normalize to 48-byte
/// big-endian field elements (strip leading zeros, then left-pad).
fn decode_p384_private_scalar(tc_id: u64, private_hex: &str) -> Vec<u8> {
    let raw = hex_decode_tc(tc_id, "private", private_hex);
    let start = raw.iter().position(|&b| b != 0).unwrap_or(raw.len());
    let mut v = if start >= raw.len() {
        vec![0u8; 48]
    } else {
        raw[start..].to_vec()
    };
    if v.len() > 48 {
        panic!("tcId {tc_id} private scalar longer than 48 bytes after normalization");
    }
    if v.len() < 48 {
        let mut padded = vec![0u8; 48];
        padded[48 - v.len()..].copy_from_slice(&v);
        v = padded;
    }
    v
}

fn run_ecdh_case(tc_id: u64, public_hex: &str, private_hex: &str, shared_hex: &str, result: &str) {
    let private_bytes = decode_p384_private_scalar(tc_id, private_hex);
    let pub_der = hex_decode_tc(tc_id, "public", public_hex);
    let shared_expected = if shared_hex.is_empty() {
        Vec::new()
    } else {
        hex_decode_tc(tc_id, "shared", shared_hex)
    };

    match result {
        "valid" => {
            let pk = BrainpoolP384PublicKey::from_public_key_der(&pub_der)
                .unwrap_or_else(|e| panic!("tcId {tc_id} valid public DER: {e:?}"));
            let scalar = BrainpoolP384Scalar::from_secret_key_bytes_for_test(&private_bytes)
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
            let Ok(pk) = BrainpoolP384PublicKey::from_public_key_der(&pub_der) else {
                return;
            };
            let Ok(scalar) = BrainpoolP384Scalar::from_secret_key_bytes_for_test(&private_bytes)
            else {
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
            let sk_ok = SecretKey::<BrainpoolP384r1>::from_slice(&private_bytes).ok();
            let pk_ok = BrainpoolP384PublicKey::from_public_key_der(&pub_der).ok();
            match (sk_ok, pk_ok) {
                (Some(_), Some(pk)) => {
                    let Ok(scalar) =
                        BrainpoolP384Scalar::from_secret_key_bytes_for_test(&private_bytes)
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
fn wycheproof_brainpool384_ecdh_json() {
    let data = include_str!("../tests/data/ecdh_brainpoolP384r1_test.json");
    let root: serde_json::Value =
        serde_json::from_str(data).expect("wycheproof ECDH JSON must parse");
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

fn run_ecdsa_case(
    tc_id: u64,
    vk: &BrainpoolP384VerifyingKey,
    msg: &[u8],
    sig_raw: &[u8],
    result: &str) {
    let sig = match BrainpoolP384Signature::from_der_bytes_for_test(sig_raw) {
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
fn wycheproof_brainpool384_ecdsa_sha384_json() {
    let data = include_str!("../tests/data/ecdsa_brainpoolP384r1_sha384_test.json");
    let root: serde_json::Value =
        serde_json::from_str(data).expect("wycheproof ECDSA JSON must parse");
    let groups = root["testGroups"].as_array().expect("testGroups array");
    for group in groups {
        let der = group["publicKeyDer"].as_str().expect("publicKeyDer");
        let der_bytes = hex::decode(der).expect("publicKeyDer hex");
        let vk = BrainpoolP384VerifyingKey::from_public_key_der(&der_bytes)
            .expect("verifying key from DER");
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
