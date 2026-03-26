//! Wycheproof JSON vectors for X25519 (`tests/data/wycheproof/x25519_test.json`).

use x25519_dalek::{PublicKey, StaticSecret};

fn hex_decode_tc(tc_id: u64, label: &str, s: &str) -> Vec<u8> {
    hex::decode(s).unwrap_or_else(|e| panic!("tcId {tc_id} {label} hex: {e}"))
}

fn run_case(
    tc_id: u64,
    public_hex: &str,
    private_hex: &str,
    shared_hex: &str,
    result: &str,
) {
    let pub_raw = hex_decode_tc(tc_id, "public", public_hex);
    let priv_raw = hex_decode_tc(tc_id, "private", private_hex);
    let shared_exp = hex_decode_tc(tc_id, "shared", shared_hex);

    assert_eq!(pub_raw.len(), 32, "tcId {tc_id}");
    assert_eq!(priv_raw.len(), 32, "tcId {tc_id}");

    let mut priv_arr = [0u8; 32];
    priv_arr.copy_from_slice(&priv_raw);
    let sk = StaticSecret::from(priv_arr);

    let mut pub_arr = [0u8; 32];
    pub_arr.copy_from_slice(&pub_raw);
    let pk = PublicKey::from(pub_arr);

    let ss = sk.diffie_hellman(&pk);

    match result {
        "valid" | "acceptable" => {
            assert_eq!(
                ss.as_bytes().as_slice(),
                shared_exp.as_slice(),
                "tcId {tc_id} shared secret mismatch"
            );
        }
        other => panic!("tcId {tc_id} unknown result {other:?}"),
    }
}

#[test]
fn wycheproof_x25519_json() {
    let data = include_str!("../tests/data/wycheproof/x25519_test.json");
    let root: serde_json::Value = serde_json::from_str(data).expect("wycheproof X25519 JSON");
    let groups = root["testGroups"].as_array().expect("testGroups");
    for group in groups {
        let tests = group["tests"].as_array().expect("tests");
        for t in tests {
            let tc_id = t["tcId"].as_u64().expect("tcId");
            let public_hex = t["public"].as_str().expect("public");
            let private_hex = t["private"].as_str().expect("private");
            let shared_hex = t["shared"].as_str().expect("shared");
            let result = t["result"].as_str().expect("result");
            run_case(tc_id, public_hex, private_hex, shared_hex, result);
        }
    }
}
