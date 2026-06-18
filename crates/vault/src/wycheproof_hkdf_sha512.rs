//! Wycheproof JSON vectors for HKDF-SHA-512 (`tests/data/wycheproof/hkdf_sha512_test.json`).

use hkdf::Hkdf;
use sha2::Sha512;

#[test]
fn wycheproof_hkdf_sha512_json() {
    let data = include_str!("../tests/data/wycheproof/hkdf_sha512_test.json");
    let root: serde_json::Value = serde_json::from_str(data).expect("wycheproof HKDF-SHA512 JSON");
    let groups = root["testGroups"].as_array().expect("testGroups");
    for group in groups {
        if group["type"].as_str() != Some("HkdfTest") {
            continue;
        }
        let tests = group["tests"].as_array().expect("tests");
        for t in tests {
            let tc_id = t["tcId"].as_u64().expect("tcId");
            let ikm = hex::decode(t["ikm"].as_str().expect("ikm")).expect("ikm hex");
            let salt = hex::decode(t["salt"].as_str().expect("salt")).expect("salt hex");
            let info = hex::decode(t["info"].as_str().expect("info")).expect("info hex");
            let size = t["size"].as_u64().expect("size") as usize;
            let result = t["result"].as_str().expect("result");

            let hk = Hkdf::<Sha512>::new(Some(&salt), &ikm);

            let mut okm = vec![0u8; size];
            let exp_hex = t["okm"].as_str().unwrap_or("");
            let exp = if exp_hex.is_empty() {
                Vec::new()
            } else {
                hex::decode(exp_hex).expect("okm hex")
            };

            match hk.expand(&info, &mut okm) {
                Ok(()) => {
                    if result == "invalid" {
                        assert_ne!(
                            okm.as_slice(),
                            exp.as_slice(),
                            "tcId {tc_id} invalid must not match okm"
                        );
                    } else {
                        assert_eq!(okm.as_slice(), exp.as_slice(), "tcId {tc_id} okm mismatch");
                    }
                }
                Err(_) => {
                    assert_eq!(result, "invalid", "tcId {tc_id} expand must succeed");
                }
            }
        }
    }
}
