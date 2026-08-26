//! Wycheproof JSON vectors for HMAC-SHA-256 (`tests/data/wycheproof/hmac_sha256_test.json`).

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

#[test]
fn wycheproof_hmac_sha256_json() {
    let data = include_str!("../tests/data/wycheproof/hmac_sha256_test.json");
    let root: serde_json::Value = serde_json::from_str(data).expect("wycheproof HMAC JSON");
    let groups = root["testGroups"].as_array().expect("testGroups");
    for group in groups {
        if group["type"].as_str() != Some("MacTest") {
            continue;
        }
        let tag_size_bits = group["tagSize"].as_u64().expect("tagSize") as usize;
        assert_eq!(tag_size_bits % 8, 0, "tag bits must be byte-aligned");
        let tag_len = tag_size_bits / 8;

        let tests = group["tests"].as_array().expect("tests");
        for t in tests {
            let tc_id = t["tcId"].as_u64().expect("tcId");
            let key = hex::decode(t["key"].as_str().expect("key")).expect("key hex");
            let msg = hex::decode(t["msg"].as_str().expect("msg")).expect("msg hex");
            let tag = hex::decode(t["tag"].as_str().expect("tag")).expect("tag hex");
            let result = t["result"].as_str().expect("result");

            let mut mac = <HmacSha256 as hmac::digest::KeyInit>::new_from_slice(&key).expect("hmac key");
            mac.update(&msg);
            let full = mac.finalize().into_bytes();
            assert!(
                tag_len <= full.len(),
                "tcId {tc_id} tag longer than HMAC output"
            );
            let computed = &full[..tag_len];

            match result {
                "valid" => {
                    assert!(
                        bool::from(computed.ct_eq(tag.as_slice())),
                        "tcId {tc_id} tag mismatch"
                    );
                }
                "invalid" => {
                    assert!(
                        !bool::from(computed.ct_eq(tag.as_slice())),
                        "tcId {tc_id} invalid tag must not verify"
                    );
                }
                other => panic!("tcId {tc_id} unknown result {other:?}"),
            }
        }
    }
}
