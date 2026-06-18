//! Known-answer tests: `cascade_encrypt` must match committed hex in
//! [`fixtures/cascade_cess_kat.json`](fixtures/cascade_cess_kat.json), and
//! `cascade_decrypt` must recover the plaintext from that blob.
//!
//! Golden ciphertexts are produced by the `cascade-kat-gen` binary, not asserted
//! via an encrypt-then-decrypt round-trip inside this file.

use cipher_profile::{
    cascade_blob_before_outermost_encrypt, cascade_decrypt, cascade_encrypt, CascadeCiphertext,
    CipherProfileError, ProfileRegistry,
};
use heapless::String;
use serde_json::Value;
use subtle::ConstantTimeEq;

const FIXTURE: &str = include_str!("fixtures/cascade_cess_kat.json");

fn tr<T, E: core::fmt::Debug>(r: Result<T, E>) -> T {
    match r {
        Ok(v) => v,
        Err(e) => panic!("{:?}", e),
    }
}

fn hex_decode(s: &str) -> Vec<u8> {
    hex::decode(s.trim()).unwrap_or_else(|e| panic!("hex decode: {e}"))
}

#[test]
fn cascade_cess_kat_matches_fixture() {
    let doc: Value = serde_json::from_str(FIXTURE).expect("parse cascade_cess_kat.json");
    assert_eq!(doc["schema_version"], 1);
    let ikm = hex_decode(doc["ikm_hex"].as_str().expect("ikm_hex"));
    let aad = hex_decode(doc["aad_hex"].as_str().expect("aad_hex"));
    let pt = hex_decode(doc["plaintext_hex"].as_str().expect("plaintext_hex"));
    let vectors = doc["vectors"].as_array().expect("vectors array");
    let reg = ProfileRegistry::with_builtins();

    for row in vectors {
        let name = row["profile"].as_str().expect("profile");
        let expected = hex_decode(row["expected_ciphertext_hex"].as_str().expect("hex"));
        let profile = tr(reg.get(name).ok_or("missing profile"));
        let got = tr(cascade_encrypt(profile, &ikm, &aad, &pt));
        assert_eq!(
            got.ciphertext.as_slice(),
            expected.as_slice(),
            "cascade_encrypt ciphertext mismatch for profile {name}"
        );
        let mut pname = String::new();
        tr(pname.push_str(name));
        let ct = CascadeCiphertext {
            profile_name: pname,
            ciphertext: {
                let mut v = heapless::Vec::new();
                for b in expected {
                    tr(v.push(b));
                }
                v
            },
        };
        let out = tr(cascade_decrypt(profile, &ikm, &aad, &ct));
        assert!(
            bool::from(out.as_bytes().ct_eq(pt.as_slice())),
            "cascade_decrypt of golden ct must recover plaintext (profile {name})"
        );
    }
}

#[test]
fn cascade_cess_kat_intermediate_matches_fixture() {
    let doc: Value = serde_json::from_str(FIXTURE).expect("parse cascade_cess_kat.json");
    let ikm = hex_decode(doc["ikm_hex"].as_str().expect("ikm_hex"));
    let aad = hex_decode(doc["aad_hex"].as_str().expect("aad_hex"));
    let pt = hex_decode(doc["plaintext_hex"].as_str().expect("plaintext_hex"));
    let vectors = doc["vectors"].as_array().expect("vectors array");
    let reg = ProfileRegistry::with_builtins();
    for row in vectors {
        let name = row["profile"].as_str().expect("profile");
        let Some(hex_s) = row["intermediate_before_outer_hex"].as_str() else {
            continue;
        };
        let profile = tr(reg.get(name).ok_or("missing profile"));
        let expect_inter = hex_decode(hex_s);
        let got_inter = tr(cascade_blob_before_outermost_encrypt(profile, &ikm, &aad, &pt));
        assert_eq!(
            got_inter.as_slice(),
            expect_inter.as_slice(),
            "intermediate blob (profile {name})"
        );
    }
}

#[test]
fn cascade_cess_kat_decrypt_rejects_wrong_profile_name() {
    let doc: Value = serde_json::from_str(FIXTURE).expect("parse");
    let ikm = hex_decode(doc["ikm_hex"].as_str().unwrap());
    let aad = hex_decode(doc["aad_hex"].as_str().unwrap());
    let row = doc["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["profile"].as_str() == Some("conservative"))
        .expect("conservative row");
    let expected = hex_decode(row["expected_ciphertext_hex"].as_str().unwrap());
    let reg = ProfileRegistry::with_builtins();
    let profile = tr(reg.get("conservative").ok_or("missing"));
    let mut wrong = String::new();
    tr(wrong.push_str("wrong-profile"));
    let mut buf = heapless::Vec::new();
    for b in expected {
        tr(buf.push(b));
    }
    let ct = CascadeCiphertext {
        profile_name: wrong,
        ciphertext: buf,
    };
    let r = cascade_decrypt(profile, &ikm, &aad, &ct);
    assert!(matches!(r, Err(CipherProfileError::ProfileMismatch)));
}
