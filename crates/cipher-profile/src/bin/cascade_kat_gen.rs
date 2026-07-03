//! Emit [`tests/fixtures/cascade_cess_kat.json`] for committed cascade KATs.
//!
//! Run from the workspace root (or crate root) and redirect stdout to the fixture:
//!
//! ```text
//! cargo run -p cipher-profile --bin cascade-kat-gen > crates/cipher-profile/tests/fixtures/cascade_cess_kat.json
//! ```
//!
//! The integration test compares `cascade_encrypt` output to `expected_ciphertext_hex`
//! and checks `cascade_decrypt` on that blob recovers the plaintext. Golden values are
//! produced **outside** the test binary by this tool so encrypt/decrypt cannot drift
//! together against an inline round-trip assertion alone.

use cipher_profile::{
    cascade_blob_before_outermost_encrypt, cascade_decrypt, cascade_encrypt, ProfileRegistry,
};
use serde_json::{json, Map, Value};
use subtle::ConstantTimeEq;

fn main() {
    let ikm: Vec<u8> = vec![0x31u8; 32];
    let aad = b"profile||fp||ts";
    let pt: Vec<u8> = vec![0x77u8; 64];
    let reg = ProfileRegistry::with_builtins();
    let mut rows = Vec::new();
    for name in [
        "standard",
        "conservative",
        "conservative-shamir",
    ] {
        let profile = reg.get(name).expect("builtin profile");
        let suite_id = cess::suite_id_for_profile_name(name).map(|u| format!("0x{:04x}", u));
        let ct = cascade_encrypt(profile, &ikm, aad, &pt).expect("encrypt");
        assert_eq!(ct.profile_name.as_str(), name);
        let out = cascade_decrypt(profile, &ikm, aad, &ct).expect("decrypt self-check");
        assert!(bool::from(out.as_bytes().ct_eq(pt.as_slice())));
        let mut row = Map::new();
        row.insert("profile".into(), json!(name));
        row.insert("suite_id".into(), json!(suite_id));
        row.insert(
            "expected_ciphertext_hex".into(),
            json!(hex::encode(ct.ciphertext.as_slice())),
        );
        if profile.layers().len() >= 2 {
            let blob = cascade_blob_before_outermost_encrypt(profile, &ikm, aad, &pt)
                .expect("intermediate blob");
            row.insert(
                "intermediate_before_outer_hex".into(),
                json!(hex::encode(blob.as_slice())),
            );
        }
        rows.push(Value::Object(row));
    }
    let doc = json!({
        "schema_version": 1,
        "description": "CESS-mapped built-in profiles: fixed IKM/AAD/PT; expected outer cascade ciphertext (hex). Multi-layer rows include intermediate_before_outer_hex (bytes fed to the outer Serpent EtM step). Regenerate: cargo run -p cipher-profile --bin cascade-kat-gen > crates/cipher-profile/tests/fixtures/cascade_cess_kat.json",
        "ikm_hex": hex::encode(&ikm),
        "aad_hex": hex::encode(aad),
        "plaintext_hex": hex::encode(&pt),
        "vectors": rows,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&doc).expect("serialize json")
    );
}
