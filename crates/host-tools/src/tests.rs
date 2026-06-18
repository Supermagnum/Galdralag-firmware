use crate::sha256_manifest_chunk;

#[test]
fn sha256_empty_matches_known_vector() {
    let out = sha256_manifest_chunk(&[]);
    let exp =
        hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").unwrap();
    assert_eq!(out.as_slice(), exp.as_slice());
}

#[test]
fn verify_bundle_stub_errors() {
    assert!(crate::verify_update_bundle_stub(&[], &[]).is_err());
}
