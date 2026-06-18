//! BSI TR-03111 JSON vectors (ECDH cross-check; ECDSA project-owned KAT rows).

use galdr_core::fake_hal::FakeTrng;
use serde_json::Value;
use vault::brainpool::{BrainpoolPublicKey, BrainpoolScalar};
use vault::brainpool384::{
    BrainpoolP384PublicKey, BrainpoolP384Scalar, BrainpoolP384Signature, BrainpoolP384SigningKey,
    BrainpoolP384VerifyingKey,
};
use vault::brainpool512::{
    BrainpoolP512PublicKey, BrainpoolP512Scalar, BrainpoolP512Signature, BrainpoolP512SigningKey,
    BrainpoolP512VerifyingKey,
};
use vault::ecdsa_brainpool::{BrainpoolSignature, BrainpoolSigningKey, BrainpoolVerifyingKey};

fn ecdh_rows(v: &Value) -> &[Value] {
    v.get("vectors")
        .and_then(|x| x.get("ecdh"))
        .and_then(|x| x.as_array())
        .map(|a| a.as_slice())
        .expect("vectors.ecdh array")
}

fn ecdsa_sign_rows(v: &Value) -> &[Value] {
    match v
        .get("vectors")
        .and_then(|x| x.get("ecdsa_sign"))
        .and_then(|a| a.as_array())
    {
        Some(a) => a.as_slice(),
        None => &[],
    }
}

fn ecdsa_verify_rows(v: &Value) -> &[Value] {
    match v
        .get("vectors")
        .and_then(|x| x.get("ecdsa_verify"))
        .and_then(|a| a.as_array())
    {
        Some(a) => a.as_slice(),
        None => &[],
    }
}

fn hex_decode(label: &str, s: &str) -> Vec<u8> {
    hex::decode(s).unwrap_or_else(|e| panic!("{label}: hex: {e}"))
}

#[test]
fn bsi_tr03111_brainpool256r1_ecdh() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/bsi_vectors/tr03111_brainpool256r1.json"
    );
    let data = std::fs::read_to_string(path).expect("read BSI JSON");
    let f: Value = serde_json::from_str(&data).expect("parse BSI JSON");
    assert_eq!(f["curve"].as_str(), Some("BrainpoolP256r1"));
    for (i, row) in ecdh_rows(&f).iter().enumerate() {
        let d = hex_decode("d_alice", row["d_alice"].as_str().expect("d_alice"));
        let mut d32 = [0u8; 32];
        d32.copy_from_slice(&d);
        let sk = BrainpoolScalar::from_secret_key_bytes_for_test(&d32).expect("scalar");
        let peer = hex_decode("Q_bob", row["Q_bob"].as_str().expect("Q_bob"));
        let pk = BrainpoolPublicKey::from_sec1(&peer).expect("peer pk");
        let ss = sk.diffie_hellman(&pk).expect("ecdh");
        let exp = hex_decode("shared", row["shared_secret"].as_str().expect("shared"));
        assert_eq!(
            ss.as_bytes(),
            exp.as_slice(),
            "ecdh row {i} shared secret mismatch"
        );
        let qalice = hex_decode("Q_alice", row["Q_alice"].as_str().expect("Q_alice"));
        let derived_pk = sk.public_key().expect("pk");
        assert_eq!(derived_pk.to_sec1_uncompressed().as_slice(), qalice.as_slice());
    }
}

#[test]
fn bsi_tr03111_brainpool384r1_ecdh() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/bsi_vectors/tr03111_brainpool384r1.json"
    );
    let data = std::fs::read_to_string(path).expect("read BSI JSON");
    let f: Value = serde_json::from_str(&data).expect("parse BSI JSON");
    assert_eq!(f["curve"].as_str(), Some("BrainpoolP384r1"));
    for (i, row) in ecdh_rows(&f).iter().enumerate() {
        let d = hex_decode("d_alice", row["d_alice"].as_str().expect("d_alice"));
        let sk = BrainpoolP384Scalar::from_secret_key_bytes_for_test(&d).expect("scalar");
        let peer = hex_decode("Q_bob", row["Q_bob"].as_str().expect("Q_bob"));
        let pk = BrainpoolP384PublicKey::from_sec1(&peer).expect("peer pk");
        let ss = sk.diffie_hellman(&pk).expect("ecdh");
        let exp = hex_decode("shared", row["shared_secret"].as_str().expect("shared"));
        assert_eq!(
            ss.as_bytes(),
            exp.as_slice(),
            "ecdh row {i} shared secret mismatch"
        );
    }
}

#[test]
fn bsi_tr03111_brainpool512r1_ecdh() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/bsi_vectors/tr03111_brainpool512r1.json"
    );
    let data = std::fs::read_to_string(path).expect("read BSI JSON");
    let f: Value = serde_json::from_str(&data).expect("parse BSI JSON");
    assert_eq!(f["curve"].as_str(), Some("BrainpoolP512r1"));
    for (i, row) in ecdh_rows(&f).iter().enumerate() {
        let d = hex_decode("d_alice", row["d_alice"].as_str().expect("d_alice"));
        let sk = BrainpoolP512Scalar::from_secret_key_bytes_for_test(&d).expect("scalar");
        let peer = hex_decode("Q_bob", row["Q_bob"].as_str().expect("Q_bob"));
        let pk = BrainpoolP512PublicKey::from_sec1(&peer).expect("peer pk");
        let ss = sk.diffie_hellman(&pk).expect("ecdh");
        let exp = hex_decode("shared", row["shared_secret"].as_str().expect("shared"));
        assert_eq!(
            ss.as_bytes(),
            exp.as_slice(),
            "ecdh row {i} shared secret mismatch"
        );
    }
}

#[test]
fn bsi_tr03111_brainpool256r1_ecdsa() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/bsi_vectors/tr03111_brainpool256r1.json"
    );
    let data = std::fs::read_to_string(path).expect("read BSI JSON");
    let f: Value = serde_json::from_str(&data).expect("parse BSI JSON");
    let mut trng = FakeTrng::from_seed(0xEC05_A256);
    for (i, row) in ecdsa_sign_rows(&f).iter().enumerate() {
        let d = hex_decode("d_hex", row["d_hex"].as_str().expect("d_hex"));
        let mut d32 = [0u8; 32];
        d32.copy_from_slice(&d);
        let sk = BrainpoolSigningKey::from_scalar_bytes_for_test(&d32).expect("signing key");
        let msg = hex_decode("msg_hex", row["msg_hex"].as_str().expect("msg_hex"));
        let got = sk.sign(&msg, &mut trng).expect("sign");
        let exp = hex_decode("sig_der_hex", row["sig_der_hex"].as_str().expect("sig_der_hex"));
        assert_eq!(got.der_bytes(), exp.as_slice(), "ecdsa_sign row {i}");
    }
    for (i, row) in ecdsa_verify_rows(&f).iter().enumerate() {
        let q = hex_decode("Q_hex", row["Q_hex"].as_str().expect("Q_hex"));
        let vk = BrainpoolVerifyingKey::from_sec1(&q).expect("verifying key");
        let msg = hex_decode("msg_hex", row["msg_hex"].as_str().expect("msg_hex"));
        let sig = BrainpoolSignature::from_der_bytes(
            &hex_decode("sig_der_hex", row["sig_der_hex"].as_str().expect("sig_der_hex")),
        )
        .expect("DER signature");
        let expect = row["expect"].as_str().expect("expect");
        let r = vk.verify(&msg, &sig);
        match expect {
            "accept" => assert!(r.is_ok(), "ecdsa_verify row {i} expected accept: {r:?}"),
            "reject" => assert!(r.is_err(), "ecdsa_verify row {i} expected reject"),
            other => panic!("ecdsa_verify row {i}: unknown expect {other:?}"),
        }
    }
}

#[test]
fn bsi_tr03111_brainpool384r1_ecdsa() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/bsi_vectors/tr03111_brainpool384r1.json"
    );
    let data = std::fs::read_to_string(path).expect("read BSI JSON");
    let f: Value = serde_json::from_str(&data).expect("parse BSI JSON");
    let mut trng = FakeTrng::from_seed(0xEC05_A384);
    for (i, row) in ecdsa_sign_rows(&f).iter().enumerate() {
        let d = hex_decode("d_hex", row["d_hex"].as_str().expect("d_hex"));
        let mut d48 = [0u8; 48];
        d48.copy_from_slice(&d);
        let sk = BrainpoolP384SigningKey::from_scalar_bytes_for_test(&d48).expect("signing key");
        let msg = hex_decode("msg_hex", row["msg_hex"].as_str().expect("msg_hex"));
        let got = sk.sign(&msg, &mut trng).expect("sign");
        let exp = hex_decode("sig_der_hex", row["sig_der_hex"].as_str().expect("sig_der_hex"));
        assert_eq!(got.der_bytes(), exp.as_slice(), "ecdsa_sign row {i}");
    }
    for (i, row) in ecdsa_verify_rows(&f).iter().enumerate() {
        let q = hex_decode("Q_hex", row["Q_hex"].as_str().expect("Q_hex"));
        let vk = BrainpoolP384VerifyingKey::from_sec1(&q).expect("verifying key");
        let msg = hex_decode("msg_hex", row["msg_hex"].as_str().expect("msg_hex"));
        let sig = BrainpoolP384Signature::from_der_bytes(
            &hex_decode("sig_der_hex", row["sig_der_hex"].as_str().expect("sig_der_hex")),
        )
        .expect("DER signature");
        let expect = row["expect"].as_str().expect("expect");
        let r = vk.verify(&msg, &sig);
        match expect {
            "accept" => assert!(r.is_ok(), "ecdsa_verify row {i} expected accept: {r:?}"),
            "reject" => assert!(r.is_err(), "ecdsa_verify row {i} expected reject"),
            other => panic!("ecdsa_verify row {i}: unknown expect {other:?}"),
        }
    }
}

#[test]
fn bsi_tr03111_brainpool512r1_ecdsa() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/bsi_vectors/tr03111_brainpool512r1.json"
    );
    let data = std::fs::read_to_string(path).expect("read BSI JSON");
    let f: Value = serde_json::from_str(&data).expect("parse BSI JSON");
    let mut trng = FakeTrng::from_seed(0xEC05_A512);
    for (i, row) in ecdsa_sign_rows(&f).iter().enumerate() {
        let d = hex_decode("d_hex", row["d_hex"].as_str().expect("d_hex"));
        let mut d64 = [0u8; 64];
        d64.copy_from_slice(&d);
        let sk = BrainpoolP512SigningKey::from_scalar_bytes_for_test(&d64).expect("signing key");
        let msg = hex_decode("msg_hex", row["msg_hex"].as_str().expect("msg_hex"));
        let got = sk.sign(&msg, &mut trng).expect("sign");
        let exp = hex_decode("sig_der_hex", row["sig_der_hex"].as_str().expect("sig_der_hex"));
        assert_eq!(got.der_bytes(), exp.as_slice(), "ecdsa_sign row {i}");
    }
    for (i, row) in ecdsa_verify_rows(&f).iter().enumerate() {
        let q = hex_decode("Q_hex", row["Q_hex"].as_str().expect("Q_hex"));
        let vk = BrainpoolP512VerifyingKey::from_sec1(&q).expect("verifying key");
        let msg = hex_decode("msg_hex", row["msg_hex"].as_str().expect("msg_hex"));
        let sig = BrainpoolP512Signature::from_der_bytes(
            &hex_decode("sig_der_hex", row["sig_der_hex"].as_str().expect("sig_der_hex")),
        )
        .expect("DER signature");
        let expect = row["expect"].as_str().expect("expect");
        let r = vk.verify(&msg, &sig);
        match expect {
            "accept" => assert!(r.is_ok(), "ecdsa_verify row {i} expected accept: {r:?}"),
            "reject" => assert!(r.is_err(), "ecdsa_verify row {i} expected reject"),
            other => panic!("ecdsa_verify row {i}: unknown expect {other:?}"),
        }
    }
}

/// Prints `sig_der_hex` for each curve (vault RFC 6979 / DER). Refresh JSON with:
/// `cargo test -p vault bsi_ecdsa_sig_hex_dump -- --ignored --nocapture`
#[test]
#[ignore]
fn bsi_ecdsa_sig_hex_dump() {
    let msg = hex_decode("msg", "67616c6472616c61672d747230333131312d65636473612d6b61742d7631");
    let mut t256 = FakeTrng::from_seed(0xEC05_A256);
    let d256 = hex_decode("d256", "62e7bbfc99af20b70131d4762de9a94870b82744accd1b7ed3f30548e4e15ad3");
    let mut a32 = [0u8; 32];
    a32.copy_from_slice(&d256);
    let s256 = BrainpoolSigningKey::from_scalar_bytes_for_test(&a32)
        .unwrap()
        .sign(&msg, &mut t256)
        .unwrap();
    eprintln!("P256 {}", hex::encode(s256.der_bytes()));

    let mut t384 = FakeTrng::from_seed(0xEC05_A384);
    let d384 = hex_decode(
        "d384",
        "24ddf0fbb41c28365d302dd9d26ff9c32c76c85fa8b9138a3ec621d0caff6de8a724b45d6fe0d9180044242b9f41c84b",
    );
    let mut a48 = [0u8; 48];
    a48.copy_from_slice(&d384);
    let s384 = BrainpoolP384SigningKey::from_scalar_bytes_for_test(&a48)
        .unwrap()
        .sign(&msg, &mut t384)
        .unwrap();
    eprintln!("P384 {}", hex::encode(s384.der_bytes()));

    let mut t512 = FakeTrng::from_seed(0xEC05_A512);
    let d512 = hex_decode(
        "d512",
        "6280eb95405fa8c0e9d970547301bbefb152c8c8114abc730c89bf6db3f7d949fcfd7ebb82fd2dbd43d28d47bf4ed95de97baed19f7d087cf303d2b0cd413767",
    );
    let mut a64 = [0u8; 64];
    a64.copy_from_slice(&d512);
    let s512 = BrainpoolP512SigningKey::from_scalar_bytes_for_test(&a64)
        .unwrap()
        .sign(&msg, &mut t512)
        .unwrap();
    eprintln!("P512 {}", hex::encode(s512.der_bytes()));
}
