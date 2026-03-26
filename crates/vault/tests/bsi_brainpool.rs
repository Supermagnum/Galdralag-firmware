//! BSI TR-03111 JSON vectors (cross-check ECDH; ECDSA arrays reserved for future extracts).

use serde_json::Value;
use vault::brainpool::{BrainpoolPublicKey, BrainpoolScalar};
use vault::brainpool384::{BrainpoolP384PublicKey, BrainpoolP384Scalar};
use vault::brainpool512::{BrainpoolP512PublicKey, BrainpoolP512Scalar};

fn ecdh_rows(v: &Value) -> &[Value] {
    v.get("vectors")
        .and_then(|x| x.get("ecdh"))
        .and_then(|x| x.as_array())
        .map(|a| a.as_slice())
        .expect("vectors.ecdh array")
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
