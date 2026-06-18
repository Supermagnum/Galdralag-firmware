//! JSON vectors in `tests/data/shamir_vectors.json`.

use galdr_vault::shamir::{shamir_recover, ShamirError, ShamirShare};
use serde_json::Value;

#[test]
fn shamir_vectors_json_recover() -> Result<(), ShamirError> {
    let data = include_str!("data/shamir_vectors.json");
    let root: Value = serde_json::from_str(data).expect("parse shamir_vectors.json");
    for vec in root["vectors"].as_array().expect("vectors") {
        let k = vec["k"].as_u64().expect("k") as u8;
        let secret =
            hex::decode(vec["secret_hex"].as_str().expect("secret_hex")).expect("secret hex");
        let mut collected = heapless::Vec::<ShamirShare, 255>::new();
        for s in vec["shares"].as_array().expect("shares") {
            let idx = s["index"].as_u64().expect("index") as u8;
            let val = hex::decode(s["value_hex"].as_str().expect("value_hex")).expect("value hex");
            let share = ShamirShare::try_from_index_value(idx, &val)?;
            collected
                .push(share)
                .map_err(|_| ShamirError::InvalidParameters)?;
        }
        let r = shamir_recover(collected.as_slice(), k)?;
        assert_eq!(
            r.as_slice(),
            secret.as_slice(),
            "vector {:?}",
            vec.get("name")
        );
    }
    Ok(())
}
