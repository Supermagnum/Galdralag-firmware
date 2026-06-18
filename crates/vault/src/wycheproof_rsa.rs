//! Wycheproof JSON vectors for RSA (OAEP, PSS, PKCS#1 v1.5 verify). Files live under `tests/data/wycheproof/`.

use serde_json::Value;

use crate::rsa_keys::{
    Pkcs1v15, RsaOaepCiphertext, RsaPkcs1Signature, RsaPrivateKey, RsaPublicKey, RsaPssSignature,
};

fn run_oaep_group(group: &Value) -> Result<(), String> {
    let pkcs8_hex = group
        .get("privateKeyPkcs8")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing privateKeyPkcs8".to_string())?;
    let pkcs8 = hex::decode(pkcs8_hex).map_err(|e| e.to_string())?;
    let sk = RsaPrivateKey::from_pkcs8_der(&pkcs8).map_err(|e| format!("import: {e:?}"))?;
    let tests = group
        .get("tests")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "tests".to_string())?;
    for t in tests {
        let tc = t.get("tcId").and_then(|v| v.as_u64()).unwrap_or(0);
        let ct = hex::decode(
            t.get("ct")
                .and_then(|v| v.as_str())
                .ok_or_else(|| format!("tc {tc} ct"))?,
        )
        .map_err(|e| e.to_string())?;
        let msg_hex = t
            .get("msg")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("tc {tc} msg"))?;
        let msg = hex::decode(msg_hex).map_err(|e| e.to_string())?;
        let label_hex = t
            .get("label")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let label = hex::decode(label_hex).map_err(|e| e.to_string())?;
        if !label.is_empty() && core::str::from_utf8(&label).is_err() {
            continue;
        }
        let expect = t
            .get("result")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("tc {tc} result"))?;
        let ct_wrapped = RsaOaepCiphertext::from_bytes_fuzz(&ct);
        let got = sk.decrypt_oaep(&ct_wrapped, label.as_slice());
        match expect {
            "valid" => match got {
                Ok(pt) => {
                    if pt.as_slice() != msg.as_slice() {
                        eprintln!("OAEP tcId {tc}: plaintext mismatch");
                        return Err(format!("tc {tc} plaintext"));
                    }
                }
                Err(e) => {
                    eprintln!("OAEP tcId {tc}: expected valid got {e:?}");
                    return Err(format!("tc {tc} decrypt {e:?}"));
                }
            },
            "invalid" => {
                if got.is_ok() {
                    eprintln!("OAEP tcId {tc}: expected invalid got Ok");
                    return Err(format!("tc {tc} expected invalid"));
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn run_pss_group_sha256(group: &Value) -> Result<(), String> {
    if group.get("sha").and_then(|s| s.as_str()) != Some("SHA-256")
        || group.get("mgfSha").and_then(|s| s.as_str()) != Some("SHA-256")
    {
        return Ok(());
    }
    let der_hex = group
        .get("publicKeyDer")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "publicKeyDer".to_string())?;
    let der = hex::decode(der_hex).map_err(|e| e.to_string())?;
    let pk = RsaPublicKey::from_spki_der(&der).map_err(|e| format!("spki: {e:?}"))?;
    let tests = group
        .get("tests")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "tests".to_string())?;
    for t in tests {
        let tc = t.get("tcId").and_then(|v| v.as_u64()).unwrap_or(0);
        let msg = hex::decode(
            t.get("msg")
                .and_then(|v| v.as_str())
                .ok_or_else(|| format!("tc {tc} msg"))?,
        )
        .map_err(|e| e.to_string())?;
        let sig = hex::decode(
            t.get("sig")
                .and_then(|v| v.as_str())
                .ok_or_else(|| format!("tc {tc} sig"))?,
        )
        .map_err(|e| e.to_string())?;
        let expect = t
            .get("result")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("tc {tc} result"))?;
        let sigw = RsaPssSignature::from_bytes_fuzz(&sig);
        let got = pk.verify_pss_sha256(&msg, &sigw);
        match expect {
            "valid" => {
                if got.is_err() {
                    eprintln!("PSS-256 tcId {tc}: expected valid got {got:?}");
                    return Err(format!("tc {tc} verify {got:?}"));
                }
            }
            "invalid" => {
                if got.is_ok() {
                    eprintln!("PSS-256 tcId {tc}: expected invalid");
                    return Err(format!("tc {tc} expected invalid"));
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn run_pss_group_sha512(group: &Value) -> Result<(), String> {
    if group.get("sha").and_then(|s| s.as_str()) != Some("SHA-512")
        || group.get("mgfSha").and_then(|s| s.as_str()) != Some("SHA-512")
    {
        return Ok(());
    }
    let der_hex = group
        .get("publicKeyDer")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "publicKeyDer".to_string())?;
    let der = hex::decode(der_hex).map_err(|e| e.to_string())?;
    let pk = RsaPublicKey::from_spki_der(&der).map_err(|e| format!("spki: {e:?}"))?;
    let tests = group
        .get("tests")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "tests".to_string())?;
    for t in tests {
        let tc = t.get("tcId").and_then(|v| v.as_u64()).unwrap_or(0);
        let msg = hex::decode(
            t.get("msg")
                .and_then(|v| v.as_str())
                .ok_or_else(|| format!("tc {tc} msg"))?,
        )
        .map_err(|e| e.to_string())?;
        let sig = hex::decode(
            t.get("sig")
                .and_then(|v| v.as_str())
                .ok_or_else(|| format!("tc {tc} sig"))?,
        )
        .map_err(|e| e.to_string())?;
        let expect = t
            .get("result")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("tc {tc} result"))?;
        let sigw = RsaPssSignature::from_bytes_fuzz(&sig);
        let got = pk.verify_pss_sha512(&msg, &sigw);
        match expect {
            "valid" => {
                if got.is_err() {
                    eprintln!("PSS-512 tcId {tc}: expected valid got {got:?}");
                    return Err(format!("tc {tc} verify {got:?}"));
                }
            }
            "invalid" => {
                if got.is_ok() {
                    eprintln!("PSS-512 tcId {tc}: expected invalid");
                    return Err(format!("tc {tc} expected invalid"));
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn run_pkcs1_group(group: &Value) -> Result<(), String> {
    if group.get("sha").and_then(|s| s.as_str()) != Some("SHA-256") {
        return Ok(());
    }
    let der_hex = group
        .get("publicKeyDer")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "publicKeyDer".to_string())?;
    let der = hex::decode(der_hex).map_err(|e| e.to_string())?;
    let pk = RsaPublicKey::from_spki_der(&der).map_err(|e| format!("spki: {e:?}"))?;
    let tests = group
        .get("tests")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "tests".to_string())?;
    for t in tests {
        let tc = t.get("tcId").and_then(|v| v.as_u64()).unwrap_or(0);
        let msg = hex::decode(
            t.get("msg")
                .and_then(|v| v.as_str())
                .ok_or_else(|| format!("tc {tc} msg"))?,
        )
        .map_err(|e| e.to_string())?;
        let sig = hex::decode(
            t.get("sig")
                .and_then(|v| v.as_str())
                .ok_or_else(|| format!("tc {tc} sig"))?,
        )
        .map_err(|e| e.to_string())?;
        let expect = t
            .get("result")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("tc {tc} result"))?;
        let sigw = RsaPkcs1Signature::from_bytes_fuzz(&sig);
        let got = pk.verify_pkcs1_sha256(Pkcs1v15, &msg, &sigw);
        match expect {
            "valid" => {
                if got.is_err() {
                    eprintln!("PKCS1 tcId {tc}: expected valid got {got:?}");
                    return Err(format!("tc {tc} verify {got:?}"));
                }
            }
            "invalid" => {
                if got.is_ok() {
                    eprintln!("PKCS1 tcId {tc}: expected invalid");
                    return Err(format!("tc {tc} expected invalid"));
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn wycheproof_path(name: &str) -> String {
    format!("{}/tests/data/wycheproof/{}", env!("CARGO_MANIFEST_DIR"), name)
}

fn run_pss_group_sha256_file(name: &str) -> Result<(), String> {
    let data = std::fs::read_to_string(wycheproof_path(name)).map_err(|e| e.to_string())?;
    let v: Value = serde_json::from_str(&data).map_err(|e| e.to_string())?;
    let groups = v
        .get("testGroups")
        .and_then(|g| g.as_array())
        .ok_or_else(|| "testGroups".to_string())?;
    for g in groups {
        run_pss_group_sha256(g)?;
    }
    Ok(())
}

fn run_pss_group_sha512_file(name: &str) -> Result<(), String> {
    let data = std::fs::read_to_string(wycheproof_path(name)).map_err(|e| e.to_string())?;
    let v: Value = serde_json::from_str(&data).map_err(|e| e.to_string())?;
    let groups = v
        .get("testGroups")
        .and_then(|g| g.as_array())
        .ok_or_else(|| "testGroups".to_string())?;
    for g in groups {
        run_pss_group_sha512(g)?;
    }
    Ok(())
}

fn run_oaep_file(name: &str) -> Result<(), String> {
    let data = std::fs::read_to_string(wycheproof_path(name)).map_err(|e| e.to_string())?;
    let v: Value = serde_json::from_str(&data).map_err(|e| e.to_string())?;
    let groups = v
        .get("testGroups")
        .and_then(|g| g.as_array())
        .ok_or_else(|| "testGroups".to_string())?;
    for g in groups {
        if g.get("sha").and_then(|s| s.as_str()) == Some("SHA-256")
            && g.get("mgfSha").and_then(|s| s.as_str()) == Some("SHA-256")
        {
            run_oaep_group(g)?;
        }
    }
    Ok(())
}

fn run_pkcs1_sig_file(name: &str) -> Result<(), String> {
    let data = std::fs::read_to_string(wycheproof_path(name)).map_err(|e| e.to_string())?;
    let v: Value = serde_json::from_str(&data).map_err(|e| e.to_string())?;
    let groups = v
        .get("testGroups")
        .and_then(|g| g.as_array())
        .ok_or_else(|| "testGroups".to_string())?;
    for g in groups {
        run_pkcs1_group(g)?;
    }
    Ok(())
}

#[test]
fn wycheproof_rsa_oaep_sha256_mgf1sha256() {
    for f in [
        "rsa_oaep_2048_sha256_mgf1sha256_test.json",
        "rsa_oaep_3072_sha256_mgf1sha256_test.json",
        "rsa_oaep_4096_sha256_mgf1sha256_test.json",
    ] {
        run_oaep_file(f).unwrap_or_else(|e| panic!("{f}: {e}"));
    }
}

#[test]
fn wycheproof_rsa_pss_sha256() {
    run_pss_group_sha256_file("rsa_pss_2048_sha256_mgf1_32_test.json")
        .unwrap_or_else(|e| panic!("{e}"));
}

#[test]
fn wycheproof_rsa_pss_sha512() {
    run_pss_group_sha512_file("rsa_pss_4096_sha512_mgf1_64_test.json")
        .unwrap_or_else(|e| panic!("{e}"));
}

#[test]
fn wycheproof_rsa_pkcs1_sha256() {
    run_pkcs1_sig_file("rsa_signature_2048_sha256_test.json").unwrap_or_else(|e| panic!("{e}"));
}
