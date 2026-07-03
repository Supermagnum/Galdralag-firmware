//! Incremental dudect runner: skip harnesses with cached PASS in `crates/security-tests/dudect_results.json`.

use serde_json::{Map, Value};
use std::collections::HashSet;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Command, Stdio};

/// Keep in sync with `crates/security-tests/src/dudect_harnesses.rs` `harnesses` array (length and order optional; set must match).
const ALL_KNOWN: &[&str] = &[
    "timing_subtle_eq_u256",
    "timing_chacha_tag_check",
    "timing_aes_gcm_tag_check",
    "timing_hmac_verify",
    "timing_hkdf_derive",
    "timing_ed25519_verify",
    "timing_x25519_ecdh",
    "timing_brainpool256_scalar_mult",
    "timing_brainpool384_scalar_mult",
    "timing_ephemeral_ecdh",
    "timing_signature_verify",
    "timing_fingerprint_lookup",
    "timing_shamir_recover",
    "timing_serpent_tag_check",
    "timing_twofish_tag_check",
    "timing_cascade_auth_failure",
    "timing_cascade_inner_vs_outer_failure",
    "timing_pin_compare",
    "timing_rsa_oaep_decrypt",
    "timing_rsa_pss_verify",
    "timing_pbkdf2",
    "timing_sha256",
    "timing_sha512",
    "timing_sha3_256",
    "timing_sha3_512",
    "timing_blake2b",
    "timing_blake2s",
    "timing_blake3",
    "dudect_session_token_verify_constant_time",
    "dudect_template_decrypt_constant_time",
    "dudect_signature_verify_constant_time",
];

const CACHE_REL: &str = "crates/security-tests/dudect_results.json";

pub fn run(workspace_root: &Path, args: impl Iterator<Item = String>) -> i32 {
    let args: Vec<String> = args.collect();
    let run_all = args.iter().any(|s| s == "--all");
    let run_full = args.iter().any(|s| s == "--full");
    let explicit: Vec<&str> = args
        .iter()
        .filter(|a| !a.starts_with("--"))
        .map(String::as_str)
        .collect();

    let cache_path = workspace_root.join(CACHE_REL);

    let cached_pass: HashSet<String> = if run_all || !explicit.is_empty() {
        HashSet::new()
    } else {
        match load_passing_harnesses(&cache_path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("timing-test: failed to read {}: {e}", cache_path.display());
                return 1;
            }
        }
    };

    let to_run: Vec<String> = if !explicit.is_empty() {
        explicit.iter().map(|s| (*s).to_string()).collect()
    } else if run_all {
        ALL_KNOWN.iter().map(|s| (*s).to_string()).collect()
    } else {
        ALL_KNOWN
            .iter()
            .filter(|name| !cached_pass.contains(**name))
            .map(|s| (*s).to_string())
            .collect()
    };

    if to_run.is_empty() {
        println!("All dudect harnesses have recorded passing results.");
        println!("Use `cargo run -p xtask -- timing-test --all` to re-run all, or name specific harnesses.");
        return 0;
    }

    if run_all || !explicit.is_empty() {
        println!("Running {} harness(es):", to_run.len());
    } else {
        println!(
            "Running {} harness(es) (skipping {} with cached PASS):",
            to_run.len(),
            cached_pass.len()
        );
    }
    for name in &to_run {
        println!("  + {name}");
    }

    let multiplier = if run_full { "3" } else { "1" };
    let dudect_list = to_run.join(",");

    let mut cmd = Command::new("cargo");
    cmd.current_dir(workspace_root)
        .args([
            "run",
            "-p",
            "security-tests",
            "--features",
            "dudect",
            "--bin",
            "dudect_galdr",
            "--",
        ])
        .env("DUDECT_HARNESSES", &dudect_list)
        .env("DUDECT_SAMPLE_MULTIPLIER", multiplier)
        .env("DUDECT_JSON_OUTPUT", "1")
        .stdin(Stdio::inherit())
        .stderr(Stdio::inherit())
        .stdout(Stdio::piped());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("timing-test: failed to spawn cargo: {e}");
            return 1;
        }
    };

    let stdout = child.stdout.take().expect("piped stdout");
    let mut json_lines: Vec<Value> = Vec::new();
    for line in BufReader::new(stdout).lines() {
        let Ok(line) = line else { break };
        println!("{line}");
        let t = line.trim();
        if t.starts_with('{') {
            if let Ok(v) = serde_json::from_str::<Value>(t) {
                json_lines.push(v);
            }
        }
    }

    let status = match child.wait() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("timing-test: wait failed: {e}");
            return 1;
        }
    };

    if !status.success() {
        eprintln!("timing-test FAILED — one or more harnesses exceeded threshold.");
        return status.code().unwrap_or(1);
    }

    if let Err(e) = merge_pass_results_into_cache(&cache_path, &json_lines) {
        eprintln!(
            "timing-test: failed to update {}: {e}",
            cache_path.display()
        );
        return 1;
    }

    0
}

fn load_passing_harnesses(
    path: &Path,
) -> Result<HashSet<String>, Box<dyn std::error::Error + Send + Sync>> {
    let text = fs::read_to_string(path).unwrap_or_else(|_| "{}".to_string());
    let map: Map<String, Value> = serde_json::from_str(&text)?;
    let mut out = HashSet::new();
    for (k, v) in map {
        if v.get("status").and_then(|x| x.as_str()) == Some("PASS") {
            out.insert(k);
        }
    }
    Ok(out)
}

fn merge_pass_results_into_cache(
    path: &Path,
    json_lines: &[Value],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let text = fs::read_to_string(path).unwrap_or_else(|_| "{}".to_string());
    let mut map: Map<String, Value> = serde_json::from_str(&text)?;

    for v in json_lines {
        let Some(obj) = v.as_object() else {
            continue;
        };
        if obj.get("status").and_then(|x| x.as_str()) != Some("PASS") {
            continue;
        }
        let Some(name) = obj.get("harness").and_then(|x| x.as_str()) else {
            continue;
        };
        let samples = obj.get("samples").cloned().unwrap_or(Value::Null);
        let t = obj.get("t").cloned().unwrap_or(Value::Null);
        map.insert(
            name.to_string(),
            serde_json::json!({
                "samples": samples,
                "t": t,
                "status": "PASS",
            }),
        );
    }

    fs::write(path, serde_json::to_string_pretty(&map)?)?;
    Ok(())
}
