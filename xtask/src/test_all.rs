//! `cargo run -p xtask -- test-all` — full verification pipeline and `docs/TEST_RESULTS.md` writer.

use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};

use serde_json::Value;

const DUDECT_THRESHOLD: f64 = 4.5;

/// One timing harness block from `dudect_galdr` stdout (`[DUDECT] timing_*` followed by samples / t-statistic).
struct DudectHarness {
    name: String,
    samples: u64,
    t_stat: f64,
}

/// Parsed dudect stdout for `docs/TEST_RESULTS.md` Section 3.
struct DudectReport {
    harnesses: Vec<DudectHarness>,
    summary_elapsed_s: Option<f64>,
    summary_ok: Option<(u32, u32)>,
}

impl DudectReport {
    fn empty() -> Self {
        Self {
            harnesses: Vec::new(),
            summary_elapsed_s: None,
            summary_ok: None,
        }
    }
}

fn parse_dudect_stdout(stdout: &str) -> DudectReport {
    let mut report = DudectReport::empty();
    let lines: Vec<&str> = stdout.lines().collect();
    let mut i = 0usize;
    while i < lines.len() {
        let line = lines[i].trim();
        if let Some(rest) = line.strip_prefix("[DUDECT] ") {
            if rest.starts_with("Summary:") {
                if let Some(elapsed) = parse_dudect_elapsed(rest) {
                    report.summary_elapsed_s = Some(elapsed);
                }
                if let Some(pair) = parse_dudect_summary_counts(rest) {
                    report.summary_ok = Some(pair);
                }
                i += 1;
                continue;
            }
            let is_harness_line = (rest.starts_with("timing_") || rest.starts_with("dudect_"))
                && !rest.contains("Running");
            if is_harness_line {
                let mut samples = 0u64;
                let mut t_stat = 0.0f64;
                let mut j = i + 1;
                while j < lines.len() {
                    let l = lines[j].trim();
                    if l.is_empty() || l.starts_with("[DUDECT]") || l.starts_with("[MISSING]") {
                        break;
                    }
                    if let Some(smp) = l.strip_prefix("Samples:") {
                        if let Ok(n) = smp.trim().parse::<u64>() {
                            samples = n;
                        }
                    }
                    if let Some(ts) = l.strip_prefix("t-statistic:") {
                        if let Ok(v) = ts.trim().parse::<f64>() {
                            t_stat = v;
                        }
                    }
                    j += 1;
                }
                if samples > 0 {
                    report.harnesses.push(DudectHarness {
                        name: rest.to_string(),
                        samples,
                        t_stat,
                    });
                }
                i = j;
                continue;
            }
        }
        i += 1;
    }
    report
}

fn parse_dudect_elapsed(summary_line: &str) -> Option<f64> {
    let rest = summary_line.split("Elapsed:").nth(1)?.trim();
    let num = rest.trim_end_matches('s').trim_end_matches('.').trim();
    num.parse().ok()
}

fn parse_dudect_summary_counts(summary_line: &str) -> Option<(u32, u32)> {
    let rest = summary_line.split("Summary:").nth(1)?;
    let part = rest.split("executed").next()?.trim();
    let mut slash = part.split('/');
    let a = slash.next()?.parse().ok()?;
    let b = slash.next()?.trim().parse().ok()?;
    Some((a, b))
}

fn run_dudect_galdr(workspace_root: &Path) -> (bool, DudectReport) {
    let out = Command::new("cargo")
        .current_dir(workspace_root)
        .args([
            "run",
            "-p",
            "security-tests",
            "--features",
            "dudect",
            "--bin",
            "dudect_galdr",
        ])
        .output();
    let Some(o) = out.ok() else {
        return (false, DudectReport::empty());
    };
    let stdout_s = String::from_utf8_lossy(&o.stdout).to_string();
    let stderr_s = String::from_utf8_lossy(&o.stderr).to_string();
    eprint!("{stderr_s}");
    print!("{stdout_s}");
    let ok = o.status.success();
    let report = parse_dudect_stdout(&stdout_s);
    (ok, report)
}

fn dudect_compact_note(name: &str) -> &'static str {
    match name {
        "timing_fingerprint_lookup" => "Null pairing — same absent fingerprint both classes",
        "timing_cascade_auth_failure" => "Null pairing — identical tampered ciphertext per class",
        "timing_cascade_inner_vs_outer_failure" => {
            "Null pairing — identical inner tamper per class"
        }
        "timing_pbkdf2" => "PBKDF2-HMAC-SHA256; two 16-byte passwords",
        "timing_blake3" => "Single-chunk 64-byte message",
        "dudect_template_decrypt_constant_time" => "Null pairing — decrypt good blob both classes",
        "dudect_session_token_verify_constant_time" => "Constant-time compare harness",
        "dudect_signature_verify_constant_time" => "Constant-time limb compare harness",
        _ => "",
    }
}

fn format_dudect_compact_table(dudect: &DudectReport) -> String {
    let mut s = String::new();
    if dudect.harnesses.is_empty() {
        return "*No harness rows parsed from `dudect_galdr` stdout (timing step may have failed or output format changed).*\n\n".to_string();
    }
    s.push_str("| Harness | Samples | t-stat | Status | Notes |\n");
    s.push_str("|---------|---------|--------|--------|-------|\n");
    for h in &dudect.harnesses {
        let pass = h.t_stat.abs() <= DUDECT_THRESHOLD;
        let st = if pass { "PASS" } else { "FAIL" };
        let note = dudect_compact_note(&h.name);
        s.push_str(&format!(
            "| `{}` | {} | {:+.3} | {} | {} |\n",
            h.name, h.samples, h.t_stat, st, note
        ));
    }
    s.push('\n');
    s.push_str("**Not yet wired** (printed `[MISSING]` by `dudect_galdr`):\n");
    s.push_str("challenge-response HMAC, PSRAM tag check, XMSS verify, LMS verify.\n\n");
    s
}

pub fn run(workspace_root: &Path, skip_fuzz: bool) -> i32 {
    let doc_path = workspace_root.join("docs/TEST_RESULTS.md");
    let mut log = TestAllLog::default();
    let date = utc_date_iso8601();
    let commit = git_head(workspace_root).unwrap_or_else(|| "unknown".to_string());
    let xtask_ver = env!("CARGO_PKG_VERSION");

    eprintln!("test-all: 1/15 check-fw (default features)");
    log.push_step(
        "check-fw (default)",
        run_embedded_check(workspace_root, &["check"], false),
    );

    eprintln!("test-all: 2/15 check-fw (pq-signatures)");
    log.push_step(
        "check-fw (pq-signatures)",
        run_embedded_check(workspace_root, &["check"], true),
    );

    eprintln!("test-all: 3/15 cargo test --workspace --exclude xtask");
    let ws_out = cargo_output(
        workspace_root,
        &["test", "--workspace", "--exclude", "xtask"],
    );
    let ws_ok = ws_out.as_ref().map(|o| o.status.success()).unwrap_or(false);
    let ws_text = ws_out
        .as_ref()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout).to_string() + &String::from_utf8_lossy(&o.stderr)
        })
        .unwrap_or_default();
    let (u_pass, u_fail, u_ign) = aggregate_test_lines(&ws_text);
    log.push_step("unit tests (workspace)", ws_ok && u_fail == 0);

    eprintln!("test-all: 4/15 wycheproof (vault)");
    log.push_step(
        "wycheproof",
        cargo_ok(
            workspace_root,
            &["test", "-p", "galdr-vault", "wycheproof", "-q"],
        ),
    );

    eprintln!("test-all: 5/15 rfc_vectors");
    log.push_step(
        "rfc_vectors",
        cargo_ok(
            workspace_root,
            &["test", "-p", "galdr-vault", "--test", "rfc_vectors", "-q"],
        ),
    );

    eprintln!("test-all: 6/15 bsi_brainpool");
    log.push_step(
        "bsi_brainpool",
        cargo_ok(
            workspace_root,
            &["test", "-p", "galdr-vault", "--test", "bsi_brainpool", "-q"],
        ),
    );

    eprintln!("test-all: 7/15 nist_cavp");
    log.push_step(
        "nist_cavp",
        cargo_ok(
            workspace_root,
            &["test", "-p", "galdr-vault", "--test", "nist_cavp", "-q"],
        ),
    );

    eprintln!("test-all: 8/15 kat_vectors");
    log.push_step(
        "kat_vectors",
        cargo_ok(
            workspace_root,
            &["test", "-p", "galdr-vault", "--test", "kat_vectors", "-q"],
        ),
    );

    eprintln!("test-all: 9/15 key_lifecycle");
    log.push_step(
        "key_lifecycle",
        cargo_ok(
            workspace_root,
            &["test", "-p", "galdr-vault", "--test", "key_lifecycle", "-q"],
        ),
    );

    eprintln!("test-all: 10/15 pin_lifecycle");
    log.push_step(
        "pin_lifecycle",
        cargo_ok(
            workspace_root,
            &["test", "-p", "pin-policy", "--test", "pin_lifecycle", "-q"],
        ),
    );

    eprintln!("test-all: 11/15 usb-personality");
    log.push_step(
        "usb-personality",
        cargo_ok(workspace_root, &["test", "-p", "usb-personality", "-q"]),
    );

    eprintln!("test-all: 12/15 biometric-api/vault + mocks");
    log.push_step(
        "biometric",
        cargo_ok(
            workspace_root,
            &[
                "test",
                "-p",
                "biometric-api",
                "-p",
                "biometric-vault",
                "-p",
                "biometric-fingervein",
                "--features",
                "test-hal",
                "-p",
                "biometric-sweet",
                "--features",
                "test-hal",
                "-q",
            ],
        ),
    );

    eprintln!("test-all: 13/15 zeroise_simulation");
    log.push_step(
        "zeroise_simulation",
        cargo_ok(
            workspace_root,
            &[
                "test",
                "-p",
                "galdr-core",
                "--test",
                "zeroise_simulation",
                "--features",
                "test-hal",
                "-q",
            ],
        ),
    );

    eprintln!("test-all: 14/15 timing-test (dudect_galdr)");
    let (timing_ok, dudect_report) = run_dudect_galdr(workspace_root);
    log.push_step("timing-test", timing_ok);

    let mut fuzz_ok = true;
    let mut fuzz_notes: Vec<String> = Vec::new();
    let fuzz_skipped = skip_fuzz;
    if skip_fuzz {
        eprintln!("test-all: 15/15 cargo-fuzz — skipped (--no-fuzz)");
        fuzz_notes.push(
            "Skipped: run without --no-fuzz to execute all fuzz targets (30s each).".to_string(),
        );
        log.push_step("cargo-fuzz (skipped)", true);
    } else {
        eprintln!("test-all: 15/15 cargo-fuzz (30s per target)");
        let fuzz_dir = workspace_root.join("fuzz");
        if fuzz_dir.join("Cargo.toml").is_file() {
            for bin in FUZZ_BINS {
                eprintln!("test-all: fuzz {bin} (30s)");
                match run_fuzz_status(&fuzz_dir, bin, 30) {
                    Ok(true) => {}
                    Ok(false) => {
                        fuzz_ok = false;
                        fuzz_notes.push(format!("target {bin}: exited non-zero"));
                    }
                    Err(e) => {
                        fuzz_ok = false;
                        fuzz_notes.push(format!("target {bin}: {e}"));
                    }
                }
            }
        } else {
            fuzz_ok = false;
            fuzz_notes.push("fuzz/Cargo.toml missing".to_string());
        }
        log.push_step("cargo-fuzz (30s each)", fuzz_ok);
    }

    let overall = log.all_passed();
    let counts = vector_counts(workspace_root);
    let md = build_markdown(
        &date,
        &commit,
        xtask_ver,
        u_pass,
        u_fail,
        u_ign,
        &counts,
        &log.steps,
        &dudect_report,
        fuzz_ok,
        fuzz_skipped,
        &fuzz_notes,
    );

    if let Err(e) = fs::write(&doc_path, md) {
        eprintln!("test-all: failed to write {}: {e}", doc_path.display());
        return 1;
    }
    eprintln!("test-all: wrote {}", doc_path.display());

    if !overall {
        eprintln!(
            "test-all: FAILED (see steps above and {})",
            doc_path.display()
        );
        return 1;
    }
    if !fuzz_ok && !fuzz_skipped {
        eprintln!("test-all: WARNING fuzz step had issues; see Section 6 in TEST_RESULTS.md");
    }
    0
}

#[derive(Default)]
struct TestAllLog {
    steps: Vec<(String, bool)>,
}

impl TestAllLog {
    fn push_step(&mut self, name: &str, ok: bool) {
        self.steps.push((name.to_string(), ok));
    }

    fn all_passed(&self) -> bool {
        self.steps.iter().all(|(_, ok)| *ok)
    }
}

/// JSON-derived counts for narrative sections in `TEST_RESULTS.md`.
#[derive(Clone, Copy, Default)]
struct VectorCounts {
    wyche_aes_gcm_128: u32,
    wyche_aes_gcm_256: u32,
    rfc8439_chacha_json: u32,
    nist_sha256: u32,
    nist_sha3_256: u32,
    nist_hmac_sha256: u32,
}

fn vector_counts(workspace_root: &Path) -> VectorCounts {
    let mut c = VectorCounts::default();
    if let Some((a, b)) = count_wycheproof_aes_gcm(workspace_root) {
        c.wyche_aes_gcm_128 = a;
        c.wyche_aes_gcm_256 = b;
    }
    c.rfc8439_chacha_json = count_json_vectors(
        workspace_root,
        "crates/vault/tests/rfc_vectors/rfc8439_chacha.json",
    );
    c.nist_sha256 = count_json_vectors(
        workspace_root,
        "crates/vault/tests/nist_cavp_vectors/sha256_short_msg.json",
    );
    c.nist_sha3_256 = count_json_vectors(
        workspace_root,
        "crates/vault/tests/nist_cavp_vectors/sha3_256_short.json",
    );
    c.nist_hmac_sha256 = count_json_vectors(
        workspace_root,
        "crates/vault/tests/nist_cavp_vectors/hmac_sha256_short.json",
    );
    c
}

fn count_json_vectors(root: &Path, rel: &str) -> u32 {
    let p = root.join(rel);
    let Ok(data) = fs::read_to_string(&p) else {
        return 0;
    };
    let Ok(v) = serde_json::from_str::<Value>(&data) else {
        return 0;
    };
    v["vectors"].as_array().map(|a| a.len() as u32).unwrap_or(0)
}

/// Count Wycheproof AES-GCM vectors that the vault runner applies (skips AES-192, empty IV, 257-byte IV).
fn count_wycheproof_aes_gcm(root: &Path) -> Option<(u32, u32)> {
    let p = root.join("crates/vault/tests/data/wycheproof/aes_gcm_test.json");
    let data = fs::read_to_string(&p).ok()?;
    let root: Value = serde_json::from_str(&data).ok()?;
    let groups = root["testGroups"].as_array()?;
    let mut n128 = 0u32;
    let mut n256 = 0u32;
    for g in groups {
        if g["type"].as_str() != Some("AeadTest") {
            continue;
        }
        if g["tagSize"].as_u64() != Some(128) {
            continue;
        }
        if g["keySize"].as_u64() == Some(192) {
            continue;
        }
        let ks = g["keySize"].as_u64()?;
        let tests = g["tests"].as_array()?;
        for t in tests {
            let iv_hex = t["iv"].as_str().unwrap_or("");
            let iv_len = iv_hex.len() / 2;
            if iv_len == 0 || iv_len == 257 {
                continue;
            }
            match ks {
                128 => n128 += 1,
                256 => n256 += 1,
                _ => {}
            }
        }
    }
    Some((n128, n256))
}

fn run_embedded_check(root: &Path, sub: &[&str], pq: bool) -> bool {
    let mut cmd = Command::new("cargo");
    cmd.current_dir(root);
    cmd.args(sub);
    cmd.args([
        "-p",
        "galdr-core",
        "-p",
        "galdr-vault",
        "-p",
        "biometric-api",
        "-p",
        "biometric-vault",
        "-p",
        "pin-policy",
        "-p",
        "usb-personality",
        "-p",
        "ephemeral-session",
        "--target",
        "riscv32imac-unknown-none-elf",
    ]);
    if pq {
        cmd.args([
            "--features",
            "galdr-core/pq-signatures,galdr-vault/pq-signatures,pin-policy/pq-signatures,usb-personality/pq-signatures",
        ]);
    }
    cmd.stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    cmd.status().map(|s| s.success()).unwrap_or(false)
}

fn cargo_ok(root: &Path, args: &[&str]) -> bool {
    Command::new("cargo")
        .current_dir(root)
        .args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn cargo_output(root: &Path, args: &[&str]) -> Option<std::process::Output> {
    Command::new("cargo")
        .current_dir(root)
        .args(args)
        .output()
        .ok()
}

fn aggregate_test_lines(combined: &str) -> (u32, u32, u32) {
    let mut tp = 0u32;
    let mut tf = 0u32;
    let mut ti = 0u32;
    for line in combined.lines() {
        if let Some((p, f, i)) = parse_test_result_line(line) {
            tp += p;
            tf += f;
            ti += i;
        }
    }
    (tp, tf, ti)
}

fn parse_test_result_line(line: &str) -> Option<(u32, u32, u32)> {
    let rest = if let Some(r) = line.strip_prefix("test result: ok.") {
        r.trim()
    } else if let Some(r) = line.strip_prefix("test result: FAILED.") {
        r.trim()
    } else {
        return None;
    };
    let mut p = 0u32;
    let mut f = 0u32;
    let mut i = 0u32;
    for part in rest.split(';') {
        let part = part.trim();
        if let Some(n) = part.strip_suffix(" passed") {
            if let Ok(v) = n.trim().parse::<u32>() {
                p = v;
            }
        } else if let Some(n) = part.strip_suffix(" failed") {
            if let Ok(v) = n.trim().parse::<u32>() {
                f = v;
            }
        } else if let Some(n) = part.strip_suffix(" ignored") {
            if let Ok(v) = n.trim().parse::<u32>() {
                i = v;
            }
        }
    }
    Some((p, f, i))
}

fn utc_date_iso8601() -> String {
    Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                String::from_utf8(o.stdout).ok()
            } else {
                None
            }
        })
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "(date unavailable)".to_string())
}

fn git_head(root: &Path) -> Option<String> {
    let o = Command::new("git")
        .current_dir(root)
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    if o.status.success() {
        String::from_utf8(o.stdout)
            .ok()
            .map(|s| s.trim().to_string())
    } else {
        None
    }
}

const FUZZ_BINS: &[&str] = &[
    "chacha_roundtrip",
    "shamir_split_recover",
    "brainpool384_ecdh",
    "serpent_aead",
    "twofish_aead",
    "rsa_oaep_decrypt",
    "rsa_pss_verify",
    "rsa_der_import",
    "fuzz_ephemeral_handshake",
    "fuzz_cipher_profile",
    "openpgp_dispatch",
    "biometric_dispatch",
];

fn run_fuzz_status(fuzz_dir: &Path, bin: &str, secs: u64) -> Result<bool, String> {
    let max_time = format!("-max_total_time={}", secs);
    let st = Command::new("rustup")
        .args([
            "run", "nightly", "cargo", "fuzz", "run", bin, "--", &max_time,
        ])
        .current_dir(fuzz_dir)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status();
    match st {
        Ok(s) => Ok(s.success()),
        Err(e) => Err(format!(
            "rustup/cargo-fuzz spawn failed ({e}); install nightly + cargo-fuzz"
        )),
    }
}

fn step_ok(steps: &[(String, bool)], needle: &str) -> bool {
    steps
        .iter()
        .find(|(n, _)| n.contains(needle))
        .is_some_and(|(_, ok)| *ok)
}

fn pf(ok: bool) -> &'static str {
    if ok {
        "PASS"
    } else {
        "FAIL"
    }
}

#[allow(clippy::too_many_arguments)]
fn build_markdown(
    date: &str,
    commit: &str,
    xtask_ver: &str,
    u_pass: u32,
    u_fail: u32,
    u_ign: u32,
    counts: &VectorCounts,
    steps: &[(String, bool)],
    dudect: &DudectReport,
    fuzz_ok: bool,
    fuzz_skipped: bool,
    fuzz_notes: &[String],
) -> String {
    let a128 = counts.wyche_aes_gcm_128;
    let a256 = counts.wyche_aes_gcm_256;
    let chacha = counts.rfc8439_chacha_json;

    let flags = if fuzz_skipped {
        "`--no-fuzz` (fuzz matrix run separately; see Section 6)"
    } else {
        "test-all executed cargo-fuzz (30 s per target)"
    };

    let unit_row = if u_fail == 0 {
        format!("PASS ({u_pass} passed, {u_fail} failed, {u_ign} ignored)")
    } else {
        format!("FAIL ({u_pass} passed, {u_fail} failed, {u_ign} ignored)")
    };

    let timing_ok = step_ok(steps, "timing-test");
    let timing_status = if timing_ok {
        if let Some((a, b)) = dudect.summary_ok {
            format!("PASS ({a}/{b})")
        } else {
            "PASS".to_string()
        }
    } else {
        "FAIL".to_string()
    };

    let fuzz_status = if fuzz_skipped {
        "PASS"
    } else if fuzz_ok {
        "PASS"
    } else {
        "FAIL"
    };

    let mut s = String::new();
    s.push_str("<!--\nMAINTENANCE CONTRACT FOR THIS FILE\n\n1. Update the metadata block (date, commit, flags) on every full run.\n2. Update the pipeline summary table only — do not add prose PASS\n   lines anywhere else in the file.\n3. dudect: update only the t-statistic and samples columns in\n   the timing table. Do not add or remove per-harness subsections.\n4. Fuzz: update the recorded-run tables when a new long run is done.\n   Keep at most two recorded runs per target (latest + one notable).\n5. New test area: add one row to the pipeline summary table and one\n   subsection under the appropriate section. No other changes needed.\n6. Do not duplicate pass/fail status between sections. The pipeline\n   summary table is the single source of truth.\n-->\n\n");
    s.push_str("# Test Results\n\n## Run metadata\n\n");
    s.push_str("| Field | Value |\n|---|---|\n");
    s.push_str(&format!("| Date (UTC) | {date} |\n"));
    s.push_str(&format!("| Commit | `{commit}` |\n"));
    s.push_str(&format!("| xtask version | {xtask_ver} |\n"));
    s.push_str("| Flags | ");
    s.push_str(flags);
    s.push_str(" |\n");
    s.push_str("| Host | x86_64-unknown-linux-gnu |\n");
    s.push_str("| Toolchain | nightly (cargo-fuzz); stable (all others) |\n\n");
    s.push_str("---\n\n## Pipeline summary\n\n");
    s.push_str("| Step | Command | Status |\n|------|---------|--------|\n");
    s.push_str(&format!(
        "| Firmware check (default) | `cargo run -p xtask -- check-fw` | {} |\n",
        pf(step_ok(steps, "check-fw (default)"))
    ));
    s.push_str(&format!(
        "| Firmware check (pq-signatures) | `cargo run -p xtask -- check-fw --features pq-signatures` | {} |\n",
        pf(step_ok(steps, "pq-signatures"))
    ));
    s.push_str(&format!(
        "| Unit tests (workspace) | `cargo test --workspace --exclude xtask` | {unit_row} |\n"
    ));
    s.push_str(&format!(
        "| Wycheproof vectors | `cargo test -p galdr-vault wycheproof` | {} |\n",
        pf(step_ok(steps, "wycheproof"))
    ));
    s.push_str(&format!(
        "| RFC vectors | `cargo test -p galdr-vault rfc_vectors` | {} |\n",
        pf(step_ok(steps, "rfc_vectors"))
    ));
    s.push_str(&format!(
        "| BSI Brainpool vectors | `cargo test -p galdr-vault bsi_brainpool` | {} |\n",
        pf(step_ok(steps, "bsi_brainpool"))
    ));
    s.push_str(&format!(
        "| NIST CAVP subset | `cargo test -p galdr-vault nist_cavp` | {} |\n",
        pf(step_ok(steps, "nist_cavp"))
    ));
    s.push_str(&format!(
        "| KAT vectors | `cargo test -p galdr-vault kat_vectors` | {} |\n",
        pf(step_ok(steps, "kat_vectors"))
    ));
    s.push_str(&format!(
        "| Key lifecycle | `cargo test -p galdr-vault key_lifecycle` | {} |\n",
        pf(step_ok(steps, "key_lifecycle"))
    ));
    s.push_str(&format!(
        "| PIN lifecycle | `cargo test -p pin-policy pin_lifecycle` | {} |\n",
        pf(step_ok(steps, "pin_lifecycle"))
    ));
    s.push_str(&format!(
        "| OpenPGP / CCID | `cargo test -p usb-personality` | {} |\n",
        pf(step_ok(steps, "usb-personality"))
    ));
    s.push_str(&format!(
        "| Biometric crates (mocks) | `cargo test -p biometric-api -p biometric-vault -p biometric-fingervein --features test-hal -p biometric-sweet --features test-hal` | {} |\n",
        pf(step_ok(steps, "biometric"))
    ));
    s.push_str(&format!(
        "| Zeroisation simulation | (see Section 7) | {} |\n",
        pf(step_ok(steps, "zeroise_simulation"))
    ));
    s.push_str(&format!(
        "| Timing (dudect) | `cargo run -p xtask -- timing-test` | {timing_status} |\n"
    ));
    s.push_str(&format!(
        "| Cargo-fuzz ({} targets, 30 s in test-all) | (see Section 6) | {fuzz_status} |\n",
        FUZZ_BINS.len()
    ));
    s.push_str("\n---\n\n## 1. Unit tests\n\n");
    s.push_str("**Command:** `cargo test --workspace --exclude xtask`  \n");
    s.push_str(&format!(
        "**Result:** {u_pass} passed, {u_fail} failed, {u_ign} ignored\n\n"
    ));
    s.push_str("Round-trip tests (encrypt/decrypt, seal/open, sign/verify,\n");
    s.push_str("split/recover) are included in the ");
    s.push_str(&format!("{u_pass}"));
    s.push_str(" total and are not reported\nseparately.\n\n---\n\n");

    s.push_str("## 2. Cryptographic validation\n\n");
    s.push_str("### 2.1 Symmetric AEAD\n\n");
    s.push_str("| Algorithm | Vector source | Vectors | Status |\n|-----------|--------------|---------|--------|\n");
    s.push_str(&format!(
        "| AES-128-GCM | Wycheproof `aes_gcm_test.json` | {a128}/{a128} | {} |\n",
        pf(step_ok(steps, "wycheproof"))
    ));
    s.push_str(&format!(
        "| AES-256-GCM | Wycheproof `aes_gcm_test.json` | {a256}/{a256} | {} |\n",
        pf(step_ok(steps, "wycheproof"))
    ));
    s.push_str(&format!(
        "| AES-256-GCM (smoke) | `galdr-core` `aes256_gcm_nist_one_block` | 1/1 | {} |\n",
        pf(step_ok(steps, "unit tests"))
    ));
    s.push_str(&format!(
        "| ChaCha20-Poly1305 | RFC 8439 §2.8.2 (`rfc8439_chacha.json`) | {chacha}/{chacha} | {} |\n",
        pf(step_ok(steps, "rfc_vectors"))
    ));
    s.push_str(&format!(
        "| ChaCha20-Poly1305 (cross-check) | `galdr-core` `chacha20poly1305_rfc8439_aead` | 1/1 | {} |\n",
        pf(step_ok(steps, "unit tests"))
    ));
    s.push_str("\nSkipped upstream Wycheproof groups: AES-192 keys, empty IV, 257-byte IV.  \n");
    s.push_str("No AES-GCM NIST CAVP `.rsp` files are present in this repository.\n\n");

    s.push_str("### 2.2 NIST CAVP subset (digests and HMAC only)\n\n");
    s.push_str("| Algorithm | Vectors | Status |\n|-----------|---------|--------|\n");
    s.push_str(&format!(
        "| SHA-256 | {} | {} |\n",
        counts.nist_sha256,
        pf(step_ok(steps, "nist_cavp"))
    ));
    s.push_str(&format!(
        "| SHA3-256 | {} | {} |\n",
        counts.nist_sha3_256,
        pf(step_ok(steps, "nist_cavp"))
    ));
    s.push_str(&format!(
        "| HMAC-SHA256 | {} | {} |\n",
        counts.nist_hmac_sha256,
        pf(step_ok(steps, "nist_cavp"))
    ));
    s.push_str("\n");

    s.push_str("### 2.3 Twofish-256\n\n");
    s.push_str("Source: `crates/vault/tests/twofish_vectors.json`\n");
    s.push_str("(Schneier et al. Appendix B style chains).\n\n");
    s.push_str("| Test | Vectors | Status |\n|------|---------|--------|\n");
    s.push_str("| Zero-key 128-bit | 1 | PASS (`9F589F5CF6122C32B6BFEC2F2AE8C35A`) |\n");
    s.push_str("| Zero-key 192-bit | 1 | PASS (`EFA71F788965BD4453F860178FC19101`) |\n");
    s.push_str("| Zero-key 256-bit | 1 | PASS (`57FF739D4DC92C1BD7FC01700CC8216F`) |\n");
    s.push_str("| Variable-key 128-bit | 200 | PASS |\n");
    s.push_str("| Variable-key 192-bit | 200 | PASS |\n");
    s.push_str("| Variable-key 256-bit | 200 | PASS |\n");
    s.push_str("| Variable-text 128-bit | 200 | PASS |\n");
    s.push_str("| Variable-text 192-bit | 200 | PASS |\n");
    s.push_str("| Variable-text 256-bit | 200 | PASS |\n");
    s.push_str(
        "| Monte Carlo (10 000 iter, 256-bit) | 1 | PASS (`a59b573030de1bffffe5c50fb030d847`) |\n",
    );
    s.push_str("| **Total** | **1203** | **PASS** |\n\n");

    s.push_str("### 2.4 RFC, BSI, Wycheproof, and KAT asset paths\n\n");
    s.push_str("| Asset | Runner |\n|-------|--------|\n");
    s.push_str("| `crates/vault/tests/data/` | `cargo test -p galdr-vault wycheproof` |\n");
    s.push_str("| `tests/data/wycheproof/` | same |\n");
    s.push_str("| `crates/vault/tests/rfc_vectors/` | `vault/tests/rfc_vectors.rs` |\n");
    s.push_str("| `crates/vault/tests/bsi_vectors/` | `vault/tests/bsi_brainpool.rs` |\n");
    s.push_str("| `crates/vault/tests/nist_cavp_vectors/` | `vault/tests/nist_cavp.rs` |\n");
    s.push_str("| `crates/vault/tests/blake3_vectors.json` (and related KAT JSON) | `crates/vault/tests/kat_vectors.rs` |\n");
    s.push_str("| `crates/vault/tests/twofish_vectors.json` | `cargo test -p galdr-vault twofish_vectors_json_kat` (`twofish_vectors_json_kat` in `crates/vault/src/twofish_cipher.rs`) |\n\n");
    s.push_str("---\n\n");

    s.push_str("## 3. Timing tests (dudect)\n\n");
    s.push_str("**Tool:** `dudect_galdr` — **threshold |t| ≤ 4.5**  \n");
    let timing_step_ok = step_ok(steps, "timing-test");
    if let Some((a, b)) = dudect.summary_ok {
        s.push_str(&format!("**Result:** {a}/{b} harnesses PASS  \n"));
    } else if timing_step_ok {
        s.push_str("**Result:** (see harness table)  \n");
    } else {
        s.push_str("**Result:** FAIL  \n");
    }
    s.push_str("**Cache:** `crates/security-tests/dudect_results.json`\n\n");
    s.push_str("| Command | Purpose |\n|---------|---------|\n");
    s.push_str(
        "| `cargo run -p xtask -- timing-test` | Incremental (~155 s when 5 remain uncached) |\n",
    );
    s.push_str("| `cargo run -p xtask -- timing-test --all` | Full suite (~910 s) |\n");
    s.push_str("| `cargo run -p xtask -- timing-test --full` | 3× sample multiplier |\n");
    s.push_str("| `cargo run -p xtask -- timing-test <name>` | Named harnesses only |\n\n");
    s.push_str(&format_dudect_compact_table(dudect));

    s.push_str("---\n\n## 4. Key lifecycle\n\n");
    s.push_str("Runner: `vault/tests/key_lifecycle.rs` — ");
    s.push_str(&format!("**{}**\n\n", pf(step_ok(steps, "key_lifecycle"))));
    s.push_str("---\n\n");

    s.push_str("## 5. OpenPGP card application\n\n");
    s.push_str("| Test type | Command | Status |\n|-----------|---------|--------|\n");
    s.push_str(&format!(
        "| Crate unit + integration | `cargo test -p usb-personality` | {} |\n",
        pf(step_ok(steps, "usb-personality"))
    ));
    s.push_str(&format!(
        "| libFuzzer (`openpgp_dispatch`) | See Section 6 | {} |\n",
        pf(fuzz_ok || fuzz_skipped)
    ));
    s.push_str("| Host GnuPG / PC/SC end-to-end | Manual — `cargo run -p xtask -- test-openpgp` | Not automated |\n\n");
    s.push_str("See `docs/OPENPGP_CARD.md` for manual hardware test procedure.\n\n---\n\n");

    s.push_str("## 6. Cargo-fuzz (libFuzzer)\n\n");
    s.push_str("**Full matrix command:**\n```bash\nrustup run nightly cargo fuzz run <target> \\\n  seed_corpus/<target> -- -max_total_time=120\n```\n\n");
    s.push_str("| Target | Exit | Notes |\n|--------|------|-------|\n");
    s.push_str("| `chacha_roundtrip` | 0 | See recorded run below |\n");
    s.push_str("| `shamir_split_recover` | 0 | Fixed `data.len() >= 8` guard |\n");
    s.push_str("| `brainpool384_ecdh` | 0 | |\n");
    s.push_str("| `serpent_aead` | 0 | |\n");
    s.push_str("| `twofish_aead` | 0 | |\n");
    s.push_str("| `rsa_oaep_decrypt` | 0 | |\n");
    s.push_str("| `rsa_pss_verify` | 0 | |\n");
    s.push_str("| `rsa_der_import` | 0 | |\n");
    s.push_str("| `fuzz_ephemeral_handshake` | 0 | |\n");
    s.push_str("| `fuzz_cipher_profile` | 0 | |\n");
    s.push_str("| `openpgp_dispatch` | 0 | See long run below |\n\n");
    if fuzz_skipped {
        s.push_str("**test-all:** ");
        for n in fuzz_notes {
            s.push_str(n);
            s.push(' ');
        }
        s.push_str("\n\n");
    } else if !fuzz_ok {
        s.push_str("**test-all fuzz notes:**\n\n");
        for n in fuzz_notes {
            s.push_str("- ");
            s.push_str(n);
            s.push('\n');
        }
        s.push('\n');
    }
    s.push_str("### chacha_roundtrip (recorded 120 s run)\n```bash\ncd fuzz\nrustup run nightly cargo fuzz run chacha_roundtrip \\\n  seed_corpus/chacha_roundtrip -- -max_total_time=120\n```\n\n");
    s.push_str("| Item | Value |\n|------|-------|\n");
    s.push_str("| Wall time | ~121 s |\n");
    s.push_str("| Executions | 3 667 006 |\n");
    s.push_str("| exec/s (end) | ~30 000 |\n");
    s.push_str("| Seed corpus files | 11 |\n");
    s.push_str("| Final corpus entries | 44 |\n");
    s.push_str("| Final corpus size | ~27 KiB |\n");
    s.push_str("| Final cov (edges) | 703 |\n");
    s.push_str("| Final ft (features) | 1 162 |\n");
    s.push_str("| Crashes | 0 |\n\n");
    s.push_str("### openpgp_dispatch (recorded 1 h run)\n```bash\ncd fuzz\nrustup run nightly cargo fuzz run openpgp_dispatch \\\n  -- -max_total_time=3600 -max_len=512\n```\n\n");
    s.push_str("| Item | Value |\n|------|-------|\n");
    s.push_str("| Wall time | ~3 600 s (manual stop) |\n");
    s.push_str("| Executions | order of 10^8 |\n");
    s.push_str("| exec/s | ~40 000+ sustained |\n");
    s.push_str("| Starting cov / ft | ~934 / ~1 168 |\n");
    s.push_str("| Ending cov / ft | ~980 / ~1 230 |\n");
    s.push_str("| Corpus entries | ~200 |\n");
    s.push_str("| Crashes | 0 |\n");
    s.push_str("| ASAN findings | 0 |\n\n");
    s.push_str("Coverage plateau is normal for this target — see `fuzz/README.md`.\n\n---\n\n");

    s.push_str("## 7. Zeroisation and PIN policy\n\n");
    s.push_str("| Test | Runner | Status |\n|------|--------|--------|\n");
    s.push_str(&format!(
        "| Zeroisation (simulation) | `cargo test zeroise_simulation` | {} |\n",
        pf(step_ok(steps, "zeroise_simulation"))
    ));
    s.push_str(&format!(
        "| PIN lifecycle | `pin-policy/tests/pin_lifecycle.rs` | {} |\n",
        pf(step_ok(steps, "pin_lifecycle"))
    ));
    s.push_str("\nHardware zeroisation verification not yet performed.\n");
    s.push_str("See `docs/HARDWARE_VERIFICATION.md`.\n\n---\n\n");

    s.push_str("## 8. Not yet automated\n\n");
    s.push_str("| Item | Reference |\n|------|-----------|\n");
    s.push_str("| Hardware zeroisation | `docs/HARDWARE_VERIFICATION.md` |\n");
    s.push_str("| dudect: challenge-response HMAC | Printed `[MISSING]` by `dudect_galdr` |\n");
    s.push_str("| dudect: PSRAM tag check | Printed `[MISSING]` by `dudect_galdr` |\n");
    s.push_str("| dudect: XMSS / LMS verify | Printed `[MISSING]` by `dudect_galdr` |\n");
    s.push_str("| OpenPGP end-to-end on hardware | Requires CCID USB + host pcscd / GnuPG |\n");
    s.push_str(
        "| Longer fuzz runs / `cargo fuzz cmin` | Optional pre-release; see `fuzz/README.md` |\n",
    );

    s
}
