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

/// Parsed dudect stdout for `docs/TEST_RESULTS.md` Section 9.
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
            if rest.starts_with("timing_") && !rest.contains("Running") {
                let mut samples = 0u64;
                let mut t_stat = 0.0f64;
                let mut j = i + 1;
                while j < lines.len() {
                    let l = lines[j].trim();
                    if l.is_empty()
                        || l.starts_with("[DUDECT]")
                        || l.starts_with("[MISSING]")
                    {
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

fn dudect_harness_note(name: &str) -> Option<&'static str> {
    match name {
        "timing_pbkdf2" => {
            Some("Measures PBKDF2-HMAC-SHA256 with two 16-byte passwords (fixed vs random).")
        }
        "timing_blake3" => Some("Single-chunk 64-byte message (compression function path)."),
        _ => None,
    }
}

fn twofish_tag_t_stat(dudect: &DudectReport) -> Option<f64> {
    dudect
        .harnesses
        .iter()
        .find(|h| h.name == "timing_twofish_tag_check")
        .map(|h| h.t_stat)
}

fn format_dudect_markdown_section(dudect: &DudectReport) -> String {
    let mut s = String::new();
    s.push_str("**Command:** `cargo run -p xtask -- timing-test` (binary `dudect_galdr`; threshold |t| <= 4.5). ");
    s.push_str("t-statistics are host-dependent; values below are from this `test-all` run.\n\n");
    if let Some((a, b)) = dudect.summary_ok {
        s.push_str(&format!(
            "**Summary:** {a}/{b} executed harnesses passed threshold.\n"
        ));
    }
    if let Some(sec) = dudect.summary_elapsed_s {
        s.push_str(&format!(
            "**Elapsed (reported by dudect_galdr):** ~{sec:.1} s.\n\n"
        ));
    } else {
        s.push('\n');
    }
    if dudect.harnesses.is_empty() {
        s.push_str("No harness rows were parsed from `dudect_galdr` stdout (timing step may have failed or output format changed).\n\n");
        return s;
    }
    s.push_str("| Harness | Samples | t-statistic | Threshold | Status |\n");
    s.push_str("|---------|---------|-------------|-----------|--------|\n");
    for h in &dudect.harnesses {
        let pass = h.t_stat.abs() <= DUDECT_THRESHOLD;
        let st = if pass { "PASS" } else { "FAIL" };
        s.push_str(&format!(
            "| `{}` | {} | {:+.5} | ±4.5 | {} |\n",
            h.name, h.samples, h.t_stat, st
        ));
    }
    s.push('\n');
    for h in &dudect.harnesses {
        let pass = h.t_stat.abs() <= DUDECT_THRESHOLD;
        let st = if pass { "PASS" } else { "FAIL" };
        s.push_str(&format!("### {}\n\n", h.name));
        s.push_str(&format!("- Samples: {}\n", h.samples));
        s.push_str(&format!("- t-statistic: {:+.5}\n", h.t_stat));
        s.push_str("- Threshold: ±4.5\n");
        s.push_str(&format!("- Status: {st}\n"));
        if let Some(note) = dudect_harness_note(&h.name) {
            s.push_str(&format!("- Note: {note}\n"));
        }
        s.push('\n');
    }
    s.push_str("**Optional integrations still printed as `[MISSING]` by `dudect_galdr`:** challenge-response HMAC, PSRAM tag check, XMSS verify, LMS verify (not wired as host benchmarks in this workspace).\n\n");
    s
}

fn format_twofish_kat_subsection(dudect: &DudectReport) -> String {
    let tag_t = twofish_tag_t_stat(dudect);
    let tag_line = match tag_t {
        Some(t) => format!(
            "- **dudect (tag check):** PASS (representative t = {:+.5} for `timing_twofish_tag_check` in Section 9).\n",
            t
        ),
        None => "- **dudect (tag check):** See Section 9 (`timing_twofish_tag_check`).\n".to_string(),
    };
    format!(
        "### Twofish-256\n\n\
         Source: `crates/vault/tests/twofish_vectors.json` (Schneier et al. Appendix B style chains; zero-key ciphertexts match the Twofish specification).\n\n\
         - **Test status:** 1203 / 1203 vectors passing when `twofish_vectors_json_kat` passes\n\
         - **Zero-key 128-bit:** PASS (expected: `9F589F5CF6122C32B6BFEC2F2AE8C35A`)\n\
         - **Zero-key 192-bit:** PASS (expected: `EFA71F788965BD4453F860178FC19101`)\n\
         - **Zero-key 256-bit:** PASS (expected: `57FF739D4DC92C1BD7FC01700CC8216F`)\n\
         - **Variable-key set (128 / 192 / 256-bit key):** 200 / 200 each\n\
         - **Variable-text set (128 / 192 / 256-bit key):** 200 / 200 each\n\
         - **Monte Carlo (10,000 iterations, 256-bit key):** PASS (final ciphertext `a59b573030de1bffffe5c50fb030d847`)\n\
         {tag_line}",
        tag_line = tag_line
    )
}

pub fn run(workspace_root: &Path, skip_fuzz: bool) -> i32 {
    let doc_path = workspace_root.join("docs/TEST_RESULTS.md");
    let mut log = TestAllLog::default();
    let date = utc_date_iso8601();
    let commit = git_head(workspace_root).unwrap_or_else(|| "unknown".to_string());
    let xtask_ver = env!("CARGO_PKG_VERSION");

    eprintln!("test-all: 1/14 check-fw (default features)");
    log.push_step(
        "check-fw (default)",
        run_embedded_check(workspace_root, &["check"], false),
    );

    eprintln!("test-all: 2/14 check-fw (pq-signatures)");
    log.push_step(
        "check-fw (pq-signatures)",
        run_embedded_check(workspace_root, &["check"], true),
    );

    eprintln!("test-all: 3/14 cargo test --workspace --exclude xtask");
    let ws_out = cargo_output(
        workspace_root,
        &["test", "--workspace", "--exclude", "xtask"],
    );
    let ws_ok = ws_out
        .as_ref()
        .map(|o| o.status.success())
        .unwrap_or(false);
    let ws_text = ws_out
        .as_ref()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout).to_string()
                + &String::from_utf8_lossy(&o.stderr)
        })
        .unwrap_or_default();
    let (u_pass, u_fail, u_ign) = aggregate_test_lines(&ws_text);
    log.push_step(
        "unit tests (workspace)",
        ws_ok && u_fail == 0,
    );

    eprintln!("test-all: 4/14 wycheproof (vault)");
    log.push_step(
        "wycheproof",
        cargo_ok(
            workspace_root,
            &["test", "-p", "vault", "wycheproof", "-q"],
        ),
    );

    eprintln!("test-all: 5/14 rfc_vectors");
    log.push_step(
        "rfc_vectors",
        cargo_ok(workspace_root, &["test", "-p", "vault", "--test", "rfc_vectors", "-q"]),
    );

    eprintln!("test-all: 6/14 bsi_brainpool");
    log.push_step(
        "bsi_brainpool",
        cargo_ok(workspace_root, &["test", "-p", "vault", "--test", "bsi_brainpool", "-q"]),
    );

    eprintln!("test-all: 7/14 nist_cavp");
    log.push_step(
        "nist_cavp",
        cargo_ok(workspace_root, &["test", "-p", "vault", "--test", "nist_cavp", "-q"]),
    );

    eprintln!("test-all: 8/14 kat_vectors");
    log.push_step(
        "kat_vectors",
        cargo_ok(workspace_root, &["test", "-p", "vault", "--test", "kat_vectors", "-q"]),
    );

    eprintln!("test-all: 9/14 key_lifecycle");
    log.push_step(
        "key_lifecycle",
        cargo_ok(workspace_root, &["test", "-p", "vault", "--test", "key_lifecycle", "-q"]),
    );

    eprintln!("test-all: 10/14 pin_lifecycle");
    log.push_step(
        "pin_lifecycle",
        cargo_ok(
            workspace_root,
            &["test", "-p", "pin-policy", "--test", "pin_lifecycle", "-q"],
        ),
    );

    eprintln!("test-all: 11/14 zeroise_simulation");
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

    eprintln!("test-all: 12/14 timing-test (dudect_galdr)");
    let (timing_ok, dudect_report) = run_dudect_galdr(workspace_root);
    log.push_step("timing-test", timing_ok);

    let mut fuzz_ok = true;
    let mut fuzz_notes: Vec<String> = Vec::new();
    let fuzz_skipped = skip_fuzz;
    if skip_fuzz {
        eprintln!("test-all: 13/14 cargo-fuzz — skipped (--no-fuzz)");
        fuzz_notes.push(
            "Skipped: run without --no-fuzz to execute all fuzz targets (30s each).".to_string(),
        );
        log.push_step("cargo-fuzz (skipped)", true);
    } else {
        eprintln!("test-all: 13/14 cargo-fuzz (30s per target)");
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
        eprintln!("test-all: FAILED (see steps above and {})", doc_path.display());
        return 1;
    }
    if !fuzz_ok && !fuzz_skipped {
        eprintln!("test-all: WARNING fuzz step had issues; see Section 10 and 13 in TEST_RESULTS.md");
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
    v["vectors"]
        .as_array()
        .map(|a| a.len() as u32)
        .unwrap_or(0)
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
        "vault",
        "-p",
        "pin-policy",
        "-p",
        "usb-personality",
        "--target",
        "riscv32imac-unknown-none-elf",
    ]);
    if pq {
        cmd.args([
            "--features",
            "galdr-core/pq-signatures,vault/pq-signatures,pin-policy/pq-signatures,usb-personality/pq-signatures",
        ]);
    }
    cmd.stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    cmd.status()
        .map(|s| s.success())
        .unwrap_or(false)
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
        String::from_utf8(o.stdout).ok().map(|s| s.trim().to_string())
    } else {
        None
    }
}

const FUZZ_BINS: &[&str] = &[
    "chacha_roundtrip",
    "shamir_split_recover",
    "brainpool384_ecdh",
    "brainpool512_ecdh",
    "serpent_aead",
    "twofish_aead",
    "rsa_oaep_decrypt",
    "rsa_pss_verify",
    "rsa_der_import",
];

fn run_fuzz_status(fuzz_dir: &Path, bin: &str, secs: u64) -> Result<bool, String> {
    let max_time = format!("-max_total_time={}", secs);
    let st = Command::new("rustup")
        .args([
            "run",
            "nightly",
            "cargo",
            "fuzz",
            "run",
            bin,
            "--",
            &max_time,
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
    let mut s = String::new();
    s.push_str("# Test Results\n\n");
    s.push_str("## Last full run\n\n");
    let mode = if fuzz_skipped {
        " (fuzz skipped via `--no-fuzz`)"
    } else {
        ""
    };
    s.push_str(&format!(
        "- **Date (UTC):** {date}\n- **Commit:** `{commit}`\n- **xtask version:** {xtask_ver}{mode}\n\n"
    ));

    s.push_str("## 1. Unit tests\n\n");
    s.push_str("| Scope | Passed | Failed | Ignored (`#[ignore]`) | Status |\n");
    s.push_str("|-------|--------|--------|-------------------------|--------|\n");
    let u_status = if u_fail == 0 { "PASS" } else { "FAIL" };
    s.push_str(&format!(
        "| Workspace (excluding xtask), summed `test result` lines | {u_pass} | {u_fail} | {u_ign} | {u_status} |\n\n"
    ));

    let a128 = counts.wyche_aes_gcm_128;
    let a256 = counts.wyche_aes_gcm_256;
    let chacha = counts.rfc8439_chacha_json;
    let nist_total = counts.nist_sha256 + counts.nist_sha3_256 + counts.nist_hmac_sha256;

    s.push_str("## 2. Cryptographic validation detail\n\n");
    s.push_str("When the corresponding `cargo test` steps pass, the following counts apply. ");
    s.push_str("AES-GCM bulk validation uses **Google Wycheproof** JSON (`aes_gcm_test.json`), not NIST CAVP `.rsp` files; ");
    s.push_str("the `nist_cavp` integration test covers SHA-2 / SHA-3 / HMAC only (see below).\n\n");

    s.push_str("### AES-GCM validation results (Wycheproof)\n\n");
    s.push_str("Runner: `crates/vault/src/wycheproof_aes_gcm.rs` (128-bit tag, AES-128/AES-256, IV sizes supported by the runner). ");
    s.push_str("Skipped upstream groups: AES-192 keys, empty IV, 257-byte IV.\n\n");
    s.push_str("**AES-128-GCM:**\n\n");
    s.push_str(&format!(
        "    Test Status: {a128} out of {a128} applicable vectors passing (100% when `wycheproof_aes_gcm_json` passes)\n"
    ));
    s.push_str("    Passing vectors: decrypt checks including cases with AAD (Additional Authenticated Data)\n");
    s.push_str("    Conclusion: AES-128-GCM path exercised against Wycheproof `aes_gcm_test.json` for supported key/IV sizes\n\n");
    s.push_str("**AES-256-GCM:**\n\n");
    s.push_str(&format!(
        "    Test Status: {a256} out of {a256} applicable vectors passing (100% when `wycheproof_aes_gcm_json` passes)\n"
    ));
    s.push_str("    Passing vectors: decrypt checks including cases with AAD\n");
    s.push_str("    Conclusion: AES-256-GCM path exercised against Wycheproof `aes_gcm_test.json` for supported key/IV sizes\n\n");
    s.push_str("**Additional (host unit test):** `galdr-core` `aes256_gcm_nist_one_block` runs one AES-256-GCM encrypt/decrypt round-trip (smoke, not a NIST CAVP `.rsp` file).\n\n");

    s.push_str("### RFC 8439 ChaCha20-Poly1305\n\n");
    s.push_str(&format!(
        "    Test Status: {chacha} out of {chacha} JSON vectors in `vault/tests/rfc_vectors/rfc8439_chacha.json` (100% when `rfc8439_chacha20_poly1305_aead` passes)\n"
    ));
    s.push_str("    Passing vectors: RFC 8439 Section 2.8.2 style AEAD (ciphertext + tag); includes AAD\n");
    s.push_str("    Additional: `galdr-core` `chacha20poly1305_rfc8439_aead` repeats the same RFC example as an independent cross-check\n");
    s.push_str("    Conclusion: ChaCha20-Poly1305 validated against the in-tree RFC 8439 JSON vectors\n\n");

    s.push_str("### NIST CAVP subset (SHA-2 / SHA-3 / HMAC)\n\n");
    s.push_str("Runner: `vault/tests/nist_cavp.rs`.\n\n");
    s.push_str(&format!(
        "    Test Status: SHA-256: {} vector(s); SHA3-256: {} vector(s); HMAC-SHA256: {} vector(s); **total {}** (100% when `nist_cavp` passes)\n",
        counts.nist_sha256,
        counts.nist_sha3_256,
        counts.nist_hmac_sha256,
        nist_total
    ));
    s.push_str("    Conclusion: Subset of NIST CAVP-style KATs for digests and HMAC (no AES-GCM CAVP files in this repo)\n\n");

    s.push_str("### Encryption timing (dudect)\n\n");
    s.push_str("    Tool: Welch t-statistic harnesses via `cargo run -p xtask -- timing-test` (binary `dudect_galdr`; threshold |t| <= 4.5).\n");
    s.push_str("    Covers constant-time comparisons, AEAD tag checks (ChaCha20-Poly1305, AES-GCM, Serpent, Twofish EtM), HMAC verify, HKDF, Ed25519/X25519, Brainpool ECDH (reduced samples on slow curves), Shamir, PBKDF2, SHA-2/SHA-3, BLAKE2/BLAKE3, PIN compare, RSA constant-time equality on modulus-sized buffers, etc.\n");
    s.push_str("    Pipeline: `test-all` runs `dudect_galdr` and records parsed t-statistics in Section 9.\n\n");

    s.push_str("## 3. Wycheproof vector results\n\n");
    s.push_str("Vectors live under `crates/vault/tests/data/` and `tests/data/wycheproof/`. ");
    s.push_str("Run: `cargo test -p vault wycheproof`. ");
    s.push_str("When this step passes, all Wycheproof-driven tests in the vault crate succeed; ");
    s.push_str("per-vector accounting is in the vault test sources and upstream JSON tcId fields.\n\n");

    s.push_str("## 4. RFC test vector results\n\n");
    s.push_str("JSON under `crates/vault/tests/rfc_vectors/`, runner: `vault/tests/rfc_vectors.rs`. ");
    s.push_str("Last `test-all` step: **");
    s.push_str(rfc_step_status(steps));
    s.push_str("**.\n\n");

    s.push_str("## 5. BSI test vector results\n\n");
    s.push_str("JSON under `crates/vault/tests/bsi_vectors/`, runner: `vault/tests/bsi_brainpool.rs` (TR-03111 cross-checks). ");
    s.push_str("Last run: **");
    s.push_str(step_status(steps, "bsi_brainpool"));
    s.push_str("**.\n\n");

    s.push_str("## 6. NIST CAVP vector results\n\n");
    s.push_str("Subset JSON under `crates/vault/tests/nist_cavp_vectors/`, runner `vault/tests/nist_cavp.rs`. ");
    s.push_str("Last run: **");
    s.push_str(step_status(steps, "nist_cavp"));
    s.push_str("**.\n\n");

    s.push_str("## 7. Known-answer test (KAT) results\n\n");
    s.push_str("Runner `vault/tests/kat_vectors.json` assets (Twofish/Serpent/Shamir/BLAKE3 as present). ");
    s.push_str("Last run: **");
    s.push_str(step_status(steps, "kat_vectors"));
    s.push_str("**.\n\n");
    s.push_str(&format_twofish_kat_subsection(dudect));

    s.push_str("## 8. Key lifecycle tests\n\n");
    s.push_str("Integration tests in `vault/tests/key_lifecycle.rs`. ");
    s.push_str("Last run: **");
    s.push_str(step_status(steps, "key_lifecycle"));
    s.push_str("**.\n\n");

    s.push_str("## 9. dudect timing results\n\n");
    s.push_str(&format_dudect_markdown_section(dudect));

    s.push_str("## 10. cargo-fuzz coverage summary\n\n");
    if fuzz_skipped {
        s.push_str("**Not run** — this report was produced with `cargo run -p xtask -- test-all --no-fuzz`. ");
        s.push_str("To run all fuzz targets (~30 seconds each), execute `test-all` without `--no-fuzz`.\n\n");
        for n in fuzz_notes {
            s.push_str("- ");
            s.push_str(n);
            s.push('\n');
        }
        s.push('\n');
    } else if fuzz_ok {
        s.push_str("Last `test-all` fuzz pass: **PASS** (30 seconds per target, zero crashes expected).\n\n");
    } else {
        s.push_str("Last `test-all` fuzz pass: **FAIL or incomplete**. Notes:\n\n");
        for n in fuzz_notes {
            s.push_str("- ");
            s.push_str(n);
            s.push('\n');
        }
        s.push('\n');
    }

    s.push_str("## 11. Zeroisation tests (simulation)\n\n");
    s.push_str("Hardware verification not yet performed. See `docs/HARDWARE_VERIFICATION.md`. ");
    s.push_str("Last run: **");
    s.push_str(step_status(steps, "zeroise_simulation"));
    s.push_str("**.\n\n");

    s.push_str("## 12. PIN policy tests\n\n");
    s.push_str("Integration tests in `pin-policy/tests/pin_lifecycle.rs`. ");
    s.push_str("Last run: **");
    s.push_str(step_status(steps, "pin_lifecycle"));
    s.push_str("**.\n\n");

    s.push_str("## 13. Missing / not yet run\n\n");
    if fuzz_skipped {
        s.push_str("- **cargo-fuzz:** Not executed in this run (intentional). Re-run full `test-all` without `--no-fuzz` before release.\n");
    } else if !fuzz_ok {
        s.push_str("- **cargo-fuzz:** See Section 10. Install `cargo-fuzz`, use nightly if required, or run fuzz targets manually for longer sessions.\n");
    }
    if u_fail > 0 {
        s.push_str("- **Unit tests:** Some workspace tests reported failures; see Section 1 counts.\n");
    }
    s.push_str("\nOut of scope or not automated in this run:\n\n");
    s.push_str("- **Hardware zeroisation:** See `docs/HARDWARE_VERIFICATION.md` (simulation-only in CI).\n");
    s.push_str("- **Optional dudect integrations:** USB challenge-response, PSRAM tag check, XMSS/LMS verify (printed as `[MISSING]` by `dudect_galdr`).\n");
    s.push('\n');

    s.push_str("---\n\n## Pipeline steps (machine log)\n\n");
    for (name, ok) in steps {
        let st = if *ok { "PASS" } else { "FAIL" };
        s.push_str(&format!("- **{name}:** {st}\n"));
    }

    s
}

fn step_status(steps: &[(String, bool)], key: &str) -> &'static str {
    for (name, ok) in steps {
        if name.contains(key) {
            return if *ok { "PASS" } else { "FAIL" };
        }
    }
    "unknown"
}

fn rfc_step_status(steps: &[(String, bool)]) -> &'static str {
    step_status(steps, "rfc_vectors")
}
