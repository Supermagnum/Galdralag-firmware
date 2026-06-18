//! Build recipes for Galdr firmware (Baochip-1x, Xous target triple).
//!
//! **TODO (developer):** Pin `rustc`, `cargo`, linker scripts, and `RUSTFLAGS` for reproducible
//! hashes per Baochip README verification section.

mod test_all;
mod timing_test;

use std::path::Path;
use std::process::{Command, Stdio};

fn main() {
    let mut a = std::env::args().skip(1);
    match a.next().as_deref() {
        Some("build-fw") => run_embedded(&["build"]),
        Some("check-fw") => run_embedded(&["check"]),
        Some("test-profiles") => {
            let st = Command::new("cargo")
                .args(["test", "-p", "cipher-profile", "--", "--test-threads=1"])
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .status()
                .expect("cargo");
            std::process::exit(st.code().unwrap_or(1));
        }
        Some("test-session") => {
            let st = Command::new("cargo")
                .args([
                    "test",
                    "-p",
                    "ephemeral-session",
                    "--",
                    "--test-threads=1",
                ])
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .status()
                .expect("cargo");
            std::process::exit(st.code().unwrap_or(1));
        }
        Some("test-host") => {
            let st = Command::new("cargo")
                .args(["test", "--workspace", "--exclude", "xtask"])
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .status()
                .expect("cargo");
            std::process::exit(st.code().unwrap_or(1));
        }
        Some("test-biometric") => {
            let st = Command::new("cargo")
                .args([
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
                    "--",
                    "--test-threads=1",
                ])
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .status()
                .expect("cargo");
            std::process::exit(st.code().unwrap_or(1));
        }
        Some("test-crypto") => {
            let st = Command::new("cargo")
                .args([
                    "test",
                    "-p",
                    "galdr-vault",
                    "-p",
                    "security-tests",
                    "--",
                    "--test-threads=1",
                ])
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .status()
                .expect("cargo");
            std::process::exit(st.code().unwrap_or(1));
        }
        Some("wycheproof") => {
            let st = Command::new("cargo")
                .args(["test", "-p", "galdr-vault", "wycheproof"])
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .status()
                .expect("cargo");
            std::process::exit(st.code().unwrap_or(1));
        }
        Some("timing-test") => {
            let mut rest: Vec<String> = a.collect();
            if rest.first().map(|s| s.as_str()) == Some("biometric") {
                rest.remove(0);
                let mut v = vec![
                    "dudect_session_token_verify_constant_time".to_string(),
                    "dudect_template_decrypt_constant_time".to_string(),
                    "dudect_signature_verify_constant_time".to_string(),
                ];
                v.append(&mut rest);
                rest = v;
            }
            let code = timing_test::run(workspace_root(), rest.into_iter());
            std::process::exit(code);
        }
        Some("fuzz") => {
            let name = a
                .next()
                .unwrap_or_else(|| "chacha_roundtrip".to_string());
            let duration_secs = a.next().and_then(|s| s.parse::<u64>().ok()).unwrap_or(60);
            run_fuzz_target(fuzz_bin_name(&name), duration_secs);
        }
        Some("fuzz-chacha") => {
            let duration_secs = a.next().and_then(|s| s.parse::<u64>().ok()).unwrap_or(60);
            run_fuzz_target("chacha_roundtrip", duration_secs);
        }
        Some("fuzz-shamir") => {
            let duration_secs = a.next().and_then(|s| s.parse::<u64>().ok()).unwrap_or(60);
            run_fuzz_target("shamir_split_recover", duration_secs);
        }
        Some("bench-rsa") => {
            let st = Command::new("cargo")
                .args([
                    "test",
                    "-p",
                    "galdr-vault",
                    "rsa_perf_baseline",
                    "--",
                    "--ignored",
                    "--nocapture",
                ])
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .status()
                .expect("cargo");
            std::process::exit(st.code().unwrap_or(1));
        }
        Some("test-all") => {
            let skip_fuzz = a.any(|s| s == "--no-fuzz");
            let code = test_all::run(workspace_root(), skip_fuzz);
            std::process::exit(code);
        }
        Some("test-openpgp") => {
            let gpg_ok = Command::new("gpg")
                .arg("--version")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if gpg_ok {
                eprintln!(
                    "test-openpgp: gpg is available. Full OpenPGP/CCID interoperability requires a USB CCID device and host pcscd; see docs/OPENPGP_CARD.md."
                );
            } else {
                eprintln!("test-openpgp: gpg not found on PATH; skipping host interoperability checks.");
            }
            std::process::exit(0);
        }
        _ => {
            eprintln!(
                "usage: cargo run -p xtask -- <build-fw|check-fw|test-session|test-profiles|test-host|test-crypto|test-biometric|test-all [--no-fuzz]|test-openpgp|wycheproof|timing-test [biometric] [--all] [--full] [HARNESS...]|bench-rsa|fuzz [TARGET] [SECS]|fuzz-chacha [SECS]|fuzz-shamir [SECS]>"
            );
            std::process::exit(2);
        }
    }
}

fn workspace_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask crate must live under workspace root")
}

fn fuzz_bin_name(name: &str) -> &str {
    match name {
        "chacha" | "chacha_roundtrip" => "chacha_roundtrip",
        "shamir" | "shamir_split_recover" => "shamir_split_recover",
        "brainpool384-ecdh" | "brainpool384_ecdh" => "brainpool384_ecdh",
        "brainpool512-ecdh" | "brainpool512_ecdh" => "brainpool512_ecdh",
        "serpent-aead" | "serpent_aead" => "serpent_aead",
        "twofish-aead" | "twofish_aead" => "twofish_aead",
        "rsa-oaep-decrypt" | "rsa_oaep_decrypt" => "rsa_oaep_decrypt",
        "rsa-pss-verify" | "rsa_pss_verify" => "rsa_pss_verify",
        "rsa-der-import" | "rsa_der_import" => "rsa_der_import",
        "ephemeral-handshake" | "ephemeral_handshake" | "fuzz_ephemeral_handshake" => {
            "fuzz_ephemeral_handshake"
        }
        "cipher-profile" | "fuzz_cipher_profile" => "fuzz_cipher_profile",
        "openpgp" | "openpgp-dispatch" | "openpgp_dispatch" => "openpgp_dispatch",
        "biometric" | "biometric-dispatch" | "biometric_dispatch" => "biometric_dispatch",
        other => other,
    }
}

fn run_fuzz_target(bin: &str, max_total_time_secs: u64) {
    let fuzz_dir = workspace_root().join("fuzz");
    if !fuzz_dir.join("Cargo.toml").is_file() {
        eprintln!("missing fuzz/Cargo.toml");
        std::process::exit(1);
    }
    let max_time = format!("-max_total_time={}", max_total_time_secs);
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
        .current_dir(&fuzz_dir)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status();
    match st {
        Ok(s) if s.success() => std::process::exit(0),
        Ok(s) => std::process::exit(s.code().unwrap_or(1)),
        Err(e) => {
            eprintln!(
                "failed to spawn cargo-fuzz ({e}). Install: cargo install cargo-fuzz, use nightly if required."
            );
            std::process::exit(1);
        }
    }
}

fn run_embedded(sub: &[&str]) {
    // Firmware-only packages for `riscv32imac-unknown-none-elf` (excludes host tools and
    // `galdralag-service`, which is gated on `xous-bsp` and not part of this target graph).
    let st = Command::new("cargo")
        .args(sub)
        .args([
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
            "-p",
            "cipher-profile",
            "--target",
            "riscv32imac-unknown-none-elf",
        ])
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .expect("cargo");
    std::process::exit(st.code().unwrap_or(1));
}
