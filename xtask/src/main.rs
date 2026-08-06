//! Build recipes for Galdr firmware (Baochip-1x, Xous target triple).
//!
//! **TODO (developer):** Pin `rustc`, `cargo`, linker scripts, and `RUSTFLAGS` for reproducible
//! hashes per Baochip README verification section.

mod test_all;
mod timing_test;

use std::path::{Path, PathBuf};
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
                .args(["test", "-p", "ephemeral-session", "--", "--test-threads=1"])
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
            let name = a.next().unwrap_or_else(|| "chacha_roundtrip".to_string());
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
                eprintln!(
                    "test-openpgp: gpg not found on PATH; skipping host interoperability checks."
                );
            }
            std::process::exit(0);
        }
        Some("build-galdralag-xous") => {
            let rest: Vec<String> = a.collect();
            let (release, board) = match parse_galdralag_xous_build_args(&rest) {
                Ok(x) => x,
                Err(msg) => {
                    eprintln!("build-galdralag-xous: {msg}");
                    std::process::exit(2);
                }
            };
            let st = run_galdralag_xous_cargo_build(release, board);
            std::process::exit(st.code().unwrap_or(1));
        }
        Some("print-galdralag-xous-cratespec") => {
            let rest: Vec<String> = a.collect();
            let (release, _board) = match parse_galdralag_xous_build_args(&rest) {
                Ok(x) => x,
                Err(msg) => {
                    eprintln!("print-galdralag-xous-cratespec: {msg}");
                    std::process::exit(2);
                }
            };
            match canonical_galdralag_elf_path(release) {
                Ok(abs) => {
                    println!("galdralag-service:{}", abs.display());
                    std::process::exit(0);
                }
                Err(msg) => {
                    eprintln!("{msg}");
                    std::process::exit(1);
                }
            }
        }
        Some("build-galdralag-stub") => {
            let profile = a.next().unwrap_or_else(|| "release".to_string());
            let release = profile != "debug";
            let st = run_galdralag_stub_cargo_build(release);
            std::process::exit(st.code().unwrap_or(1));
        }
        Some("print-galdralag-stub-cratespec") => {
            let profile = a.next().unwrap_or_else(|| "release".to_string());
            let release = profile != "debug";
            match canonical_galdralag_stub_elf_path(release) {
                Ok(abs) => {
                    println!("galdralag-stub:{}", abs.display());
                    std::process::exit(0);
                }
                Err(msg) => {
                    eprintln!("{msg}");
                    std::process::exit(1);
                }
            }
        }
        Some("build-and-register") => {
            let rest: Vec<String> = a.collect();
            let (release, xous_core, extra_flags) = match parse_build_and_register_args(&rest) {
                Ok(x) => x,
                Err(msg) => {
                    eprintln!("build-and-register: {msg}");
                    std::process::exit(2);
                }
            };

            let st = run_galdralag_xous_cargo_build(release, GaldralagBoard::Baosec);
            if !st.success() {
                eprintln!(
                    "build-and-register: cargo build for galdralag-service failed (exit {}).",
                    st.code().unwrap_or(-1)
                );
                std::process::exit(st.code().unwrap_or(1));
            }

            let elf_logical = galdralag_xous_elf_logical_path(release);
            if !elf_logical.is_file() {
                eprintln!(
                    "build-and-register: build finished but ELF is not present at {}. Refusing to emit a stale or wrong cratespec.",
                    elf_logical.display()
                );
                std::process::exit(1);
            }

            let abs = match std::fs::canonicalize(&elf_logical) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!(
                        "build-and-register: could not canonicalize {}: {e}",
                        elf_logical.display()
                    );
                    std::process::exit(1);
                }
            };

            println!("Built galdralag ELF (absolute path): {}", abs.display());
            let cratespec = format!("galdralag-service:{}", abs.display());
            println!("Cratespec: {cratespec}");

            if let Some(ref xc) = xous_core {
                if !xc.is_dir() {
                    eprintln!(
                        "build-and-register: --xous-core path is not a directory: {}",
                        xc.display()
                    );
                    std::process::exit(1);
                }
                let mut baosec_args: Vec<String> =
                    vec!["xtask".into(), "baosec".into(), cratespec.clone()];
                baosec_args.extend(extra_flags.iter().cloned());
                let display_cmd = format_command_for_display("cargo", &baosec_args);
                println!("Running: {display_cmd}");
                let run_st = Command::new("cargo")
                    .args(&baosec_args)
                    .current_dir(xc)
                    .stdin(Stdio::inherit())
                    .stdout(Stdio::inherit())
                    .stderr(Stdio::inherit())
                    .status();
                match run_st {
                    Ok(s) if s.success() => std::process::exit(0),
                    Ok(s) => {
                        eprintln!(
                            "build-and-register: cargo xtask baosec failed (exit {}).",
                            s.code().unwrap_or(-1)
                        );
                        std::process::exit(s.code().unwrap_or(1));
                    }
                    Err(e) => {
                        eprintln!(
                            "build-and-register: failed to spawn `cargo` in {}: {e}",
                            xc.display()
                        );
                        std::process::exit(1);
                    }
                }
            } else {
                println!();
                println!("Run this in your xous-core directory:");
                println!("cargo xtask baosec {cratespec} <your existing flags>");
                if !extra_flags.is_empty() {
                    println!(
                        "(You passed --extra-flags but not --xous-core; in xous-core, positional cratespecs come first, then named flags: `cargo xtask baosec {} {}`.)",
                        cratespec,
                        shell_join_for_hint(&extra_flags)
                    );
                }
                std::process::exit(0);
            }
        }
        _ => {
            eprintln!(
                "usage: cargo run -p xtask -- <build-fw|check-fw|build-galdralag-xous [release|debug] [--board baosec|dabao]|print-galdralag-xous-cratespec [release|debug]|build-galdralag-stub [release|debug]|print-galdralag-stub-cratespec [release|debug]|build-and-register [release|debug] [--xous-core DIR] [--extra-flags TOKEN ...] (extra-flags must be last)|test-session|test-profiles|test-host|test-crypto|test-biometric|test-all [--no-fuzz]|test-openpgp|wycheproof|timing-test [biometric] [--all] [--full] [HARNESS...]|bench-rsa|fuzz [TARGET] [SECS]|fuzz-chacha [SECS]|fuzz-shamir [SECS]>"
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

fn cargo_target_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("CARGO_TARGET_DIR") {
        return PathBuf::from(dir);
    }
    workspace_root().join("target")
}

fn galdralag_xous_elf_logical_path(release: bool) -> PathBuf {
    let profile_dir = if release { "release" } else { "debug" };
    workspace_root()
        .join("services/galdralag/target/riscv32imac-unknown-xous-elf")
        .join(profile_dir)
        .join("galdralag-service")
}

fn galdralag_stub_elf_logical_path(release: bool) -> PathBuf {
    let profile_dir = if release { "release" } else { "debug" };
    cargo_target_dir()
        .join("riscv32imac-unknown-xous-elf")
        .join(profile_dir)
        .join("galdralag-stub")
}

/// Board feature selection for `services/galdralag` Xous builds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GaldralagBoard {
    Baosec,
    Dabao,
}

impl GaldralagBoard {
    fn cargo_features(self) -> &'static str {
        match self {
            Self::Baosec => "xous-bsp,board-baosec",
            Self::Dabao => "xous-bsp,board-dabao",
        }
    }
}

/// Parse `[release|debug] [--board baosec|dabao]` (board defaults to baosec).
fn parse_galdralag_xous_build_args(rest: &[String]) -> Result<(bool, GaldralagBoard), String> {
    let mut i = 0usize;
    let release = if i < rest.len() && (rest[i] == "release" || rest[i] == "debug") {
        let r = rest[i] != "debug";
        i += 1;
        r
    } else {
        true
    };
    let mut board = GaldralagBoard::Baosec;
    while i < rest.len() {
        match rest[i].as_str() {
            "--board" => {
                i += 1;
                let Some(name) = rest.get(i) else {
                    return Err("--board requires baosec or dabao".into());
                };
                board = match name.as_str() {
                    "baosec" => GaldralagBoard::Baosec,
                    "dabao" => GaldralagBoard::Dabao,
                    other => {
                        return Err(format!(
                            "unknown --board {other:?} (expected baosec or dabao)"
                        ));
                    }
                };
                i += 1;
            }
            other => {
                return Err(format!(
                    "unexpected argument {other:?} (expected [release|debug] [--board baosec|dabao])"
                ));
            }
        }
    }
    Ok((release, board))
}

/// Temporary Cargo.toml / getrandom patches required to compile `galdralag-service` against the
/// bundled xous-core tree (same intent as `scripts/build_dabao_image.sh`). Always restored on drop.
struct GaldralagManifestWorkaround {
    manifest: PathBuf,
    lock: PathBuf,
    getrandom: PathBuf,
    manifest_bak: Option<PathBuf>,
    lock_bak: Option<PathBuf>,
    getrandom_bak: Option<PathBuf>,
}

impl GaldralagManifestWorkaround {
    fn apply(board: GaldralagBoard) -> Result<Self, String> {
        let root = workspace_root();
        let manifest = root.join("services/galdralag/Cargo.toml");
        let lock = root.join("services/galdralag/Cargo.lock");
        let getrandom = root.join("xous-core/imports/getrandom/Cargo.toml");
        let marker = "GALDRALAG_XOUS_BUILD_WORKAROUND";

        let mut this = Self {
            manifest: manifest.clone(),
            lock: lock.clone(),
            getrandom: getrandom.clone(),
            manifest_bak: None,
            lock_bak: None,
            getrandom_bak: None,
        };

        let text = std::fs::read_to_string(&manifest)
            .map_err(|e| format!("read {}: {e}", manifest.display()))?;
        if text.contains(marker) {
            eprintln!(
                "galdralag xous build: {} already contains {marker}; skipping patch",
                manifest.display()
            );
            return Ok(this);
        }

        let manifest_bak = std::env::temp_dir().join(format!(
            "galdralag-Cargo.toml.{}.bak",
            std::process::id()
        ));
        std::fs::copy(&manifest, &manifest_bak)
            .map_err(|e| format!("backup {}: {e}", manifest.display()))?;
        this.manifest_bak = Some(manifest_bak);

        if lock.is_file() {
            let lock_bak = std::env::temp_dir().join(format!(
                "galdralag-Cargo.lock.{}.bak",
                std::process::id()
            ));
            std::fs::copy(&lock, &lock_bak)
                .map_err(|e| format!("backup {}: {e}", lock.display()))?;
            this.lock_bak = Some(lock_bak);
        }

        let getrandom_bak = std::env::temp_dir().join(format!(
            "getrandom-Cargo.toml.{}.bak",
            std::process::id()
        ));
        std::fs::copy(&getrandom, &getrandom_bak)
            .map_err(|e| format!("backup {}: {e}", getrandom.display()))?;
        this.getrandom_bak = Some(getrandom_bak);

        // Align path-crate version with services/galdralag/Cargo.lock (0.2.17).
        let gr = std::fs::read_to_string(&getrandom)
            .map_err(|e| format!("read {}: {e}", getrandom.display()))?;
        let gr_new = gr.replacen("version = \"0.2.12\"", "version = \"0.2.17\"", 1);
        if gr_new == gr {
            return Err(format!(
                "expected getrandom version 0.2.12 in {} for workaround bump",
                getrandom.display()
            ));
        }
        std::fs::write(&getrandom, gr_new)
            .map_err(|e| format!("write {}: {e}", getrandom.display()))?;

        let mut patched = text;
        let old_pddb =
            "pddb = { path = \"../../xous-core/services/pddb\", default-features = false, features = [\"mbbb\"] }";
        // baosec: full board-baosec PDDB feature (matches scripts/build_dabao_image.sh).
        // dabao: enable gen2 only so keystore-api gets TOTAL_CHECKSUMS without also
        // activating bao1x-hal/board-baosec (which conflicts with board-dabao).
        let new_pddb = match board {
            GaldralagBoard::Baosec => {
                "pddb = { path = \"../../xous-core/services/pddb\", default-features = false, features = [\"mbbb\", \"board-baosec\"] }"
            }
            GaldralagBoard::Dabao => {
                "pddb = { path = \"../../xous-core/services/pddb\", default-features = false, features = [\"mbbb\", \"gen2\"] }"
            }
        };
        if !patched.contains(old_pddb) {
            return Err(format!(
                "expected pddb mbbb-only line not found in {}",
                manifest.display()
            ));
        }
        patched = patched.replacen(old_pddb, new_pddb, 1);

        // Current tree: board feature is selected via --features, not hard-wired on the dep.
        let needle =
            "bao1x-hal = { path = \"../../xous-core/libs/bao1x-hal\", features = [\"std\"] }";
        if !patched.contains(needle) {
            return Err(format!(
                "expected bao1x-hal std-only line not found in {}",
                manifest.display()
            ));
        }
        let insert = match board {
            GaldralagBoard::Baosec => {
                // Same as scripts/build_dabao_image.sh: blitstr2 fonts; pddb board-baosec
                // already wires ux-api/board-baosec via bao1x-hal.
                format!(
                    "{needle}\n# {marker} (injected by xtask; restored after build)\nblitstr2 = {{ path = \"../../xous-core/libs/blitstr2\", features = [\"bao1x\", \"board-baosec\"] }}\n"
                )
            }
            GaldralagBoard::Dabao => {
                // pddb always depends on ux-api (default features) but does not enable the
                // optional blitstr2 crate or a platform module. Enable ux-api/board-baosec
                // (screen constants + blitstr2 only — does not activate bao1x-hal/board-baosec).
                format!(
                    "{needle}\n# {marker} (injected by xtask; restored after build)\nux-api = {{ path = \"../../xous-core/libs/ux-api\", default-features = false, features = [\"std\", \"board-baosec\"] }}\nblitstr2 = {{ path = \"../../xous-core/libs/blitstr2\", features = [\"bao1x\", \"board-baosec\"] }}\n"
                )
            }
        };
        patched = patched.replacen(needle, &insert, 1);

        let patch_anchor = "[patch.crates-io]\n";
        if !patched.contains(patch_anchor) {
            return Err(format!(
                "[patch.crates-io] missing in {}",
                manifest.display()
            ));
        }
        let after_patch = patched
            .split_once("[patch.crates-io]")
            .map(|(_, rest)| rest)
            .unwrap_or("");
        if !after_patch.contains("getrandom") {
            patched = patched.replacen(
                patch_anchor,
                &format!("{patch_anchor}# {marker}\ngetrandom = {{ path = \"../../xous-core/imports/getrandom\" }}\n"),
                1,
            );
        }

        std::fs::write(&manifest, patched)
            .map_err(|e| format!("write {}: {e}", manifest.display()))?;
        eprintln!(
            "galdralag xous build: temporarily patched {} + getrandom for {:?} (restored after build)",
            manifest.display(),
            board
        );
        Ok(this)
    }

    fn restore(&mut self) {
        if let Some(bak) = self.manifest_bak.take() {
            let _ = std::fs::copy(&bak, &self.manifest);
            let _ = std::fs::remove_file(&bak);
        }
        if let Some(bak) = self.lock_bak.take() {
            let _ = std::fs::copy(&bak, &self.lock);
            let _ = std::fs::remove_file(&bak);
        }
        if let Some(bak) = self.getrandom_bak.take() {
            let _ = std::fs::copy(&bak, &self.getrandom);
            let _ = std::fs::remove_file(&bak);
        }
    }
}

impl Drop for GaldralagManifestWorkaround {
    fn drop(&mut self) {
        self.restore();
    }
}

fn run_galdralag_xous_cargo_build(
    release: bool,
    board: GaldralagBoard,
) -> std::process::ExitStatus {
    let mut workaround = match GaldralagManifestWorkaround::apply(board) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("galdralag xous build: manifest workaround failed: {e}");
            std::process::exit(1);
        }
    };

    let manifest = workspace_root().join("services/galdralag/Cargo.toml");
    let mut args = vec![
        "build".to_string(),
        "--manifest-path".to_string(),
        manifest.to_string_lossy().into_owned(),
        "--target".to_string(),
        "riscv32imac-unknown-xous-elf".to_string(),
        "--features".to_string(),
        board.cargo_features().to_string(),
    ];
    if release {
        args.push("--release".to_string());
    }
    eprintln!(
        "galdralag xous build: cargo features {}",
        board.cargo_features()
    );
    let status = match Command::new("cargo")
        .args(&args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
    {
        Ok(s) => s,
        Err(e) => {
            eprintln!("galdralag xous build: failed to spawn cargo: {e}");
            workaround.restore();
            std::process::exit(1);
        }
    };
    // Explicit restore before returning so callers see a clean tree even if Drop is delayed.
    workaround.restore();
    status
}

fn run_galdralag_stub_cargo_build(release: bool) -> std::process::ExitStatus {
    let mut args = vec![
        "build".to_string(),
        "-p".to_string(),
        "galdralag-stub".to_string(),
        "--target".to_string(),
        "riscv32imac-unknown-xous-elf".to_string(),
    ];
    if release {
        args.push("--release".to_string());
    }
    match Command::new("cargo")
        .args(&args)
        .current_dir(workspace_root())
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
    {
        Ok(s) => s,
        Err(e) => {
            eprintln!("galdralag-stub xous build: failed to spawn cargo: {e}");
            std::process::exit(1);
        }
    }
}

fn canonical_galdralag_elf_path(release: bool) -> Result<PathBuf, String> {
    let elf = galdralag_xous_elf_logical_path(release);
    if !elf.is_file() {
        return Err(format!(
            "print-galdralag-xous-cratespec: ELF not found at {} (build galdralag for this profile first).",
            elf.display()
        ));
    }
    std::fs::canonicalize(&elf).map_err(|e| {
        format!(
            "print-galdralag-xous-cratespec: canonicalize {}: {e}",
            elf.display()
        )
    })
}

fn canonical_galdralag_stub_elf_path(release: bool) -> Result<PathBuf, String> {
    let elf = galdralag_stub_elf_logical_path(release);
    if !elf.is_file() {
        return Err(format!(
            "print-galdralag-stub-cratespec: ELF not found at {} (run build-galdralag-stub first).",
            elf.display()
        ));
    }
    std::fs::canonicalize(&elf).map_err(|e| {
        format!(
            "print-galdralag-stub-cratespec: canonicalize {}: {e}",
            elf.display()
        )
    })
}

/// `[release|debug]`, then any of `--xous-core PATH` (once) and/or `--extra-flags` (must be last; consumes remainder).
fn parse_build_and_register_args(
    rest: &[String],
) -> Result<(bool, Option<PathBuf>, Vec<String>), String> {
    let mut i = 0usize;
    let release = if i < rest.len() && (rest[i] == "release" || rest[i] == "debug") {
        let r = rest[i] != "debug";
        i += 1;
        r
    } else {
        true
    };

    let mut xous_core: Option<PathBuf> = None;
    let mut extra_flags: Vec<String> = Vec::new();

    while i < rest.len() {
        if rest[i] == "--xous-core" {
            i += 1;
            if i >= rest.len() {
                return Err("--xous-core requires a directory path.".into());
            }
            xous_core = Some(PathBuf::from(&rest[i]));
            i += 1;
        } else if rest[i] == "--extra-flags" {
            i += 1;
            while i < rest.len() {
                extra_flags.push(rest[i].clone());
                i += 1;
            }
            break;
        } else {
            return Err(format!(
                "unexpected argument {:?} (optional: release | debug; then --xous-core DIR; --extra-flags must be last and takes all following tokens)",
                rest[i]
            ));
        }
    }

    Ok((release, xous_core, extra_flags))
}

fn format_command_for_display(program: &str, args: &[String]) -> String {
    let mut parts = vec![program.to_string()];
    parts.extend(args.iter().cloned());
    shell_join_for_hint(&parts)
}

fn shell_join_for_hint(parts: &[String]) -> String {
    parts
        .iter()
        .map(|s| {
            if s.is_empty() || s.chars().any(|c| c.is_whitespace() || c == '\'') {
                format!("{:?}", s)
            } else {
                s.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn fuzz_bin_name(name: &str) -> &str {
    match name {
        "chacha" | "chacha_roundtrip" => "chacha_roundtrip",
        "shamir" | "shamir_split_recover" => "shamir_split_recover",
        "brainpool384-ecdh" | "brainpool384_ecdh" => "brainpool384_ecdh",
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
            "run", "nightly", "cargo", "fuzz", "run", bin, "--", &max_time,
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
    // `galdralag-service`: use `cargo run -p xtask -- build-and-register` or `build-galdralag-xous`.
    let st = Command::new("cargo")
        .args(sub)
        .args([
            "-p",
            "galdr-core",
            "-p",
            "galdr-vault",
            "-p",
            "contact-store",
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
