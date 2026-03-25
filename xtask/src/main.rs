//! Build recipes for Galdr firmware (Baochip-1x, Xous target triple).
//!
//! **TODO (developer):** Pin `rustc`, `cargo`, linker scripts, and `RUSTFLAGS` for reproducible
//! hashes per Baochip README verification section.

use std::process::{Command, Stdio};

fn main() {
    let mut a = std::env::args().skip(1);
    match a.next().as_deref() {
        Some("build-fw") => run_embedded(&["build"]),
        Some("check-fw") => run_embedded(&["check"]),
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
        _ => {
            eprintln!("usage: cargo run -p xtask -- <build-fw|check-fw|test-host>");
            std::process::exit(2);
        }
    }
}

fn run_embedded(sub: &[&str]) {
    let st = Command::new("cargo")
        .args(sub)
        .args([
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
        ])
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .expect("cargo");
    std::process::exit(st.code().unwrap_or(1));
}
