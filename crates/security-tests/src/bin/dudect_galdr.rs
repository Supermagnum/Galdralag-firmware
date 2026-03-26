//! Dudect-style timing harnesses for Galdr crypto paths (Welch t; threshold |t| <= 4.5).
//!
//! Run: `cargo run -p security-tests --features dudect --bin dudect_galdr`
//! or: `cargo run -p xtask -- timing-test`

#![forbid(unsafe_code)]

fn main() {
    std::process::exit(security_tests::run_dudect_harnesses());
}
