# Debugging instructions

This document collects **practical commands and environment variables** for narrowing failures when working on the Galdralag firmware workspace (Rust crates, host tools, and the embedded target). It does not replace the threat model or crypto policy; it is an operator checklist.

For **recorded test matrices** and fuzz metadata, see [TEST_RESULTS.md](TEST_RESULTS.md). For **toolchain and xtask recipes**, see [GALDRALAG_DEV_REFERENCE.md](GALDRALAG_DEV_REFERENCE.md) and [dev-ref.md](dev-ref.md).

---

## 1. Panics and stack traces (host tests and binaries)

When a test or host binary panics or returns `Err`, enable a full backtrace:

```bash
RUST_BACKTRACE=1 cargo test -p vault --lib
RUST_BACKTRACE=full cargo test -p cipher-profile
```

Use `full` when line numbers are elided or the default trace stops too early.

---

## 2. Verbose compiler and linker output

To see **why** a crate fails to compile or link (missing symbols, wrong features, cfg gates):

```bash
cargo build -vv -p galdra-core-host
cargo check -vv -p vault
```

For the firmware triple (see below), `xtask` forwards to `cargo`; you can add verbosity by running the underlying `cargo` command from [GALDRALAG_DEV_REFERENCE.md](GALDRALAG_DEV_REFERENCE.md) with `-vv` if you need linker script or `RUSTFLAGS` detail.

---

## 3. Narrowing test scope

Run **one package**:

```bash
cargo test -p ephemeral-session
cargo test -p usb-personality
```

Run **one test** by name filter (substring match):

```bash
cargo test -p vault ecdh_commutativity
```

Run a **single test** exactly (avoids matching similarly named tests):

```bash
cargo test -p vault ecdh_commutativity -- --exact
```

Show **println!** and test output interleaved (default hides success output):

```bash
cargo test -p vault -- --nocapture
```

Tests marked **`#[ignore]`** (slow, hardware-specific, or optional):

```bash
cargo test -p vault -- --ignored
```

Workspace default often **excludes `xtask`**:

```bash
cargo test --workspace --exclude xtask
cargo test -p xtask
```

---

## 4. `xtask` shortcuts (focused suites)

From the repository root:

| Command | Use when |
|---------|----------|
| `cargo run -p xtask -- check-fw` | Embedded `riscv32imac-unknown-none-elf` compile errors without a full `build` |
| `cargo run -p xtask -- build-fw` | Full firmware image build for the same triple |
| `cargo run -p xtask -- test-host` | Broad host-side workspace tests (excluding `xtask`) |
| `cargo run -p xtask -- test-crypto` | `vault` + `security-tests` with single test thread |
| `cargo run -p xtask -- test-profiles` | `cipher-profile` only |
| `cargo run -p xtask -- test-session` | `ephemeral-session` only |
| `cargo run -p xtask -- test-biometric` | Biometric crates with `test-hal` where needed |
| `cargo run -p xtask -- wycheproof` | Vault Wycheproof-style JSON corpora |
| `cargo run -p xtask -- timing-test` | Dudect harness (see GALDRALAG_DEV_REFERENCE) |
| `cargo run -p xtask -- test-all` | Full pipeline (optional `--no-fuzz` to skip `cargo-fuzz`) |
| `cargo run -p xtask -- test-openpgp` | Quick host check: reports whether `gpg` is on `PATH` (does not substitute for a CCID reader) |
| `cargo run -p xtask -- bench-rsa` | Slow ignored RSA baseline in `vault` (`--ignored --nocapture`) |

If an `xtask` command fails, re-run the equivalent **`cargo test …`** shown in `xtask/src/main.rs` so you can append **`-- --nocapture`** or a test name filter. For **`fuzz`** target names and aliases, run **`cargo run -p xtask --`** with no further arguments: the process prints a **`usage:`** line listing accepted verbs.

---

## 5. Firmware target (`riscv32imac-unknown-none-elf`)

Install the target once:

```bash
rustup target add riscv32imac-unknown-none-elf
```

Then use **`check-fw`** / **`build-fw`** as above. If the failure is in a specific crate, locate it under `crates/` and run:

```bash
cargo check -p <crate-name> --target riscv32imac-unknown-none-elf
```

(Only crates that declare that target in their build will succeed; host-only crates are checked on the host triple instead.)

Integration status for **USB CCID on Xous** is described in [XOUS_CCID_INTEGRATION.md](XOUS_CCID_INTEGRATION.md); until that wiring lands, **GnuPG against real hardware** may still fail at the OS/USB layer even when unit tests pass.

---

## 6. Lint and type-only checks

Fast feedback without running tests:

```bash
cargo clippy --workspace --exclude xtask -- -D warnings
cargo check --workspace --exclude xtask
```

Scope to one crate when iterating:

```bash
cargo clippy -p galdr-core --all-targets
```

---

## 7. Fuzzing (libFuzzer)

The **`fuzz/`** tree is a separate Cargo workspace. See [`fuzz/README.md`](../fuzz/README.md) for targets and `cargo fuzz run …` examples. If **`cargo fuzz`** requires nightly on your machine:

```bash
cd fuzz && cargo +nightly fuzz run <target_name>
```

Use **minimized** crash artifacts (`cargo fuzz tmin`) only after you can reproduce a crash reliably; store reproducers outside the tree if they contain secrets.

---

## 8. Host tools (`galdra`, `galdrad`, `galdra-gtk`)

Operational behaviour, environment, and provisioning flows are in [GALDRA-TOOL.md](GALDRA-TOOL.md). For **device-dependent** failures, prefer a **VM** or disposable user session; some tests are **`#[ignore]`** until a token is present.

---

## 9. OpenPGP / CCID on Linux

Reader enumeration, `pcscd`, `udev`, and GnuPG **`scdaemon`** behaviour are covered in [OPENPGP_CARD.md](OPENPGP_CARD.md). Typical checks:

- `pcscd` running and the device listed by `pcsc_scan` or equivalent.
- Correct **udev** rules so your user can open the reader.
- **`gpg --card-status`** after unplug/replug to confirm session state.

---

## 10. Biometrics and hardware-in-the-loop

- **PAD / metrics methodology:** [BIOMETRIC_TESTING.md](BIOMETRIC_TESTING.md)
- **Board-level or lab checks:** [HARDWARE_TEST.md](HARDWARE_TEST.md), [HARDWARE_VERIFICATION.md](HARDWARE_VERIFICATION.md)

---

## 11. Documentation and rustdoc

Browse API docs for a crate:

```bash
cargo doc -p vault --open --no-deps
```

Use **`--document-private-items`** only when debugging internal modules; do not treat that output as a stable public API.

---

## 12. When to stop and open an issue

Collect before reporting:

1. **Exact command** and **full terminal output** (or last 200 lines of `cargo … -vv`).
2. **`rustc -V`**, **`cargo -V`**, and **`rust-toolchain.toml`** contents if not default stable.
3. **Host OS** and whether the failure is **host triple** vs **`riscv32imac-unknown-none-elf`**.
4. For crypto surprises: whether **vectors** or **fuzz** seeds reproduce (never paste production keys).

This keeps triage focused on reproducible steps rather than guesswork.
