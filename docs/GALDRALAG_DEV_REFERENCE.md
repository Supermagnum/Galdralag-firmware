# Galdralag developer reference

Host tooling, cryptographic regression tests, and fuzzing entry points for this workspace.

## Toolchain

- **Stable Rust** for normal `cargo test` / `cargo clippy` (see `rust-toolchain.toml`).
- **`riscv32imac-unknown-none-elf`** for firmware checks: `rustup target add riscv32imac-unknown-none-elf`.
- **cargo-fuzz** (optional): `cargo install cargo-fuzz`. Many setups require **nightly** for `cargo fuzz`; use `cargo +nightly fuzz run …` if stable fails.

## Workspace commands (via xtask)

| Command | Purpose |
|--------|---------|
| `cargo run -p xtask -- check-fw` | `cargo check` for embedded crates on `riscv32imac-unknown-none-elf`. |
| `cargo run -p xtask -- build-fw` | Same triple, `cargo build`. |
| `cargo run -p xtask -- test-host` | Host tests for all workspace members except `xtask`. |
| `cargo run -p xtask -- test-crypto` | `vault` + `security-tests` unit/integration tests. |
| `cargo run -p xtask -- wycheproof` | Runs vault tests whose names match `wycheproof` (ChaCha JSON runner). |
| `cargo run -p xtask -- timing-test` | Host tests for `security-tests` (dudect stubs). |
| `cargo run -p xtask -- fuzz` or `fuzz-chacha` | `cargo fuzz run chacha_roundtrip` from `fuzz/` (requires cargo-fuzz). |
| `cargo run -p xtask -- fuzz-shamir` | `cargo fuzz run shamir_split_recover`. |

Direct equivalents without xtask:

```text
cargo test -p vault
cargo test -p vault wycheproof
cargo test -p security-tests
cd fuzz && cargo fuzz run chacha_roundtrip
```

## Wycheproof-style ChaCha20-Poly1305

- Vectors live at `crates/vault/tests/data/wycheproof_chacha20_poly1305_test.json`.
- The runner is a **unit test** in `crates/vault/src/wycheproof_chacha.rs` (parsed with `serde_json`; `ct` is ciphertext followed by the Poly1305 tag, matching vault’s `ChaChaCiphertext` layout).
- The on-disk format follows the common Wycheproof **AeadTest** shape (`testGroups` / `tests` with hex `key`, `iv`, `aad`, `msg`, `ct`, `result` of `valid` or `invalid`).
- To add vectors from the larger upstream corpora (for example community Wycheproof JSON), merge compatible `AeadTest` groups or convert fields to the same hex layout. Keep file size and licensing in mind when vendoring third-party JSON.

## Shamir JSON vectors

- File: `crates/vault/tests/data/shamir_vectors.json`.
- Integration test: `crates/vault/tests/shamir_vectors.rs` (uses `ShamirShare::try_from_index_value`).
- Regenerate share hex for a known `FakeTrng` seed and parameters:

  ```text
  cargo run -p vault --example shamir_vector_dump
  ```

## Fuzz targets

Directory `fuzz/` is a standalone Cargo package (see `fuzz/Cargo.toml`, isolated `[workspace]` for cargo-fuzz).

| Target | Exercises |
|--------|-----------|
| `chacha_roundtrip` | `chacha_encrypt` / `chacha_decrypt` with `FakeTrng`-derived keys and nonces. |
| `shamir_split_recover` | `shamir_split` and `shamir_recover` on bounded parameters. |

## Dudect / timing analysis

- Crate **`security-tests`** exposes stub functions (`dudect_stub_*`) returning `DudectStatus::NotRun` until a real dudect (or similar) harness is wired.
- Use `cargo run -p xtask -- timing-test` or `cargo test -p security-tests` to keep CI aware of the placeholder API.

## Hal / test features

Enable `galdr-core` feature **`test-hal`** only in tests and host tools. Do not enable it in production firmware images.
