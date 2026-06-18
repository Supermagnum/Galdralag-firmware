# Test Results

## Last full run

- **Date (UTC):** 2026-03-26T16:59:37Z (header updated with Wycheproof run below)
- **Commit:** `09e0c963b7f5f8029f94f4cd269dfccc522d71b8`
- **Rust toolchain:** rustc 1.94.0 (4a4ef493e 2026-03-02)
- **xtask version:** 0.1.0
- **Wycheproof:** `cargo run -p xtask -- wycheproof` — 18/18 PASS, ~24.2 s wall time (see [Section 3](#3-wycheproof-vector-results))

## 1. Unit tests

| Scope | Passed | Failed | Ignored (`#[ignore]`) | Status |
|-------|--------|--------|-------------------------|--------|
| Workspace (excluding xtask), summed `test result` lines | 343 | 0 | 13 | PASS |

## 2. Cryptographic validation detail

When the corresponding `cargo test` steps pass, the following counts apply. AES-GCM bulk validation uses **Google Wycheproof** JSON (`aes_gcm_test.json`), not NIST CAVP `.rsp` files; the `nist_cavp` integration test covers SHA-2 / SHA-3 / HMAC only (see below).

### AES-GCM validation results (Wycheproof)

Runner: `crates/vault/src/wycheproof_aes_gcm.rs` (128-bit tag, AES-128/AES-256, IV sizes supported by the runner). Skipped upstream groups: AES-192 keys, empty IV, 257-byte IV.

**AES-128-GCM:**

    Test Status: 105 out of 105 applicable vectors passing (100% when `wycheproof_aes_gcm_json` passes)
    Passing vectors: decrypt checks including cases with AAD (Additional Authenticated Data)
    Conclusion: AES-128-GCM path exercised against Wycheproof `aes_gcm_test.json` for supported key/IV sizes

**AES-256-GCM:**

    Test Status: 102 out of 102 applicable vectors passing (100% when `wycheproof_aes_gcm_json` passes)
    Passing vectors: decrypt checks including cases with AAD
    Conclusion: AES-256-GCM path exercised against Wycheproof `aes_gcm_test.json` for supported key/IV sizes

**Additional (host unit test):** `galdr-core` `aes256_gcm_nist_one_block` runs one AES-256-GCM encrypt/decrypt round-trip (smoke, not a NIST CAVP `.rsp` file).

### RFC 8439 ChaCha20-Poly1305

    Test Status: 1 out of 1 JSON vectors in `vault/tests/rfc_vectors/rfc8439_chacha.json` (100% when `rfc8439_chacha20_poly1305_aead` passes)
    Passing vectors: RFC 8439 Section 2.8.2 style AEAD (ciphertext + tag); includes AAD
    Additional: `galdr-core` `chacha20poly1305_rfc8439_aead` repeats the same RFC example as an independent cross-check
    Conclusion: ChaCha20-Poly1305 validated against the in-tree RFC 8439 JSON vectors

### NIST CAVP subset (SHA-2 / SHA-3 / HMAC)

Runner: `vault/tests/nist_cavp.rs`.

    Test Status: SHA-256: 2 vector(s); SHA3-256: 1 vector(s); HMAC-SHA256: 1 vector(s); **total 4** (100% when `nist_cavp` passes)
    Conclusion: Subset of NIST CAVP-style KATs for digests and HMAC (no AES-GCM CAVP files in this repo)

### Encryption timing (dudect)

    Tool: Welch t-statistic harnesses via `cargo run -p xtask -- timing-test` (binary `dudect_galdr`; threshold |t| <= 4.5).
    Covers constant-time comparisons, AEAD tag checks, HMAC/HKDF, Ed25519/X25519, Brainpool ECDH (reduced sample counts on slow curves), Shamir, Serpent tag, PIN compare, RSA ct-eq on modulus-sized buffers, etc.
    Pipeline: `test-all` may run `cargo test -p security-tests` (stub API); full host dudect requires `timing-test` and reads stdout/stderr.

## 3. Wycheproof vector results

**Command:** `cargo run -p xtask -- wycheproof` (runs `cargo test -p vault wycheproof`; vault `lib` unit tests whose names match the `wycheproof` filter).

**Recorded run (UTC):** 2026-03-26 — **Commit:** `09e0c963b7f5f8029f94f4cd269dfccc522d71b8`

| Metric | Value |
|--------|-------|
| Tests run | 18 |
| Passed | 18 |
| Failed | 0 |
| Ignored | 0 |
| Wall time (vault `lib` test binary) | ~24.2 s |

**Conclusion:** All Wycheproof-driven tests in the vault crate **PASS**. Per-vector behaviour is asserted in the Rust runners (`crates/vault/src/wycheproof_*.rs`); upstream JSON uses `tcId` / `result` fields as in [Google Wycheproof](https://github.com/C2SP/wycheproof).

### Per-suite results (each test: PASS)

| # | Rust test (as printed by `cargo test -p vault wycheproof`) | Primary JSON inputs (under `crates/vault/tests/data/` unless noted) |
|---|------------------------------------------------------------|----------------------------------------------------------------------|
| 1 | `wycheproof_chacha::wycheproof_chacha20_poly1305_json` | `wycheproof_chacha20_poly1305_test.json` |
| 2 | `wycheproof_hmac_sha256::wycheproof_hmac_sha256_json` | `wycheproof/hmac_sha256_test.json` |
| 3 | `wycheproof_hmac_sha512::wycheproof_hmac_sha512_json` | `wycheproof/hmac_sha512_test.json` |
| 4 | `wycheproof_aes_gcm::wycheproof_aes_gcm_json` | `wycheproof/aes_gcm_test.json` |
| 5 | `wycheproof_hkdf_sha256::wycheproof_hkdf_sha256_json` | `wycheproof/hkdf_sha256_test.json` |
| 6 | `wycheproof_hkdf_sha512::wycheproof_hkdf_sha512_json` | `wycheproof/hkdf_sha512_test.json` |
| 7 | `wycheproof_x25519::wycheproof_x25519_json` | `wycheproof/x25519_test.json` |
| 8 | `wycheproof_rsa::wycheproof_rsa_pss_sha256` | `wycheproof/rsa_pss_2048_sha256_mgf1_32_test.json` (PSS-SHA256 groups) |
| 9 | `wycheproof_ed25519::wycheproof_ed25519_json` | `wycheproof/ed25519_test.json` |
| 10 | `wycheproof_ecdsa_brainpool256::wycheproof_brainpool256_ecdsa_sha256_json` | `wycheproof/ecdsa_brainpoolP256r1_sha256_test.json` |
| 11 | `wycheproof_rsa::wycheproof_rsa_pkcs1_sha256` | `wycheproof/rsa_signature_2048_sha256_test.json` |
| 12 | `wycheproof_brainpool256::wycheproof_brainpool256_ecdh_json` | `wycheproof/ecdh_brainpoolP256r1_test.json` |
| 13 | `wycheproof_brainpool384::wycheproof_brainpool384_ecdsa_sha384_json` | `ecdsa_brainpoolP384r1_sha384_test.json` |
| 14 | `wycheproof_rsa::wycheproof_rsa_pss_sha512` | `wycheproof/rsa_pss_4096_sha512_mgf1_64_test.json` (PSS-SHA512 groups) |
| 15 | `wycheproof_brainpool512::wycheproof_brainpool512_ecdsa_sha512_json` | `ecdsa_brainpoolP512r1_sha512_test.json` |
| 16 | `wycheproof_brainpool512::wycheproof_brainpool512_ecdh_json` | `ecdh_brainpoolP512r1_test.json` |
| 17 | `wycheproof_brainpool384::wycheproof_brainpool384_ecdh_json` | `ecdh_brainpoolP384r1_test.json` |
| 18 | `wycheproof_rsa::wycheproof_rsa_oaep_sha256_mgf1sha256` | `wycheproof/rsa_oaep_2048_sha256_mgf1sha256_test.json`, `rsa_oaep_3072_sha256_mgf1sha256_test.json`, `rsa_oaep_4096_sha256_mgf1sha256_test.json` |

Other vault integration test binaries (`tests/*.rs`) report **0 tests** when this filter is used; that is expected.

## 4. RFC test vector results

JSON under `crates/vault/tests/rfc_vectors/`, runner: `vault/tests/rfc_vectors.rs`. Last `test-all` step: **PASS**.

## 5. BSI test vector results

JSON under `crates/vault/tests/bsi_vectors/`, runner: `vault/tests/bsi_brainpool.rs` (TR-03111 cross-checks). Last run: **PASS**.

## 6. NIST CAVP vector results

Subset JSON under `crates/vault/tests/nist_cavp_vectors/`, runner `vault/tests/nist_cavp.rs`. Last run: **PASS**.

## 7. Known-answer test (KAT) results

Runner `vault/tests/kat_vectors.json` assets (Twofish/Serpent/Shamir/BLAKE3 as present). Last run: **PASS**.

## 8. Key lifecycle tests

Integration tests in `vault/tests/key_lifecycle.rs`. Last run: **PASS**.

## 9. dudect timing results

**Recorded run:** 2026-03-26 — **Command:** `cargo run -p xtask -- timing-test` (dev profile, host-dependent).

| Metric | Value |
|--------|-------|
| Harnesses executed | 15 |
| Passed (|t| <= 4.5) | 15 |
| Wall time | ~266 s (example) |

**Conclusion:** All listed harnesses **PASS** when |t| stays within threshold; t-statistics vary by machine. Stubs (`dudect_stub_*`, `[MISSING]` integrations) remain **NotRun** or unimplemented as printed at end of `dudect_galdr` output.

## 10. cargo-fuzz coverage summary

**Not run** — this report was produced with `cargo run -p xtask -- test-all --no-fuzz`. To run all fuzz targets (~30 seconds each), execute `test-all` without `--no-fuzz`.

- Skipped: run without --no-fuzz to execute all fuzz targets (30s each).

## 11. Zeroisation tests (simulation)

Hardware verification not yet performed. See `docs/HARDWARE_VERIFICATION.md`. Last run: **PASS**.

## 12. PIN policy tests

Integration tests in `pin-policy/tests/pin_lifecycle.rs`. Last run: **PASS**.

## 13. Missing / not yet run

- **cargo-fuzz:** Not executed in this run (intentional). Re-run full `test-all` without `--no-fuzz` before release.

---

## Pipeline steps (machine log)

- **check-fw (default):** PASS
- **check-fw (pq-signatures):** PASS
- **unit tests (workspace):** PASS
- **wycheproof:** PASS
- **rfc_vectors:** PASS
- **bsi_brainpool:** PASS
- **nist_cavp:** PASS
- **kat_vectors:** PASS
- **key_lifecycle:** PASS
- **pin_lifecycle:** PASS
- **zeroise_simulation:** PASS
- **timing-test:** PASS
- **cargo-fuzz (skipped):** PASS
