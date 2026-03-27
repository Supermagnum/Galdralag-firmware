# Test Results

## Last full run

- **Date (UTC):** 2026-03-27T03:25:00Z
- **Commit:** `b5c905d1ae57133e212ed5f6e67f0646f5018518`
- **xtask version:** 0.1.0 (fuzz skipped via `--no-fuzz`)

**Section 1** unit-test totals were recomputed at this commit with `cargo test --workspace --exclude xtask` (sum of every `test result:` line). **Section 9** lists t-statistics from **`crates/security-tests/dudect_results.json`** (authoritative PASS cache updated when `cargo run -p xtask -- timing-test` succeeds). Values are host-dependent. For a **full** dudect sweep (~910 s on a typical developer machine), use `timing-test --all`; the default `timing-test` skips harnesses already marked PASS in that JSON file.

## 1. Unit tests

| Scope | Passed | Failed | Ignored (`#[ignore]`) | Status |
|-------|--------|--------|-------------------------|--------|
| Workspace (excluding xtask), summed `test result` lines | 398 | 0 | 14 | PASS |

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
    Covers constant-time comparisons, AEAD tag checks (ChaCha20-Poly1305, AES-GCM, Serpent, Twofish EtM), HMAC verify, HKDF, Ed25519/X25519, Brainpool ECDH (reduced samples on slow curves), ephemeral-session ECDH (10k samples), Brainpool handshake signature verify, InMemoryTrustStore fingerprint lookup, Shamir, PBKDF2, SHA-2/SHA-3, BLAKE2/BLAKE3, PIN compare, RSA constant-time equality on modulus-sized buffers, etc.
    Pipeline: `test-all` runs a **full** `dudect_galdr` (all harnesses; no PASS cache). Section 9 documents results aligned with **`dudect_results.json`**, which incremental `timing-test` runs extend after each successful pass.

## 3. Wycheproof vector results

Vectors live under `crates/vault/tests/data/` and `tests/data/wycheproof/`. Run: `cargo test -p vault wycheproof`. When this step passes, all Wycheproof-driven tests in the vault crate succeed; per-vector accounting is in the vault test sources and upstream JSON tcId fields.

## 4. RFC test vector results

JSON under `crates/vault/tests/rfc_vectors/`, runner: `vault/tests/rfc_vectors.rs`. Last `test-all` step: **PASS**.

## 5. BSI test vector results

JSON under `crates/vault/tests/bsi_vectors/`, runner: `vault/tests/bsi_brainpool.rs` (TR-03111 cross-checks). Last run: **PASS**.

## 6. NIST CAVP vector results

Subset JSON under `crates/vault/tests/nist_cavp_vectors/`, runner `vault/tests/nist_cavp.rs`. Last run: **PASS**.

## 7. Known-answer test (KAT) results

Runner `vault/tests/kat_vectors.json` assets (Twofish/Serpent/Shamir/BLAKE3 as present). Last run: **PASS**.

### Twofish-256

Source: `crates/vault/tests/twofish_vectors.json` (Schneier et al. Appendix B style chains; zero-key ciphertexts match the Twofish specification).

- **Test status:** 1203 / 1203 vectors passing when `twofish_vectors_json_kat` passes
- **Zero-key 128-bit:** PASS (expected: `9F589F5CF6122C32B6BFEC2F2AE8C35A`)
- **Zero-key 192-bit:** PASS (expected: `EFA71F788965BD4453F860178FC19101`)
- **Zero-key 256-bit:** PASS (expected: `57FF739D4DC92C1BD7FC01700CC8216F`)
- **Variable-key set (128 / 192 / 256-bit key):** 200 / 200 each
- **Variable-text set (128 / 192 / 256-bit key):** 200 / 200 each
- **Monte Carlo (10,000 iterations, 256-bit key):** PASS (final ciphertext `a59b573030de1bffffe5c50fb030d847`)
- **dudect (tag check):** PASS (representative t = -1.74366 for `timing_twofish_tag_check` in Section 9).
## 8. Key lifecycle tests

Integration tests in `vault/tests/key_lifecycle.rs`. Last run: **PASS**.

## 9. dudect timing results

**Commands (xtask):**

- `cargo run -p xtask -- timing-test` — runs harnesses **not** yet recorded as PASS in **`crates/security-tests/dudect_results.json`** (fast for day-to-day work).
- `cargo run -p xtask -- timing-test --all` — full suite (~910 s typical); ignores the cache.
- `cargo run -p xtask -- timing-test --full` — 3x sample multiplier for whatever harnesses run (often combined with `--all` before release).
- `cargo run -p xtask -- timing-test timing_sha256 …` — run only named harnesses (cache ignored for those names).

Binary: **`dudect_galdr`**, threshold **|t| <= 4.5**. **PASS** rows in **`dudect_results.json`** are merged from JSON lines on stdout when a run exits 0. t-statistics are host-dependent; the table matches the checked-in cache at [Last full run](#last-full-run).

**Summary:** 29/29 executed harnesses passed threshold (|t| <= 4.5) in the recorded cache.

**Elapsed:** a **full** `--all` run is on the order of **~910 s** on a developer machine; incremental runs only time non-cached harnesses (for example ~155 s when five remained).

| Harness | Samples | t-statistic | Threshold | Status |
|---------|---------|-------------|-----------|--------|
| `timing_subtle_eq_u256` | 100000 | -1.37078 | ±4.5 | PASS |
| `timing_chacha_tag_check` | 100000 | +1.52140 | ±4.5 | PASS |
| `timing_aes_gcm_tag_check` | 100000 | -0.85914 | ±4.5 | PASS |
| `timing_hmac_verify` | 100000 | -2.06906 | ±4.5 | PASS |
| `timing_hkdf_derive` | 100000 | -3.50326 | ±4.5 | PASS |
| `timing_ed25519_verify` | 100000 | +1.51008 | ±4.5 | PASS |
| `timing_x25519_ecdh` | 100000 | +1.77939 | ±4.5 | PASS |
| `timing_brainpool256_scalar_mult` | 5000 | +1.48477 | ±4.5 | PASS |
| `timing_brainpool384_scalar_mult` | 5000 | -2.67990 | ±4.5 | PASS |
| `timing_brainpool512_scalar_mult` | 15000 | -1.55175 | ±4.5 | PASS |
| `timing_ephemeral_ecdh` | 10000 | +3.18711 | ±4.5 | PASS |
| `timing_signature_verify` | 10000 | -2.33506 | ±4.5 | PASS |
| `timing_fingerprint_lookup` | 100000 | +2.58782 | ±4.5 | PASS |
| `timing_shamir_recover` | 100000 | +1.91206 | ±4.5 | PASS |
| `timing_serpent_tag_check` | 100000 | -2.15022 | ±4.5 | PASS |
| `timing_twofish_tag_check` | 100000 | -1.74366 | ±4.5 | PASS |
| `timing_cascade_auth_failure` | 100000 | +2.19458 | ±4.5 | PASS |
| `timing_cascade_inner_vs_outer_failure` | 100000 | +1.55774 | ±4.5 | PASS |
| `timing_pin_compare` | 100000 | -1.82845 | ±4.5 | PASS |
| `timing_rsa_oaep_decrypt` | 100000 | -1.68044 | ±4.5 | PASS |
| `timing_rsa_pss_verify` | 100000 | +2.99207 | ±4.5 | PASS |
| `timing_pbkdf2` | 100000 | -2.44431 | ±4.5 | PASS |
| `timing_sha256` | 100000 | -1.31473 | ±4.5 | PASS |
| `timing_sha512` | 100000 | -1.95467 | ±4.5 | PASS |
| `timing_sha3_256` | 200000 | -3.89831 | ±4.5 | PASS |
| `timing_sha3_512` | 200000 | -1.51956 | ±4.5 | PASS |
| `timing_blake2b` | 100000 | +2.04292 | ±4.5 | PASS |
| `timing_blake2s` | 100000 | -2.53810 | ±4.5 | PASS |
| `timing_blake3` | 100000 | -1.47562 | ±4.5 | PASS |

### timing_subtle_eq_u256

- Samples: 100000
- t-statistic: -1.37078
- Threshold: ±4.5
- Status: PASS

### timing_chacha_tag_check

- Samples: 100000
- t-statistic: +1.52140
- Threshold: ±4.5
- Status: PASS

### timing_aes_gcm_tag_check

- Samples: 100000
- t-statistic: -0.85914
- Threshold: ±4.5
- Status: PASS

### timing_hmac_verify

- Samples: 100000
- t-statistic: -2.06906
- Threshold: ±4.5
- Status: PASS

### timing_hkdf_derive

- Samples: 100000
- t-statistic: -3.50326
- Threshold: ±4.5
- Status: PASS

### timing_ed25519_verify

- Samples: 100000
- t-statistic: +1.51008
- Threshold: ±4.5
- Status: PASS

### timing_x25519_ecdh

- Samples: 100000
- t-statistic: +1.77939
- Threshold: ±4.5
- Status: PASS

### timing_brainpool256_scalar_mult

- Samples: 5000
- t-statistic: +1.48477
- Threshold: ±4.5
- Status: PASS

### timing_brainpool384_scalar_mult

- Samples: 5000
- t-statistic: -2.67990
- Threshold: ±4.5
- Status: PASS

### timing_brainpool512_scalar_mult

- Samples: 15000
- t-statistic: -1.55175
- Threshold: ±4.5
- Status: PASS

### timing_shamir_recover

- Samples: 100000
- t-statistic: +1.91206
- Threshold: ±4.5
- Status: PASS

### timing_serpent_tag_check

- Samples: 100000
- t-statistic: -2.15022
- Threshold: ±4.5
- Status: PASS

### timing_twofish_tag_check

- Samples: 100000
- t-statistic: -1.74366
- Threshold: ±4.5
- Status: PASS

### timing_cascade_auth_failure

- Samples: 100000
- t-statistic: +2.19458
- Threshold: ±4.5
- Status: PASS
- Note: Welch **null** pairing (identical tampered ciphertext per class) to test harness/measurement stability; not a differential success-vs-failure probe.

### timing_cascade_inner_vs_outer_failure

- Samples: 100000
- t-statistic: +1.55774
- Threshold: ±4.5
- Status: PASS
- Note: Welch **null** pairing (identical inner tamper per class); see `timing_cascade_auth_failure`.

### timing_pin_compare

- Samples: 100000
- t-statistic: -1.82845
- Threshold: ±4.5
- Status: PASS

### timing_rsa_oaep_decrypt

- Samples: 100000
- t-statistic: -1.68044
- Threshold: ±4.5
- Status: PASS

### timing_rsa_pss_verify

- Samples: 100000
- t-statistic: +2.99207
- Threshold: ±4.5
- Status: PASS

### timing_pbkdf2

- Samples: 100000
- t-statistic: -2.44431
- Threshold: ±4.5
- Status: PASS
- Note: Measures PBKDF2-HMAC-SHA256 with two 16-byte passwords (fixed vs random).

### timing_sha256

- Samples: 100000
- t-statistic: -1.31473
- Threshold: ±4.5
- Status: PASS

### timing_sha512

- Samples: 100000
- t-statistic: -1.95467
- Threshold: ±4.5
- Status: PASS

### timing_sha3_256

- Samples: 200000
- t-statistic: -3.89831
- Threshold: ±4.5
- Status: PASS

### timing_sha3_512

- Samples: 200000
- t-statistic: -1.51956
- Threshold: ±4.5
- Status: PASS

### timing_blake2b

- Samples: 100000
- t-statistic: +2.04292
- Threshold: ±4.5
- Status: PASS

### timing_blake2s

- Samples: 100000
- t-statistic: -2.53810
- Threshold: ±4.5
- Status: PASS

### timing_blake3

- Samples: 100000
- t-statistic: -1.47562
- Threshold: ±4.5
- Status: PASS
- Note: Single-chunk 64-byte message (compression function path).

### timing_ephemeral_ecdh

- Samples: 10000
- t-statistic: +3.18711
- Threshold: ±4.5
- Status: PASS

### timing_signature_verify

- Samples: 10000
- t-statistic: -2.33506
- Threshold: ±4.5
- Status: PASS

### timing_fingerprint_lookup

- Samples: 100000
- t-statistic: +2.58782
- Threshold: ±4.5
- Status: PASS
- Note: Welch **null** pairing (same absent fingerprint for both classes); not a differential hit-vs-miss lookup probe.

**Optional integrations still printed as `[MISSING]` by `dudect_galdr`:** challenge-response HMAC, PSRAM tag check, XMSS verify, LMS verify (not wired as host benchmarks in this workspace).

## 10. cargo-fuzz coverage summary

**Not run** — this report was produced with `cargo run -p xtask -- test-all --no-fuzz`. To run all fuzz targets (~30 seconds each), execute `test-all` without `--no-fuzz`.

- Skipped: run without --no-fuzz to execute all fuzz targets (30s each).
- **fuzz_ephemeral_handshake:** `InitMessage::parse` / `ResponseMessage::parse` (`cargo run -p xtask -- fuzz ephemeral-handshake 60`).
- **fuzz_cipher_profile:** `CipherProfile::from_bytes` and `cascade_decrypt` (`cargo run -p xtask -- fuzz cipher-profile 60`).

## 11. Zeroisation tests (simulation)

Hardware verification not yet performed. See `docs/HARDWARE_VERIFICATION.md`. Last run: **PASS**.

## 12. PIN policy tests

Integration tests in `pin-policy/tests/pin_lifecycle.rs`. Last run: **PASS**.

## 13. Missing / not yet run

- **cargo-fuzz:** Not executed in this run (intentional). Re-run full `test-all` without `--no-fuzz` before release.

Out of scope or not automated in this run:

- **Hardware zeroisation:** See `docs/HARDWARE_VERIFICATION.md` (simulation-only in CI).
- **Optional dudect integrations:** USB challenge-response, PSRAM tag check, XMSS/LMS verify (printed as `[MISSING]` by `dudect_galdr`).

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
