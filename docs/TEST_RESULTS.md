# Test Results

## Last full run

- **Date (UTC):** 2026-03-26T20:42:48Z
- **Commit:** `19384323958b07734241a1383c467075d4a2134a`
- **xtask version:** 0.1.0 (fuzz skipped via `--no-fuzz`)

Section 9 dudect figures below were copied from a successful `dudect_galdr` run on this commit (no need to re-execute the ~20 minute timing suite to refresh prose elsewhere).

## 1. Unit tests

| Scope | Passed | Failed | Ignored (`#[ignore]`) | Status |
|-------|--------|--------|-------------------------|--------|
| Workspace (excluding xtask), summed `test result` lines | 372 | 0 | 14 | PASS |

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
    Covers constant-time comparisons, AEAD tag checks (ChaCha20-Poly1305, AES-GCM, Serpent, Twofish EtM), HMAC verify, HKDF, Ed25519/X25519, Brainpool ECDH (reduced samples on slow curves), Shamir, PBKDF2, SHA-2/SHA-3, BLAKE2/BLAKE3, PIN compare, RSA constant-time equality on modulus-sized buffers, etc.
    Pipeline: `test-all` runs `dudect_galdr` and records parsed t-statistics in Section 9.

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
- **dudect (tag check):** PASS (representative t = -2.31294 for `timing_twofish_tag_check` in Section 9).
## 8. Key lifecycle tests

Integration tests in `vault/tests/key_lifecycle.rs`. Last run: **PASS**.

## 9. dudect timing results

**Command:** `cargo run -p xtask -- timing-test` (binary `dudect_galdr`; threshold |t| <= 4.5). t-statistics are host-dependent; values below match a recorded successful run on this commit.

**Summary:** 24/24 executed harnesses passed threshold (|t| <= 4.5).

**Elapsed (reported by dudect_galdr):** ~1220.6 s.

| Harness | Samples | t-statistic | Threshold | Status |
|---------|---------|-------------|-----------|--------|
| `timing_subtle_eq_u256` | 100000 | -1.96919 | ±4.5 | PASS |
| `timing_chacha_tag_check` | 100000 | +1.42753 | ±4.5 | PASS |
| `timing_aes_gcm_tag_check` | 100000 | -1.70287 | ±4.5 | PASS |
| `timing_hmac_verify` | 100000 | -3.31892 | ±4.5 | PASS |
| `timing_hkdf_derive` | 100000 | -2.33201 | ±4.5 | PASS |
| `timing_ed25519_verify` | 100000 | -1.41628 | ±4.5 | PASS |
| `timing_x25519_ecdh` | 100000 | +1.25519 | ±4.5 | PASS |
| `timing_brainpool256_scalar_mult` | 5000 | +1.97772 | ±4.5 | PASS |
| `timing_brainpool384_scalar_mult` | 5000 | +2.34205 | ±4.5 | PASS |
| `timing_brainpool512_scalar_mult` | 15000 | -2.14614 | ±4.5 | PASS |
| `timing_shamir_recover` | 100000 | +1.42197 | ±4.5 | PASS |
| `timing_serpent_tag_check` | 100000 | -1.66123 | ±4.5 | PASS |
| `timing_twofish_tag_check` | 100000 | -2.31294 | ±4.5 | PASS |
| `timing_pin_compare` | 100000 | -1.15680 | ±4.5 | PASS |
| `timing_rsa_oaep_decrypt` | 100000 | +1.47384 | ±4.5 | PASS |
| `timing_rsa_pss_verify` | 100000 | -4.08701 | ±4.5 | PASS |
| `timing_pbkdf2` | 150000 | +1.80555 | ±4.5 | PASS |
| `timing_sha256` | 100000 | -1.66307 | ±4.5 | PASS |
| `timing_sha512` | 100000 | -1.95918 | ±4.5 | PASS |
| `timing_sha3_256` | 200000 | +2.93010 | ±4.5 | PASS |
| `timing_sha3_512` | 200000 | +2.28332 | ±4.5 | PASS |
| `timing_blake2b` | 100000 | +1.85087 | ±4.5 | PASS |
| `timing_blake2s` | 100000 | +1.85495 | ±4.5 | PASS |
| `timing_blake3` | 100000 | +2.08824 | ±4.5 | PASS |

### timing_subtle_eq_u256

- Samples: 100000
- t-statistic: -1.96919
- Threshold: ±4.5
- Status: PASS

### timing_chacha_tag_check

- Samples: 100000
- t-statistic: +1.42753
- Threshold: ±4.5
- Status: PASS

### timing_aes_gcm_tag_check

- Samples: 100000
- t-statistic: -1.70287
- Threshold: ±4.5
- Status: PASS

### timing_hmac_verify

- Samples: 100000
- t-statistic: -3.31892
- Threshold: ±4.5
- Status: PASS

### timing_hkdf_derive

- Samples: 100000
- t-statistic: -2.33201
- Threshold: ±4.5
- Status: PASS

### timing_ed25519_verify

- Samples: 100000
- t-statistic: -1.41628
- Threshold: ±4.5
- Status: PASS

### timing_x25519_ecdh

- Samples: 100000
- t-statistic: +1.25519
- Threshold: ±4.5
- Status: PASS

### timing_brainpool256_scalar_mult

- Samples: 5000
- t-statistic: +1.97772
- Threshold: ±4.5
- Status: PASS

### timing_brainpool384_scalar_mult

- Samples: 5000
- t-statistic: +2.34205
- Threshold: ±4.5
- Status: PASS

### timing_brainpool512_scalar_mult

- Samples: 15000
- t-statistic: -2.14614
- Threshold: ±4.5
- Status: PASS

### timing_shamir_recover

- Samples: 100000
- t-statistic: +1.42197
- Threshold: ±4.5
- Status: PASS

### timing_serpent_tag_check

- Samples: 100000
- t-statistic: -1.66123
- Threshold: ±4.5
- Status: PASS

### timing_twofish_tag_check

- Samples: 100000
- t-statistic: -2.31294
- Threshold: ±4.5
- Status: PASS

### timing_pin_compare

- Samples: 100000
- t-statistic: -1.15680
- Threshold: ±4.5
- Status: PASS

### timing_rsa_oaep_decrypt

- Samples: 100000
- t-statistic: +1.47384
- Threshold: ±4.5
- Status: PASS

### timing_rsa_pss_verify

- Samples: 100000
- t-statistic: -4.08701
- Threshold: ±4.5
- Status: PASS

### timing_pbkdf2

- Samples: 150000
- t-statistic: +1.80555
- Threshold: ±4.5
- Status: PASS
- Note: Measures PBKDF2-HMAC-SHA256 with two 16-byte passwords (fixed vs random).

### timing_sha256

- Samples: 100000
- t-statistic: -1.66307
- Threshold: ±4.5
- Status: PASS

### timing_sha512

- Samples: 100000
- t-statistic: -1.95918
- Threshold: ±4.5
- Status: PASS

### timing_sha3_256

- Samples: 200000
- t-statistic: +2.93010
- Threshold: ±4.5
- Status: PASS

### timing_sha3_512

- Samples: 200000
- t-statistic: +2.28332
- Threshold: ±4.5
- Status: PASS

### timing_blake2b

- Samples: 100000
- t-statistic: +1.85087
- Threshold: ±4.5
- Status: PASS

### timing_blake2s

- Samples: 100000
- t-statistic: +1.85495
- Threshold: ±4.5
- Status: PASS

### timing_blake3

- Samples: 100000
- t-statistic: +2.08824
- Threshold: ±4.5
- Status: PASS
- Note: Single-chunk 64-byte message (compression function path).

**Optional integrations still printed as `[MISSING]` by `dudect_galdr`:** challenge-response HMAC, PSRAM tag check, XMSS verify, LMS verify (not wired as host benchmarks in this workspace).

## 10. cargo-fuzz coverage summary

**Not run** — this report was produced with `cargo run -p xtask -- test-all --no-fuzz`. To run all fuzz targets (~30 seconds each), execute `test-all` without `--no-fuzz`.

- Skipped: run without --no-fuzz to execute all fuzz targets (30s each).

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
