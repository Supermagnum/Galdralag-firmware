<!--
MAINTENANCE CONTRACT FOR THIS FILE

1. Update the metadata block (date, commit, flags) on every full run.
2. Update the pipeline summary table only — do not add prose PASS
   lines anywhere else in the file.
3. dudect: update only the t-statistic column and samples column in
   the timing table. Do not add or remove per-harness subsections.
4. Fuzz: update the recorded-run tables when a new long run is done.
   Keep at most two recorded runs per target (latest + one notable).
5. New test area: add one row to the pipeline summary table and one
   subsection under the appropriate section. No other changes needed.
6. Do not duplicate pass/fail status between sections. The pipeline
   summary table is the single source of truth.
7. When `#[ignore]` tests are added or removed, update Section 3.1 so the
   breakdown still matches the **ignored** count in the pipeline summary.
-->

# Test Results

## Last full run

```toml
date_utc       = "2026-04-06T22:21:19Z"
commit         = "4b95193135db26614cc053c34aea2b6159a297c5"
xtask_version  = "0.1.0"
flags          = "--no-fuzz skipped; full fuzz matrix run separately"
host           = "x86_64-unknown-linux-gnu"
toolchain      = "nightly (cargo-fuzz targets); stable (all others)"
```

## Pipeline summary

| Step | Command | Status |
|------|---------|--------|
| Firmware check (default) | `cargo run -p xtask -- check-fw` | PASS |
| Firmware check (pq-signatures) | `cargo run -p xtask -- check-fw --features pq-signatures` | PASS |
| Unit tests (workspace) | `cargo test --workspace --exclude xtask` | PASS (568 passed, 0 failed, 17 ignored) |
| Wycheproof vectors | `cargo test -p vault wycheproof` | PASS |
| RFC vectors | `cargo test -p vault rfc_vectors` | PASS |
| BSI Brainpool vectors | `cargo test -p vault bsi_brainpool` | PASS |
| NIST CAVP subset | `cargo test -p vault nist_cavp` | PASS |
| KAT vectors | `cargo test -p vault kat_vectors` | PASS |
| Key lifecycle | `cargo test -p vault key_lifecycle` | PASS |
| PIN lifecycle | `cargo test -p pin-policy pin_lifecycle` | PASS |
| Zeroisation simulation | [Section 8](#8-zeroisation-tests) | PASS |
| Timing (dudect, incremental) | `cargo run -p xtask -- timing-test` | PASS (29/29 harnesses) |
| Cargo-fuzz (12 targets, 120 s) | [Section 6](#6-cargo-fuzz-libfuzzer) | PASS (skipped in test-all; see Section 6) |
| OpenPGP / CCID | `cargo test -p usb-personality` | PASS |

## 3. Unit tests

**Command:** `cargo test --workspace --exclude xtask`  
**Result:** 568 passed, 0 failed, 17 ignored

Round-trip tests (encrypt/decrypt, seal/open, sign/verify, split/recover) are included in the 568 total. They are not reported separately. Representative locations:

| Area | File | Key tests |
|------|------|-----------|
| Cipher cascade | `crates/cipher-profile/tests/cascade_integration.rs` | `cascade_roundtrip_all_builtins`, `cascade_hkdf_info_symmetric_encrypt_vs_decrypt_per_layer` |
| CESS Mode A outer | `crates/cess` | `mode_a::chacha_roundtrip`, `seal_open_roundtrip_every_listed_suite_id`, `wire::listed_ids_roundtrip` |
| Vault ciphers | `crates/vault/tests/key_lifecycle.rs` | Full vault round-trips per cipher; ChaCha/Serpent/Twofish AEAD, Shamir split/recover |
| Fuzz (not in total) | `fuzz/fuzz_targets/chacha_roundtrip.rs` | ChaCha encrypt/decrypt with random inputs; [Section 6](#6-cargo-fuzz-libfuzzer) |

### 3.1 Ignored tests (17)

The **17 ignored** in the pipeline summary are all `#[ignore]` tests in the workspace run. They are not failures; they are skipped by default until you pass `--ignored` (optionally with `-p <crate>`).

| Count | Location | Why ignored |
|------:|----------|-------------|
| 3 | `galdra/tests/cli_profiles.rs` | Need a connected token, Shamir test harness, or share fixtures from hardware; not runnable in a typical headless CI run. |
| 2 | `crates/vault/src/rsa_keys.rs` | `test_rsa_keygen_2048` is slow; `rsa_perf_baseline` is for occasional perf measurement (see `docs/PERFORMANCE.md`). |
| 12 | `crates/vault/tests/key_lifecycle.rs` | Most are duplicate **post-drop / ZeroizeOnDrop** checks already covered in narrower `vault` unit tests; plus slow **`lifecycle_rsa_generate`** and RSA zeroize covered under `rsa_keys` tests. |

**Breakdown:** 3 + 2 + 12. **Reported ignored:** **17** (must match the pipeline summary and Section 3 result line; if not, update this table).

**Run ignored tests:** `cargo test --workspace --exclude xtask -- --ignored`

## 4. Cryptographic validation

### 4.1 Symmetric AEAD

| Algorithm | Vector source | Vectors | Status |
|-----------|--------------|---------|--------|
| AES-128-GCM | Google Wycheproof `aes_gcm_test.json` | 105/105 | PASS |
| AES-256-GCM | Google Wycheproof `aes_gcm_test.json` | 102/102 | PASS |
| AES-256-GCM (smoke) | `galdr-core` `aes256_gcm_nist_one_block` | 1/1 | PASS |
| ChaCha20-Poly1305 | RFC 8439 §2.8.2 (`rfc8439_chacha.json`) | 1/1 | PASS |
| ChaCha20-Poly1305 (cross-check) | `galdr-core` `chacha20poly1305_rfc8439_aead` | 1/1 | PASS |

**Note:** AES-GCM uses Wycheproof JSON, not NIST CAVP `.rsp` files. AES-192, empty IV, and 257-byte IV groups are skipped upstream.

### 4.2 NIST CAVP subset (digests and HMAC only)

| Algorithm | Vectors | Status |
|-----------|---------|--------|
| SHA-256 | 2 | PASS |
| SHA3-256 | 1 | PASS |
| HMAC-SHA256 | 1 | PASS |

No AES-GCM CAVP `.rsp` files are present in this repository.

### 4.3 Twofish-256

Source: `crates/vault/tests/twofish_vectors.json` (Schneier et al. Appendix B style chains).

| Test | Vectors | Status |
|------|---------|--------|
| Zero-key 128-bit | 1 | PASS (`9F589F5CF6122C32B6BFEC2F2AE8C35A`) |
| Zero-key 192-bit | 1 | PASS (`EFA71F788965BD4453F860178FC19101`) |
| Zero-key 256-bit | 1 | PASS (`57FF739D4DC92C1BD7FC01700CC8216F`) |
| Variable-key 128-bit | 200 | PASS |
| Variable-key 192-bit | 200 | PASS |
| Variable-key 256-bit | 200 | PASS |
| Variable-text 128-bit | 200 | PASS |
| Variable-text 192-bit | 200 | PASS |
| Variable-text 256-bit | 200 | PASS |
| Monte Carlo (10 000 iter, 256-bit) | 1 | PASS (`a59b573030de1bffffe5c50fb030d847`) |
| **Total** | **1203** | **PASS** |

### 4.4 Cascade HKDF info symmetry

Runner: `cascade_hkdf_info_symmetric_encrypt_vs_decrypt_per_layer` in `crates/cipher-profile/tests/cascade_integration.rs`  
Checks that HKDF-SHA256 `layer_key_info` and `layer_nonce_info` strings match between encrypt and decrypt order for all built-in profiles, then runs a full cascade round-trip on the same PRK.  
**Status:** PASS

### 4.5 RFC, BSI, and Wycheproof (non-AES)

| Suite | Runner | Status |
|-------|--------|--------|
| Wycheproof (vault crate) | `cargo test -p vault wycheproof` | PASS |
| RFC vectors | `vault/tests/rfc_vectors.rs` | PASS |
| BSI TR-03111 Brainpool | `vault/tests/bsi_brainpool.rs` | PASS |

## 5. Timing tests (dudect)

**Tool:** `dudect_galdr`  
**Threshold:** |t| ≤ 4.5 (Welch t-statistic)  
**Commands:**

| Command | Purpose |
|---------|---------|
| `cargo run -p xtask -- timing-test` | Incremental (skips cached PASS harnesses) |
| `cargo run -p xtask -- timing-test --all` | Full suite (~910 s) |
| `cargo run -p xtask -- timing-test --full` | 3× sample multiplier |

**Cache:** `crates/security-tests/dudect_results.json`  
**Result:** 29/29 harnesses PASS

| Harness | Samples | t-stat | Status | Notes |
|---------|---------|--------|--------|-------|
| `timing_subtle_eq_u256` | 100000 | +1.471 | PASS |  |
| `timing_chacha_tag_check` | 100000 | -2.674 | PASS |  |
| `timing_aes_gcm_tag_check` | 100000 | +1.005 | PASS |  |
| `timing_hmac_verify` | 100000 | -1.246 | PASS |  |
| `timing_hkdf_derive` | 100000 | +2.474 | PASS |  |
| `timing_ed25519_verify` | 100000 | +1.447 | PASS |  |
| `timing_x25519_ecdh` | 100000 | +1.556 | PASS |  |
| `timing_brainpool256_scalar_mult` | 5000 | -1.434 | PASS |  |
| `timing_brainpool384_scalar_mult` | 5000 | -1.787 | PASS |  |
| `timing_brainpool512_scalar_mult` | 15000 | -2.246 | PASS |  |
| `timing_ephemeral_ecdh` | 10000 | +1.066 | PASS |  |
| `timing_signature_verify` | 10000 | -2.905 | PASS |  |
| `timing_fingerprint_lookup` | 100000 | +1.127 | PASS | Null pairing (same absent fingerprint both classes) |
| `timing_shamir_recover` | 100000 | -1.276 | PASS |  |
| `timing_serpent_tag_check` | 100000 | +1.973 | PASS |  |
| `timing_twofish_tag_check` | 100000 | -2.244 | PASS |  |
| `timing_cascade_auth_failure` | 100000 | -2.784 | PASS | Null pairing (identical tampered ciphertext per class) |
| `timing_cascade_inner_vs_outer_failure` | 100000 | +2.805 | PASS | Null pairing (identical inner tamper per class) |
| `timing_pin_compare` | 100000 | +1.202 | PASS |  |
| `timing_rsa_oaep_decrypt` | 100000 | -1.615 | PASS |  |
| `timing_rsa_pss_verify` | 100000 | -2.255 | PASS |  |
| `timing_pbkdf2` | 100000 | -1.149 | PASS | PBKDF2-HMAC-SHA256; two 16-byte passwords |
| `timing_sha256` | 100000 | +2.177 | PASS |  |
| `timing_sha512` | 100000 | -2.088 | PASS |  |
| `timing_sha3_256` | 200000 | +1.774 | PASS |  |
| `timing_sha3_512` | 200000 | +1.671 | PASS |  |
| `timing_blake2b` | 100000 | +1.724 | PASS |  |
| `timing_blake2s` | 100000 | +2.177 | PASS |  |
| `timing_blake3` | 100000 | -2.127 | PASS | Single-chunk 64-byte message |

**Not yet wired (printed as `[MISSING]` by `dudect_galdr`):** challenge-response HMAC, PSRAM tag check, XMSS verify, LMS verify.

## 6. Cargo-fuzz (libFuzzer)

**Full matrix command:**

```bash
rustup run nightly cargo fuzz run <target> \
  seed_corpus/<target> -- -max_total_time=120
```

| Target | Exit | Notes |
|--------|------|-------|
| `chacha_roundtrip` | 0 | [Recorded run below](#chacha_roundtrip-recorded-120-s-run) |
| `shamir_split_recover` | 0 | Fixed `data.len() >= 8` guard |
| `brainpool384_ecdh` | 0 | |
| `brainpool512_ecdh` | 0 | |
| `serpent_aead` | 0 | |
| `twofish_aead` | 0 | |
| `rsa_oaep_decrypt` | 0 | |
| `rsa_pss_verify` | 0 | |
| `rsa_der_import` | 0 | |
| `fuzz_ephemeral_handshake` | 0 | |
| `fuzz_cipher_profile` | 0 | |
| `openpgp_dispatch` | 0 | [Long run below](#openpgp_dispatch-recorded-1-h-run) |

**test-all:** Skipped: run without --no-fuzz to execute all fuzz targets (30s each). 

### chacha_roundtrip (recorded 120 s run)

| Item | Value |
|------|-------|
| Wall time | ~121 s |
| Executions | 3 667 006 |
| exec/s (end) | ~30 000 |
| Seed corpus files | 11 |
| Final corpus entries | 44 |
| Final corpus size | ~27 KiB |
| Final cov (edges) | 703 |
| Final ft (features) | 1 162 |
| Crashes | 0 |

### openpgp_dispatch (recorded 1 h run)

| Item | Value |
|------|-------|
| Wall time | ~3 600 s (manual stop) |
| Executions | order of 10^8 |
| exec/s | ~40 000+ sustained |
| Starting cov / ft | ~934 / ~1 168 |
| Ending cov / ft | ~980 / ~1 230 |
| Corpus entries | ~200 |
| Crashes | 0 |
| ASAN findings | 0 |

## 7. Wycheproof, RFC, BSI, NIST, KAT vectors

Covered in [Section 4](#4-cryptographic-validation). Raw JSON assets:

| Asset path | Runner |
|------------|--------|
| `crates/vault/tests/data/` | `cargo test -p vault wycheproof` |
| `tests/data/wycheproof/` | same |
| `crates/vault/tests/rfc_vectors/` | `vault/tests/rfc_vectors.rs` |
| `crates/vault/tests/bsi_vectors/` | `vault/tests/bsi_brainpool.rs` |
| `crates/vault/tests/nist_cavp_vectors/` | `vault/tests/nist_cavp.rs` |
| `crates/vault/tests/blake3_vectors.json` (and related KAT JSON) | `crates/vault/tests/kat_vectors.rs` |
| `crates/vault/tests/twofish_vectors.json` | `cargo test -p vault twofish_vectors_json_kat` (`twofish_vectors_json_kat` in `crates/vault/src/twofish_cipher.rs`) |

## 8. Zeroisation tests

Simulation only. Hardware verification not yet performed.  
See `docs/HARDWARE_VERIFICATION.md`.  
**Status:** PASS (simulation)

## 9. PIN policy tests

Runner: `pin-policy/tests/pin_lifecycle.rs`  
**Status:** PASS

## 10. OpenPGP card application

| Test type | Command | Status |
|-----------|---------|--------|
| Crate unit + integration | `cargo test -p usb-personality` | PASS |
| libFuzzer (`openpgp_dispatch`) | [Section 6](#6-cargo-fuzz-libfuzzer) | PASS |
| Host GnuPG / PC/SC end-to-end | Manual; `cargo run -p xtask -- test-openpgp` | Not automated |

See `docs/OPENPGP_CARD.md` for manual hardware test procedure.

## 11. Not yet automated

| Item | Reference |
|------|-----------|
| Hardware zeroisation | `docs/HARDWARE_VERIFICATION.md` |
| dudect: challenge-response HMAC | Printed `[MISSING]` by `dudect_galdr` |
| dudect: PSRAM tag check | Printed `[MISSING]` by `dudect_galdr` |
| dudect: XMSS / LMS verify | Printed `[MISSING]` by `dudect_galdr` |
| OpenPGP end-to-end on hardware | Requires CCID USB + host pcscd / GnuPG |
| Longer fuzz runs / `cargo fuzz cmin` | Optional pre-release; see `fuzz/README.md` |
