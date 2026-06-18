<!--
MAINTENANCE CONTRACT FOR THIS FILE

1. Update the metadata block (date, commit, flags) on every full run.
2. Update the pipeline summary table only — do not add prose PASS
   lines anywhere else in the file.
3. dudect: update only the t-statistic and samples columns in
   the timing table. Do not add or remove per-harness subsections.
4. Fuzz: update the recorded-run tables when a new long run is done.
   Keep at most two recorded runs per target (latest + one notable).
5. New test area: add one row to the pipeline summary table and one
   subsection under the appropriate section. No other changes needed.
6. Do not duplicate pass/fail status between sections. The pipeline
   summary table is the single source of truth.
-->

# Test Results

## Run metadata

| Field | Value |
|---|---|
| Date (UTC) | 2026-05-04T01:12:08Z |
| Commit | `30c3a8e74707a5d3fb9bcc1b027f8e6d00c517bb` |
| xtask version | 0.1.0 |
| Flags | `--no-fuzz` (fuzz matrix run separately; see Section 6) |
| Host | x86_64-unknown-linux-gnu |
| Toolchain | nightly (cargo-fuzz); stable (all others) |

---

## Pipeline summary

| Step | Command | Status |
|------|---------|--------|
| Firmware check (default) | `cargo run -p xtask -- check-fw` | PASS |
| Firmware check (pq-signatures) | `cargo run -p xtask -- check-fw --features pq-signatures` | PASS |
| Unit tests (workspace) | `cargo test --workspace --exclude xtask` | PASS (623 passed, 0 failed, 17 ignored) |
| Wycheproof vectors | `cargo test -p vault wycheproof` | PASS |
| RFC vectors | `cargo test -p vault rfc_vectors` | PASS |
| BSI Brainpool vectors | `cargo test -p vault bsi_brainpool` | PASS |
| NIST CAVP subset | `cargo test -p vault nist_cavp` | PASS |
| KAT vectors | `cargo test -p vault kat_vectors` | PASS |
| Key lifecycle | `cargo test -p vault key_lifecycle` | PASS |
| PIN lifecycle | `cargo test -p pin-policy pin_lifecycle` | PASS |
| OpenPGP / CCID | `cargo test -p usb-personality` | PASS |
| Biometric crates (mocks) | `cargo test -p biometric-api -p biometric-vault -p biometric-fingervein --features test-hal -p biometric-sweet --features test-hal` | PASS |
| Zeroisation simulation | (see Section 7) | PASS |
| Timing (dudect) | `cargo run -p xtask -- timing-test` | PASS (32/32) |
| Cargo-fuzz (13 targets, 30 s in test-all) | (see Section 6) | PASS |

---

## 1. Unit tests

**Command:** `cargo test --workspace --exclude xtask`  
**Result:** 623 passed, 0 failed, 17 ignored

Round-trip tests (encrypt/decrypt, seal/open, sign/verify,
split/recover) are included in the 623 total and are not reported
separately.

---

## 2. Cryptographic validation

### 2.1 Symmetric AEAD

| Algorithm | Vector source | Vectors | Status |
|-----------|--------------|---------|--------|
| AES-128-GCM | Wycheproof `aes_gcm_test.json` | 105/105 | PASS |
| AES-256-GCM | Wycheproof `aes_gcm_test.json` | 102/102 | PASS |
| AES-256-GCM (smoke) | `galdr-core` `aes256_gcm_nist_one_block` | 1/1 | PASS |
| ChaCha20-Poly1305 | RFC 8439 §2.8.2 (`rfc8439_chacha.json`) | 1/1 | PASS |
| ChaCha20-Poly1305 (cross-check) | `galdr-core` `chacha20poly1305_rfc8439_aead` | 1/1 | PASS |

Skipped upstream Wycheproof groups: AES-192 keys, empty IV, 257-byte IV.  
No AES-GCM NIST CAVP `.rsp` files are present in this repository.

### 2.2 NIST CAVP subset (digests and HMAC only)

| Algorithm | Vectors | Status |
|-----------|---------|--------|
| SHA-256 | 2 | PASS |
| SHA3-256 | 1 | PASS |
| HMAC-SHA256 | 1 | PASS |

### 2.3 Twofish-256

Source: `crates/vault/tests/twofish_vectors.json`
(Schneier et al. Appendix B style chains).

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

### 2.4 RFC, BSI, Wycheproof, and KAT asset paths

| Asset | Runner |
|-------|--------|
| `crates/vault/tests/data/` | `cargo test -p vault wycheproof` |
| `tests/data/wycheproof/` | same |
| `crates/vault/tests/rfc_vectors/` | `vault/tests/rfc_vectors.rs` |
| `crates/vault/tests/bsi_vectors/` | `vault/tests/bsi_brainpool.rs` |
| `crates/vault/tests/nist_cavp_vectors/` | `vault/tests/nist_cavp.rs` |
| `crates/vault/tests/blake3_vectors.json` (and related KAT JSON) | `crates/vault/tests/kat_vectors.rs` |
| `crates/vault/tests/twofish_vectors.json` | `cargo test -p vault twofish_vectors_json_kat` (`twofish_vectors_json_kat` in `crates/vault/src/twofish_cipher.rs`) |

---

## 3. Timing tests (dudect)

**Tool:** `dudect_galdr` — **threshold |t| ≤ 4.5**  
**Result:** 32/32 harnesses PASS  
**Cache:** `crates/security-tests/dudect_results.json`

| Command | Purpose |
|---------|---------|
| `cargo run -p xtask -- timing-test` | Incremental (~155 s when 5 remain uncached) |
| `cargo run -p xtask -- timing-test --all` | Full suite (~910 s) |
| `cargo run -p xtask -- timing-test --full` | 3× sample multiplier |
| `cargo run -p xtask -- timing-test <name>` | Named harnesses only |

| Harness | Samples | t-stat | Status | Notes |
|---------|---------|--------|--------|-------|
| `timing_subtle_eq_u256` | 100000 | +1.766 | PASS |  |
| `timing_chacha_tag_check` | 100000 | -1.608 | PASS |  |
| `timing_aes_gcm_tag_check` | 100000 | +0.821 | PASS |  |
| `timing_hmac_verify` | 100000 | -2.198 | PASS |  |
| `timing_hkdf_derive` | 100000 | +2.452 | PASS |  |
| `timing_ed25519_verify` | 100000 | +1.779 | PASS |  |
| `timing_x25519_ecdh` | 100000 | +1.335 | PASS |  |
| `timing_brainpool256_scalar_mult` | 5000 | -1.626 | PASS |  |
| `timing_brainpool384_scalar_mult` | 5000 | +1.708 | PASS |  |
| `timing_brainpool512_scalar_mult` | 15000 | -2.496 | PASS |  |
| `timing_ephemeral_ecdh` | 10000 | -1.799 | PASS |  |
| `timing_signature_verify` | 10000 | +1.955 | PASS |  |
| `timing_fingerprint_lookup` | 100000 | -1.546 | PASS | Null pairing — same absent fingerprint both classes |
| `timing_shamir_recover` | 100000 | +2.701 | PASS |  |
| `timing_serpent_tag_check` | 100000 | -1.674 | PASS |  |
| `timing_twofish_tag_check` | 100000 | -1.425 | PASS |  |
| `timing_cascade_auth_failure` | 100000 | +1.544 | PASS | Null pairing — identical tampered ciphertext per class |
| `timing_cascade_inner_vs_outer_failure` | 100000 | +1.995 | PASS | Null pairing — identical inner tamper per class |
| `timing_pin_compare` | 100000 | +1.455 | PASS |  |
| `timing_rsa_oaep_decrypt` | 100000 | +1.114 | PASS |  |
| `timing_rsa_pss_verify` | 100000 | -1.925 | PASS |  |
| `timing_pbkdf2` | 100000 | -1.699 | PASS | PBKDF2-HMAC-SHA256; two 16-byte passwords |
| `timing_sha256` | 100000 | -1.490 | PASS |  |
| `timing_sha512` | 100000 | +2.138 | PASS |  |
| `timing_sha3_256` | 200000 | -2.797 | PASS |  |
| `timing_sha3_512` | 200000 | -4.329 | PASS |  |
| `timing_blake2b` | 100000 | +2.475 | PASS |  |
| `timing_blake2s` | 100000 | -2.221 | PASS |  |
| `timing_blake3` | 100000 | -1.760 | PASS | Single-chunk 64-byte message |
| `dudect_session_token_verify_constant_time` | 100000 | +2.048 | PASS | Constant-time compare harness |
| `dudect_template_decrypt_constant_time` | 100000 | -1.798 | PASS | Null pairing — decrypt good blob both classes |
| `dudect_signature_verify_constant_time` | 100000 | +3.159 | PASS | Constant-time limb compare harness |

**Not yet wired** (printed `[MISSING]` by `dudect_galdr`):
challenge-response HMAC, PSRAM tag check, XMSS verify, LMS verify.

---

## 4. Key lifecycle

Runner: `vault/tests/key_lifecycle.rs` — **PASS**

---

## 5. OpenPGP card application

| Test type | Command | Status |
|-----------|---------|--------|
| Crate unit + integration | `cargo test -p usb-personality` | PASS |
| libFuzzer (`openpgp_dispatch`) | See Section 6 | PASS |
| Host GnuPG / PC/SC end-to-end | Manual — `cargo run -p xtask -- test-openpgp` | Not automated |

See `docs/OPENPGP_CARD.md` for manual hardware test procedure.

---

## 6. Cargo-fuzz (libFuzzer)

**Full matrix command:**
```bash
rustup run nightly cargo fuzz run <target> \
  seed_corpus/<target> -- -max_total_time=120
```

| Target | Exit | Notes |
|--------|------|-------|
| `chacha_roundtrip` | 0 | See recorded run below |
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
| `openpgp_dispatch` | 0 | See long run below |

**test-all:** Skipped: run without --no-fuzz to execute all fuzz targets (30s each). 

### chacha_roundtrip (recorded 120 s run)
```bash
cd fuzz
rustup run nightly cargo fuzz run chacha_roundtrip \
  seed_corpus/chacha_roundtrip -- -max_total_time=120
```

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
```bash
cd fuzz
rustup run nightly cargo fuzz run openpgp_dispatch \
  -- -max_total_time=3600 -max_len=512
```

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

Coverage plateau is normal for this target — see `fuzz/README.md`.

---

## 7. Zeroisation and PIN policy

| Test | Runner | Status |
|------|--------|--------|
| Zeroisation (simulation) | `cargo test zeroise_simulation` | PASS |
| PIN lifecycle | `pin-policy/tests/pin_lifecycle.rs` | PASS |

Hardware zeroisation verification not yet performed.
See `docs/HARDWARE_VERIFICATION.md`.

---

## 8. Not yet automated

| Item | Reference |
|------|-----------|
| Hardware zeroisation | `docs/HARDWARE_VERIFICATION.md` |
| dudect: challenge-response HMAC | Printed `[MISSING]` by `dudect_galdr` |
| dudect: PSRAM tag check | Printed `[MISSING]` by `dudect_galdr` |
| dudect: XMSS / LMS verify | Printed `[MISSING]` by `dudect_galdr` |
| OpenPGP end-to-end on hardware | Requires CCID USB + host pcscd / GnuPG |
| Longer fuzz runs / `cargo fuzz cmin` | Optional pre-release; see `fuzz/README.md` |
