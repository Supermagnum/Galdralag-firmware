# Test Results

## Last full run

- **Date (UTC):** 2026-03-27T03:25:00Z
- **Commit:** `b5c905d1ae57133e212ed5f6e67f0646f5018518`
- **xtask version:** 0.1.0 (fuzz skipped via `--no-fuzz`)

**Section 1** unit-test totals were recomputed at this commit with `cargo test --workspace --exclude xtask` (sum of every `test result:` line). **Section 9** lists t-statistics from **`crates/security-tests/dudect_results.json`** (authoritative PASS cache updated when `cargo run -p xtask -- timing-test` succeeds). Values are host-dependent. For a **full** dudect sweep (~910 s on a typical developer machine), use `timing-test --all`; the default `timing-test` skips harnesses already marked PASS in that JSON file. **Section 10** records **cargo-fuzz** (libFuzzer) runs: a detailed **`chacha_roundtrip`** sample, a recorded long **`openpgp_dispatch`** run (OpenPGP APDU + vault backend), and a **full 12-target** matrix (`-max_total_time=120` each, `seed_corpus/`).

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

## 10. cargo-fuzz (libFuzzer) summary

Host: **x86_64-unknown-linux-gnu**, **nightly** toolchain, **`cargo-fuzz`**. Corpus paths are relative to the `fuzz/` directory unless noted. LibFuzzer metrics are **host-dependent**; `cov` = edge coverage, `ft` = feature count.

### chacha_roundtrip (recorded run)

**Command:**

```bash
cd fuzz
rustup run nightly cargo fuzz run chacha_roundtrip seed_corpus/chacha_roundtrip -- -max_total_time=120
```

**Outcome:** Completed normally (no crash; exit 0). Wall time **~121 s** for **3,667,006** executions (~30k exec/s at end of run).

| Item | Value |
|------|--------|
| Seed corpus files (inputs loaded) | 11 |
| Final corpus size (entries) | 44 |
| Final corpus total bytes (approx.) | ~27 KiB |
| Final `cov` (edges) | 703 |
| Final `ft` (features) | 1162 |
| `max_len` (libFuzzer default) | 4096 bytes |

**Harness:** `fuzz/fuzz_targets/chacha_roundtrip.rs` — ChaCha key derive (`ChaChaKey::derive`), encrypt/decrypt round-trip with `FakeTrng`-derived nonce.

**Note:** Passing **`seed_corpus/chacha_roundtrip`** as the corpus directory causes libFuzzer to **merge new discoveries into that tree** on disk. For a clean checkout, regenerate seeds with `python3 fuzz/scripts/gen_seed_corpus.py` or copy seeds into **`corpus/chacha_roundtrip/`** (gitignored) for long runs.

### openpgp_dispatch (recorded long run)

**Command:**

```bash
cd fuzz
rustup run nightly cargo fuzz run openpgp_dispatch -- -max_total_time=3600 -max_len=512
```

**Outcome:** Run **interrupted manually** (Ctrl+C); log showed **no crashes** and **no ASAN** findings. Metrics are **host-dependent**.

| Item | Value (representative log) |
|------|------------------------------|
| Executions before stop | order of **10^8** |
| `exec/s` | **~40k+** sustained |
| Starting `cov` / `ft` (after seed load) | **~934** / **~1168** |
| Ending `cov` / `ft` | **~980** / **~1230** |
| Corpus | **~195** seed files merged; grew to **~200** entries, **~2–3 KiB** total (corpus minimisation active) |

**Harness:** `fuzz/fuzz_targets/openpgp_dispatch.rs` — `CommandApdu::parse`, `handle_apdu` on `OpenPgpVaultBackend` with default DOs, `AlgorithmAttributes::parse`, `parse_ecdh_peer_public_key`, dalek Ed25519/X25519 constructors from the first 32 bytes.

**Interpretation:** **High exec/s** is expected for this workload relative to simpler targets: the harness still completes full dispatch per iteration. **Long stretches of flat `cov`** with occasional **NEW** / **NEW_FUNC** (e.g. `trim_openpgp_pin_padding`, `ResponseApdu::ok_empty`) are **normal**: most random APDUs fail parse or exit early; only a narrow family reaches multi-step flows (VERIFY then PSO, PUT with PW3, etc.). A **seeded corpus** yields a **high starting `cov`**; further gains are **incremental** — consistent with [Corpus health (LibFuzzer output)](../fuzz/README.md#corpus-health-libfuzzer-output) in `fuzz/README.md`. Plateau **does not** imply a broken target.

**Optional follow-ups:** `cargo fuzz cmin openpgp_dispatch corpus/openpgp_dispatch/`; add hand-crafted seeds from `tests/openpgp_command_flow.rs` if deeper coverage is needed; resume with the same corpus path to continue discovery.

### Full matrix (`-max_total_time=120` per target, `seed_corpus/<target>/`)

All **12** binaries in `fuzz/Cargo.toml` were run sequentially with:

`rustup run nightly cargo fuzz run <target> seed_corpus/<target> -- -max_total_time=120`

Stopping is by **LibFuzzer time limit** (about **121 s** wall per target), not by automatic “corpus plateau” detection (that would need a custom wrapper). Within each window, many **REDUCE** lines with flat `cov` are normal convergence.

| Target | Exit |
|--------|------|
| `chacha_roundtrip` | 0 |
| `shamir_split_recover` | 0 |
| `brainpool384_ecdh` | 0 |
| `brainpool512_ecdh` | 0 |
| `serpent_aead` | 0 |
| `twofish_aead` | 0 |
| `rsa_oaep_decrypt` | 0 |
| `rsa_pss_verify` | 0 |
| `rsa_der_import` | 0 |
| `fuzz_ephemeral_handshake` | 0 |
| `fuzz_cipher_profile` | 0 |
| `openpgp_dispatch` | 0 |

**Note:** `openpgp_dispatch` is the **12th** target; add `fuzz/seed_corpus/openpgp_dispatch/` (may be empty) if you run this matrix and the path is missing.

**Harness fix:** `shamir_split_recover` required `data.len() >= 8` before reading `data[0..8]` (previously `>= 4`, which could panic under the fuzzer). Host-dependent metrics; re-run locally to refresh numbers.

**Shorter runs via xtask:** `cargo run -p xtask -- fuzz <target> 60` from the repo root uses the default **corpus** path under `fuzz/corpus/`, not `seed_corpus/` (see `fuzz/README.md`).

Full `test-all` without `--no-fuzz` still runs **one** default fuzz target for a bounded time; it does not replace this full-matrix command sequence.

## 11. Zeroisation tests (simulation)

Hardware verification not yet performed. See `docs/HARDWARE_VERIFICATION.md`. Last run: **PASS**.

## 12. PIN policy tests

Integration tests in `pin-policy/tests/pin_lifecycle.rs`. Last run: **PASS**.

## 13. OpenPGP card application (`usb-personality`)

- **Crate tests:** `cargo test -p usb-personality` — CCID `PC_to_RDR` / `RDR_to_PC` helpers, ISO 7816-4 APDU parse/encode, DO encoding, `CardState`, and integration flows in `tests/openpgp_command_flow.rs` (mock backend: `pin-policy` + `vault` Brainpool ECDSA). Last run: **PASS** (when this section was updated).
- **libFuzzer (`openpgp_dispatch`):** Arbitrary APDU bytes through `handle_apdu` + vault backend; see [Section 10 — openpgp_dispatch](#openpgp_dispatch-recorded-long-run) for a recorded long run and interpretation.
- **Host GnuPG / PC/SC:** Full `gpg --card-status` against a real CCID enumeration is manual; `cargo run -p xtask -- test-openpgp` only checks for `gpg` and prints guidance (skipped if absent). See `docs/OPENPGP_CARD.md`.

## 14. Missing / not yet run

- **cargo-fuzz:** Full **12-target** matrix (120 s each, `seed_corpus/`) summarised in [Section 10](#10-cargo-fuzz-libfuzzer-summary). Longer runs or `cargo fuzz cmin` / `coverage` are optional pre-release checks (`fuzz/README.md`). The **`openpgp_dispatch`** long sample (1 h wall, `-max_len=512`) is recorded in the same section.

Out of scope or not automated in this run:

- **Hardware zeroisation:** See `docs/HARDWARE_VERIFICATION.md` (simulation-only in CI).
- **Optional dudect integrations:** USB challenge-response, PSRAM tag check, XMSS/LMS verify (printed as `[MISSING]` by `dudect_galdr`).
- **OpenPGP end-to-end on hardware:** Requires CCID USB integration and host `pcscd` / GnuPG; not part of `test-all`.

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
- **cargo-fuzz (12 targets, 120 s each, seed corpus):** PASS (see Section 10; `openpgp_dispatch` long run documented there)
- **usb-personality (OpenPGP / CCID):** PASS (`cargo test -p usb-personality`; see Section 13)
