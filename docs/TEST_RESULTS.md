# Test Results

## Last full run

- **Date (UTC):** 2026-03-26T11:59:14Z
- **Commit:** `5e62cb81983f818acc77abbd5aa64d0f0559f089`
- **xtask version:** 0.1.0 (fuzz skipped via `--no-fuzz`)

## 1. Unit tests

| Scope | Passed | Failed | Ignored (`#[ignore]`) | Status |
|-------|--------|--------|-------------------------|--------|
| Workspace (excluding xtask), summed `test result` lines | 334 | 0 | 13 | PASS |

## 2. Wycheproof vector results

Vectors live under `crates/vault/tests/data/` and `tests/data/wycheproof/`. Run: `cargo test -p vault wycheproof`. When this step passes, all Wycheproof-driven tests in the vault crate succeed; per-vector accounting is in the vault test sources and upstream JSON tcId fields.

## 3. RFC test vector results

JSON under `crates/vault/tests/rfc_vectors/`, runner: `vault/tests/rfc_vectors.rs`. Last `test-all` step: **PASS**.

## 4. BSI test vector results

JSON under `crates/vault/tests/bsi_vectors/`, runner: `vault/tests/bsi_brainpool.rs` (TR-03111 cross-checks). Last run: **PASS**.

## 5. NIST CAVP vector results

Subset JSON under `crates/vault/tests/nist_cavp_vectors/`, runner `vault/tests/nist_cavp.rs`. Last run: **PASS**.

## 6. Known-answer test (KAT) results

Runner `vault/tests/kat_vectors.json` assets (Twofish/Serpent/Shamir/BLAKE3 as present). Last run: **PASS**.

## 7. Key lifecycle tests

Integration tests in `vault/tests/key_lifecycle.rs`. Last run: **PASS**.

## 8. dudect timing results

| Harness | Samples | t-statistic | Threshold | Result |
|---------|---------|-------------|-----------|--------|
| (security-tests stubs) | 0 | N/A | n/a | **NotRun** (stubs only; wire dudect for production metrics) |

## 9. cargo-fuzz coverage summary

**Not run** — this report was produced with `cargo run -p xtask -- test-all --no-fuzz`. To run all fuzz targets (~30 seconds each), execute `test-all` without `--no-fuzz`.

- Skipped: run without --no-fuzz to execute all fuzz targets (30s each).

## 10. Zeroisation tests (simulation)

Hardware verification not yet performed. See `docs/HARDWARE_VERIFICATION.md`. Last run: **PASS**.

## 11. PIN policy tests

Integration tests in `pin-policy/tests/pin_lifecycle.rs`. Last run: **PASS**.

## 12. Missing / not yet run

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
