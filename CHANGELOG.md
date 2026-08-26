# Changelog

All notable changes to this project are documented in this file.

## Unreleased

### Security

- **`sequoia-openpgp` 1.22 → 2.4.1 (RUSTSEC-2025-0136):** Upgraded host OpenPGP stack (`sequoia-openpgp` **2.4.1**, `sequoia-net` **0.30.1** in lockstep). Upstream `aes_key_unwrap` could panic (or OOM-panic) on a crafted PKESK/SKESK with a too-short wrapped key; fixed in sequoia-openpgp ≥ 2.1.0. Reachable from `galdra` / `galdrad` / `galdra-core-host` decrypt and related OpenPGP paths. No GHSA filed here — this is an upstream advisory.
- **`rand` 0.8.5 → 0.8.8 (RUSTSEC-2026-0097):** Workspace pin and lockfile; also refresh transitive `rand` 0.9.2 → 0.9.5 and 0.10.0 → 0.10.2. The advisory is an unsound `thread_rng`/logger reseed case; production Shamir split uses `OsRng`.
- **`rsa` 0.9.10 / RUSTSEC-2023-0071 (Marvin):** Still pinned; no 0.9.x fix. GitHub alert “closed” is not a version fix. Documented as **T15** in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md); CI `cargo-audit` allow-lists this ID only with that note.
- **Shamir host split RNG (critical):** Production host Shamir split (`galdra shamir split`, `galdrad` `POST /shamir/split`, `galdra-gtk` split UI) used `FakeTrng::from_seed(0x5F4D_414D_4952)` for polynomial coefficients. With GF(256) XOR arithmetic, **one share plus public source code recovered the full secret**; K-of-N threshold did not apply. Introduced in commit `ec9faa90e1be5c5bc656245e786c87ccf564a971` (2026-06-18); fixed in commit `7db5e08851b2f0c48b65a00caa579f1d5ec077dd`. **Any shares produced before the fix commit must be treated as compromised** — re-provision and re-split affected keys. See [docs/SECURITY_ADVISORY_SHAMIR_RNG.md](docs/SECURITY_ADVISORY_SHAMIR_RNG.md).
- **Fix:** `OsRng` on the production path; `ShamirSplitRng` trait restricts approved entropy sources; `test-hal` removed from `galdra-core-host` release dependencies; `xtask check-host` verifies release host builds; regression tests for non-determinism and cross-secret independence.

### Added

- **GitHub Actions CI** (`.github/workflows/ci.yml`): `test-all --no-fuzz --no-dudect`, `cargo-audit` on all three lockfiles, and firmware `riscv32` checks on every PR and push to `main`. Weekly scheduled `test-all` with fuzz **and** dudect (plus `workflow_dispatch`). Dudect is not a PR gate: it is ~15–20 minutes on GitHub-hosted runners. See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for `cargo-audit` allow-list.

### Changed

- **RSA OpenPGP card operations:** Documents no longer list RSA-2048/3072/4096 as a working card algorithm. Attributes can be stored via PUT DATA; GENERATE, PSO:CDS, and PSO:DECIPHER fail for RSA slots. Vault `rsa_keys` remains OAEP/PSS plus PKCS#1 v1.5 sign/verify. See [docs/OPENPGP_CARD.md](docs/OPENPGP_CARD.md). **T15** description in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) narrowed to match (accepted-risk status unchanged).
- **OpenPGP hidden recipients:** With sequoia 2.x (SEIPDv2 / PKESK6 when Features enable AEAD), anonymous recipients are encoded by omitting the PKESK recipient identifier (`Recipient::set_key_handle(None)`), not `KeyID::wildcard`. CLI/API flags for hidden recipients are unchanged; only the on-wire PKESK recipient field for newly encrypted messages differs from the 1.x wildcard KeyID form when AEAD PKESK6 is used.
- **`StandardPolicy` cutoffs (sequoia 2.x defaults):** Version-4 ElGamal keys and IDEA/CAST5 in SEIPDv1 messages are rejected after 2025-02-01 per upstream policy. This project already used `StandardPolicy::new()` without custom cutoffs; decrypting such legacy material now fails policy where 1.x might have accepted it. DSA rejection remains scheduled for 2030-02-01.

### Removed

- **In-tree `bp512` crate** (`crates/bp512`): BrainpoolP512r1 curve arithmetic that was authored in this repository and incorrectly described elsewhere as an audited RustCrypto crate. Field/scalar math reused the upstream `primefield` / `crypto-bigint` stack, but the curve definition, constants wiring, and vault integration were project-maintained and not independently audited.
- **`high-assurance` cipher profile** and CESS built-in mapping to suite id `0x0012`. This profile is retired, not repointed to P-384 or any other curve. Existing ciphertext sealed under `high-assurance` / `0x0012` is not readable with current firmware.
- **BrainpoolP512r1** from ephemeral session curves (wire id `0x03` is no longer accepted), OpenPGP card algorithm attributes, host profile curve parsing (`brainpool512` / `bp512`), contact-store `KeyAlgo` wire value `5`, and all P512-specific tests, Wycheproof/BSI fixtures, fuzz target `brainpool512_ecdh`, and dudect harness `timing_brainpool512_scalar_mult`.

### Rationale

RustCrypto [`elliptic-curves`](https://github.com/RustCrypto/elliptic-curves) does not ship a maintained `bp512` crate ([tracking issue #114](https://github.com/RustCrypto/elliptic-curves/issues/114)). The in-tree substitute duplicated the `bp384` layout with P-512 domain parameters. That packaging was mislabeled in code and documentation as audited upstream RustCrypto code. Until an independently reviewed upstream implementation exists, P-512 support is not offered.

### Notes

- Brainpool **P256r1** and **P384r1** remain via crates.io `bp256` / `bp384`.
- No replacement profile is planned for the retired `high-assurance` name.

### Explicit rejection (host and firmware)

Legacy wire values (`key_algo` **`0x05`**, ephemeral curve **`0x03`**, CESS suite **`0x0012`**, profile name **`high-assurance`**) now fail with typed errors and user-facing messages that name the artifact and state that P-512 / `high-assurance` was removed (not a decrypt retry or corruption on the user's side). See `galdr_core::legacy_removed` and `GaldraError::RemovedLegacyCrypto` on the host.

### Added

- **Host OpenPGP stale P-512 scan:** `galdra device status` and `galdrad` `GET /device/status` read C1/C2/C3 via PC/SC and warn when any slot still stores BrainpoolP512r1 algorithm attributes from older firmware. `galdra identity fingerprint` and `galdra encrypt` (profiles without ephemeral ECDH) preflight the SIG slot before reading the public key. Read-only; no card writes. See [docs/OPENPGP_CARD.md](docs/OPENPGP_CARD.md).

### CCID / xous-core targeting (Unreleased)

Labels: **[docs]** no firmware/host behavior change; **[tooling]** build/dev scripts; **[code]** source that can change runtime behavior; **[tracking]** backlog only.

#### Tooling

- **[tooling]** `scripts/check_xous_core_preflight.sh` and `cargo run -p xtask -- check-xous-core` (read-only; expected branch `feature/usb-bao1x-ccid-openpgp`). Failure output states the mismatch and a copy-pasteable `ln -sfn <sibling> ./xous-core`.
- **[tooling]** `scripts/build_dabao_ccid_image.sh` builds `galdralag-service` and invokes sibling `cargo xtask dabao-ccid <cratespec>` without editing xous-core. Preflight runs first so a stale nested tree cannot produce a silent transport-only-looking image.

#### Docs

- **[docs]** Provisioning (Persona A): root README, `services/galdralag/README.md`, and [docs/HARDWARE_BRINGUP_TEST_PLAN.md](docs/HARDWARE_BRINGUP_TEST_PLAN.md) mark USB CDC two-line PIN provisioning as **legacy / non-Dabao-CCID**; Dabao lab defaults, `baosec`+`ccid-pddb`, and `dev-provisioning` are the documented routes. Plain `dabao-ccid` called out as transport-only.
- **[docs]** CCID ownership write-up in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): `usb-bao1x` owns inline GetSlotStatus / IccPowerOn; Galdralag owns deferred XfrBlock APDUs. `answered_inline_by_usb_bao1x()` is **opcode-only** (not transport-aware); skip is Xous IPC only. Tests: `inline_usb_bao1x_opcodes` + `non_xous_ccid_class_answers_inline_opcodes`.
- **[docs]** [docs/HARDWARE_BRINGUP_TEST_PLAN.md](docs/HARDWARE_BRINGUP_TEST_PLAN.md) lab run 2026-08-18: pyusb smoke — inline GetSlotStatus/IccPowerOn OK; deferred XfrBlock SELECT timeout (`galdralag-stub` image).

#### Tracking

- **[tracking]** PC/SC vendor filter for `device status` — scans any OpenPGP card in the first reader until an FSFE/GnuPG manufacturer ID is assigned. Firmware `build_aid(0x20A0, …)` misuses the USB VID as AID manufacturer bytes. See [docs/OPENPGP_CARD.md](docs/OPENPGP_CARD.md).
- **[tracking]** [docs/XOUS_CORE_UPSTREAM_REQUESTS.md](docs/XOUS_CORE_UPSTREAM_REQUESTS.md) for Persona A / ATR / cratespec / libccid items that belong in xous-core. Lab 2026-08-18: `pcscd` `WriteUSB` timeout after ATR (section 7); Phase 2 stub image same failure (section 8).
- **[tooling]** `scripts/build_dabao_ccid_stub_image.sh` — dabao-ccid + `galdralag-stub` for isolated XfrBlock/SELECT transport tests (section 13 of bring-up plan).

#### Code

- **[code]** Xous `galdralag-service` and `galdralag-stub` no longer `CcidTx` IccPowerOn (0x62) or GetSlotStatus (0x65) if those frames arrive on `CcidRxDeferred` (`PcToRdr::answered_inline_by_usb_bao1x`). In-process `CcidClass` / `OpenPgpCcidDispatcher` still answers them for non-Xous USB.
