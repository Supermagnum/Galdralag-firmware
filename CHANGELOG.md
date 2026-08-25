# Changelog

All notable changes to this project are documented in this file.

## Unreleased

### Security

- **Shamir host split RNG (critical):** Production host Shamir split (`galdra shamir split`, `galdrad` `POST /shamir/split`, `galdra-gtk` split UI) used `FakeTrng::from_seed(0x5F4D_414D_4952)` for polynomial coefficients. With GF(256) XOR arithmetic, **one share plus public source code recovered the full secret**; K-of-N threshold did not apply. Introduced in commit `ec9faa90e1be5c5bc656245e786c87ccf564a971` (2026-06-18); fixed in commit `d8628017dfd07afd352e7384b53f9e06b80ce41a`. **Any shares produced before the fix commit must be treated as compromised** — re-provision and re-split affected keys. See [docs/SECURITY_ADVISORY_SHAMIR_RNG.md](docs/SECURITY_ADVISORY_SHAMIR_RNG.md).
- **Fix:** `OsRng` on the production path; `ShamirSplitRng` trait restricts approved entropy sources; `test-hal` removed from `galdra-core-host` release dependencies; `xtask check-host` verifies release host builds; regression tests for non-determinism and cross-secret independence.

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
