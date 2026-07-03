# Changelog

All notable changes to this project are documented in this file.

## Unreleased

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
- **Documented (not implemented):** PC/SC vendor filter for `device status` — scans any OpenPGP card in the first reader until an FSFE/GnuPG manufacturer ID is assigned for Baochip/Galdralag ([xous-core#875](https://github.com/betrusted-io/xous-core/issues/875)).
