# Galdralag — Capabilities and Future Expansion

This document describes what the Galdralag firmware already supports, and
identifies realistic future additions with suitable Rust crates for each.

The same standard applied to the current dependency tree applies to all future
additions: preference for audited, `no_std`-compatible crates from the RustCrypto
ecosystem or equivalently well-reviewed projects. Crates marked "not yet audited"
should not be integrated until independent audits are available.

---

## Current Capabilities

The device is already an OpenPGP card compatible security token. This is not a
minor detail — OpenPGP card compatibility gives the device immediate, out-of-the-box
support for a wide range of serious use cases through existing host-side tooling,
with no further firmware work required.

What this means in practice:

- **GnuPG integration** — signing, encryption, and authentication operations via
  GnuPG's OpenPGP card driver. Works on Linux, macOS, and Windows today.

- **SSH authentication** — via `gpg-agent` with `enable-ssh-support`. The device
  appears as an SSH authentication token to any SSH client that uses `gpg-agent`.
  No additional firmware required.

- **Git commit signing** — via `gpg.program=gpg` or `gpg.format=openpgp`.
  Signed commits and tags using a hardware-bound key.

- **S/MIME email signing and encryption** — through GnuPG's S/MIME support
  (`gpgsm`) and compatible mail clients such as Thunderbird and Evolution.

- **Code and artifact signing** — any tool that calls GnuPG for signing operations
  benefits immediately, including release scripts, package managers, and CI pipelines.

- **Document signing and notarisation** — signing arbitrary files with a
  hardware-bound key whose private material never leaves the device.

- **Offline CA operations** — the device can hold a CA signing key and issue
  certificates through GnuPG's certificate tooling or OpenSC's PKCS#11 interface.

On top of standard OpenPGP card behaviour, this repository adds or specifies the
following (with the implementation boundaries called out where they matter):

- **Authenticated ephemeral ECDH (forward secrecy design).** The `ephemeral-session`
  crate implements the handshake and session key derivation (Brainpool curves,
  HKDF); see [EPHEMERAL_SESSION.md](EPHEMERAL_SESSION.md). Host tooling links that
  crate (`galdra-core-host`). Device firmware implements OpenPGP-side ECDH and
  related primitives in `usb-personality` / `vault` but does **not** depend on
  `ephemeral-session` directly. Strong forward-secrecy guarantees still depend on
  product integration and on-device zeroisation behaviour; the same document notes
  limits of hardware verification to date.
- **Shamir K-of-N (split/recover math in `vault`).** GF(256) Shamir split and
  recovery live in `crates/vault`. Today’s **host-orchestrated** flows export the
  signing key from the token (when connected), run `vault::shamir::*` on the
  **host** to build or combine shares, then re-import the recovered material —
  see [API_REFERENCE.md](API_REFERENCE.md) and `galdra-core-host/src/shamir_ops.rs`.
  That is multi-party **custody of shares**, not “the full Shamir lifecycle only
  inside the MCU RAM.”
- **Cipher-agnostic named profiles** with cascade support and audit metadata
  (`cipher-profile` and related docs) — implemented in tree.
- **Optional bulk decoy storage (microSD or PSRAM)** — specified in
  [Psram.md](Psram.md) (and SD integration notes); **no working decoy volume stack
  is implemented in this repository yet.** `usb-personality` models a
  `MassStorageDecoy` persona and tests that secrets are not exposed on that path;
  product behaviour remains future work aligned with the design spec.
- **Fully open stack** (where the hardware and tooling ship that way): CERN-OHL-W-2.0
  RTL, open schematics, reproducible bootloader, Rust/Xous OS, IRIS-inspectable
  silicon — positioning for the Dabao/Baochip platform, not something this doc
  proves line-by-line in source.

This combination makes Galdralag a compelling device for journalism and source
protection, whistleblower infrastructure, scientific data provenance, enterprise
key custody, and software supply chain integrity — all without changes to
existing host-side tooling.

---

## Planned Additions

### 1. Password Vault

Store per-site credentials encrypted in RRAM behind the existing PIN policy.
Retrieval via the authenticated host-tools interface only — no USB keyboard
personality, no HID emulation.

| Crate | Role | Notes |
|-------|------|-------|
| `postcard` | Compact binary serialisation of credential records | `no_std`, deterministic output, used in production embedded Rust. Not a cryptographic crate — encryption handled by existing deps. No formal security audit; assess suitability carefully. |
| `serde` | Derive `Serialize`/`Deserialize` on credential entry types | Paired with `postcard`. |
| `zeroize` | Zeroise credential structs on drop | Already in the dependency tree. |

Cryptographic protection of vault entries uses `aes-gcm` or `chacha20poly1305`
plus `hkdf` with a new `KeyPurpose::PasswordEntry` domain label — all already
in tree. No new cryptographic crates required.

---

### 2. Kerberos / PKINIT Enterprise Authentication

Authenticate to Active Directory, FreeIPA, or MIT Kerberos infrastructure using
PKINIT (RFC 4556). The token presents a certificate-backed identity to a KDC
instead of a password, via the existing CCID interface and OpenSC or PKCS#11
middleware on the host.

| Crate | Role | Notes |
|-------|------|-------|
| `x509-cert` | X.509 certificate parsing and encoding (RFC 5280) | Pure Rust, RustCrypto project, `no_std` compatible. Not yet independently audited. |
| `cms` | PKINIT AuthPack signing (DER-encoded CMS SignedData) | Pure Rust, RustCrypto project, `no_std` compatible. Not yet independently audited. |
| `der` | ASN.1 DER encoding/decoding — required by `cms` and `x509-cert` | Pure Rust, RustCrypto project, `no_std` with heapless support. |
| `pkcs8` | Private key encoding/decoding (RFC 5208, RFC 5958) | RustCrypto project, `no_std` compatible. |
| `spki` | X.509 Subject Public Key Info encoding | RustCrypto project, `no_std` compatible. |

No standalone Rust PKINIT client crate suitable for `no_std` embedded use exists
at time of writing. The firmware only performs the signing operation; PKINIT
protocol handling lives entirely in host-side tooling.

Planned: Q2 hardware availability.

---

### 3. Post-Quantum Cryptography Profile Additions

Add ML-KEM, ML-DSA, and SLH-DSA algorithm entries to the existing cipher-agnostic
profile system once independently audited crates are available.

| Crate | Notes |
|-------|-------|
| `ml-kem` (RustCrypto) | `no_std` compatible, tested against NIST KAT vectors. No independent audit as of 2025 — RustCrypto README explicitly states this. Do not integrate before audit. |
| `ml-dsa` (RustCrypto) | `no_std` compatible, tested against NIST KAT vectors. No independent audit as of 2025. Same caveat. |
| `slh-dsa` (RustCrypto) | `no_std` compatible, tested against NIST KAT vectors. No independent audit as of 2025. Same caveat. |
| `libcrux-ml-kem` (Cryspen) | Formally verified using hax/F* framework; used in production by Mozilla. Most rigorous verification story currently available. Uncovered the KyberSlash timing bug in other implementations. Watch for formal audit availability. |

Hybrid classical+PQC profiles (e.g. X25519 + ML-KEM-768) should be the first
deployment target. The existing cipher-agnostic profile system accommodates this
without architectural changes.

Integration is intentionally deferred until at least one crate covering ML-KEM
and ML-DSA has completed an independent security audit.

---

### 4. Biometric pre-gate (design)

See [BIOMETRIC_API.md](BIOMETRIC_API.md) for the on-token template storage and
`galdrad` relay model. Before any **deployment** claim for that path:

- **PAD testing** must follow **ISO/IEC 30107-3** methodology; informal spoof
  tests are not enough for product or security positioning.
- **Matching accuracy** must be benchmarked against the **datasets published
  alongside the sweet platform (CandyFV)** and the **datasets associated with the
  ESP32-CAM device paper**, so numbers stay aligned with those public baselines.

**Rust integration tests** follow the existing **`test-hal` / `dudect` /
`cargo-fuzz`** pattern already in the workspace (same as other crates: **`test-hal`**
fakes, **`dudect`** for timing-critical paths, **`cargo-fuzz`** under `fuzz/`;
see [Psram.md](Psram.md) for the consolidated description).

---

## Crates Explicitly Excluded

| Crate | Reason |
|-------|--------|
| `pqcrypto-*` family | FFI bindings to C reference implementations — not suitable for `no_std` embedded target |
| `openssl` | Does not support `no_std`; C dependency |
| Any TOTP/HOTP crate | No RTC; protocol mismatch for this device class |
| Any FIDO2/CTAP2 crate | No user-presence button; fundamental incompatibility |

---

## Audit Status Summary

The "Yes" entries below record **dependency policy** (commonly cited independent
audits for those crates). They are **not** assertions proven inside this
repository; confirm against each upstream project before production sign-off.

| Crate | Independently Audited |
|-------|----------------------|
| `aes-gcm`, `chacha20poly1305`, `ed25519-dalek`, `x25519-dalek`, `hkdf`, `pbkdf2`, `hmac`, `sha2`, `sha3`, `blake2`, `blake3`, `zeroize`, `subtle`, `p256`, `p384` | Yes (per upstream; existing deps) |
| `vsss-rs` | Yes (per upstream; existing dep) |
| `der`, `cms`, `x509-cert`, `pkcs8`, `spki` | No |
| `ml-kem`, `ml-dsa`, `slh-dsa` | No |
| `postcard` | No |
