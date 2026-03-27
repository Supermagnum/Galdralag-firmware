# Galdr — Galdralag Firmware

> **Status:** Implementation in progress — no production-ready release exists.
> Cryptographic primitives are drawn exclusively from audited workspace
> dependencies. Post-quantum algorithms are feature-gated and marked
> **PENDING INDEPENDENT AUDIT**. See [Post-quantum status](#post-quantum-status).

> **Note:** Parts of this project were developed with AI assistance (Claude, Anthropic).
> The design, cryptographic choices, and security decisions have not been reviewed
> by a professional cryptographer. Treat this as an experimental project and apply
> your own critical judgement. Independent expert review is strongly recommended
> before any production deployment.

It is ready for testing by humans; using a **virtual machine** for that is suggested. There may be bugs that automated tests have not discovered.

---

## About the name

**Galdr** is the Old Norse practice of spoken or sung magic: incantations
used to bind, protect, or reveal. In the sagas it names the act of casting
the spell itself, not only the words. Sometimes also used to activate magic
rune inscriptions, as on the [Kragehul I lance shaft](https://en.wikipedia.org/wiki/Kragehul_I),
the [Lindholm amulet](https://en.wikipedia.org/wiki/Lindholm_amulet),
the [Vadstena bracteate](https://en.wikipedia.org/wiki/Vadstena_bracteate),
and other Elder Futhark finds.

**Galdralag** is the metrical form used for galdr: structured, precise,
rule-bound verse in which the pattern is part of the force of the spell.
The suffix *lag* is akin to "law" or "pattern."

**Runes** were literally secret, encoded knowledge — the shamanic usage
was only known to those who understood.

---

## What this is

Firmware for **Baochip-1x** (Dabao evaluation board) devices running the
**[Xous](https://github.com/betrusted-io/xous-core)** microkernel, built
for `riscv32imac-unknown-none-elf`.

The device is a hardware security token in the same category as
Nitrokey-class devices, with OpenPGP smartcard-class behaviour and an
encrypted vault. The full hardware stack — RTL, schematics, bootloader,
OS — is open source and auditable.

Hardware specification, boot model, requirement tables, and ComboHash/PKE
usage are documented in the
**[Baochip-1x firmware design README](https://raw.githubusercontent.com/Supermagnum/Baochip-1x-firmware/refs/heads/main/README.md)**.
Architecture notes for this repository: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## Documentation

- **[Galdra — Token Management Tool Specification](https://github.com/Supermagnum/Galdralag-firmware/blob/main/docs/GALDRA-TOOL.md)** — host tools (`galdra` CLI, `galdrad` daemon, `galdra-gtk`), contacts, groups, OpenPGP workflows, and operational behaviour.
- **[Glossary](https://github.com/Supermagnum/Galdralag-firmware/blob/main/docs/GLOSSARY.md)** — short definitions of terms used across this repository.

Same files in a local clone: [docs/GALDRA-TOOL.md](docs/GALDRA-TOOL.md), [docs/GLOSSARY.md](docs/GLOSSARY.md).

---

## Build, install, and uninstall

Use a **stable Rust** toolchain as pinned in [rust-toolchain.toml](rust-toolchain.toml). Firmware uses the `riscv32imac-unknown-none-elf` target; host tools use the host triple.

### Compile firmware

1. Install the embedded target:

   ```bash
   rustup target add riscv32imac-unknown-none-elf
   ```

2. Type-check firmware crates (fails if `test-hal` would leak into production builds):

   ```bash
   cargo run -p xtask -- check-fw
   ```

3. Build firmware crates in release mode:

   ```bash
   cargo run -p xtask -- build-fw
   ```

   Object code and archives land under `target/riscv32imac-unknown-none-elf/release/`. A full bootable **Xous** system image for a specific board is produced by the wider Baochip / Xous integration flow when you follow that product’s build; `xtask` here runs `cargo build` for the firmware library crates listed in `xtask` (not a single ready-to-flash file by itself).

### Flashing

This repository does **not** ship a one-command flasher. Programming the **Baochip-1x** (JTAG, ROM/USB boot, or vendor tools) follows the board and silicon documentation. Start from the **[Baochip-1x firmware design README](https://raw.githubusercontent.com/Supermagnum/Baochip-1x-firmware/refs/heads/main/README.md)** and your board’s flashing guide.

### Compile and install host tools (`galdra`, `galdrad`, `galdra-gtk`)

Host crates live at the workspace root: `galdra/`, `galdrad/`, `galdra-gtk/`.

**GTK 4 (required for `galdra-gtk` only):** install development packages so `pkg-config` can find `gtk4` (crate `gtk4` 0.9). Examples: Debian/Ubuntu — `libgtk-4-dev`; Fedora — `gtk4-devel`; Arch — `gtk4`.

Build release binaries from the repository root:

```bash
cargo build --release -p galdra -p galdrad -p galdra-gtk
```

Executables: `target/release/galdra`, `target/release/galdrad`, `target/release/galdra-gtk`.

**Install** into `~/.cargo/bin` (adjust `--path` if you are not in the repo root):

```bash
cargo install --locked --path galdra
cargo install --locked --path galdrad
cargo install --locked --path galdra-gtk
```

You can instead copy those three binaries to any directory on your `PATH`.

### Uninstall host tools

If you used `cargo install --path` as above:

```bash
cargo uninstall galdra
cargo uninstall galdrad
cargo uninstall galdra-gtk
```

If you copied binaries manually, remove the files you added. Firmware is not “installed” on the host; erasing or reflashing the device is covered by your hardware documentation.

---

## Key capabilities

### What makes this token unusual

- **Authenticated ephemeral ECDH on-device** — true cryptographic forward
  secrecy. Each session generates a fresh ephemeral key pair on the token's
  hardware TRNG. The long-term key signs the ephemeral offer but never
  participates in key agreement. Past sessions cannot be decrypted even from
  a fully compromised long-term key. To the project authors' knowledge, no
  commercial hardware security token provides this as a first-class feature.

- **Shamir K-of-N secret sharing on-device** — the long-term key can be
  split into N shares requiring K to reconstruct, with no single holder able
  to recover the key alone. To the project authors' knowledge, no commercial
  token provides this as a first-class feature either.

- **Cipher-agnostic profile system** — symmetric ciphers, ECDHE curves, and
  Shamir configuration are combined into named, auditable profiles. A cascade
  of multiple independent ciphers (e.g. Serpent-256 + ChaCha20-Poly1305) can
  be selected per session. Every profile selection is logged in the audit trail.

- **Optional PSRAM decoy volume** — if a PSRAM chip is fitted, the device
  presents as ordinary USB mass storage to any host that does not know the
  authentication protocol. The PSRAM content is intentionally unencrypted and
  unremarkable — a decoy. Real key material lives in on-chip RRAM behind the
  vault and PIN policy.

- **Fully open stack** — CERN-OHL-W-2.0 RTL, open schematics, reproducible
  bootloader, Rust/Xous OS, IRIS-inspectable silicon.

### Cryptographic capabilities

All primitives come from independently audited workspace dependencies.
Nothing is implemented in-tree.

#### Asymmetric / key agreement

| Algorithm | Standard | Notes |
|-----------|----------|-------|
| BrainpoolP256r1 ECDH + ECDSA | RFC 5639, BSI TR-03111 | BSI-standardised, no NSA involvement |
| BrainpoolP384r1 ECDH + ECDSA | RFC 5639, BSI TR-03111 | ~192-bit security |
| BrainpoolP512r1 ECDH + ECDSA | RFC 5639, BSI TR-03111 | ~256-bit security |
| X25519 ECDH | RFC 7748 | |
| Ed25519 sign / verify | RFC 8032 | |
| RSA-2048 / 3072 / 4096 OAEP, PSS | RFC 8017 | Minimum 2048-bit enforced |
| P-256, P-384 | NIST | Via `p256` / `p384` workspace deps |

#### Symmetric / AEAD

| Algorithm | Standard | Notes |
|-----------|----------|-------|
| AES-256-GCM | FIPS 197, NIST SP 800-38D | Hardware AES on Baochip-1x |
| ChaCha20-Poly1305 | RFC 8439 | No NSA involvement |
| Twofish-256 | Schneier et al. 1998 | AES finalist, no NSA involvement |
| Serpent-256 | Anderson / Biham / Knudsen 1998 | AES finalist, 32 rounds, conservative margin |

#### Key derivation / MAC / digest

| Algorithm | Standard |
|-----------|----------|
| HKDF (SHA-256 / SHA-512) | RFC 5869 |
| HMAC (SHA-256 / SHA-512) | RFC 2104 |
| PBKDF2 | RFC 8018 |
| SHA-2 (224 / 256 / 384 / 512) | FIPS 180-4 |
| SHA-3 family | FIPS 202 |
| BLAKE2b / BLAKE2s | RFC 7693 |
| BLAKE3 | BLAKE3 specification |

#### Key management

| Feature | Notes |
|---------|-------|
| Shamir K-of-N secret sharing | `vsss-rs` — on-device split and recovery |
| Authenticated ephemeral ECDH | Forward-secret session protocol — `ephemeral-session` crate |
| Cipher profile system | User-configurable cipher cascade — `cipher-profile` crate |

### Security properties

| Property | Implementation |
|----------|---------------|
| Forward secrecy | Ephemeral ECDH: long-term key signs only, never agrees |
| PIN counter before compare | Counter flushed to RRAM before `subtle::ConstantTimeEq` — no exceptions |
| Hardware zeroisation | TRNG-sourced multi-pass overwrite; boot0 zeroises before USB enumeration |
| No secret on USB bus | Uninformed host sees only standard mass-storage; no fingerprint possible |
| Monotonic tamper evidence | Hardware one-way counters in always-on domain |
| Constant-time operations | All secret comparisons via `subtle`; verified by dudect harnesses |
| test-hal never in production | Enforced by `check-fw` xtask |

### PIN policy

- Minimum length: **5 alphanumeric characters** — enforced at parser boundary,
  before `pin-policy` is called. Short inputs do not increment the counter.
- Default attempt threshold: **3** (configurable 3–10 at provisioning).
  Matches hardware token industry standard (Nitrokey, YubiKey, ISO 7816).
- On threshold: full hardware zeroisation triggered.
- Challenge/response passphrase (USB informed-host path): minimum 5 characters,
  transmitted only as `HMAC-SHA256(HostChallengeKey, nonce || passphrase)`.

---

## Post-quantum status

### Implemented — unaudited crate (feature-gated)

XMSS (RFC 8391, NIST SP 800-208) and LMS/HSS (RFC 8554, NIST SP 800-208)
are implemented behind `--features pq-signatures`. The underlying Rust crates
have not been independently audited. See
[docs/PQ_SIGNATURES.md](docs/PQ_SIGNATURES.md) and
[docs/STATEFUL_SIG_STATE.md](docs/STATEFUL_SIG_STATE.md).

### Pending independent audit — not yet implemented

These algorithms are NIST-standardised. Implementation is blocked on an
independently audited `no_std` Rust crate becoming available.

| Algorithm | Standard | Awaiting |
|-----------|----------|---------|
| ML-KEM | FIPS 203 | Audited `no_std` Rust crate |
| ML-DSA | FIPS 204 | Audited `no_std` Rust crate |
| SLH-DSA | FIPS 205 | Audited `no_std` Rust crate |
| FN-DSA (FALCON) | FIPS 206 draft | Standard finalisation + audited crate |
| HQC | Draft ~2027 | Standard finalisation + audited crate |

**Note on libcrux:** A 2026 academic paper identified specification-level bugs
in libcrux's formally verified ML-KEM and ML-DSA implementations including
proofs rendered unsound. Check the libcrux changelog before evaluating it.

### Will not be implemented

**BIKE** was eliminated from NIST standardisation in March 2025 in favour of
HQC. **NTRU** encryption was eliminated in July 2022. Neither has a path to a
NIST standard.

---

## Zeroisation — hardware caveat

The zeroisation implementation is **software-correct but hardware-unverified**.
It has been tested using `test-hal` simulation only. Physical verification on
Baochip-1x silicon (JTAG memory inspection, power-cycle resilience, side-channel
confirmation) has not yet been performed. See
[docs/HARDWARE_VERIFICATION.md](docs/HARDWARE_VERIFICATION.md).

---

## Test results

Full vector coverage, dudect t-statistics, RFC / BSI / NIST CAVP pass/fail
tables, and key lifecycle results:
**[docs/TEST_RESULTS.md](docs/TEST_RESULTS.md)**

```
cargo run -p xtask -- test-all
```

---

## Workspace layout

| Crate | Role |
|-------|------|
| `galdr-core` | HAL traits (`MonotonicCounter`, `HardwareTrng`, `ZeroiseController`, `VaultStorage`), shared errors, `test-hal` fakes |
| `vault` | RRAM vault contracts, HKDF `KeyPurpose` labels, key material types (`zeroize`, no `Clone`/`Copy`) |
| `pin-policy` | PIN state machine; counter increment before `subtle::ConstantTimeEq`; threshold zeroisation |
| `usb-personality` | Mass-storage vs authenticated-unlock personas; challenge/response; USB disconnect-on-lock |
| `psram-store` | Optional PSRAM block device; probe-absent short-circuit; mount/unmount access gate |
| `ephemeral-session` | Authenticated ephemeral ECDH session protocol; forward secrecy |
| `cipher-profile` | User-configurable cipher cascade profiles; built-in and user-defined |
| `security-tests` | dudect timing harnesses for all cryptographic paths |
| `host-tools` | Host manifest hashing, update verification, `psram-unlock` binary |
| `xtask` | Build, check, test, fuzz, timing-test orchestration |

---

## Cryptographic dependency policy

Primitives are **not implemented in-tree**. All cryptographic work uses
audited workspace dependencies from the RustCrypto project (except `vsss-rs`
and the dalek family, which have had independent review):

```
aes-gcm  chacha20poly1305  ed25519-dalek  x25519-dalek
hkdf  pbkdf2  hmac  sha2  sha3  blake2  blake3
vsss-rs  zeroize  subtle  p256  p384
```

Using audited crates means this project inherits their audit history rather
than introducing unreviewed cryptographic code.

---

## Quick start

Firmware build prerequisites and install paths are in [Build, install, and uninstall](#build-install-and-uninstall) above.

```bash
rustup target add riscv32imac-unknown-none-elf
cargo test --workspace --exclude xtask
cargo run -p xtask -- check-fw
cargo run -p xtask -- build-fw
cargo run -p xtask -- test-host
cargo run -p xtask -- test-all
cargo run -p xtask -- timing-test
```

**Fuzzing (libFuzzer):** install `cargo-fuzz`, use nightly, then e.g. `cargo run -p xtask -- fuzz chacha_roundtrip 60`. Target names, xtask aliases, and **recommended corpus seeds** per target are in [fuzz/README.md](fuzz/README.md).

Enable `galdr-core` feature `test-hal` **only** in tests or host tools.
Never enable it in production firmware images — enforced by `check-fw`.

---

## License

GNU General Public License v3.0 — see [LICENSE](LICENSE).
