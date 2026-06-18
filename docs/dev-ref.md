# Galdralag Firmware — Developer Reference

**Project:** Galdralag firmware (Baochip-1x / Dabao evaluation board)
**Status:** Design specification — no implementation exists yet
**Date:** 2026-03-25

---

## Table of Contents

- [Project overview](#project-overview)
- [Target and build environment](#target-and-build-environment)
- [Workspace layout](#workspace-layout)
- [Cryptographic dependencies](#cryptographic-dependencies)
- [Security invariants](#security-invariants)
- [Workspace dependency policy](#workspace-dependency-policy)
- [Crate responsibilities](#crate-responsibilities)
  - [galdr-core](#galdr-core)
  - [vault](#vault)
  - [pin-policy](#pin-policy)
  - [usb-personality](#usb-personality)
  - [psram-store](#psram-store)
  - [host-tools](#host-tools)
  - [xtask](#xtask)
- [HAL traits](#hal-traits)
  - [PsramInterface](#psraminterface)
  - [AesGcmAccelerator](#aesgcmaccelerator)
- [KeyPurpose labels](#keypurpose-labels)
- [PSRAM behavior](#psram-behavior)
  - [Graceful degradation contract](#graceful-degradation-contract)
  - [Host-visible states](#host-visible-states)
- [Test surface](#test-surface)
  - [Unit tests](#unit-tests)
  - [Wycheproof vectors](#wycheproof-vectors)
  - [cargo-fuzz targets](#cargo-fuzz-targets)
  - [dudect timing harnesses](#dudect-timing-harnesses)
- [xtask commands](#xtask-commands)
- [Code quality rules](#code-quality-rules)
- [New files and crates — summary table](#new-files-and-crates--summary-table)

---

## Project overview

Galdralag is the firmware project for **Baochip-1x** (Dabao evaluation board)
devices running the **Xous** microkernel, built for `riscv32imac-unknown-none-elf`.

Eval board hardware (KiCad, switches, pinout): **[baochip/dabao](https://github.com/baochip/dabao)**. **SW2** toggles **bootloader mode** for programming (see the dabao schematic).
Firmware design and platform notes: **[Supermagnum/Baochip-1x-firmware](https://github.com/Supermagnum/Baochip-1x-firmware)**.

The firmware targets OpenPGP smartcard-class behaviour and vault semantics,
in the same product category as Nitrokey-class devices, with the platform and
boot security model documented in that Baochip-1x firmware repository.

Hardware goals, boot model, crypto profiles, and host-visible USB behaviour
are aligned with it (requirement tables, ComboHash/PKE usage, Shamir, reproducible updates, test-vector sources).

---

## Target and build environment

| Item | Value |
|------|-------|
| CPU target | `riscv32imac-unknown-none-elf` |
| Application CPU | 350 MHz VexRiscv RV32-IMAC with MMU and Zkn scalar AES extensions |
| I/O coprocessors | 4 × 700 MHz PicoRV32 BIO cores |
| On-chip memory | 4 MiB RRAM (non-volatile), 2 MiB SRAM, 256 KiB I/O buffers |
| Crypto accelerators | PKE, ComboHash, AES block, TRNG — all at 175 MHz |
| Always-on domain | AORAM (8 KiB), 256-bit backup register, one-way counters, WDT, RTC |
| USB | High Speed via USB-C |
| OS | Xous microkernel (betrusted-io/xous-core) |
| Optional external storage | PSRAM chip via QSPI — **may not be fitted** |

```
rustup target add riscv32imac-unknown-none-elf
cargo test --workspace --exclude xtask
cargo run -p xtask -- check-fw
cargo run -p xtask -- build-fw
cargo run -p xtask -- test-host
```

`no_std` applies everywhere except `host-tools` and `xtask`. Enable the
`galdr-core` feature `test-hal` only in tests or host tools — never in
production firmware images.

---

## Workspace layout

| Crate | Role |
|-------|------|
| `galdr-core` | HAL traits (`MonotonicCounter`, `HardwareTrng`, `ZeroiseController`, `VaultStorage`, `PsramInterface`, `AesGcmAccelerator`), shared errors, `test-hal` fakes |
| `vault` | RRAM vault contracts, HKDF domain separation labels (`KeyPurpose`), key material types (`zeroize`, no `Clone`/`Copy`) |
| `pin-policy` | PIN state machine; counter increment before `subtle::ConstantTimeEq` PIN check; threshold zeroisation |
| `usb-personality` | Mass-storage vs authenticated-unlock personalities; challenge/response protocol handler; USB disconnect-on-lock |
| `psram-store` | PSRAM block device abstraction; probe-absent short-circuit; mount/unmount access gate |
| `host-tools` | Host manifest hashing / update verification stubs (`std`); `psram-unlock` userspace binary |
| `xtask` | Embedded `cargo build` / `check` / `test-host` / `fuzz` / `timing-test` orchestration |

---

## Cryptographic dependencies

Cryptographic primitives are **not** implemented in-tree. Use only the audited
workspace dependencies listed below. Do not implement any cryptographic
primitive from scratch under any circumstances.

| Crate | Purpose |
|-------|---------|
| `aes-gcm` | AES-256-GCM AEAD |
| `chacha20poly1305` | ChaCha20-Poly1305 AEAD |
| `ed25519-dalek` | Ed25519 signing and verification |
| `x25519-dalek` | X25519 key agreement |
| `hkdf` | HKDF key derivation (RFC 5869) |
| `pbkdf2` | PBKDF2 / OpenPGP S2K |
| `hmac` | HMAC construction |
| `sha2` | SHA-224, SHA-256, SHA-384, SHA-512 |
| `sha3` | SHA-3 family |
| `blake2` | BLAKE2b / BLAKE2s |
| `blake3` | BLAKE3 |
| `vsss-rs` | Shamir secret sharing |
| `zeroize` | Secure memory zeroing |
| `subtle` | Constant-time comparisons |
| `p256` | NIST P-256 |
| `p384` | NIST P-384 |

These crates are part of the RustCrypto project (except `vsss-rs` and the
dalek family). All have had independent security audits and are widely used
in production security software. Using them means the project inherits that
audit history rather than introducing new unreviewed cryptographic code.

---

## Security invariants

These invariants must never be violated. No exception, no "temporary" workaround.

**Invariant 1 — Counter before compare.**
The PIN attempt counter is incremented and flushed to RRAM before the
constant-time comparison (`subtle::ConstantTimeEq`). This ordering must be
preserved even under simulated RRAM flush failure. Tests must verify the
sequence under failure conditions.

**Invariant 2 — No Clone, no Copy, Zeroize on drop.**
Key material types must not derive `Clone` or `Copy`. Every type that holds
key bytes, PIN bytes, or intermediate cryptographic state must implement
`zeroize::Zeroize` and zeroize on drop.

**Invariant 3 — No secret material on the USB bus.**
No secret material may be observable on the USB bus to an unauthenticated
host. USB descriptors must be identical for the "PSRAM absent" and "PSRAM
present but locked" states. A passive USB observer must not be able to
fingerprint whether PSRAM is fitted or whether the device has enhanced
capabilities.

**Invariant 4 — test-hal never in production.**
The `test-hal` feature of `galdr-core` must never appear in a production
firmware image. The `check-fw` xtask subcommand enforces this at CI time.

**Invariant 5 — Typed errors everywhere.**
All fallible operations return typed errors. No `unwrap` or `expect` anywhere
in `no_std` crates. Use `?` with typed error propagation throughout.

**Invariant 6 — USB disconnect on lock.**
When any lock event occurs (explicit lock command, session timeout, PIN
threshold breach), the firmware must call `psram-store::unmount()`, issue a
USB disconnect via the Xous USB stack API, wait for disconnect to complete,
and then re-enumerate in the unauthenticated persona. Omitting this step
leaves the host OS with a mounted volume it can no longer read, causing
filesystem corruption.

---

## Workspace dependency policy

- All cryptographic dependencies must appear in the workspace `Cargo.toml`
  with pinned versions. Crates may not add their own separate versions.
- `test-hal` must be a `dev-dependency` or behind a `cfg(feature = "test-hal")`
  gate. The `check-fw` xtask command verifies no `test-hal` feature is active
  in any `riscv32imac-unknown-none-elf` build.
- `std`-only crates (`host-tools`, `xtask`) may use `std` freely. All other
  crates are `no_std` + `no_alloc` unless a specific allocation need is
  justified and reviewed.
- `unsafe` is permitted only for Xous syscall interfaces. Every `unsafe` block
  requires a `// SAFETY:` comment explaining the invariant being upheld.

---

## Crate responsibilities

### galdr-core

Provides HAL traits, shared error types, and `test-hal` fakes. This crate has
no business logic. It is the dependency boundary between hardware-specific
code and the portable firmware layers.

All HAL traits are generic parameters consumed by higher-level crates.
Production implementations live in the Xous driver layer. `test-hal` fakes
live behind `#[cfg(feature = "test-hal")]` and must never be compiled into
production images.

### vault

Owns the RRAM vault contract: key storage layout, HKDF domain separation
labels (`KeyPurpose`), and key material types. No key material type may
implement `Clone` or `Copy`. All key material types implement `Zeroize`.

HKDF `info` strings for domain separation are derived from `KeyPurpose`
variants. Each variant maps to a unique, fixed byte string. The mapping is
tested with explicit input/output vectors.

### pin-policy

Implements the PIN attempt state machine. The counter increment and RRAM
flush happen **before** the constant-time comparison — this ordering is the
defining invariant of this crate and must be preserved in all code paths
including error paths.

At the attempt threshold, zeroisation is triggered via the `ZeroiseController`
HAL trait. This mirrors the boot0 zeroisation path for signature failures.

### usb-personality

Manages all host-visible USB personas. Responsible for:

- Selecting and presenting the correct USB descriptor set based on
  authentication state and PSRAM presence.
- Handling the vendor-specific SCSI command protocol for challenge/response
  authentication.
- Enforcing the minimum 5-character alphanumeric passphrase at the command
  parser boundary, before `pin-policy` sees the input.
- Triggering USB disconnect/re-enumeration on any lock event.

No secret material may flow to the host through any descriptor, string, or
control transfer visible to an unauthenticated host.

### psram-store

Provides a `BlockDevice` abstraction over the optional PSRAM chip. See
[PSRAM behavior](#psram-behavior) for the full contract.

This crate has no cryptographic responsibilities beyond consuming the
`AesGcmAccelerator` HAL trait for the block encryption path. It does not
implement or select cryptographic algorithms directly.

### host-tools

`std` crate. Contains:

- Manifest hashing and update verification stubs.
- `psram-unlock` binary: detects the device by VID/PID, sends
  `GET_CHALLENGE`, collects a passphrase from the user via stdin or pinentry,
  constructs and sends `SEND_RESPONSE`. Zeroises the passphrase buffer after
  use. Must not store the passphrase in any file, environment variable, shell
  history, or process argument.

### xtask

`std` crate. Orchestrates all build, check, test, fuzz, and timing-test
operations. All subcommands propagate non-zero exit codes so CI fails fast.

---

## HAL traits

These traits are defined in `galdr-core`. Production implementations wrap
Xous driver APIs. `test-hal` fakes are feature-gated.

### PsramInterface

```rust
pub trait PsramInterface {
    type Error;

    /// Probe the QSPI bus for a PSRAM chip.
    /// Returns Ok(Some(geometry)) if a chip is present and recognised,
    /// Ok(None) if no chip is detected, or Err on bus fault.
    fn probe(&mut self) -> Result<Option<PsramGeometry>, Self::Error>;

    fn read(&mut self, offset: u32, buf: &mut [u8]) -> Result<(), Self::Error>;
    fn write(&mut self, offset: u32, buf: &[u8]) -> Result<(), Self::Error>;
}

pub struct PsramGeometry {
    pub total_bytes: u32,
    pub page_size:   u16,
}
```

The `test-hal` fake must support simulating both `Ok(None)` (chip absent)
and `Ok(Some(geometry))` (chip present) so both branches are exercisable
without hardware.

### AesGcmAccelerator

Abstracts the Baochip-1x hardware AES block and Zkn pipeline. The `test-hal`
fake wraps the `aes-gcm` crate directly.

```rust
pub trait AesGcmAccelerator {
    type Error;

    fn encrypt_in_place(
        &mut self,
        key:     &[u8; 32],
        nonce:   &[u8; 12],
        aad:     &[u8],
        buf:     &mut [u8],
        tag_out: &mut [u8; 16],
    ) -> Result<(), Self::Error>;

    fn decrypt_in_place(
        &mut self,
        key:   &[u8; 32],
        nonce: &[u8; 12],
        aad:   &[u8],
        buf:   &mut [u8],
        tag:   &[u8; 16],
    ) -> Result<(), Self::Error>;
}
```

`psram-store` takes `AesGcmAccelerator` as a generic parameter. This keeps
the PSRAM block encryption path testable on the host and replaceable with the
hardware path at link time.

---

## KeyPurpose labels

All HKDF-derived keys are domain-separated by `KeyPurpose`. Each variant maps
to a unique, fixed `info` byte string passed to `HKDF-Expand`. No two variants
may share an `info` string.

```rust
pub enum KeyPurpose {
    // Existing variants (defined in vault crate):
    // … document existing variants here as they are implemented …

    // PSRAM block encryption:
    PsramStorage,       // AES-256-GCM key for PSRAM block encryption
                        // info: b"galdralag/psram/storage/v1"
    PsramSessionNonce,  // Per-mount nonce root; rotated on each successful unlock
                        // info: b"galdralag/psram/session-nonce/v1"

    // Challenge/response authentication:
    HostChallengeKey,   // HMAC-SHA256 key for challenge/response with informed host
                        // info: b"galdralag/usb/challenge-key/v1"
                        // Derived fresh per session; never persisted to RRAM
    HostChallengeNonce, // Per-challenge TRNG nonce root; single-use
                        // info: b"galdralag/usb/challenge-nonce/v1"
                        // Invalidated after one SEND_RESPONSE attempt
}
```

HKDF domain separation between all `KeyPurpose` variants must be tested with
explicit input/output vectors in `vault` unit tests. The test vectors must
cover both the valid derivation path and the case where two different
`KeyPurpose` variants with the same input key and salt produce distinct output.

---

## PSRAM behavior

### Graceful degradation contract

This contract is normative. All code paths must implement it exactly.

**State 1 — PSRAM absent (chip not fitted or probe returns `Ok(None)`):**
The device **remains a hardware security token** in full: RRAM vault, PIN
policy, OpenPGP card application (CCID), and other token features are
unchanged. What is missing is **only** the optional external PSRAM bulk block
device. For the **uninformed-host** USB persona, firmware still uses whatever
small on-chip decoy mass-storage volume is configured (same as State 2 for
that persona). No PSRAM-related LUN is advertised. USB descriptors for that
persona are identical to State 2. The host cannot distinguish this state from
State 2 with respect to mass-storage presentation.

**State 2 — PSRAM present, device unauthenticated:**
Same USB presentation as State 1. The PSRAM content is not visible to the
host. USB descriptors are byte-for-byte identical to State 1.

**State 3 — PSRAM present, authentication succeeded:**
`psram-store::mount()` is called. The PSRAM LUN becomes visible to the host
as a plain mass-storage block device. A USB disconnect/re-enumeration cycle
advertises the new LUN. Block reads and writes are passed through to PSRAM
without transformation. See [PSRAM content policy](#psram-content-policy).

**State 4 — Lock event (timeout, explicit LOCK command, PIN threshold breach,
or power cycle):**

1. `psram-store::unmount()` is called. All subsequent block operations return
   errors.
2. The firmware calls the Xous USB stack disconnect API.
3. The firmware waits for disconnect to complete.
4. The device re-enumerates in State 2.

The USB disconnect step is mandatory. See Security Invariant 6.

### PSRAM content policy

**The contents of the PSRAM are intentionally not encrypted.** Block reads
and writes are passed to the PSRAM chip without cryptographic transformation.
The PSRAM volume is a decoy: it presents as ordinary, unremarkable storage to
any host that mounts it. Its purpose is to give a curious or adversarial party
nothing of interest to find, while real key material and vault contents remain
isolated in on-chip RRAM and are never exposed through this path.

This is a deception-by-design property. Do not add encryption to the
`psram-store` block path. Any future change to this policy requires an
explicit design review and a revision to this document and to
`docs/PSRAM_DESIGN.md`.

The `AesGcmAccelerator` HAL trait and `KeyPurpose::PsramStorage` /
`KeyPurpose::PsramSessionNonce` labels are defined in anticipation of a
possible future profile in which encryption is desired. They are not used by
the current `psram-store` implementation. Their HKDF domain separation is
tested because the labels exist; the block path does not invoke them.

### Host-visible states

| State | USB presentation | Notes |
|-------|-----------------|-------|
| Absent or unauthenticated | Decoy mass-storage LUN only | Descriptors identical in both cases |
| Authenticated, PSRAM present | PSRAM LUN visible | Plain block device; no encryption |
| Wrong passphrase / no driver | Falls back, no enhanced path advertised | Indistinguishable from unauthenticated |

### Challenge/response protocol

The `usb-personality` crate handles the following vendor-specific SCSI
commands. The exact CDB byte layout is defined in `docs/HOST_PROTOCOL.md`.

**`GET_CHALLENGE`**
Device returns a fresh 32-byte TRNG-sourced nonce. This nonce is single-use.
A second `GET_CHALLENGE` before a response is sent invalidates the first
nonce; any subsequent response attempt using the invalidated nonce must fail.

**`SEND_RESPONSE`**
Host sends `HMAC-SHA256(HostChallengeKey, nonce || passphrase_utf8_nfc)`.
The device verifies the response via `pin-policy` (counter-before-compare
invariant applies). On success, `psram-store::mount()` is called and a USB
re-enumeration cycle occurs. On failure, the attempt counter is incremented.
At threshold, zeroisation is triggered.

**`LOCK`**
Explicit lock command. Triggers State 4 (unmount + USB disconnect +
re-enumeration).

Minimum passphrase length (5 alphanumeric characters) is enforced at the
command parser boundary in `usb-personality`, before `pin-policy` sees the
input. This prevents noise from consuming attempt counter budget.

---

## Test surface

All hardware-dependent tests use `test-hal` fakes from `galdr-core`
(`feature = "test-hal"`). No physical hardware is required to run any test
in the suite.

### Unit tests

**galdr-core / psram-store**

- Probe absent path: fake returns `Ok(None)`; all `BlockDevice` calls return
  `Err(PsramError::NotFitted)`; `usb-personality` enumerates with descriptors
  matching the no-PSRAM case byte-for-byte.
- Probe present path: fake returns `Ok(Some(geometry))`; `BlockDevice` calls
  succeed after `mount()`; fail before `mount()`.
- Mount/unmount lifecycle: `mount()` → block I/O succeeds → `unmount()` →
  block I/O returns `Err(PsramError::NotMounted)` → USB disconnect triggered.
- Block pass-through: data written via `write_block` is returned unchanged by
  `read_block`; no transformation applied.

**vault**

- HKDF domain separation: for each `KeyPurpose` variant pair, verify that
  identical input key and salt produce distinct output.
- Explicit derivation vectors: fixed input → expected output for each variant.
  Vectors must be stored as test data, not computed at test time.
- `PsramStorage` and `PsramSessionNonce` vector tests: required even though
  the current block path does not invoke them, because the labels exist.

**pin-policy**

- Counter-before-compare ordering: simulate RRAM flush failure between counter
  increment and comparison; verify the counter increment is not lost.
- Wrong PIN: counter increments; comparison fails; key material not released.
- PIN at threshold − 1: counter increments; no zeroisation.
- PIN at threshold: zeroisation triggered via `ZeroiseController` fake;
  verify the zeroisation call precedes any further state transitions.
- Correct PIN: counter does not increment on success.

**usb-personality**

- Descriptor parity: assert USB descriptor bytes are identical for
  `PsramState::Absent` and `PsramState::Present(Locked)`.
- Challenge freshness: two consecutive `GET_CHALLENGE` calls return distinct
  nonces.
- Nonce invalidation: issue `GET_CHALLENGE`, issue second `GET_CHALLENGE`,
  attempt response with first nonce; must fail.
- Minimum passphrase enforcement: 4-character passphrase rejected at parser
  boundary; attempt counter not incremented.
- Lock-on-threshold sequence: verify `unmount()` called before USB disconnect,
  and USB disconnect called before re-enumeration.

### Wycheproof vectors

Pull test vectors from `https://github.com/C2SP/wycheproof` using the
`wycheproof` crate or by deserialising the JSON directly.

Run **all** vectors including the `"invalid"` and `"acceptable"` groups.
Assert correct accept/reject behaviour for each flag. Any vector where the
implementation accepts or rejects differently from the Wycheproof expected
result must cause the test to fail with the vector ID printed to stderr.

| Algorithm | Vector file | Used by |
|-----------|-------------|---------|
| AES-256-GCM | `aes_gcm_test.json` | `AesGcmAccelerator` test-hal fake; `KeyPurpose::PsramStorage` path |
| ChaCha20-Poly1305 | `chacha20_poly1305_test.json` | `chacha20poly1305` workspace dep |
| HMAC-SHA256 | `hmac_sha256_test.json` | Challenge/response `HostChallengeKey` path |
| HKDF-SHA256 | `hkdf_sha256_test.json` | `KeyPurpose` domain separation |
| Ed25519 | `eddsa_test.json` | Boot chain signature verification |
| X25519 | `x25519_test.json` | Ephemeral ECDH session model |

### cargo-fuzz targets

Create `fuzz/Cargo.toml` at workspace root declaring `libfuzzer-sys` as a
dependency. All targets compile for `x86_64` using `test-hal` fakes; no
hardware required.

| Target | What it fuzzes | Acceptance criteria |
|--------|---------------|---------------------|
| `fuzz_psram_block_rw` | Arbitrary LBA + length sequences against a mounted fake PSRAM volume | No panic; no corruption of adjacent blocks; only typed errors returned |
| `fuzz_usb_personality_with_psram` | Arbitrary host SCSI command byte sequences against the personality handler | No panic; no state leak; no secret material in any response |
| `fuzz_host_protocol` | Arbitrary vendor command byte sequences at the command parser boundary | No panic; malformed commands rejected before reaching `pin-policy` |
| `fuzz_passphrase_input` | Arbitrary byte sequences as passphrase | Minimum-length rejection without panic; attempt counter not incremented for parser-rejected inputs |
| `fuzz_vault_roundtrip` | Arbitrary `KeyPurpose` derivation inputs | No panic; distinct outputs for distinct variants |
| `fuzz_pin_policy` | Arbitrary byte sequences as PIN input | No panic; counter ordering preserved; zeroisation not triggered below threshold |

Each fuzz target must document its entry point and the invariant it is
checking in a comment at the top of the file.

### dudect timing harnesses

Add to a `security-tests` crate (or under `host-tools`). Run with
`cargo run -p xtask -- timing-test`. Exit non-zero if any t-statistic
exceeds the threshold.

**Threshold:** `|t| > 4.5` at 100 000 samples.

| Harness | Path under test | What must not leak |
|---------|----------------|-------------------|
| `timing_pin_compare` | PIN comparison in `pin-policy` | No timing difference between wrong-PIN-early-byte and wrong-PIN-late-byte |
| `timing_challenge_response` | HMAC verification in `SEND_RESPONSE` handler | No timing difference between correct and incorrect response |
| `timing_psram_tag_check` | AES-GCM tag verification in `AesGcmAccelerator` test-hal fake | No timing difference between tag match and tag mismatch; no timing oracle on the authentication tag |
| `timing_hkdf_derive` | HKDF derivation for any `KeyPurpose` involving secret key material | No timing difference correlated with key bytes |

---

## xtask commands

All subcommands propagate non-zero exit codes. CI must treat any non-zero
exit as a blocking failure.

| Command | Action |
|---------|--------|
| `cargo run -p xtask -- check-fw` | `cargo check` for `riscv32imac-unknown-none-elf`; verifies no `test-hal` feature active |
| `cargo run -p xtask -- build-fw` | Release build for `riscv32imac-unknown-none-elf` |
| `cargo run -p xtask -- test-host` | `cargo test --workspace --exclude xtask` |
| `cargo run -p xtask -- test-psram` | Runs `psram-store` + `vault` unit tests with `test-hal` fake |
| `cargo run -p xtask -- test-host-protocol` | Runs `host-tools/psram-unlock` protocol conformance tests |
| `cargo run -p xtask -- wycheproof` | Runs only the Wycheproof vector tests across all applicable crates |
| `cargo run -p xtask -- fuzz [TARGET] [SECONDS]` | Runs `cargo fuzz` for the named target for the given duration |
| `cargo run -p xtask -- fuzz psram-block-rw 60` | Fuzzes the PSRAM block read/write path for 60 seconds |
| `cargo run -p xtask -- fuzz usb-personality-psram 60` | Fuzzes the USB personality handler with PSRAM mounted |
| `cargo run -p xtask -- fuzz host-protocol 60` | Fuzzes the vendor SCSI command parser |
| `cargo run -p xtask -- fuzz passphrase-input 60` | Fuzzes passphrase input handling |
| `cargo run -p xtask -- timing-test` | Runs all dudect harnesses; exits non-zero if any `\|t\| > 4.5` |

---

## Code quality rules

These rules apply to all crates in the workspace.

- No `unwrap` or `expect` anywhere in `no_std` crates. Use `?` with typed
  error propagation.
- All public items must have doc comments.
- No `unsafe` except for Xous syscall interfaces. Every `unsafe` block
  requires a `// SAFETY:` comment explaining the invariant being upheld.
- `zeroize::Zeroize` must be derived or manually implemented on every type
  that holds key bytes, PIN bytes, or intermediate cryptographic state.
- `cargo clippy -- -D warnings` must pass clean before any merge.
- No cryptographic primitive implemented in-tree. Use only the audited
  workspace dependencies listed in [Cryptographic dependencies](#cryptographic-dependencies).
- The `test-hal` feature must appear only in `dev-dependencies` or behind
  explicit `cfg(feature = "test-hal")` gates. The `check-fw` xtask command
  is the enforcement mechanism.
- All fuzz targets must include a comment at the top of the file stating
  which invariant the target is checking.
- All dudect harnesses must print the measured t-statistic to stdout
  regardless of pass/fail so trends can be tracked across commits.

---

## New files and crates — summary table

| Deliverable | Type | Notes |
|-------------|------|-------|
| `psram-store/` | new `no_std` crate | Block device abstraction; plain pass-through; mount/unmount access gate; probe-absent short-circuit |
| `galdr-core` trait `PsramInterface` | trait addition | QSPI probe + read/write; `test-hal` fake with simulated absent/present |
| `galdr-core` trait `AesGcmAccelerator` | trait addition | Hardware AES path abstraction; `test-hal` fake wraps `aes-gcm` crate |
| `usb-personality` extensions | crate extension | Challenge/response handler; USB disconnect-on-lock; descriptor parity invariant; minimum passphrase enforcement at parser |
| `host-tools/psram-unlock/` | new `std` binary | Linux passphrase entry; vendor SCSI command sender; passphrase buffer zeroised after use |
| `vault` `KeyPurpose` additions | enum extension | `PsramStorage`, `PsramSessionNonce`, `HostChallengeKey`, `HostChallengeNonce` |
| `docs/HOST_PROTOCOL.md` | documentation | Vendor SCSI CDB layout; HMAC construction; passphrase encoding; third-party driver contract |
| `docs/PSRAM_DESIGN.md` | documentation | Graceful degradation contract; auth sequence; lock sequence; no-encryption policy rationale |
| `docs/XOUS_INTEGRATION.md` | documentation | Xous USB disconnect API call; record the specific call during bring-up |
| `fuzz/fuzz_psram_block_rw.rs` | fuzz target | Arbitrary LBA + length sequences |
| `fuzz/fuzz_usb_personality_with_psram.rs` | fuzz target | Arbitrary SCSI command sequences against mounted PSRAM |
| `fuzz/fuzz_host_protocol.rs` | fuzz target | Arbitrary vendor command byte sequences |
| `fuzz/fuzz_passphrase_input.rs` | fuzz target | Arbitrary passphrase byte sequences |
| `fuzz/fuzz_vault_roundtrip.rs` | fuzz target | Arbitrary `KeyPurpose` derivation inputs |
| `fuzz/fuzz_pin_policy.rs` | fuzz target | Arbitrary PIN input byte sequences |
| `security-tests/timing_pin_compare` | dudect harness | PIN comparison timing |
| `security-tests/timing_challenge_response` | dudect harness | HMAC verification timing on challenge/response path |
| `security-tests/timing_psram_tag_check` | dudect harness | AES-GCM tag check timing |
| `security-tests/timing_hkdf_derive` | dudect harness | HKDF derivation timing for secret-keyed paths |
