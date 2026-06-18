# PSRAM Software Stack — Design & Implementation Specification

**Project:** Galdralag firmware (Baochip-1x / Dabao evaluation board)
**Status:** Design specification — no implementation exists yet
**Date:** 2026-03-25

---

## Table of Contents

- [Overview and design intent](#overview-and-design-intent)
- [Hardware context](#hardware-context)
- [Graceful degradation contract](#graceful-degradation-contract)
- [Host-visible behavior](#host-visible-behavior)
  - [Uninformed host](#uninformed-host)
  - [Informed host](#informed-host)
- [New crate: `psram-store`](#new-crate-psram-store)
- [Changes to `usb-personality`](#changes-to-usb-personality)
- [New HAL traits in `galdr-core`](#new-hal-traits-in-galdr-core)
- [New `KeyPurpose` labels in `vault`](#new-keypurpose-labels-in-vault)
- [Host-tools additions](#host-tools-additions)
- [Test surface](#test-surface)
- [xtask additions](#xtask-additions)
- [New files and crates — summary table](#new-files-and-crates--summary-table)
- [Host protocol specification](#host-protocol-specification)
- [Security notes](#security-notes)

---

## Overview and design intent

An optional PSRAM chip may be fitted to the Baochip-1x / Dabao board for bulk
storage presentation to the host. **The chip may also be absent entirely.** All
software in this stack must handle the no-PSRAM case cleanly and silently, with
no spurious PSRAM LUN and **no loss of security-token function**: the device is
always a hardware security token; PSRAM is an optional **supplementary** bulk
decoy store. For comparisons that matter to mass-storage descriptors, observable
USB behaviour matches the PSRAM-fitted-but-locked case (see below).

**The contents of the PSRAM are intentionally not encrypted.** The PSRAM volume
presents as a plain, readable filesystem to any host that mounts it. Its purpose
is to appear as ordinary, unremarkable storage — a decoy that gives a curious or
adversarial party nothing of interest to find, while real key material and vault
contents remain isolated in on-chip RRAM and are never exposed through this path.

This is a **deception-by-design** property. Do not add encryption to the PSRAM
block path. Any future change to this policy requires an explicit design review
and a revision to this document.

---

## Hardware context

| Item | Detail |
|------|--------|
| SoC | Baochip-1x (VexRiscv RV32-IMAC, 350 MHz, Zkn AES extensions) |
| Crypto accelerators | PKE, ComboHash, AES block, TRNG — all at 175 MHz |
| On-chip NV storage | 4 MiB RRAM (vault, key material, boot chain) |
| Optional external storage | PSRAM chip, connected via QSPI — **may not be fitted** |
| USB | High Speed via USB-C |
| OS | Xous microkernel (betrusted-io/xous-core), Rust, MMU process isolation |

The PSRAM chip, when present, is external to the SoC and sits on the QSPI bus.
It is volatile (contents lost on power cycle) and has no hardware authentication
or access control of its own. All access-control and persona-switching logic
lives entirely in firmware.

---

## Graceful degradation contract

This contract is normative. All code paths must implement it exactly.

1. **PSRAM absent (chip not fitted or probe fails):** the device **still
   operates as a hardware security token** (vault, PIN, OpenPGP/CCID, etc.).
   The only omission is the optional PSRAM bulk block device. For the
   **uninformed** USB mass-storage persona, firmware uses whatever small
   on-chip decoy volume is configured. No PSRAM-related LUN is advertised. The
   host cannot distinguish this mass-storage presentation from "PSRAM fitted but
   locked."

2. **PSRAM present, device unauthenticated:** same USB presentation as case 1.
   The PSRAM content is not visible to the host until authentication succeeds.
   The USB descriptors are identical to the no-PSRAM case.

3. **PSRAM present, authentication succeeded:** the PSRAM LUN becomes visible to
   the host as a plain mass-storage volume. Contents are readable and writable
   with no encryption. The volume appears as normal storage to any OS.

4. **Lock event (any cause — timeout, explicit lock command, PIN threshold
   breach, power cycle):**
   - The PSRAM LUN is synchronously unmounted in firmware.
   - The firmware issues a USB disconnect followed by re-enumeration.
   - The device re-enumerates in the unauthenticated persona (case 2).
   - The host receives a clean disconnect signal so it does not hold stale
     filesystem state against a volume that is no longer accessible.
   - The USB disconnect-on-lock step is **mandatory**. Omitting it leaves the
     host OS with a mounted volume it can no longer read, causing filesystem
     corruption from the host's perspective.

---

## Host-visible behavior

### Uninformed host

The device presents as a standard USB mass-storage device. When PSRAM is absent
or the device is unauthenticated, the storage presented is the uninformed decoy
volume only. There is no requirement for special drivers for this persona.

No vendor string, extra interface descriptor, unusual bcdUSB value, or any other
field in the USB descriptors may differ between the "PSRAM absent" and "PSRAM
present but locked" states. A passive USB observer must not be able to
fingerprint whether PSRAM is fitted.

### Informed host

A vendor-supplied or integrator-supplied userspace component on the host
(see [Host-tools additions](#host-tools-additions)) can:

1. Recognise the device by USB VID/PID.
2. Issue a vendor-specific command requesting a fresh TRNG-sourced challenge
   from the device.
3. Collect a passphrase from the user (minimum 5 alphanumeric characters;
   policy may enforce longer secrets).
4. Send the response as `HMAC(HostChallengeKey, challenge || passphrase)` so
   a passive USB observer cannot replay the credential.
5. On correct response, the device unlocks the PSRAM LUN and re-enumerates
   with the storage volume visible.
6. On wrong response, or if the host component is absent, the device falls
   back to uninformed mass-storage behaviour without advertising the enhanced
   path.

---

## New crate: `psram-store`

**Type:** `no_std` library crate
**Location:** `psram-store/`

### Responsibilities

- At boot, probe the QSPI bus for the PSRAM chip (read JEDEC ID or perform a
  known-good write-read-back sequence). If the probe returns nothing
  recognisable, set internal state to `PsramState::Absent` and make all
  subsequent public API calls return `Err(PsramError::NotFitted)` immediately.
  No panic, no silent success.

- Expose a `BlockDevice` trait that the `usb-personality` crate consumes:

  ```rust
  pub trait BlockDevice {
      type Error;
      fn block_count(&self) -> u32;
      fn block_size(&self) -> u16;
      fn read_block(&mut self, lba: u32, buf: &mut [u8]) -> Result<(), Self::Error>;
      fn write_block(&mut self, lba: u32, buf: &[u8]) -> Result<(), Self::Error>;
  }
  ```

- **No encryption of block data.** Reads and writes are passed through to PSRAM
  without transformation. This is intentional — see
  [Overview and design intent](#overview-and-design-intent).

- Implement `mount()` and `unmount()`. `mount()` transitions from
  `PsramState::Present(Locked)` to `PsramState::Present(Mounted)` and makes
  `read_block` / `write_block` succeed. `unmount()` transitions back to
  `Locked` and makes block operations return errors. Neither call touches
  key material (there is none for PSRAM) — mount/unmount here is purely a
  logical access-control gate driven by the authentication state held in
  `usb-personality`.

- All public types must derive or manually implement `core::fmt::Debug` with
  no secret-revealing fields. There are no key-material types in this crate.

### PSRAM geometry

Detect geometry from the JEDEC probe response where possible. Fall back to a
compile-time default (e.g. 8 MiB, 512-byte blocks) if the chip does not
support geometry queries. Expose `PsramGeometry { total_bytes: u32,
page_size: u16 }` from the probe result.

---

## Changes to `usb-personality`

This crate holds the state machine for all USB personas. It needs the following
additions.

### Persona negotiation at USB enumeration

- If `PsramState::Absent` or `PsramState::Present(Locked)`: enumerate with a
  single mass-storage LUN backed by the on-chip decoy volume. Descriptors are
  identical in both states.
- If `PsramState::Present(Mounted)`: enumerate with the PSRAM LUN visible as a
  second mass-storage LUN, or replace the decoy LUN with the PSRAM LUN,
  according to the product policy documented in `docs/HOST_PROTOCOL.md`.

### Challenge/response protocol handler

- Expose a vendor-specific SCSI command handler (CDB format defined in
  `docs/HOST_PROTOCOL.md`) for the following operations:
  - `GET_CHALLENGE`: device returns a fresh 32-byte TRNG-sourced nonce. This
    nonce is single-use; a second `GET_CHALLENGE` before a response invalidates
    the first.
  - `SEND_RESPONSE`: host sends `HMAC-SHA256(HostChallengeKey, nonce || passphrase)`.
    Device verifies via `pin-policy` (same counter-before-compare invariant as
    PIN checks — the passphrase is a PIN from the policy engine's perspective).
    On success, calls `psram-store::mount()` and triggers USB re-enumeration.
    On failure, increments the attempt counter. At threshold, triggers full
    zeroisation per the boot0 policy.
  - `LOCK`: explicit lock command. Device calls `psram-store::unmount()` and
    triggers USB disconnect/re-enumeration.

- Minimum passphrase length enforcement (5 alphanumeric characters) must occur
  in the command parser, not deferred to the policy layer.

### USB disconnect-on-lock

When any lock event occurs (explicit `LOCK` command, session timeout, PIN
threshold breach), the firmware must:

1. Call `psram-store::unmount()`.
2. Call the Xous USB stack's disconnect API.
3. Wait for the disconnect to complete.
4. Re-enumerate in the unauthenticated persona.

This is a required Xous USB stack integration point. The specific Xous API call
will be determined during board bring-up; record it in `docs/XOUS_INTEGRATION.md`
once identified.

### Descriptor parity invariant

Add a compile-time or startup assertion that the USB descriptors produced for
`PsramState::Absent` and `PsramState::Present(Locked)` are byte-for-byte
identical. This invariant must be tested (see [Test surface](#test-surface)).

---

## New HAL traits in `galdr-core`

### `PsramInterface`

```rust
pub trait PsramInterface {
    type Error;
    fn probe(&mut self) -> Result<Option<PsramGeometry>, Self::Error>;
    fn read(&mut self, offset: u32, buf: &mut [u8]) -> Result<(), Self::Error>;
    fn write(&mut self, offset: u32, buf: &[u8]) -> Result<(), Self::Error>;
}

pub struct PsramGeometry {
    pub total_bytes: u32,
    pub page_size:   u16,
}
```

The `test-hal` fake (feature-gated under `test-hal`) must back this with a
`heapless::Vec` or a fixed-size array so that the full `psram-store` stack can
be exercised on the host without hardware. The fake must support simulating both
probe-absent (returns `Ok(None)`) and probe-present (returns `Ok(Some(geometry))`)
to cover both branches in tests.

---

## New `KeyPurpose` labels in `vault`

```rust
pub enum KeyPurpose {
    // … existing variants …
    HostChallengeKey,     // HMAC-SHA256 key for challenge/response with informed host
                          // Derived fresh per session; never persisted to RRAM
    HostChallengeNonce,   // Per-challenge TRNG nonce root; single-use, invalidated
                          // after one SEND_RESPONSE attempt regardless of outcome
}
```

Note: there are no PSRAM encryption keys because PSRAM content is not encrypted.
The `HostChallengeKey` is the only new vault-derived secret required for this
feature.

HKDF domain separation labels for these variants must be tested against
explicit input/output vectors in the `vault` unit tests.

---

## Host-tools additions

### Linux userspace component

A small `std` binary (or daemon) to be added under `host-tools/psram-unlock/`:

- Detects the device by USB VID/PID using `rusb` or a platform udev rule.
- Sends `GET_CHALLENGE` via the vendor SCSI command path.
- Reads a passphrase from the user via stdin, pinentry, or a simple TTY prompt.
  Minimum 5 alphanumeric characters enforced client-side before transmission.
- Constructs and sends `SEND_RESPONSE`.
- Reports success or failure to the user; on failure, reports remaining attempts
  if the device returns that information.
- Must not store the passphrase in any file, environment variable, shell
  history, or process argument. Read into a zeroed buffer; zeroize after use.

### Protocol documentation

`docs/HOST_PROTOCOL.md` must define:

- USB VID/PID values used to identify the device.
- Exact SCSI CDB byte layout for `GET_CHALLENGE`, `SEND_RESPONSE`, and `LOCK`.
- Transfer direction and length for each command.
- Response format and error codes.
- HMAC construction: `HMAC-SHA256(HostChallengeKey, nonce || passphrase_bytes)`.
- Passphrase encoding (UTF-8, NFC-normalised, no trailing null).

This document is the interface contract for third-party driver authors. It must
be kept in sync with any changes to `usb-personality`'s command handler.

---

## Test surface

All tests follow the established project pattern: `test-hal` fakes for hardware,
Wycheproof vectors for crypto, `cargo-fuzz` targets for parsers and APIs,
`dudect` harnesses for timing-sensitive paths.

### Unit tests

- **Probe absent path:** fake returns `Ok(None)`; all `BlockDevice` calls return
  `Err(PsramError::NotFitted)`; `usb-personality` enumerates in the uninformed
  persona; descriptors match the no-PSRAM case byte-for-byte.
- **Probe present, unmounted:** `read_block` / `write_block` return
  `Err(PsramError::NotMounted)`; host persona is still uninformed.
- **Mount/unmount lifecycle:** successful challenge/response → `mount()` →
  block I/O succeeds → `unmount()` → block I/O fails → USB disconnect triggered.
- **Descriptor parity:** assert that USB descriptor bytes are identical for
  `Absent` and `Present(Locked)`.
- **Challenge freshness:** two consecutive `GET_CHALLENGE` calls must return
  distinct nonces. A second call before a response must invalidate the first
  nonce (the first response attempt after a re-challenge must fail).
- **Minimum passphrase enforcement:** passphrase of 4 characters must be
  rejected at the parser boundary before reaching `pin-policy`.
- **Lock-on-threshold:** at PIN attempt threshold, `unmount()` is called and
  USB disconnect is triggered; verify the sequence order.

### Wycheproof vectors

- **HMAC-SHA256:** run all Wycheproof HMAC-SHA256 test vectors (valid and
  invalid groups) against the challenge/response HMAC path. Any vector where
  the implementation accepts/rejects differently from the expected result must
  fail the test and print the vector ID.

### cargo-fuzz targets

Add to `fuzz/`:

| Target | What it fuzzes |
|--------|---------------|
| `fuzz_psram_block_rw` | Arbitrary LBA + length sequences; must never panic or corrupt adjacent blocks |
| `fuzz_host_protocol` | Arbitrary USB vendor command byte sequences; must never crash, leak state, or accept a malformed command |
| `fuzz_passphrase_input` | Arbitrary byte sequences as passphrase; must enforce minimum-length rejection without panicking |

All fuzz targets compile for `x86_64` using `test-hal` fakes; no hardware required.

### dudect harnesses

Add to the `security-tests` crate (or `host-tools`):

| Harness | What it measures |
|---------|-----------------|
| `timing_challenge_response` | HMAC verification on the `SEND_RESPONSE` path; correct vs. wrong response must show no timing difference (threshold: `|t| > 4.5` at 100 000 samples) |

Run with:
```
cargo run -p xtask -- timing-test
```
Exit non-zero if threshold is exceeded.

---

## xtask additions

Extend `xtask` with the following subcommands. All must propagate non-zero exit
codes so CI fails fast.

| Command | Action |
|---------|--------|
| `cargo run -p xtask -- test-psram` | Runs `psram-store` + `usb-personality` unit tests with `test-hal` fake |
| `cargo run -p xtask -- test-host-protocol` | Runs `host-tools/psram-unlock` protocol conformance tests |
| `cargo run -p xtask -- fuzz psram-block-rw 60` | Runs the `fuzz_psram_block_rw` target for 60 seconds |
| `cargo run -p xtask -- fuzz host-protocol 60` | Runs the `fuzz_host_protocol` target for 60 seconds |
| `cargo run -p xtask -- fuzz passphrase-input 60` | Runs the `fuzz_passphrase_input` target for 60 seconds |
| `cargo run -p xtask -- timing-test` | Runs all dudect harnesses including the new challenge/response path |
| `cargo run -p xtask -- wycheproof` | (already proposed) Now also runs HMAC-SHA256 vectors for the challenge key path |

---

## New files and crates — summary table

| Deliverable | Type | Notes |
|-------------|------|-------|
| `psram-store/` | new `no_std` crate | Block device abstraction; no encryption; mount/unmount access gate; probe-absent short-circuit |
| `galdr-core` trait `PsramInterface` | trait addition | QSPI probe + read/write; `test-hal` fake with simulated absent/present |
| `usb-personality` extensions | crate extension | Challenge/response handler; USB disconnect-on-lock; descriptor parity invariant |
| `host-tools/psram-unlock/` | new `std` binary | Linux passphrase entry; vendor SCSI command sender; zeroises passphrase buffer after use |
| `vault` `KeyPurpose` additions | enum extension | `HostChallengeKey`, `HostChallengeNonce` |
| `docs/HOST_PROTOCOL.md` | documentation | Vendor SCSI command layout; HMAC construction; passphrase encoding; third-party driver contract |
| `docs/PSRAM.md` | documentation | Graceful degradation contract; auth sequence; lock sequence; "no encryption" policy rationale |
| `docs/XOUS_INTEGRATION.md` | documentation | Record the Xous USB disconnect API call once identified during bring-up |
| `fuzz/fuzz_psram_block_rw.rs` | fuzz target | Arbitrary LBA + length sequences |
| `fuzz/fuzz_host_protocol.rs` | fuzz target | Arbitrary vendor command byte sequences |
| `fuzz/fuzz_passphrase_input.rs` | fuzz target | Arbitrary passphrase byte sequences |
| dudect harness `timing_challenge_response` | security-tests addition | HMAC timing on challenge/response path |

---

## Host protocol specification

*(Placeholder — fill in during bring-up. The fields below are the minimum required
content for `docs/HOST_PROTOCOL.md`.)*

- **VID/PID:** TBD (assigned by project)
- **Command transport:** SCSI vendor-specific command (opcode `0xC0` reserved;
  exact byte layout TBD)
- **`GET_CHALLENGE` CDB:** `[0xC0, 0x01, 0x00, …]`; direction: device-to-host;
  length: 32 bytes; returns a single-use TRNG nonce
- **`SEND_RESPONSE` CDB:** `[0xC0, 0x02, 0x00, …]`; direction: host-to-device;
  length: 32 bytes; payload: `HMAC-SHA256(HostChallengeKey, nonce || passphrase_utf8_nfc)`
- **`LOCK` CDB:** `[0xC0, 0x03, 0x00, …]`; direction: none; triggers unmount
  and re-enumeration
- **Response codes:** `0x00` success, `0x01` wrong credential, `0x02` locked
  (threshold reached), `0x03` no PSRAM fitted, `0x04` challenge expired

---

## Security notes

**Why no encryption on PSRAM?** The PSRAM volume is a decoy. Its value is that
it looks like ordinary, unremarkable storage to anyone who inspects it. Adding
encryption would either require publishing the key (defeating the decoy) or
require a second authentication step (making the decoy less convincing). The
real secrets live in RRAM behind the vault and PIN policy, not in PSRAM.

**Descriptor parity is a security property.** If the USB descriptors differ
between the PSRAM-absent and PSRAM-locked states, an adversary can determine
whether PSRAM is fitted and target the authentication path accordingly. The
firmware must not give this information away.

**The challenge/response HMAC is mandatory.** Sending the raw passphrase over
USB would expose it to any passive USB bus observer or captured USB traffic. The
HMAC construction over a fresh TRNG nonce ensures the credential cannot be
replayed even if the USB traffic is recorded.

**Passphrase minimum enforcement at the parser boundary.** Enforcing the minimum
length in the command parser (before `pin-policy` sees the input) means the
attempt counter is not incremented for obviously invalid inputs. This marginally
reduces the ability to exhaust the counter with noise, and simplifies the
policy engine's invariants.

**USB disconnect-on-lock is a data-integrity property as well as a security
property.** A host OS that holds an open filesystem on a volume that suddenly
becomes inaccessible will attempt recovery writes, which will fail. The explicit
disconnect/re-enumerate cycle gives the host OS a clean signal to unmount,
preventing filesystem corruption in the host's view.
