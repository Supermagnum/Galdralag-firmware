# On-chip RRAM layout (Baochip-1x)

This document ties the **4,194,304 byte** (4 MiB exactly) on-chip **RRAM** capacity
named in [`crates/vault`](../crates/vault/src/lib.rs) and platform docs to **layout
constants and HAL traits** in this repository. It does **not** replace the
platform memory map in [Supermagnum/Baochip-1x-firmware](https://github.com/Supermagnum/Baochip-1x-firmware);
integrators must reconcile sketches here with that map before shipping firmware.

## Table of contents

- [Capacity and HAL](#capacity-and-hal)
- [Documented regions from source](#documented-regions-from-source)
- [Wear and write frequency](#wear-and-write-frequency)
- [Power-off and zeroisation](#power-off-and-zeroisation)

---

## Capacity and HAL

| Item | Value / contract |
|------|------------------|
| **Total RRAM** | **4,194,304 bytes** (4 MiB) — per vault crate docs aligning with Baochip-1x |
| **Byte access** | [`VaultStorage::read` / `write`](https://github.com/Supermagnum/Galdralag-firmware/blob/main/crates/galdr-core/src/hal.rs) (`offset: u64`, byte slices) |
| **Always-on abuse bounds** | [`MonotonicCounter`](https://github.com/Supermagnum/Galdralag-firmware/blob/main/crates/galdr-core/src/hal.rs) — PIN and future stateful-signature abuse; **increment before PIN compare** per `pin-policy` |
| **Active wipe** | [`ZeroiseController::zeroise_region`](https://github.com/Supermagnum/Galdralag-firmware/blob/main/crates/galdr-core/src/hal.rs) — policy-defined regions |

> **Hardware caveat:** Vault and zeroisation behaviour are verified in `test-hal`
> simulation and unit tests only. Physical verification on Baochip-1x silicon has
> not been performed. See [HARDWARE_VERIFICATION.md](HARDWARE_VERIFICATION.md).

---

## Documented regions from source

Constants below come from [`crates/vault/src/layout.rs`](../crates/vault/src/layout.rs),
[`public_key_vault.rs`](../crates/vault/src/public_key_vault.rs),
[`session_long_term_signing.rs`](../crates/vault/src/session_long_term_signing.rs),
and related modules. Comments in source call the layout **sketches** — full
allocation through 4 MiB is **not** enumerated in one place in this tree.

| Region (conceptual) | Offset / span (from code) | Notes |
|---------------------|---------------------------|--------|
| **Prefix / policy header** | Bytes **0..256** implied before public-key table | First **public-key** slot starts at offset **256** (`PUBLIC_KEY_REGION_BASE`) |
| **Public-key DER table** | Base **256**, reserved span **65,536** bytes (`PUBLIC_KEY_TABLE_BYTES`) | **2,048** bytes per [`PublicKeySlot`](https://github.com/Supermagnum/Galdralag-firmware/blob/main/crates/vault/src/public_key_vault.rs); payloads are **public**, unencrypted |
| **Sealed OpenPGP private blobs** | **SIG** at `256 + 65536` = **65,792**; **DEC** and **AUT** follow | **93** bytes each (`SEALED_BLOB_BYTES`); AEAD-wrapped scalars; end = **66,071** (`SEALED_KEY_REGION_END`) |
| **Session long-term Brainpool keys** | Base **1,048,576** (`0x100_000`); **512** bytes × slot | Plaintext scalars in tree today — see module rustdoc **“production should wrap”** warning |
| **RSA wrapped key slots** | **Slot-relative:** `slot_index × 8,192` bytes | [`rsa_vault.rs`](../crates/vault/src/rsa_vault.rs) does **not** embed a global base; the integrator’s `VaultStorage` view must not overlap other regions |
| **PIN policy record** | **Layout-defined offset** (parameter to read/write APIs) | **64** bytes (`VAULT_PIN_POLICY_RECORD_BYTES`); magic `GPPL` — exact RRAM offset **not** fixed in Rust sources here |
| **Stateful PQ signature state (XMSS / LMS)** | — | **Not implemented** in this repository yet; [`PQ_SIGNATURES.md`](PQ_SIGNATURES.md) documents placeholder feature only. **No** RRAM slot layout for state indices exists in source. |

**Not in RRAM as dedicated layout:** Shamir **share** payloads for distribution are built on the **host** in current tooling; shares are not described as stored in named RRAM slots in this codebase.

---

## Wear and write frequency

RRAM supports finite write endurance per cell; exact cycle counts and retention are
**silicon-datasheet** matters and are **not** stated in this repository.

**What causes RRAM writes in design (not an exhaustive silicon model):**

| Subsystem | Typical persistence event |
|-----------|-----------------------------|
| **PIN policy** | Provisioning / PIN change writes verifier blob; **counter** updates via `MonotonicCounter` (implementation maps to NV, not necessarily every attempt — see `pin-policy` tests) |
| **Sealed keys / RSA / public keys** | Key generation, import, delete |
| **Profile or audit (future)** | Any design that appends audit records would add writes — **append-only RRAM audit log not implemented** (see [AUDIT_LOG.md](AUDIT_LOG.md)) |

**Wear levelling:** No wear-levelling algorithm for RRAM appears in this repository.

> **Open engineering question:** Endurance under realistic PIN-attempt, provisioning,
> and key-update workloads should be **measured on hardware** and budgeted against
> vendor RRAM specs; that analysis is **not** in-tree.

---

## Power-off and zeroisation

| State | Typical behaviour (design / code) |
|-------|-------------------------------------|
| **Power loss** | OpenPGP **session** and **PIN verified** state reset on reconnect (see main [README](../README.md)); **private** blobs remain unless wipe policy runs |
| **PIN breach / policy** | `pin-policy` drives **zeroisation** trigger toward [`ZeroiseController`](https://github.com/Supermagnum/Galdralag-firmware/blob/main/crates/galdr-core/src/hal.rs); **logical** resume-before-USB model in [`ZeroiseBootState`](https://github.com/Supermagnum/Galdralag-firmware/blob/main/crates/pin-policy/src/zeroise_fsm.rs) (**TODO** wire to boot0 per rustdoc) |
| **Order of wipe** | **Region IDs** and multi-pass ordering are **platform / boot0** concerns; this repo does not enumerate pass order byte-for-byte. Coordinate with Baochip-1x boot and [HARDWARE_VERIFICATION.md](HARDWARE_VERIFICATION.md). |

See also [KEY_LIFECYCLE.md](KEY_LIFECYCLE.md) for key material lifecycle.

---

## See also

- [ARCHITECTURE.md](ARCHITECTURE.md) — subsystem map
- [dev-ref.md](dev-ref.md) — HAL and vault invariants
- [API_REFERENCE.md](API_REFERENCE.md) — host protocol annex
