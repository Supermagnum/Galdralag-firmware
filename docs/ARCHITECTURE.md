# Galdr / Galdralag firmware architecture (Baochip-1x, Xous)

> **Status: design target — not current isolation.** Sections 1–6 below describe the intended
> multi-process Xous layout (`vaultd`, `pind`, `usbd`, counter driver). **Today's firmware does not
> run those as separate Xous servers.** On Xous, `galdralag-service` statically links `galdr-vault`,
> `pin-policy`, and `usb-personality` (via `baochip-openpgp`) in **one process** and talks to
> `usb-bao1x` over IPC for CCID transport only. See [Current implementation](#current-implementation-xous)
> and [docs/CRATE_DEPENDENCIES.md](CRATE_DEPENDENCIES.md). Do not treat cross-process vault/USB/PIN
> boundaries as an active security property until the IPC servers exist.

This document specifies a Rust/Xous firmware architecture for the **Baochip-1x** SoC (see also the
[upstream Baochip-1x design README](https://github.com/Supermagnum/Baochip-1x-firmware)): a RISC-V application-class core, on-chip **RRAM** for durable secrets, a **USB 2.0 device** controller, and a **tamper-aware monotonic attempt counter** block. It is a **design artifact**; much of the cryptographic and policy logic is implemented as **library crates** composed in-process today.

## 1. Threat model (summary)

- **Physical attacker** may probe or power-cycle; RRAM retains data across power loss unless explicitly erased.
- **Host-attached USB** must not read vault key material; only approved personalities expose agreed endpoints and descriptors.
- **Brute force** on PIN must be bounded by hardware-backed monotonic counting, not software-only state.
- **Cross-process leakage (design goal)** — intended mitigation via separate Xous servers and capability-based IPC, each holding minimal authority. **Not enforced today** (see status note above); current code relies on library boundaries, sealing, and PIN policy inside `galdralag-service`.

## 2. Process isolation boundaries (Xous) — design target

The table describes the **target** decomposition. Crate names in parentheses map to library code that exists today but is **not** spawned as separate processes yet.

| Xous server (process) | Owns | Talks to | Must not |
|----------------------|------|----------|----------|
| **vaultd** (`vault`) | RRAM vault I/O, unwrap/seal orchestration, derived key handles (opaque to others) | PIN policy (auth result only), USB personality (personality id + policy ack) | Parse USB traffic; store PIN plaintext |
| **pind** (`pin-policy`) | PIN state machine, counter orchestration, rate/lockout policy | vaultd (trigger zeroisation), hw-counter driver | Hold long-term key material |
| **usbd** (`usb-personality`) | Descriptor tables, endpoint routing, active personality | vaultd (which blobs may be exposed under personality), host via USB IP | Derive keys; read RRAM directly |
| **counter-hal** (driver, may be merged with pind initially) | MMIO to monotonic counter IP | pind | User-visible policy |

**Capabilities (design)**: Each client holds a Xous `CID` to the server it calls. vaultd issues **opaque key handles** (indices or capability tokens) to usbd for session crypto; raw IKM never crosses the boundary. **Not implemented** as inter-process handles today — backends hold keys in the same address space as the CCID dispatcher.

**Trust boundary (design)**: Host USB stack is untrusted. Only usbd translates USB-level requests into IPC that vaultd can accept or reject based on active personality and vault policy. **Today:** APDU dispatch and vault access are direct method calls inside `galdralag-service`; the only Xous IPC on the hot path is to **`usb-bao1x`** (CCID frame I/O).

## Current implementation (Xous)

What ships in-tree for BaoSec / `baosec` images today:

| Artifact | Role |
|----------|------|
| **`galdralag-service`** (`services/galdralag`) | Single Xous process: PDDB PIN bridge, `open_or_provision_backend`, `OpenPgpCcidDispatcher` + `BaochipVaultBackend` |
| **`galdr-vault`**, **`pin-policy`**, **`usb-personality`** | Library crates **linked into** `galdralag-service` (and host tests), not separate `baosec` processes |
| **`baochip-openpgp`** | Xous-only glue: RRAM windows, vault open/provision, `PinPolicyMachine` wired into the OpenPGP backend |
| **`usb-bao1x`** (xous-core) | Separate Xous process: USB device stack; CCID bytes via `_Xous USB device driver_` IPC |
| **`vault::VaultService`** | Stub only (`VaultRequest::dispatch` → `NotImplemented`); no `vaultd` server loop |
| **`usb_personality::set_personality_stub`** | Stub only; no `usbd` server loop |

**Evidence:** `services/galdralag/src/main.rs` constructs `OpenPgpCcidDispatcher::new(backend)` and calls `dispatcher.handle_ccid(...)` in-process; CCID uses `xous::send_message` / `Buffer::lend_mut` only to `usb_conn` from `usb_bao_ipc::SERVER_NAME_USB_DEVICE`. No `xous::create_server` in `crates/vault`, `crates/pin-policy`, or `crates/usb-personality`.

### CCID message ownership (Persona A / `dabao-ccid`)

On the xous-core CCID branch ([PR #937](https://github.com/betrusted-io/xous-core/pull/937)), **`usb-bao1x` answers two commands inline in IRQ context** and never queues them to `CcidRxDeferred`:

| PC_to_RDR | Inline in `usb-bao1x` | Reaches `galdralag-service`? |
|-----------|----------------------|------------------------------|
| **GetSlotStatus (0x65)** | Yes (SlotStatus OK) | No |
| **IccPowerOn (0x62)** | Yes (fixed OpenPGP ATR) | No |
| **XfrBlock / other** | No | Yes → `OpenPgpCcidDispatcher` |

**Policy**

- **Before and after vault open:** transport owns `0x62` / `0x65` while inline answers remain enabled.
- **Authoritative APDUs:** Galdralag owns all messages delivered via `CcidRxDeferred` (typically `XfrBlock`), including SELECT / VERIFY / GENERATE / PSO, once the vault backend is ready (or the Dabao bring-up stub until then).
- If product policy later requires Galdralag-owned ATR, that is an **xous-core** change (disable or feature-gate inline IccPowerOn); see [XOUS_CORE_UPSTREAM_REQUESTS.md](XOUS_CORE_UPSTREAM_REQUESTS.md).

**Checked in-tree (not assumed):** grep of `crates/usb-personality`, `services/galdralag`, and `services/galdralag-stub` for `IccPowerOn` / `GetSlotStatus` / `0x62` / `0x65` (CCID message types, not OpenPGP status words). Paths that *can* produce ATR / SlotStatus:

| Location | Role |
|----------|------|
| `crates/usb-personality/src/ccid/command.rs` | Parses 0x62 / 0x65 |
| `PcToRdr::answered_inline_by_usb_bao1x()` | **Opcode-only** (no `#[cfg]`, no runtime transport flag). `true` for 0x62/0x65 on every build. Test: `inline_usb_bao1x_opcodes` |
| `OpenPgpCcidDispatcher::handle_ccid` | Answers 0x62 (RDR_to_PC_Parameters + ATR) and 0x65 (SlotStatus). Does **not** consult the classifier. Test: `non_xous_ccid_class_answers_inline_opcodes` |
| `crates/usb-personality/src/ccid/usb_class.rs` `CcidProtocolState::try_dispatch` | Always `handle_ccid`; **does not** call `answered_inline_by_usb_bao1x`. Same test. |
| `services/galdralag/src/main.rs` `ccid_dispatch_one` | **Only** Xous IPC call site that skips `CcidTx` when the classifier is true |
| `services/galdralag-stub` CCID loop | Equivalent skip via match arms (not the helper); stub is not in `scripts/build_dabao_ccid_image.sh` |

The classifier is **accidentally safe for now**: it is not transport-aware. Safety depends on call-site discipline (Xous IPC only). A `compile_error!` cannot span `usb-bao1x` and Galdralag (separate processes; Galdralag does not link `usb-bao1x`). Skipping `CcidTx` at the Xous loop is the guard against a double-answer if a 0x62/0x65 frame is ever queued.

**Named IPC messages in section 3–5** (`VaultOpenSession`, `PinSubmit`, `UsbSetPersonality`, …) appear **only as prose** in this document. The closest code is `VaultRequest` in `crates/vault/src/service.rs` (subset, stub, no Xous wiring). `galdr-core` documents the gap explicitly: `todo!("wire vaultd / pind / usbd Xous servers")` in `scaffold_todos.rs`.

## 3. RRAM vault layout

RRAM is modeled as a linear, byte-addressable store with **wear and retention** properties; the layout is versioned.

| Region | Offset (logical) | Size (design max) | Contents |
|--------|------------------|-------------------|----------|
| **VAULT_HDR** | 0 | 256 B | Magic, `layout_version`, `generation`, flags, checksum of header, reserved |
| **POLICY_BLK** | 256 | 512 B | Serialized PIN policy snapshot (thresholds, timeouts), sealed with device key |
| **MONO_SHADOW** | 768 | 16 B | Optional redundant copy of counter low word for diagnostics (must not be authoritative) |
| **SLOT_DIR** | 1024 | 4 KiB | Fixed array of **slot descriptors**: `{ slot_id, offset, len, type, flags, mac }` |
| **BLOB_STORE** | 5 KiB | Remaining | Encrypted/authenticated blobs (PIN verifier, backup seeds, attestation certs, …) |

**Rules**

- **Authoritative attempt count** lives in **hardware monotonic counter**, not only in RRAM. RRAM may cache a copy for UI only if clearly labeled non-authoritative.
- **Sealed blobs** use AEAD (crate-selected; not implemented in scaffolding). Each blob has an explicit **key purpose** fed into HKDF domain separation (see vault KDF module).
- **Atomic updates**: writes use **slot replacement + generation bump** in header to avoid torn metadata (implementation-specific journaling may wrap this).

**vaultd interface (IPC messages, conceptual — not wired)**

- `VaultOpenSession { client_id } -> SessionId`
- `VaultSeal { session, slot, plaintext, aad } -> Result<(), VaultError>`
- `VaultUnseal { session, slot, aad } -> Result<PlaintextHandle, VaultError>` (handle is process-local shmem or scoped buffer)
- `VaultDerive { session, purpose, context } -> Result<KeyMaterialHandle, VaultError>`
- `VaultZeroise { reason } -> !` (terminates after wipe)

## 4. PIN policy state machine

**States**

1. **BootCold** — hardware not yet verified; no PIN accepted.
2. **LockedIdle** — device idle; counter below threshold; awaiting PIN entry.
3. **AttemptCharge** — transient: counter increment **scheduled or in progress**; no cryptographic compare yet.
4. **Verifying** — PIN compare against verifier blob (constant-time compare in implementation).
5. **Unlocked** — short-lived operational state; sub-states for USB allowed/denied optional.
6. **Cooldown** — optional backoff timer after failed attempt.
7. **Bricked** — terminal after zeroisation trigger or catastrophic failure.

**Transitions (security-critical ordering)**

- **LockedIdle → AttemptCharge**: On user submit, **request counter increment first**. If increment fails or returns count `> N_max`, transition to **Bricked** (zeroisation path) without comparing PIN.
- **AttemptCharge → Verifying**: Only if post-increment count `<= N_max` and hardware acknowledges.
- **Verifying → Unlocked**: On successful compare; may reset **software** backoff only (hardware counter policy defines whether resets are allowed; default **no reset** of hardware counter to prevent replay of counter state).
- **Verifying → Cooldown or LockedIdle**: On failure; no PIN compare after increment is re-run for the same attempt (exactly one increment per submitted attempt).
- **Any → Bricked**: Zeroisation trigger from vaultd, tamper, or counter overflow policy.

**Rationale for increment-before-compare**

- Ensures **every guess consumes an attempt** even if software compare is skipped, faulted, or attacked with glitching between compare and persist.
- Prevents “free” retries if verification crashes after a correct guess but before counter update (here counter already moved).

**pind interface (conceptual — not wired)**

- `PinSubmit { pin_blob } -> Result<PinOutcome, PinError>` — internally performs increment-then-verify ordering.
- `PinGetState -> PinStateView` (coarse, for UI).
- `PinRegisterZeroisation { callback_cid, opcode }` — registration for vaultd wipe (Xous message target).

## 5. USB personality switching

**Personalities** are static profiles: VID/PID, string descriptors, interface count, endpoint map, and **which vault operations** are allowed over which endpoints.

**States**

- **PersonalityInactive** — USB stack down or not enumerated.
- **PersonalitySelected { id }** — configured but not yet visible on bus (optional).
- **PersonalityActive { id }** — host sees this device class and endpoints.

**usbd interface (conceptual — not wired)**

- `UsbSetPersonality { id, auth_token } -> Result<(), UsbError>` — `auth_token` proves caller is allowed (e.g. post-unlock capability).
- `UsbGetActive -> PersonalityId`
- `UsbTeardown -> ()` — disconnect or switch; vaultd notified to revoke ephemeral handles.

**vaultd interaction**

- On personality change, vaultd **drops** session key handles tied to the previous personality.
- Each personality maps to a **policy bitmask**: e.g. `ALLOW_FIDO`, `ALLOW_MASS_STORAGE_VIRTUAL`, `ALLOW_SERIAL_DEBUG` (debug gated by compile-time feature).

## 6. Zeroisation trigger paths

All paths end in `vaultd::VaultZeroise` (or equivalent) which:

1. Disables interrupts and USB DMA as required by SoC reference.
2. Overwrites **volatile** key buffers (via `zeroize`).
3. Issues **RRAM mass erase** or slot-by-slot secure erase per product policy.
4. Resets monotonic counter IP if hardware supports **secure clear** (if not, relies on vault erasure + brick state).
5. Reboots or halts in **Bricked**.

**Trigger sources**

| Source | Condition | Notes |
|--------|-----------|-------|
| PIN policy | Post-increment count exceeds threshold | Primary user-visible path |
| Tamper GPIO / mesh | SoC event | Driver raises to pind/vaultd |
| Debug unlock timeout | Policy | Optional |
| Explicit factory reset | Authenticated command | Separate authorization chain |
| Failed self-test | Boot | Before accepting PIN |

**Ordering**: Zeroisation **must not** depend on successful USB teardown; hardware quiesce is best-effort before erase.

## 7. Module / crate map (Rust workspace)

| Crate | Role |
|-------|------|
| `galdr-core` | HAL traits, shared errors, `test-hal` fakes |
| `vault` | Vault logic, RRAM layout types, HKDF derivation API, sensitive buffer types; **`VaultService` IPC stub** |
| `pin-policy` | State machine, `MonotonicCounter` trait, zeroisation hook (used in-process by OpenPGP backends) |
| `usb-personality` | OpenPGP/CCID dispatch and backend traits (used in-process by `galdralag-service`) |
| `baochip-openpgp` | Xous RRAM + vault open path for OpenPGP |
| `services/galdralag` | **`galdralag-service`** Xous binary composing the above |
| `host-tools` | host-side utilities (std), flashing, manifest / verification stubs |
| `xtask` | build orchestration for `riscv32imac-unknown-none-elf` and `galdralag-service` registration |

## 8. Feature flags (algorithm profiles)

Workspace/crate features gate **which** algorithms are linked (smaller attack surface for shipping profiles):

- `algo-aes-gcm` — AES-GCM support in vault (when wired).
- `algo-chacha` — ChaCha20-Poly1305 support.
- `algo-ed25519` — Ed25519 signatures (attestation, updates).
- `algo-x25519` — X25519 key agreement.
- `profile-hardened` — stricter constant-time and reduced debug surface (compile-time).

Default for scaffolding: **no** crypto beyond HKDF tests in dev; stubs return `Unsupported`.

## 9. Key derivation (contract)

- **KDF**: HKDF-SHA512 only (implementation crate: `hkdf` + `sha2`).
- **Domain separation**: Every expand uses a distinct **info** string (versioned prefix `galdr-v1/...`) per **KeyPurpose**; no two purposes share identical info.
- **IKM sources** are documented per call site (user secret, hardware root, sealed blob unwrap); IKM is never logged.

## 10. Open points (hardware-dependent)

- Baochip-1x **exact** RRAM erase granularity and timing.
- Whether monotonic counter is **one-way only** or supports authenticated reset in factory mode.
- Xous **CID** layout and memory server interaction for large blobs.

---

*Revision: 0.2 — documents design target vs current single-process `galdralag-service` composition; update when vaultd/pind/usbd IPC ships or SoC TRM is available.*
