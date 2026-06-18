# Galdr / Galdralag firmware architecture (Baochip-1x, Xous)

This document specifies a Rust/Xous firmware architecture for the **Baochip-1x** SoC (see also the
[upstream Baochip-1x design README](https://github.com/Supermagnum/Baochip-1x-firmware)): a RISC-V application-class core, on-chip **RRAM** for durable secrets, a **USB 2.0 device** controller, and a **tamper-aware monotonic attempt counter** block. It is a design artifact only; implementation lives in the workspace crates.

## 1. Threat model (summary)

- **Physical attacker** may probe or power-cycle; RRAM retains data across power loss unless explicitly erased.
- **Host-attached USB** must not read vault key material; only approved personalities expose agreed endpoints and descriptors.
- **Brute force** on PIN must be bounded by hardware-backed monotonic counting, not software-only state.
- **Cross-process leakage** is mitigated by Xous server boundaries and capability-based IPC; each server holds minimal authority.

## 2. Process isolation boundaries (Xous)

| Xous server (process) | Owns | Talks to | Must not |
|----------------------|------|----------|----------|
| **vaultd** (`vault`) | RRAM vault I/O, unwrap/seal orchestration, derived key handles (opaque to others) | PIN policy (auth result only), USB personality (personality id + policy ack) | Parse USB traffic; store PIN plaintext |
| **pind** (`pin-policy`) | PIN state machine, counter orchestration, rate/lockout policy | vaultd (trigger zeroisation), hw-counter driver | Hold long-term key material |
| **usbd** (`usb-personality`) | Descriptor tables, endpoint routing, active personality | vaultd (which blobs may be exposed under personality), host via USB IP | Derive keys; read RRAM directly |
| **counter-hal** (driver, may be merged with pind initially) | MMIO to monotonic counter IP | pind | User-visible policy |

**Capabilities**: Each client holds a Xous `CID` to the server it calls. vaultd issues **opaque key handles** (indices or capability tokens) to usbd for session crypto; raw IKM never crosses the boundary.

**Trust boundary**: Host USB stack is untrusted. Only usbd translates USB-level requests into IPC that vaultd can accept or reject based on active personality and vault policy.

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

**vaultd interface (IPC messages, conceptual)**

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

**pind interface**

- `PinSubmit { pin_blob } -> Result<PinOutcome, PinError>` — internally performs increment-then-verify ordering.
- `PinGetState -> PinStateView` (coarse, for UI).
- `PinRegisterZeroisation { callback_cid, opcode }` — registration for vaultd wipe (Xous message target).

## 5. USB personality switching

**Personalities** are static profiles: VID/PID, string descriptors, interface count, endpoint map, and **which vault operations** are allowed over which endpoints.

**States**

- **PersonalityInactive** — USB stack down or not enumerated.
- **PersonalitySelected { id }** — configured but not yet visible on bus (optional).
- **PersonalityActive { id }** — host sees this device class and endpoints.

**usbd interface**

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
| `vault` | vaultd logic, RRAM layout types, HKDF derivation API, sensitive buffer types |
| `pin-policy` | state machine, `MonotonicCounter` trait, zeroisation hook |
| `usb-personality` | personality tables and switching API stubs |
| `host-tools` | host-side utilities (std), flashing, manifest / verification stubs |
| `xtask` | build orchestration for `riscv32imac-unknown-none-elf` |

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

*Revision: 0.1 — aligned with repository scaffolding; update when SoC TRM is available.*
