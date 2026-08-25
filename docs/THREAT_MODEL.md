# Threat model

> **Status:** Experimental — not production-ready. Not independently audited. See [Independent audit status](#independent-audit-status).

This document states what Galdralag’s design aims to defend against, what it does **not** defend against, and what remains **unverified** until Baochip-1x silicon is available (expected Q2), biometric PAD is measured on hardware, and independent review is performed. It is **not** a marketing or certification artefact.

**What Galdralag is:** An **experimental**, **open-source** hardware security token firmware targeting **Baochip-1x** under **Xous**, combining **something you have** (the token), **something you know** (**PIN** verified on-device with policy and counters), and **optionally something you are** (biometric match asserted by dedicated **open** biometric hardware, templates held **encrypted** in on-chip **RRAM**, **4,194,304 bytes** total). It includes **named cipher cascade profiles**, **authenticated ephemeral ECDH** ([EPHEMERAL_SESSION.md](EPHEMERAL_SESSION.md)), **Shamir K-of-N** flows in the vault design space, and **CESS**-aligned constructions ([CESS_CONFORMANCE.md](CESS_CONFORMANCE.md)). **It is not production-ready** and **has not** been independently audited as a complete product.

**Related reading:** [README.md](../README.md) (security posture, PIN policy, zeroisation), [BIOMETRIC_API.md](BIOMETRIC_API.md), [OPENPGP_CARD.md](OPENPGP_CARD.md), [CIPHER_PROFILES.md](CIPHER_PROFILES.md), [CIPHER_PROFILE_SECURITY.md](CIPHER_PROFILE_SECURITY.md), [PQ_SIGNATURES.md](PQ_SIGNATURES.md), [HARDWARE_VERIFICATION.md](HARDWARE_VERIFICATION.md), [HARDWARE_BRINGUP_TEST_PLAN.md](HARDWARE_BRINGUP_TEST_PLAN.md), [AUDIT_LOG.md](AUDIT_LOG.md), [THREE_FACTOR_AUTH.md](THREE_FACTOR_AUTH.md).

---

## What makes this combination unusual

These are **descriptive** facts about design goals and implemented artefacts, not claims of superiority or maturity.

- **Three-factor, hardware-oriented:** The **token** is required for cryptographic operations; the **PIN** is verified on-device (`pin-policy`, `subtle::ConstantTimeEq`); an **optional** biometric path uses **match results signed on dedicated hardware** and templates **encrypted** in token **RRAM** ([BIOMETRIC_API.md](BIOMETRIC_API.md)). There is no purely software-only substitute for the token factor. Host daemons (`galdrad`) participate in policy **when wired**; full firmware enforcement of every gate is **not** complete for all flows — see threats **T5**, **T7**.

- **Biometric templates on-token:** Reference templates are intended to **never** leave the device in plaintext; encryption uses vault-derived keys (`biometric-vault`). A compromised host should not obtain raw templates from the token over the documented vault API.

- **Cipher cascade profiles:** `cipher-profile` combines symmetric cascades (e.g. multiple AEAD layers), ECDHE curve choices, and Shamir metadata into **named**, serialisable profiles ([CIPHER_PROFILES.md](CIPHER_PROFILES.md)). Breaking traffic protected by a cascade requires breaking **each** layer under the profile’s assumptions (composition proofs are standard “meet-in-the-middle does not apply per layer” reasoning; integration bugs remain possible).

- **Authenticated ephemeral ECDH and forward secrecy:** Long-term keys **authenticate** ephemeral offers but **do not** replace ephemeral ECDH for session secrecy; past sessions are not recoverable from long-term key compromise alone **when the protocol is used as specified** ([EPHEMERAL_SESSION.md](EPHEMERAL_SESSION.md)).

- **Shamir K-of-N on-device:** The vault supports splitting and recovery semantics aligned with Shamir’s scheme and project documentation ([KEY_LIFECYCLE.md](KEY_LIFECYCLE.md)); **K** shares are required to reconstruct the protected secret.

- **Open silicon stack:** Baochip RTL, schematics, bootloader chain, and **Xous** are **auditable** by third parties. **boot0** verifies **Ed25519** signatures on firmware before later stages run ([README.md](../README.md)).

- **CESS conformance:** Documented alignment with the **CESS** open specification for implemented modes ([CESS_CONFORMANCE.md](CESS_CONFORMANCE.md)).

No statement here implies that **every** commercial token lacks **some** of these properties individually. The unusual aspect is the **combination** with a **fully open** hardware/software narrative **as a goal** — together with the explicit **experimental** and **non-audited** status of **this** integration.

---

## Threat model

### Assets

| Asset | Where stored | Protection |
|-------|----------------|------------|
| OpenPGP private keys (SIG, DEC, AUT) | RRAM vault | Sealed (e.g. AES-256-GCM in vault paths); PIN required for protected card operations; optional biometric policy when provisioned and enforced |
| Biometric enrollment templates | RRAM vault (`biometric-vault` layout) | AES-256-GCM with HKDF-derived per-slot keys; plaintext templates not exported by design |
| Shamir shares | RRAM vault | Sealed shares; **K** of **N** required to reconstruct |
| PIN verifier / policy state | RRAM (policy blob); PIN not kept as reusable plaintext | Compared with `subtle::ConstantTimeEq` in `pin-policy`; attempt counters and lockout policy |
| Biometric device trust anchors | Intended RRAM vault | Ed25519 public keys for provisioned devices (design in [BIOMETRIC_API.md](BIOMETRIC_API.md)) |
| Security audit trail | **Host** databases / logs; OpenPGP backend XOR accumulator in RAM | **`ProfileAuditRecord`** and tooling exist; **persistent append-only RRAM audit log is not implemented** — [AUDIT_LOG.md](AUDIT_LOG.md) |
| Cipher profile configuration | Vault / profile store (per product wiring) | Integrity depends on vault sealing and host/tool flows; see [CIPHER_PROFILE_SECURITY.md](CIPHER_PROFILE_SECURITY.md) |
| Ephemeral session keys | Volatile RAM during session | Intended not to be committed to RRAM as long-term keys; cleared on session end / power-off ([EPHEMERAL_SESSION.md](EPHEMERAL_SESSION.md)) |

### Threats

Each row: **Attacker capability** → **Outcome** → **Mitigation** → **Caveat**

| ID | Attacker capability | Outcome | Mitigation | Caveat |
|----|----------------------|---------|------------|--------|
| **T1** | Stolen token; PIN unknown (physical access, PIN brute-force) | Cannot complete PIN verification; protected operations remain blocked; threshold triggers zeroisation | On-device PIN policy and counters; counter increment and RRAM flush **before** PIN compare in `pin-policy` | **Hardware** timing or fault attacks against PIN verification **not** characterised on silicon (Q2). Dudect runs on **host** harnesses for selected primitives — **not** a complete proof for the full PIN path on chip. **Manual** lockout verification on real hardware (power-cycle counter persistence, threshold behaviour, post-lockout key destruction) is **required** and **has not yet been performed** — see [HARDWARE_BRINGUP_TEST_PLAN.md](HARDWARE_BRINGUP_TEST_PLAN.md) section 10. |
| **T2** | Observed PIN; no physical token | Cannot perform on-card private-key operations | Physical token required for OpenPGP card operations over CCID | None known at this time for the **standard** threat model (network attacker without token). |
| **T3** | Stolen token; PIN known; biometric **provisioned** | Without a valid biometric assertion and session binding, policy intends to block PIN-gated use | Design: `galdrad` validates signed match + session token; token verifies **HMAC** via `biometric-vault` helpers | **Partially implemented:** crates and tests exist; **full** CCID/firmware path enforcing session token **before** every sensitive PIN APDU is **not** documented as complete — see **T7**. If biometric is **not** provisioned, PIN-only flows remain by design. |
| **T4** | Stolen token; PIN known; **presentation attack** on biometric device | Intended failure if liveness fails or score below threshold | Device-side liveness (e.g. vascular pulse; multimodal on sweet — see device docs) | **APCER/BPCER** on **real** hardware **not** measured; ISO/IEC 30107-3 compliance **cannot** be claimed without measured data ([BIOMETRIC_TESTING.md](BIOMETRIC_TESTING.md)). **Coercion** with a live subject is **not** a PAD problem — see **T13**. |
| **T5** | Compromised host (malware, root) | Cannot extract long-term **private keys** or **plaintext templates** from the token via documented vault boundaries; can observe **plaintext outputs** of operations the **user** performs (normal OpenPGP/host behaviour) | Keys and templates stay on token; ephemeral ECDH limits retroactive decryption of **past** sessions if protocol used correctly | Root can tamper with **`galdrad`**, **pcscd** interactions, or UI — see **T7**. Host **udev** and separate **host** daemons reduce casual abuse; they **do not** defeat a determined root attacker. **On-device:** separate `vaultd` / `pind` / `usbd` Xous processes are a **design target** only — today vault, PIN policy, and OpenPGP dispatch run **in one** `galdralag-service` process ([ARCHITECTURE.md](ARCHITECTURE.md)). |
| **T6** | Long-term **private** key compromised | **Future** signatures/decryptions impersonate the victim; **past** ephemeral sessions retain confidentiality vs this key only if ephemeral ECDH was used correctly | Forward secrecy property of authenticated ephemeral ECDH ([EPHEMERAL_SESSION.md](EPHEMERAL_SESSION.md)); Shamir reduces single-point theft of material | Wrong integration (session keys mishandled on host) can **void** forward-secrecy benefits. Key rotation response is operational. |
| **T7** | Malicious **`galdrad`** (or stub replacing it) | Biometric **pre-gate** can be **bypassed** on the host for workflows that trust the daemon | **Two independent layers required (neither substitutes for the other):** (1) host-side session-token verification — **`verify_session_token`** in **`biometric-vault`** must run before PIN APDUs are accepted when biometric policy applies; (2) on-device caller authentication on CCID transport IPC — when **`usb-bao1x`** adds **`CcidRxDeferred` / `CcidTx`** (opcodes 640/642, tracked in [xous-core #875](https://github.com/betrusted-io/xous-core/issues/875)), those opcodes must use **first-PID lock** caller auth equivalent to existing **`U2fRxDeferred` / `U2fTx`** (128/129) in the same server. Host verification alone does not stop another Xous process from sending CCID IPC; on-device PID lock alone does not stop a forged host from driving PIN APDUs if firmware accepts them without session token. | **Critical gap until wired:** If firmware does **not** enforce session token checks on **every** relevant PIN path, a forged host can send PIN APDUs **without** biometrics. CCID opcodes **640/642 are not present** in the vendored `xous-core` tree at audit refresh (2026-06); Galdralag reserves them in `usb_bao_ipc.rs` pending upstream merge. Mitigate with OS integrity, reproducible builds, restricted CCID access — **not** a full substitute for firmware enforcement. |
| **T8** | Physical attack (glitching, **power analysis**, debug/JTAG) | Potential extraction or misuse of secrets | Sealed vault, zeroisation policies, **intended** Xous server separation ([HARDWARE_VERIFICATION.md](HARDWARE_VERIFICATION.md), [ARCHITECTURE.md](ARCHITECTURE.md)) | **No** independent hardware security evaluation reported. **Multi-process vault/USB/PIN isolation is not implemented yet** — a compromise of `galdralag-service` sees all linked subsystems in one address space. Open RTL aids **review** and aids **attackers** equally. |
| **T9** | Supply-chain malicious **firmware** image | boot0 **Ed25519** verification rejects tampered images **if** verification keys are trustworthy | Signed boot chain; reproducible builds help verify binaries | Compromise of **signing keys** or **wrong** trusted keys burns operational trust (“correct build of wrong firmware”) — see “does not protect”. |
| **T10** | Downgrade or coercion of **cipher profile** | Weaker profile might reduce security margins | **CIPHER_PROFILE_SECURITY.md** discusses identifiers, traffic analysis, wildcard profile | **Automatic** append of every profile change to **RRAM** is **not** implemented ([AUDIT_LOG.md](AUDIT_LOG.md)). Whether profile selection can be forced **without** legitimate operator action depends on **concrete** CCID/host flows — treat as **deployment-dependent**. |
| **T11** | Theft of fewer than **K** Shamir shares | Cannot reconstruct secret (Shamir information-theoretic threshold) | Mathematical threshold property | Poor share storage (all shares on one laptop) collapses to a single point of failure operationally. |
| **T12** | Theft of **K** or more Shamir shares | Can reconstruct protected secret | Operational: distribute shares across boundaries; wrap shares for recipients | No technical mitigation once **K** shares leak — organisational controls only. |
| **T13** | **Coercion** (user forced to PIN/biometric) | Attacker obtains legitimate authentication | **None** by cryptography | Universal limitation of PIN/biometric systems; policy and legal controls apply. |
| **T14** | **Quantum** adversary (Shor’s algorithm) against RSA/ECC | Confidentiality/agreement based on affected classical asymmetric primitives breaks **when** large-scale quantum computers exist | PQ signatures **feature-gated** (unaudited crates); ML-KEM / ML-DSA / SLH-DSA **pending** audited `no_std` integration ([PQ_SIGNATURES.md](PQ_SIGNATURES.md)) | **Open** risk for long-lived traffic sealed only with vulnerable primitives. |

---

## What this does not protect against

- **Coercion** (**T13**).
- **Fully compromised host** for **current** user operations: plaintext after decrypt/sign on host remains visible to malware (**T5**).
- **Malicious `galdrad` / host shim** bypassing biometric intent until **both** host session-token enforcement **and** on-device CCID caller-auth are complete (**T7**).
- **Physical attacks** without independent silicon evaluation (**T8**); on-device **vaultd/pind/usbd process boundaries** are not an active mitigation until implemented.
- **Post-quantum** adversaries against classical asymmetric cryptography used today (**T14**).
- **Logic bugs**, wrong protocols, and integration mistakes — Rust reduces memory unsafety, **not** incorrect security logic.
- **Correct cryptographic signature** on the **wrong** policy or **wrong** signing key trust anchor (**T9**).
- **RRAM / flash wear** leading to data loss — endurance on Baochip-1x **not** characterised here.
- **Biometric spoofing** by sophisticated artefacts — **APCER** on real hardware **unknown** (**T4**).
- **Downgrade** or covert profile manipulation without strong operational controls (**T10**).

---

## What is unverified pending hardware (Q2)

- **Hardware zeroisation:** Simulation and `test-hal` exercises only for some paths; physical checks (JTAG, power-cycle, DPA remnants) **open** — [HARDWARE_VERIFICATION.md](HARDWARE_VERIFICATION.md).
- **Timing side-channels on silicon:** Dudect on developer machine **does not** characterise chip behaviour under **power analysis**.
- **RRAM endurance:** PIN counters, any future on-device audit region, biometric template writes — **not** measured on final silicon here.
- **Biometric PAD metrics:** Mocks in tests only; **ISO/IEC 30107-3** metrics require hardware and attack presentation material — [BIOMETRIC_TESTING.md](BIOMETRIC_TESTING.md).
- **Glitch / fault injection:** Not evaluated.

---

## Independent audit status

- This project **has not** been independently audited by a professional cryptographer or security firm **as an integrated product**.
- Cryptographic **primitives** come largely from **audited workspace crates** (RustCrypto and others); **composition**, **integration**, and **protocol** use inherit **no** automatic certification from those audits.
- **Post-quantum** crates enabled by feature flags are **explicitly unaudited** for production — [PQ_SIGNATURES.md](PQ_SIGNATURES.md).
- **Independent expert review** is **strongly** recommended before any **production** deployment claim.

This section must **remain** unless and until a **published**, **independent** audit exists — then it should be **updated** with a pointer to that report, **not** removed silently.

---

## Comparison to common hardware token capability classes

Capability classes only — **no** named commercial products.

| Capability | Typical commercial token | Galdralag (design / repo state) |
|------------|--------------------------|----------------------------------|
| OpenPGP card / CCID | Often | Yes (`usb-personality`, `baochip-openpgp`, Xous `usb-bao1x`; layout [RRAM_LAYOUT.md](RRAM_LAYOUT.md)) |
| PIN on-token | Often | Yes (`pin-policy`) |
| Biometric pre-gate | Uncommon; often fingerprint if present | Optional — **open** finger vein or sweet-class stack ([BIOMETRIC_API.md](BIOMETRIC_API.md)); wiring incomplete |
| Biometric template on-token | Rare | Intended — encrypted in **RRAM** |
| Liveness / PAD | Uncommon | Designed — **unmeasured** on shipped hardware |
| Cipher cascade profiles | Rare / absent | Yes — `cipher-profile` |
| Ephemeral ECDH forward secrecy | Rare on smartcard-class USB tokens | Yes — protocol in [EPHEMERAL_SESSION.md](EPHEMERAL_SESSION.md) |
| Shamir K-of-N on-device | Rare | Supported in vault design space |
| Post-quantum signatures | Emerging | Partial — feature-gated, **unaudited** ([PQ_SIGNATURES.md](PQ_SIGNATURES.md)) |
| Open RTL / auditable silicon stack | Rare | Yes (Baochip / Xous narrative) |
| Reproducible bootloader / Ed25519 boot0 | Varies | Yes per platform docs |
| CESS conformance | Unusual | Documented — [CESS_CONFORMANCE.md](CESS_CONFORMANCE.md) |
| Independent product audit | Often for mature lines | **No** — not yet |
| Production-ready | Often claimed for shipping products | **No** — experimental |

---

## IPC access control (userspace audit refresh, 2026-06)

Re-derived from the vendored **`xous-core/services/usb-bao1x`** tree bundled in this repository (not a submodule pin; verify before release). Galdralag **`galdralag-service`** is a **client only** to **`_Xous USB device driver_`**; in-tree **`vaultd` / `pind` / `usbd`** are library stubs without Xous servers.

### `usb-bao1x` opcode inventory vs prior audit (Table C)

| Opcode | Name | Caller auth (current vendored `main.rs`) | Notes vs prior audit |
|--------|------|------------------------------------------|----------------------|
| 0 | `LinkStatus` | None | Unchanged |
| 1 | `SendKeyCode` | **None** | Unchanged — see vendored gap below |
| 2 | `SendString` | **None** | Unchanged — log crate dependency |
| 3–12 | LED / cores / debug / autotype / observer / log level | None | Unchanged |
| 128 | `U2fTx` | **First-PID lock** (`fido_listener_pid`) | Unchanged — prior art for CCID auth |
| 129 | `U2fRxDeferred` | **First-PID lock**; others get `U2fCode::Denied` | Unchanged |
| 130 | `U2fRxTimeout` | Internal timeout pump | Unchanged |
| 256 | `IsSocCompatible` | None | Unchanged |
| 512–519 | Serial hooks / flush / send | **None** | Unchanged — see vendored gap |
| 768–769 | `IrqFidoRx` / `IrqSerialRx` | Interrupt context | Unchanged |
| 1024–1026 | Mass-storage (feature) | Not audited here | Feature-gated |
| 1027 | `HIDReadReport` | **Not dispatched** — `_` arm (log, continue) | Enum + client API in `lib.rs`; **no `match` arm in `usb-bao1x/main.rs`**. Reference impl in `usb-device-xous/main_hw.rs` (~1691): reads host HID input; **no sender auth** there either |
| 1028 | `HIDWriteReport` | **Not dispatched** — `_` arm | Would write 64-byte HID reports to USB if ported; **high privilege** (HID injection, same class as `SendKeyCode`). Reference impl (~1706): **no sender auth** |
| 1029 | `HIDSetDescriptor` | **Not dispatched** — `_` arm | Would install userland HID report descriptor (up to 1024 B). Reference impl (~1672): **no sender auth** |
| 1030 | `HIDUnsetDescriptor` | **Not dispatched** — `_` arm | Would reset HIDv2 state. Reference impl (~1687): **no sender auth** |
| 1536 | `PmicIrq` | Platform IRQ path | `bao1x` feature |
| 2048–2049 | `UsbIrqHandler` / `SuspendResume` | Internal | Unchanged |
| 4096 | `Quit` | **None** | Unchanged — terminates server |
| 4097 | `InvalidCall` | N/A (logged) | Unchanged |
| 8192 | `LogString` | None (logging API) | Hard-coded for log crate |
| **640** | **`CcidRxDeferred`** | **Not in vendored `api.rs`** | **Still absent upstream**; Galdralag expects when `ccid-openpgp` lands ([#875](https://github.com/betrusted-io/xous-core/issues/875)) |
| **642** | **`CcidTx`** | **Not in vendored `api.rs`** | **Still absent**; wire format reserved in `services/galdralag/src/usb_bao_ipc.rs` (`CcidMsgIpc` / `CcidCode`, mirroring U2F) |

Unknown opcodes hit the `_` arm: log warning and **continue** (fail-open for unimplemented variants, not fail-closed).

### Vendored `usb-bao1x` gaps (flag only — do not patch in-tree)

The following **`usb-bao1x`** opcodes are **implemented** in the vendored dispatch loop and accept IPC from **any** sender without a PID or capability check: **`SendKeyCode` (1)**, **`SendString` (2)**, **`Quit` (4096)**, and the **serial hook** family (**512–519**). A compromised or mis-registered Xous process could inject keyboard/autotype traffic, attach serial listeners, or terminate the USB server.

**HIDv2 (1027–1030) on Baochip today:** opcodes exist in `api.rs` and the **`usb-bao1x` client library** (`lib.rs`: `connect_hid_app`, `read_report`, `write_report`), but **`usb-bao1x/main.rs` has no handler** — messages hit the `_` arm (log warning, continue). There is **no active HID injection path** on the Baochip server build until handlers are ported (see `usb-device-xous/main_hw.rs` for the intended behaviour). **Upstream requirement when porting:** apply the same first-PID-lock pattern as **`U2fTx` / `U2fRxDeferred`**, especially for **`HIDWriteReport`** and **`HIDSetDescriptor`** (high privilege).

**Recommended fix (upstream):** mirror the **`U2fTx` / `U2fRxDeferred`** first-PID lock in `xous-core/services/usb-bao1x/src/main.rs` (`fido_listener_pid` pattern, lines ~403–535 in current tree): first registrant locks the interface; subsequent senders receive **`Denied`** (or equivalent) without affecting the locked owner.

**Local patching:** confirm with whoever owns the **`xous-core`** vendoring policy whether to carry a forked patch or upstream the auth change before modifying the bundled tree.

### In-tree privileged paths (this repository)

| Path | Gate (2026-06) |
|------|----------------|
| `Bao1xRebootController::enter_update_mode` | **Compile-time gate only:** requires **`UpdateModeAuthorization`** (opaque type; field not constructible outside module). Token via **`for_operator_consent()`** exists only with **`privileged-reboot`** Cargo feature. **Behavioral consent check: none** — with the feature enabled, `for_operator_consent()` returns a valid token unconditionally (`Self(())`). **Not wired to IPC; no call site in `main.rs`.** Production **`xtask build-and-register`** passes **`--features xous-bsp` only** (`privileged-reboot` off). **Open:** owner must define real operator-intent signal (see below). |
| `VaultService::dispatch` (`Seal` / `Unseal` / `ZeroiseAll`) | **`GaldrError::PrivilegedOperationDenied`** (fail-closed stub + tests) |
| `set_personality_stub` | **`GaldrError::PrivilegedOperationDenied`** (fail-closed stub + tests) |

---

## Reporting security issues

- This is an **experimental** project; there is **no** bug bounty programme.
- Report concerns via **GitHub Issues** for general bugs. For **vulnerability** reports that include **exploit** details, **contact maintainers privately first** (for example via GitHub **private vulnerability reporting** if enabled on the repository, or maintainer channels listed on the project page) so details are not disclosed prematurely.
- Do **not** post **full exploit write-ups** in public issues before maintainers have had reasonable time to respond.

---

## See also

- [GLOSSARY.md](GLOSSARY.md)
- [DUAL_KEY_QUORUM.md](DUAL_KEY_QUORUM.md) — accountability logging for quorum unlock and access (integrator requirement)
- [NFC_PN532_INTEGRATION.md](NFC_PN532_INTEGRATION.md) — optional NFC quorum narrative; not a core USB threat boundary
