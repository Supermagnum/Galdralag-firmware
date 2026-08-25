# Dual-hardware-key (two-token) quorum authorization

## Scope

This document describes an **extension pattern** for building **two-hardware-key**
(or **N-hardware-key**) authorization on top of Galdralag primitives. It is a
**design guide for integrators**, not a description of shipped firmware behaviour.

**Neither this firmware nor the current Galdra host tools enforce a quorum.** There
is no runtime path that blocks a critical operation until two separate physical
tokens have been authenticated together in the same session. Enforcing
"two tokens required" (or any K-of-N **presence** policy) is intentionally **out
of scope** for the token firmware and left to **downstream systems** — LUKS unlock
wrappers, door or access-control panels, custom daemons, HSM-style policy engines,
or other consumers of Galdralag credentials.

Galdralag's role in such a scheme is limited to acting as **one of two or more
credential sources**: for example holding or exporting **one Shamir share**, or
performing **one independent OpenPGP card authentication**. The integrator owns
quorum policy, session windows, reconstruction environment, and audit.

This is **not a roadmap commitment**. The pattern is **possible today** using
existing library and tooling primitives; orchestration and enforcement remain the
integrator's responsibility.

---

## Table of contents

- [Responsibility boundary](#responsibility-boundary)
- [Reference pattern: Shamir 2-of-N with separate tokens](#reference-pattern-shamir-2-of-n-with-separate-tokens)
- [Illustrative integration points (examples only)](#illustrative-integration-points-examples-only)
- [Security considerations for downstream systems](#security-considerations-for-downstream-systems)
- [Implementing quorum logic: Rust and memory-safe languages](#implementing-quorum-logic-rust-and-memory-safe-languages)
- [Explicit non-goals](#explicit-non-goals)
- [See also](#see-also)

---

## Responsibility boundary

### What Galdralag provides

| Capability | Where | Notes |
|------------|-------|-------|
| **Shamir K-of-N mathematics** | [`crates/vault/src/shamir.rs`](../crates/vault/src/shamir.rs) via [`vsss-rs`](https://crates.io/crates/vsss-rs) (GF(256)) | Arbitrary `(K, N)` within documented bounds; split and recover are library functions |
| **Profile-attached Shamir metadata** | [`ShamirConfig`](../crates/cipher-profile/src/shamir_cfg.rs) in [`cipher-profile`](../crates/cipher-profile/) | Built-in `conservative-shamir` is **3-of-5**; custom profiles may set e.g. **2-of-3** ([CIPHER_PROFILES.md](CIPHER_PROFILES.md)) |
| **Host split / recover orchestration** | [`galdra-core-host/src/shamir_ops.rs`](../galdra-core-host/src/shamir_ops.rs), `galdra shamir` CLI | Export key from **one** token, split or recover on **host**, write/read `.galdra-share` files; import recovered material to **one** token |
| **Single-token OpenPGP authentication** | OpenPGP card over CCID ([OPENPGP_CARD.md](OPENPGP_CARD.md)) | One token + PIN for sign/decrypt/authenticate; standard smart-card stack |
| **Per-token PIN policy** | [`pin-policy`](../crates/pin-policy/) | Attempt limits, monotonic counter before compare, lockout toward zeroisation |

### What a downstream system must implement

| Requirement | Why Galdralag does not do this |
|-------------|--------------------------------|
| **Quorum enforcement** | Firmware exposes credentials and crypto primitives; it does not decide when a door opens or a volume mounts |
| **Session / time windows** | Combining two authentications "within 60 seconds" or "same operator session" is product policy on the consumer |
| **Secure reconstruction environment** | Host `shamir_ops` runs wherever the integrator invokes it; air-gap and network isolation are not token responsibilities |
| **Binding a share to a physical token** | Exported shares are files; proving share *i* came from token *A* (not a forged host copy) requires integrator-side attestation, fingerprints, and procedural controls |
| **Partial-quorum and replay handling** | What happens when only one of two holders appears, or the same share is replayed, is consumer logic |
| **Audit logging for privileged actions** | Token audit hooks may exist in design; **quorum unlock events** (who, when, which shares) belong on the system that acts on the secret |

---

## Reference pattern: Shamir 2-of-N with separate tokens

This section walks through a **2-of-3** example using **existing** Galdra and
vault primitives. Threshold and share count are integrator choices; **K = 2** is
common for "two people must cooperate" policies.

### Setup (provisioning)

1. **Define a profile** with Shamir enabled, e.g. `galdra profile add team-luks --shamir-threshold 2 --shamir-total 3` (see [CIPHER_PROFILES.md](CIPHER_PROFILES.md)).
2. **Generate or import** the long-term signing key on **token A** (slot 0).
3. On token A (unlocked), run **`galdra shamir split`** with that profile. The host exports key material once, runs `shamir_split` ([`shamir_ops.rs`](../galdra-core-host/src/shamir_ops.rs)), and writes **three** armoured share files.
4. **Distribute shares** to three custodians (people, sites, or **separate tokens**). Operational best practice: **one share per token or offline medium**, not all shares on one laptop.
5. **Destroy or re-key** the full secret on token A if policy requires that no single device retains the whole key after split (integrator procedure; not automated by firmware today).

For a **two-token** mental model: custodian 1 holds share 1 (e.g. on token A), custodian 2 holds share 2 (e.g. on token B). Custodian 3 holds a backup share offline.

### Unlock or recovery (downstream system)

Reconstruction **must not** be assumed to run on either token. Typical flow:

1. **Collect K share files** (or read K shares from K tokens via your own export protocol) on a **controlled host** or **air-gapped** machine.
2. Run **`galdra shamir recover`** (or call `shamir_recover` from [`vault::shamir`](../crates/vault/src/shamir.rs) in your daemon) with **at least K** shares. The downstream system verifies:
   - Share headers agree on **profile**, **threshold**, **total**, and **key fingerprint**.
   - **K** distinct share **indices** are present (no duplicates).
   - Shares match the expected **fingerprint** for this volume or policy.
3. Use the reconstructed **32-byte secret** only in memory ([`zeroize`](https://crates.io/crates/zeroize) or equivalent), then:
   - Pass to **LUKS** / `cryptsetup` activation, or
   - Derive subkeys with **HKDF** per your policy, or
   - Authorize a **one-time door credential** — whatever the consumer defines.
4. **Zeroise** reconstructed material immediately after use.

**Important:** Current `galdra shamir recover` imports into **one** token slot. A
**disk-unlock daemon** would more often call `shamir_recover` and use the bytes
directly without re-importing to a token. That daemon is **integrator code**, not
part of this repository.

### Two tokens without Shamir (dual authentication)

An alternative pattern does **not** reconstruct a shared secret on the host:

- **Token A** performs OpenPGP **SIGN** over a challenge (holder 1 + PIN).
- **Token B** performs a **second** independent **SIGN** (holder 2 + PIN) within a time window.
- The **downstream controller** unlocks only if **both** signatures verify and policy matches (different key IDs, different operators, etc.).

Galdralag provides **single-token** OpenPGP auth per connection. A panel or daemon must **orchestrate two CCID sessions** (two USB devices or sequential sessions) and apply quorum rules itself. See [Illustrative integration points](#illustrative-integration-points-examples-only).

---

## Illustrative integration points (examples only)

The following are **not shipped features**. They show where an integrator would
attach quorum logic.

### LUKS / disk unlock with two share-holders

- Volume encrypted with a random master key; master key split **2-of-3** via Galdra split workflow ([KEY_LIFECYCLE.md — Shamir recovery](KEY_LIFECYCLE.md#shamir-recovery-host-orchestrated)).
- At boot, **`galdra-unlock`**-style daemon (integrator-written) prompts for **two** share files or two token-assisted exports, reconstructs on an **offline** or **minimal** initramfs environment, calls `cryptsetup activate`, zeroises key material.
- Planned shape appears in [future-todo.md](future-todo.md) (`provision-luks`, `--shamir-k`); **not implemented** in this tree.

### Door / gate controller with two CCID or NFC authentications

- Panel runs a long-lived service; on access request, requires **token tap or insert** from **guard A** and **guard B** within **T** seconds.
- Each tap: OpenPGP **VERIFY PIN** + **SIGN** challenge or present a **Shamir share** record bound to that token's fingerprint.
- Panel verifies quorum, then pulses strike / sends unlock credential.
- **NFC** transport and panel software are **design-only** today ([NFC_PN532_INTEGRATION.md](NFC_PN532_INTEGRATION.md)); firmware does not implement NFC or door logic.

### Custom daemon gating a privileged action

- Privileged action (e.g. release signing key for one operation, approve config change) requires:
  - `K` successful **`pcsc`** / OpenPGP authentications from **distinct** tokens, or
  - `K` Shamir shares + optional PIN on each token export path.
- Daemon holds **no** long-term secret; it only verifies quorum and emits an short-lived capability token.

---

## Security considerations for downstream systems

### Where reconstruction should happen

- **Prefer air-gapped or single-purpose machines** for combining shares that unlock bulk data or physical access.
- **Avoid network-facing hosts** that also browse the web or run untrusted code while holding **K** shares in memory.
- **Initramfs / early boot** unlock environments should minimise attack surface; treat reconstructed keys like LUKS master keys (short lifetime, immediate zeroisation).

### Proving a share came from the claimed token

Exported `.galdra-share` files include a **key fingerprint** in the armour header
([`ShamirShareExport`](../galdra-core-host/src/shamir_ops.rs)). A compromised host
could forge share **files** unless the downstream system also:

- Requires **on-token export** with PIN and logs token **serial** / OpenPGP fingerprint at export time.
- Wraps each share for a specific recipient (OpenPGP encrypt share file to custodian key).
- Uses ** procedural controls** (split ceremonies, witness logs) for high-assurance deployments.

Firmware does **not** today provide a signed attestation "share 2 was exported from
serial X" over CCID for Shamir export (host tooling maturity varies; see
[KEY_LIFECYCLE.md](KEY_LIFECYCLE.md)).

### Replay and partial quorum

| Situation | Downstream behaviour (integrator-defined) |
|-----------|-------------------------------------------|
| Only **K − 1** shares presented | **Fail closed**; do not cache partial progress in a way that lowers threshold later without policy |
| Same share presented twice | Reject duplicate indices (`shamir_recover` already rejects duplicate indices in [`vault::shamir`](../crates/vault/src/shamir.rs)) |
| Stale unlock session | Expire challenges; require fresh PIN verify on each token per operation |
| One token withdrawn mid-ceremony | Abort; do not issue half-authorised credentials |

### Audit logging

The **downstream system** should log: timestamp, action requested, quorum satisfied
(yes/no), **identities** (OpenPGP key IDs or operator IDs), share indices used
(not share **values**), and failure reasons. Token firmware audit trails, where
present, complement but do not replace consumer-side logs for door or volume events.

Align consumer threat modelling with [THREAT_MODEL.md](THREAT_MODEL.md) (e.g. **T11**
/ **T12** for Shamir share theft thresholds).

---

## Implementing quorum logic: Rust and memory-safe languages

Quorum enforcement code handles **PINs**, **share bytes**, and **reconstructed
master keys** in process memory. That code should live in a **memory-safe**
language with explicit secret zeroisation, not in ad hoc shell scripts.

### Rust crates useful to integrators

| Crate / area | Role in quorum systems |
|--------------|------------------------|
| [`vsss-rs`](https://crates.io/crates/vsss-rs) | Same Shamir GF(256) family as [`vault::shamir`](../crates/vault/src/shamir.rs); can be used standalone on the consumer if you do not link `galdr-vault` |
| [`galdr-vault`](../crates/vault/) / `shamir_recover` | Reuse project-tested split/recover and error handling |
| [`zeroize`](https://crates.io/crates/zeroize) | Clear sensitive buffers on drop (already used in `shamir_ops` and vault) |
| [`pcsc`](https://crates.io/crates/pcsc) | PC/SC access for **multiple** CCID tokens in one daemon |
| [`libcryptsetup-rs`](https://crates.io/crates/libcryptsetup-rs) | LUKS activate after reconstruct (evaluate API stability for your distro) |
| [`subtle`](https://crates.io/crates/subtle) | Constant-time comparisons where needed |
| [`ed25519-dalek`](https://crates.io/crates/ed25519-dalek) / [`p256`](https://crates.io/crates/p256) | Verify OpenPGP or custom challenge signatures from each token |

Evaluate **maintenance status** and **supply chain** for any crate before production;
pin versions in lockfiles.

### Why memory-safe languages matter here

- **Buffer overflows and use-after-free** in C/C++ unlock daemons can leak **K**
  shares or reconstructed keys from memory — defeating the purpose of splitting.
- **Secret lifetime** is easier to reason about with **`Zeroizing`/`zeroize`** and
  ownership discipline than with manual `memset` that compilers may optimise away.
- **Concurrency bugs** (two threads handling shares from two tokens) are a common
  source of accidental logging or double-fetch; Rust's type system reduces but does
  not eliminate logic errors — tests and fuzzing still required.

C integrators wrapping **libnfc** or **libcryptsetup** should isolate FFI boundaries
and minimise time secrets spend in C stacks; Rust orchestration with small C shims
is a common pattern ([NFC_PN532_INTEGRATION.md](NFC_PN532_INTEGRATION.md) discusses
libnfc FFI).

---

## Explicit non-goals

- **This firmware does not enforce dual-key or M-of-N physical presence** for
  OpenPGP sign/decrypt, door unlock, or drive unlock.
- **NFC / PN532 / door panels** are not implemented; see
  [NFC_PN532_INTEGRATION.md](NFC_PN532_INTEGRATION.md) (design guide only).
- **Biometric third factor** is not wired end-to-end; see
  [THREE_FACTOR_AUTH.md](THREE_FACTOR_AUTH.md) and [BIOMETRIC_API.md](BIOMETRIC_API.md).
- **No claim** that `gpg`, `scdaemon`, or standard OpenPGP card workflows invoke
  quorum logic automatically.
- **No claim** that passing tests or this document constitutes production readiness
  for organisational dual-control policies; independent review of the **whole**
  system (tokens + consumer + procedures) is required.

---

## See also

- [KEY_LIFECYCLE.md](KEY_LIFECYCLE.md) — Shamir export/import lifecycle (host-orchestrated)
- [CIPHER_PROFILES.md](CIPHER_PROFILES.md) — `ShamirConfig`, built-in profiles, `galdra shamir` commands
- [THREAT_MODEL.md](THREAT_MODEL.md) — assets, Shamir share theft (**T11**, **T12**), NFC narrative boundary
- [README — Shamir secret sharing and drive encryption](../README.md#shamir-secret-sharing-and-drive-encryption)
- [README — Standards vs. firmware-specific features](../README.md#standards-vs-firmware-specific-features)
- [NFC_PN532_INTEGRATION.md](NFC_PN532_INTEGRATION.md) — optional NFC + quorum **narrative** (not firmware)
- [GLOSSARY.md — Shamir](GLOSSARY.md) — plain-language K-of-N definition
