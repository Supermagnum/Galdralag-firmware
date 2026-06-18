# Biometric pre-gate API

> **Status:** Not yet implemented — design specification only. There is **no** Rust
> implementation of the flows below in this repository as of this document revision.

## Overview

This document specifies a future **biometric pre-gate**: optional **“something you
are”** verification **before** or **together with** PIN-gated operations, using
**open, pluggable** matchers (finger-vein or **sweet platform** full-hand modalities).

Biometric enrollment templates are stored **encrypted in the token's on-chip RRAM
vault**. The token is the single root of trust for both cryptographic key material
and biometric enrollment. Templates never leave the token in plaintext. `galdrad`
requests an encrypted template from the token at authentication time, forwards it to
the biometric device for matching, and the device discards it after the match result
is produced.

| Deployment | Per-person storage | Max persons |
|------------|-------------------|-------------|
| Finger vein only (left + right index, 3 samples each) | ~3.5 KB | ~1,150 |
| Full hand — sweet platform (palm vein + palmprint + 4× finger veins, 3 samples each) | ~15.5 KB | ~260 |
| Personal token (1–5 persons, either backend) | trivial | no constraint |

See [THREE_FACTOR_AUTH.md](THREE_FACTOR_AUTH.md) for how this fits the overall
factor model, [RRAM_LAYOUT.md](RRAM_LAYOUT.md) for on-chip layout sketches, and
[NFC_PN532_INTEGRATION.md](NFC_PN532_INTEGRATION.md) for optional NFC quorum
narrative (not implemented as firmware NFC).

**As of the current repository:** There is **no** Rust module implementing
`SignedMatchResult`, **CBOR** payloads, **Ed25519**-signed match attestations,
`galdrad` routes, or `galdra biometric` subcommands. Integration with
[`MonotonicCounter`](https://github.com/Supermagnum/Galdralag-firmware/blob/main/crates/galdr-core/src/hal.rs)
and [`VaultStorage`](https://github.com/Supermagnum/Galdralag-firmware/blob/main/crates/galdr-core/src/hal.rs)
for **session tokens** and template storage is **unspecified in code**.

---

## Threat model

### What this does not add

**Template confidentiality is hardware-rooted.** Templates are stored encrypted in
RRAM and never leave the token in plaintext. A host compromise exposes neither
templates nor keys. The remaining host-side risk is the `galdrad` process
integrity (see [What this does not protect against](#what-this-does-not-protect-against)).

---

## Architecture

```text
┌─────────────────────────────────┐
│  Biometric device               │
│  (finger vein OR sweet)         │
│                                 │
│  1. Capture live image(s)       │
│  2. Extract live template       │
│  3. Receive encrypted reference │
│     template from galdrad       │
│  4. Match live vs reference     │
│  5. Sign result with device     │
│     Ed25519 private key         │
│  6. Return SignedMatchResult    │
│  7. Discard reference template  │
└──────┬───────────────┬──────────┘
       │ USB           │ USB
       │ (result)      │ (encrypted template, from galdrad)
       ▼               │
┌─────────────────────────────────┐
│  galdrad (host daemon)          │
│                                 │
│  1. Issue nonce to device       │
│  2. Request encrypted template  │
│     from token vault (CCID)     │
│  3. Forward encrypted template  │
│     to biometric device         │
│  4. Receive SignedMatchResult   │
│  5. Verify device signature     │
│     against provisioned pubkey  │
│  6. Check score >= threshold    │
│  7. Check liveness flag set     │
│  8. Check nonce matches         │
│  9. If all pass: forward PIN    │
│     APDU + session token        │
│     Else: reject, log, wait     │
└───────────────┬─────────────────┘
                │ USB CCID
                ▼
┌─────────────────────────────────┐
│  Galdralag token (RRAM vault)   │
│                                 │
│  - Stores encrypted biometric   │
│    templates in RRAM            │
│  - Serves encrypted template    │
│    to galdrad on request        │
│  - Verifies session token       │
│  - Accepts PIN APDU only after  │
│    valid session token present  │
│  - Normal OpenPGP card ops      │
└─────────────────────────────────┘
```

---

## Enrollment

Enrollment captures multiple samples (default: 3 per finger or hand position) and
builds a reference template. The template is encrypted on the token using a vault
key that never leaves the device, then stored in the token's RRAM vault. `galdrad`
does not retain a copy. The token is the sole authoritative store for biometric
enrollment.

```bash
# Design-target commands (not implemented in this repository yet)
galdra biometric provision --help
galdra biometric enroll --help
```

**RRAM storage per enrolled person:**

| Backend | Storage per person (3 samples) |
|---------|----------------------------------|
| Finger vein (left + right index) | ~3.5 KB |
| sweet platform (full hand) | ~15.5 KB |

With ~4,035 KB available after non-biometric vault usage, the token can hold
approximately 260 persons (sweet) to 1,150 persons (finger vein only). For personal
or small-team use the storage constraint is not meaningful.

---

## RRAM storage

Biometric templates and provisioning data are stored in the token's on-chip RRAM.
The **4 MiB (4,194,304 bytes)** RRAM is partitioned between the general vault
(cryptographic keys, PIN state, Shamir shares, audit log, cipher profiles,
monotonic counters) and the biometric region.

**Estimated allocation:**

| Region | Estimated size |
|--------|---------------|
| Non-biometric vault (keys, PIN, Shamir, log, profiles, counters) | ~61 KB |
| Biometric device trust anchors (per provisioned device) | ~64 B each |
| Biometric session HMAC key | 32 B |
| Biometric template storage | remaining ~4,035 KB |

**Template encryption:** Each template is encrypted with AES-256-GCM using a
per-user key derived via HKDF from the token's master vault key. The master key
never leaves the token. The encrypted blob is what lives in RRAM and what `galdrad`
forwards to the biometric device at authentication time.

**Wear:** Template storage is written only during enrollment and re-enrollment —
infrequent operations. Authentication does not write to the template region. RRAM
endurance for the template region is not a practical concern. Regions subject to
frequent writes (PIN counter, audit log) should use wear-aware storage strategies; see
[RRAM_LAYOUT.md](RRAM_LAYOUT.md).

---

## Liveness and anti-spoof requirements

---

## Provisioning

### What provisioning stores

- In **token RRAM vault**: device Ed25519 public key (32 bytes), backend type,
  threshold, liveness requirement, modality list, and biometric session HMAC key.
  The token is the authoritative store for all provisioning data.
- In **`galdrad` runtime config** (non-persistent cache): a copy of the device
  public key and policy loaded from the token at startup, used to avoid repeated
  CCID round-trips during authentication.

---

## What this does not protect against

- **Compromised `galdrad` binary or process:** Malware on the host could tamper
  with verification logic, relay attacks, or UI—mitigations are host integrity and
  optional remote attestation (out of scope here).
- **Malicious or cloned biometric device:** Provisioning must bind a specific device
  public key on-token; see provisioning section above.

---

## References

- [THREE_FACTOR_AUTH.md](THREE_FACTOR_AUTH.md)
- [RRAM_LAYOUT.md](RRAM_LAYOUT.md)
- [future-todo.md](future-todo.md)
