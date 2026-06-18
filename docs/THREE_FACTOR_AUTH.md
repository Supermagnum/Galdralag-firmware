# Three-factor authentication model

This document explains how **possession of the token**, **knowledge of the PIN**,
and an **optional biometric pre-gate** fit together in the **Galdralag** threat
model — strictly separating what **this repository implements** from product or
integration goals.

## Table of contents

- [Factors as implemented vs planned](#factors-as-implemented-vs-planned)
- [Threat sketch](#threat-sketch)
- [Relationship to NFC quorum docs](#relationship-to-nfc-quorum-docs)

---

## Factors as implemented vs planned

| Factor | “Something you have / know / are” | In this repository (source today) |
|--------|-----------------------------------|-----------------------------------|
| **Token (USB hardware)** | **Have** — physical device with Baochip-1x, on-chip **RRAM** vault, boot chain | **Yes** — firmware targets the token; vault and OpenPGP backend assume possession of the device. |
| **PIN** | **Know** — user-chosen secret checked on-device | **Yes** — [`pin-policy`](../crates/pin-policy) enforces **monotonic counter increment before compare** and drives lockout / zeroisation policy toward [`ZeroiseController`](../crates/galdr-core/src/hal.rs). Verifier stored via [`VaultPinPolicyRecord`](../crates/vault/src/vault_pin_policy.rs). |
| **Biometric** | **Are** — physiological or behavioural match | **Not implemented** — no `SignedMatchResult`, CBOR wire format, or `galdrad` biometric routes exist in this tree. [BIOMETRIC_API.md](BIOMETRIC_API.md) is a **placeholder** for future design. |

**Claim (accurate for the code that exists):** Stealing **only** the host PC or
**only** a remote copy of the user’s passphrase is **not** enough to perform
on-token private-key operations; the **USB token** and correct **PIN** (within
attempt policy) are required for standard OpenPGP card flows. A **biometric**
would add a **third** independent gate **once** firmware and host integration
define trust, liveness, and session binding — that work is **out of scope** for
current sources.

**Inaccurate if stated without qualification:** Claiming that “no single point of compromise is sufficient” across **all three** factors **including biometrics** — biometric enforcement is **not** in this tree. Do not describe this firmware as a complete three-factor **biometric** token without integration and independent review.

---

## Threat sketch

| Adversary capability | Mitigation (relevant to implemented factors) |
|---------------------|----------------------------------------------|
| **Stolen token, no PIN** | PIN blocks and counter increment; eventually lockout / zeroisation per policy. |
| **Phished PIN, no token** | No access to on-card private ops without CCID token present. |
| **Malware on host** | Cannot extract private blobs via documented normal paths; may still observe **user PIN entry** on the PC **unless** PIN entry is on-device only — entry UX is integration-dependent. |
| **Biometric spoof (future)** | Requires liveness and trusted matcher; **not** specified here. |

---

## Relationship to NFC quorum docs

[NFC_PN532_INTEGRATION.md](NFC_PN532_INTEGRATION.md) discusses **optional NFC**
and high-level **quorum** narratives (presence, Shamir, PIN, biometric) for
**drive unlock** and access control. That file states **NFC is not implemented**
in firmware. Treat it as an **integration guide**, not a description of shipped
behaviour.

---

## See also

- [README — What this firmware is (and is not)](../README.md#what-this-firmware-is-and-is-not)
- [RRAM_LAYOUT.md](RRAM_LAYOUT.md)
- [OPENPGP_CARD.md](OPENPGP_CARD.md)
