# Key lifecycle (vault and OpenPGP)

This document summarises **how keys are created, stored, used, and destroyed**
as reflected in **`vault`**, **`usb-personality`**, and host tooling — without
inventing product features not present in source.

## Table of contents

- [Generation (on-device TRNG)](#generation-on-device-trng)
- [Import](#import)
- [Export policy](#export-policy)
- [Rotation and deletion](#rotation-and-deletion)
- [Zeroisation](#zeroisation)
- [Shamir recovery (host-orchestrated)](#shamir-recovery-host-orchestrated)

---

## Generation (on-device TRNG)

- OpenPGP **SIG / DEC / AUT** keys are generated through the [`OpenPgpBackend`](../crates/usb-personality/src/openpgp/backend.rs) surface; [`OpenPgpVaultBackend`](../crates/usb-personality/src/openpgp/vault_backend.rs) uses [`HardwareTrng`](../crates/galdr-core/src/hal.rs) and persists **sealed** private blobs at fixed offsets ([`layout`](../crates/vault/src/layout.rs)).
- **Brainpool / Ed25519 / X25519** paths follow [`vault`](../crates/vault/src) crypto helpers; nonces and AEAD wrapping use TRNG where the API requires it (`sealed_key`, ChaCha, etc.).
- **RSA** keys use [`vault_store_rsa_key`](../crates/vault/src/rsa_vault.rs) with ChaCha wrapping and per-slot HKDF labels (`KeyPurpose::RsaKeyWrap`).

> **Hardware caveat:** TRNG quality and side-channel behaviour must be validated
> on silicon per product requirements. See [HARDWARE_VERIFICATION.md](HARDWARE_VERIFICATION.md).

---

## Import

- **Private** OpenPGP key material can be **`GENERATE ASYMMETRIC KEY PAIR`** /
  `PUT KEY` style flows as implemented in the backend (see [`vault_backend.rs`](../crates/usb-personality/src/openpgp/vault_backend.rs) `persist_private_key` paths).
- **Public** keys use [`public_key_vault`](../crates/vault/src/public_key_vault.rs) (`vault_store_public_key_der`, etc.).

Host provisioning details: [GALDRA-TOOL.md](GALDRA-TOOL.md), [OPENPGP_CARD.md](OPENPGP_CARD.md).

---

## Export policy

- **Private** keys and sealed blobs: **not** exported over normal OpenPGP USB
  paths; design intent is **on-card** operations only.
- **Shamir export path (tooling):** host calls that export **32-byte signing
  material** for splitting are **not** connected in the default stub device
  ([`Device::export_signing_key_shamir_material`](../galdra-core-host/src/device.rs)
  returns `DeviceNotConnected` in the placeholder). When wired, this **briefly
  exposes secret material to host RAM** — see [API_REFERENCE.md](API_REFERENCE.md)
  and [future-todo.md](future-todo.md).
- **Public** keys and card outputs permitted by the OpenPGP card specification
  may leave the device per standard behaviour.

---

## Rotation and deletion

- Replacing a key overwrites the same sealed slot when policy allows (`overwrite` flags in vault helpers, OpenPGP `PUT KEY` semantics).
- **Deletion** clears or invalidates slots via vault delete helpers and DO / key-slot management in the OpenPGP stack (see implementation in `usb-personality` and `vault`).

Automated **rotation schedules** are a **host / organisational** concern unless
a future firmware feature defines them.

---

## Zeroisation

- **PIN exhaustion / policy breach:** `pin-policy` may trigger **`ZeroiseController`**
  paths; details depend on integration with boot firmware. See [RRAM_LAYOUT.md](RRAM_LAYOUT.md)
  and the `crates/pin-policy` sources.
- **Manual wipe / factory reset:** product-level flows belong in host tooling and boot policy; not fully enumerated here.

---

## Shamir recovery (host-orchestrated)

[`vault::shamir`](../crates/vault/src/shamir.rs) provides **split** and **recover**
mathematics. [`galdra-core-host/shamir_ops`](../galdra-core-host/src/shamir_ops.rs)
orchestrates **export → split on host** or **recover on host → import**. This is
**not** a purely on-token lifecycle stage.

**Vectors / tests:** `crates/vault/tests/key_lifecycle.rs`, Shamir fuzz targets —
see [TEST_RESULTS.md](TEST_RESULTS.md).

---

## See also

- [OPENPGP_CARD.md](OPENPGP_CARD.md)
- [API_REFERENCE.md](API_REFERENCE.md)
- [EPHEMERAL_SESSION.md](EPHEMERAL_SESSION.md) — long-term vs ephemeral keys for sessions
