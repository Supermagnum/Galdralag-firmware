# Audit logging and profile audit records

This document describes **what the repository implements today** for **security
audit trails** (cipher profile metadata and OpenPGP-side hooks) versus a
hypothetical **persistent on-device audit log**.

## Table of contents

- [Profile audit record (host- or tool-facing text)](#profile-audit-record-host--or-tool-facing-text)
- [OpenPGP backend audit hook](#openpgp-backend-audit-hook)
- [Persistent RRAM audit log](#persistent-rram-audit-log)
- [Retention and host retrieval](#retention-and-host-retrieval)

---

## Profile audit record (host- or tool-facing text)

The [`cipher-profile`](../crates/cipher-profile/src/audit.rs) crate defines
[`ProfileAuditRecord`](../crates/cipher-profile/src/audit.rs): profile name,
curve label, ordered cipher layer names, Shamir `k`/`n`, and a caller-supplied
**Unix timestamp** (RTC or host clock — **not** defined by firmware here).

[`ProfileAuditRecord::to_audit_string`](../crates/cipher-profile/src/audit.rs)
builds a **compact JSON-like ASCII** string for logging. This is suitable for
**host-side logs**, export, or future vault persistence; the format is **not**
standardised outside this repository.

**Cipher profile selection in audit trail:** Marketing-style statements in the
main README imply every profile selection is **logged**. In source, the **data
structure** for that statement exists (`ProfileAuditRecord`); **automatic append
of each selection to RRAM** is **not** implemented in this tree.

---

## OpenPGP backend audit hook

[`OpenPgpAudit`](../crates/usb-personality/src/openpgp/backend.rs) requires
`log_event(&mut self, code: u32)`.

The [`OpenPgpVaultBackend`](../crates/usb-personality/src/openpgp/vault_backend.rs)
implementation **XORs** event codes into an **in-RAM `u32` accumulator** (see
`self.audit ^= code`). That value is **not** described as written to `VaultStorage`
in the same file.

[`NullAudit`](../crates/usb-personality/src/openpgp/backend.rs) is a **no-op**
sink for bring-up.

---

## Persistent RRAM audit log

> **Status:** Not yet implemented — design specification only.

There is **no** append-only **RRAM audit region** with documented entry format,
rotation, or cryptographic sealing in this repository. Future work would need:
event type enum, payload encoding, monotonic entry index, and tamper-evidence
policy — **none** of which are specified in code reviewed for this document.

---

## Retention and host retrieval

Until a persistently stored log exists, **retention** is whatever the **host**
keeps when tools record `ProfileAuditRecord` strings or other telemetry.

**Host retrieval:** No CCID command in documented OpenPGP paths in this repo
exports a device audit log. [`galdrad`](../galdrad) routes may be extended in
future; see [API_REFERENCE.md](API_REFERENCE.md).

**Downgrade / profile forcing:** See [CIPHER_PROFILE_SECURITY.md](CIPHER_PROFILE_SECURITY.md)
for profile selection threats and mitigations at the protocol and policy layer.

---

## See also

- [CIPHER_PROFILES.md](CIPHER_PROFILES.md)
- [RRAM_LAYOUT.md](RRAM_LAYOUT.md)
- [future-todo.md](future-todo.md)
