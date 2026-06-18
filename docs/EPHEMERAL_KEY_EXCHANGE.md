# Ephemeral Key Exchange (Out-of-Band)

Specification for signed, encrypted BrainpoolP256r1 ephemeral public key offers (`.epk.gpg`)
used with the Galdralag host tool. The offer format is wire-compatible with gr-linux-crypto
(schema version 1). NFC transport is planned; the file format is unchanged when NFC is added.

See also: `docs/EPHEMERAL_SESSION.md` for the on-token `ephemeral-session` wire protocol
(`InitMessage` / `ResponseMessage`). The two protocols are complementary, not identical.

## 1. Purpose and threat model

Long-term static ECDH keys allow an adversary who later obtains the long-term private key to
decrypt recorded traffic. Ephemeral ECDH per session, authenticated by long-term keys, restores
forward secrecy for the link.

Expiry limits the window in which a stolen offer file can be abused. Combined one-time use
(`consumed`) limits replay after a successful session derivation.

This document defines a **host-to-host** envelope for exchanging uncompressed SEC1 ephemeral
public keys out-of-band. It does not replace the Galdralag firmware `ephemeral-session`
token-to-token protocol.

## 2. Key offer format (plaintext JSON)

Plaintext is UTF-8 JSON with the following fields (all required):

| Field | Type | Description |
|-------|------|-------------|
| `schema_version` | integer | Must be `1`. |
| `epk_hex` | string | Lowercase hex of uncompressed SEC1 BrainpoolP256r1 public key (65 bytes = 130 hex chars). |
| `long_term_fingerprint` | string | Lowercase hex GnuPG fingerprint of the issuer long-term signing key. |
| `signature_hex` | string | Lowercase hex of a detached GnuPG binary signature over the raw decoded `epk_hex` bytes (not over the JSON text). |
| `expires_at` | integer | UTC Unix time in seconds; offer is invalid at or after this instant. |
| `created_at` | integer | UTC Unix time in seconds when the offer was created. |
| `session_id` | string | Lowercase hex of 16 random bytes (32 hex chars). |
| `consumed` | boolean | Must be `false` in generated offers; host marks `true` after one successful derivation. |

### Deviation from Galdralag token `InitMessage` signing

The Galdralag-firmware `ephemeral-session` protocol signs
`init_sign_preimage(version, curve_wire_id, epk_bytes)` — a 2-byte prefix followed by the EPK.
See `crates/ephemeral-session/src/protocol.rs`.

This host offer format signs **only** the raw SEC1 EPK bytes with a GnuPG detached signature so
verifiers without the full token handshake stack can check the binding between the long-term key
and the ephemeral public key using any standard GnuPG installation. The two-byte prefix difference
means host offers are **not** directly usable as `InitMessage` payloads on the token, and token
`InitMessage` signatures cannot be verified as host offers. This is a deliberate trade-off in
favour of interoperability with gr-linux-crypto receivers over compatibility with the token wire
format. Both specifications document this difference explicitly.

## 3. Outer envelope (transport)

1. The JSON object is serialized with compact separators (no extra whitespace).
2. The UTF-8 blob is encrypted and signed with GnuPG: `gpg --encrypt --sign --local-user
   <issuer> --recipient <r1> [--recipient <r2> ...]` producing binary OpenPGP data (`.epk.gpg`).

Recipients must hold a GnuPG secret key to decrypt. The embedded OpenPGP signature covers the
plaintext during decryption. The inner `signature_hex` field is verified separately with
`gpg --verify` against the decoded EPK bytes.

## 4. Timestamp semantics

`created_at` and `expires_at` are UTC Unix seconds, carried inside the signed and encrypted
envelope so they cannot be altered without breaking the OpenPGP layer. Clock skew between stations
affects perceived freshness; operators should use NTP. If `expires_at` is in the past at import
or derivation time, the offer is rejected.

## 5. Expiry and consumption enforcement

An offer is valid until the **first** of:

- wall-clock time reaches `expires_at`, or
- a successful `derive_session_keys` call marks it `consumed`, or
- the operator calls `galdra epk expire <session_id> --confirm`.

Both `expires_at` and `consumed` are re-checked at derivation time, not only at import, so the
policy holds across application restarts.

## 6. Private key storage (Galdralag deviation from gr-linux-crypto)

gr-linux-crypto stores the ephemeral private key in the Linux kernel keyring with a `keyctl
timeout` matching `expires_at`. Galdralag uses a different mechanism suited to its existing
infrastructure:

- The BrainpoolP256r1 private scalar (raw 32 bytes) is stored in the `my_private_key_pem` column
  of the `ephemeral_offers` table as a binary BLOB.
- This column is NULL for imported peer offers (Galdralag never holds the peer's private key).
- After `mark_consumed` or `revoke_offer`, the column is set to NULL in-place. This is a
  best-effort zeroise: the underlying SQLite page may remain in the WAL or OS page cache until
  the page is overwritten. For maximum key hygiene, encrypt the database at rest with SQLCipher
  (`GALDRA_DB_KEY` environment variable) and treat `expires_at` as an upper bound on key lifetime.
- The private key is protected by the same access controls as the rest of the galdra-core-host
  database: file system permissions, optional SQLCipher encryption at rest, and the operating
  system process isolation. No additional keyring or hardware protection applies on the host side.
- Zeroisation of the BLOB column after consumption or expiry is on the project roadmap as a
  follow-up, consistent with the general zeroisation philosophy of the vault crate.

## 7. Audit log

Offer lifecycle events are appended to the `audit_log` table as append-only rows with a SHA-256
hash chain. Event types:

| Action wire name | Trigger |
|-----------------|---------|
| `epk_generate` | Offer created with `galdra epk generate`. |
| `epk_import` | Peer offer imported with `galdra epk import`. |
| `epk_derive` | Session keys derived (mark consumed). |
| `epk_reject` | Offer rejected at import (bad schema, expired, consumed, fingerprint mismatch, bad signature) or manually revoked (`manual_revoke` reason). |

The `subject` column holds the `session_id`. The `detail` column holds a compact JSON string
with structured context (session_id, reason, fingerprint, expires_at as applicable).

## 8. CLI subcommands

```
galdra epk generate \
    --gpg-key-id <KEY_ID> \
    --recipient <RECIPIENT> [--recipient <RECIPIENT>...] \
    --expires <SECONDS> \
    --output <FILE.epk.gpg>

galdra epk import <FILE.epk.gpg> \
    --verify-fingerprint <FINGERPRINT>

galdra epk status [--emit json]

galdra epk expire <SESSION_ID> --confirm
```

See `docs/GALDRA-TOOL.md` for full argument documentation.

## 9. Interoperability with gr-linux-crypto

A gr-linux-crypto-generated `.epk.gpg` can be imported by `galdra epk import` if:

1. The GnuPG secret key matching the file's recipients is present in the local GnuPG keyring.
2. The `schema_version` is 1.
3. The `long_term_fingerprint` matches the `--verify-fingerprint` argument.

A Galdralag-generated `.epk.gpg` can be imported by `gr-linux-crypto`'s `EphemeralKeyStore`
under the same conditions.

Cross-import is not supported without a GnuPG installation; direct import of the plaintext JSON
(bypassing GPG) is intentionally not exposed by either tool.

## 10. Planned: NFC transport

The `.epk.gpg` file is intended to be transmitted as opaque bytes over NFC without format
changes. NFC proximity provides an operational supplement; cryptographic assurance remains
OpenPGP sign+encrypt and the inner detached signature over the EPK. See `docs/NFC_PLANNED.md`
for the planned implementation approach.
