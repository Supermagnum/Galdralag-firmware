# NFC Transport — Planned

This document describes the planned NFC transport layer for ephemeral key offer exchange
(`.epk.gpg` files). NFC transport is a future milestone; the offer file format is designed to
be unchanged when NFC is added.

## Status

Not yet implemented. The Galdralag host tool and the gr-linux-crypto reference implementation
both support file-based offer exchange as the primary transport. NFC is planned as an
operational supplement for contactless on-site key exchange.

## Approach

The `.epk.gpg` blob is opaque bytes. NFC transport sends the same bytes without format changes.

| Property | Value |
|----------|-------|
| Offer format | Unchanged: GnuPG sign+encrypt over the schema version 1 JSON body. |
| Cryptographic assurance | Unchanged: OpenPGP outer envelope + inner detached ECDSA signature over the EPK. NFC proximity adds physical channel assurance only; it does not replace cryptographic binding. |
| Host-side library (Linux) | `nfcpy` (Python) for the gr-linux-crypto side; `libnfc` for a C/Rust integration on the Galdralag host. |
| NFC tag type | ISO 14443-4 / NFC Type 4 (PN532 or compatible reader). |
| Payload capacity | NFC Type 4 supports up to approximately 32 KB, which comfortably exceeds expected `.epk.gpg` size (Brainpool EPK + GnuPG framing, typically under 2 KB). |
| Proximity requirement | Approximately 4 cm for ISO 14443. Physical proximity supplements the cryptographic identity binding but does not replace it. |

## Integration point

When NFC transport is added:

1. The sender writes the `.epk.gpg` bytes to an NFC tag or pushes them over an NFC P2P channel.
2. The receiver reads the bytes and passes them directly to `galdra epk import` or equivalent.
3. No format conversion or re-signing is required.

The existing `ephemeral_offers::import_offer` function in `galdra-core-host` is the intended
entry point on the receive side.

## Related hardware

The PN532 NFC reader/writer is documented in `docs/NFC_PN532_INTEGRATION.md`. That document
covers the hardware integration for the biometric sensor path; the NFC transport for ephemeral
offers will reuse the same hardware abstraction.

## See also

- `docs/EPHEMERAL_KEY_EXCHANGE.md` — offer format specification
- `docs/EPHEMERAL_SESSION.md` — on-token ephemeral key protocol
- `docs/NFC_PN532_INTEGRATION.md` — hardware integration notes
