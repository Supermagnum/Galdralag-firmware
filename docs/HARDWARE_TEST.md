# Hardware verification (manual)

Automated CI cannot exercise USB CCID against a live host without a Baochip-1x (or compatible) board. Use this checklist when validating OpenPGP over USB on real hardware.

## OpenPGP / CCID over USB

1. Flash firmware. Connect the token to a Linux host via USB-C.
2. `lsusb` — expect `20a0:42b3` (see [OPENPGP_CARD.md](OPENPGP_CARD.md) for the udev rule if permissions fail).
3. `sudo pcsc_scan` — expect a reader entry matching the Galdralag Security Token strings.
4. `gpg --card-status` — expect AID, cardholder, and key slot fields as provisioned.
5. `gpg --card-edit` → admin → generate — key generation completes for the chosen slot.
6. `gpg --encrypt --recipient <card-key-id> test.txt` — produces a valid ciphertext.
7. `gpg --decrypt test.txt.gpg` — plaintext matches the original file.
8. SSH: export the authentication subkey to `authorized_keys`, `ssh` to localhost — login succeeds.

Record firmware revision, host OS, and any failures for regression tracking.
