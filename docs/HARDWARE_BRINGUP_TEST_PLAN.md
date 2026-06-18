# Galdralag Hardware Bring-up Test Plan

Hardware: Baochip-1x (Dabao evaluation board)  
Firmware: Galdralag (`ccid-openpgp` feature, `usb-bao1x`)  
Prerequisites: `pcscd`, `gpg` (GnuPG 2.x), `pcsc-tools`, Nitrokey attached with existing keys

---

## 0. Pre-flight

Before connecting the Galdralag device, confirm the host environment is ready.

```bash
# GnuPG version (2.2.x or 2.4.x required)
gpg --version

# pcscd running
systemctl status pcscd

# pcsc-tools available (for low-level card inspection)
pcsc_scan --version

# List existing keys from Nitrokey (these will be used as encrypt-to targets)
gpg --list-keys
```

Record the key fingerprints from `--list-keys` output. You will use these
as encrypt-to targets in step 5.

---

## 1. Device enumeration

Connect the Galdralag device via USB.

```bash
# Confirm USB device appears
lsusb | grep -i "20a0"
# Expected: Bus ... ID 20a0:42b3 ...

# Confirm pcscd sees the card reader
pcsc_scan
# Expected: Galdralag reader slot, ATR printed, card present

# Kill pcsc_scan with Ctrl+C when confirmed
```

If `lsusb` does not show `20a0:42b3`, stop here — the CCID personality is not
enumerating. Check `dmesg | tail -30` for USB errors.

---

## 2. Basic card status

```bash
gpg --card-status
```

Expected output includes:

- `Reader ...........: Galdralag Security Token`
- `Application ID ...: D276000124...` (OpenPGP AID)
- `Version ..........: 3.4` (or as set in firmware)
- `Manufacturer .....: Galdralag Project`
- `Serial number ....: <device serial>`
- Key slots: `Signature key`, `Encryption key`, `Authentication key` — all showing `[none]` on a fresh device

If any field is missing or the AID is wrong, record the actual output and cross-check
against `crates/usb-personality/src/ccid/mod.rs` constants.

---

## 3. PIN verification

Set **known** User and Admin PINs **before** CCID exercises using the **USB CDC provisioning** path (first boot only, when the device enumerates as a serial interface instead of the CCID token).

From the Galdralag firmware repository:

```bash
cargo run -p host-tools --bin galdralag-provision -- \
  --port /dev/ttyACM0 \
  --user-pin 'your-user-pin' \
  --admin-pin 'your-admin-pin'
```

Omit `--user-pin` / `--admin-pin` to be prompted securely (no echo; `rpassword` — PINs are not placed in shell history). PINs may be up to **32 bytes** each.

**Wire format:** the tool sends **two newline-terminated lines** (user PIN bytes, then admin PIN bytes), matching **xous-core** **`usb-bao1x`**. On Xous, **`usb-bao1x`** writes **PDDB** **`usb.ccid`** (**`OKV1`**, **`user_pin_line`**, **`admin_pin_line`**). If your image includes **`galdralag-service`**, it waits for that sentinel, bridges into **RRAM**, then serves **CCID** via **`usb-bao1x`** ([services/galdralag/README.md](../../services/galdralag/README.md), **`cargo run -p xtask -- build-and-register`**).

When provisioning completes, the device should re-enumerate and present **CCID** / OpenPGP as in step 2. Confirm with:

```bash
gpg --card-status
```

Then change PINs if desired (you now know the current values):

```bash
gpg --card-edit

# At the gpg/card> prompt:
admin
passwd
# Follow prompts to change User PIN and Admin PIN
quit
```

Record any new PINs securely. All subsequent steps require the User PIN.

> **Development shortcut:** Firmware built with **`dev-provisioning`** can instead use **`CCID_USER_PIN`** and **`CCID_ADMIN_PIN`** in the environment before first boot (lab only). Do not use this for production tokens.

---

## 4. Key generation on device

Generate all three key slots on the device. Keys are generated on-device and
private material never leaves the hardware.

```bash
gpg --card-edit

# At the gpg/card> prompt:
admin
generate
# Answer prompts:
#   Make off-card backup? → n (for bring-up; key material stays on device)
#   Key type: RSA or ECC per firmware capability
#   Expiry: 0 (no expiry for testing)
#   Real name, email, comment as desired
#   Confirm with User PIN and Admin PIN when prompted
quit
```

After generation:

```bash
gpg --card-status
```

All three key slots (Signature, Encryption, Authentication) should now show
fingerprints and creation dates.

---

## 5. Signing test

```bash
# Create a test file
echo "Galdralag signing test $(date -u)" > /tmp/galdralag_test.txt

# Sign with the device signature key (will prompt for User PIN)
gpg --card-status  # confirm sig key fingerprint
gpg --armor --detach-sign /tmp/galdralag_test.txt

# Verify the signature
gpg --verify /tmp/galdralag_test.txt.asc /tmp/galdralag_test.txt
```

Expected: `Good signature from ...`

---

## 6. Encryption and decryption test

Use the Nitrokey keys as encrypt-to targets alongside the Galdralag encryption key.

```bash
# List available encrypt-to targets (Nitrokey keys + newly generated Galdralag key)
gpg --list-keys

# Identify:
#   NITROKEY_FPR  — fingerprint of a Nitrokey encryption-capable key
#   GALDRALAG_FPR — fingerprint of the Galdralag encryption key (from --card-status)

# Encrypt to both devices
gpg --armor \
    --recipient <NITROKEY_FPR> \
    --recipient <GALDRALAG_FPR> \
    --encrypt /tmp/galdralag_test.txt

# Decrypt with Galdralag (will prompt for User PIN)
gpg --decrypt /tmp/galdralag_test.gpg
```

Expected: plaintext output matching `/tmp/galdralag_test.txt`.

Optionally verify Nitrokey can also decrypt the same file (cross-device
encrypt-to test).

---

## 7. Authentication / SSH test

```bash
# Enable SSH support in gpg-agent if not already set
echo "enable-ssh-support" >> ~/.gnupg/gpg-agent.conf
gpg-connect-agent reloadagent /bye

# Export the SSH public key from the device authentication slot
gpg --export-ssh-key <GALDRALAG_FPR>
```

Add the exported public key to `~/.ssh/authorized_keys` on a test target and
attempt an SSH login:

```bash
SSH_AUTH_SOCK=$(gpgconf --list-dirs agent-ssh-socket) ssh <user>@<test-host>
```

Expected: SSH authentication prompt handled by gpg-agent, User PIN requested,
login succeeds.

---

## 8. USB reset / reconnect

Test that the device recovers cleanly from a USB reset.

```bash
# Disconnect and reconnect the USB cable, then:
gpg --card-status
```

Expected: card status returns cleanly. Check `dmesg` for any USB error messages
during reconnect.

Also test `force_reset` path:

```bash
gpg-connect-agent "scd reset" /bye
gpg --card-status
```

Expected: card re-enumerates, all key slots still present.

---

## 9. RRAM layout verification

After first boot and key generation, confirm the vault data is within the
expected RRAM span documented in `docs/RRAM_LAYOUT.md`.

This is a manual check — compare the authoritative Baochip-1x memory map
against the layout table in `docs/RRAM_LAYOUT.md`. Confirm:

- OpenPGP DO store starts at logical offset 67,072
- Master record at 75,376 (36 bytes, `OGMK` + salt)
- PIN provision slots `PNU1` / `PNA1` cleared after first boot
- Exclusive end at 75,486
- No overlap with sealed-key region (ends at 66,071)
- No overlap with any platform-reserved region above 75,486

Sign off in `docs/RRAM_LAYOUT.md` under the Platform reconciliation section
once confirmed.

---

## 10. Zeroisation (hardware)

Trigger zeroisation and confirm the device responds correctly.
See `docs/HARDWARE_VERIFICATION.md` for the full procedure.

```bash
# Attempt PIN block (enter wrong User PIN 3 times)
# Then verify the device reports blocked state
gpg --card-status
```

Expected: `PIN blocked` or equivalent in card status output.
After zeroisation, all key slots should report `[none]`.

---

## 11. Results record

Update `docs/TEST_RESULTS.md` with:

- Hardware bring-up date
- Firmware commit hash
- Results of each section above (PASS / FAIL / SKIP + notes)
- `gpg --card-status` full output (copy-paste)
- Any unexpected behaviour and `dmesg` excerpts if relevant

---

## Known pre-production gaps (do not treat as test failures)

- **Operator PIN UX:** TRNG-generated first-boot PINs are not displayed on device.
  Workaround for bring-up: use `gpg --card-edit` → `passwd` after provisioning.
  See `docs/future-todo.md` section 0.
- **Zeroisation:** Hardware verification (section 10) supersedes the simulation
  results in `docs/TEST_RESULTS.md` section 11.
- **Optional dudect integrations:** `challenge-response HMAC`, `PSRAM tag check`,
  `XMSS/LMS verify` remain `[MISSING]` until those paths are wired.
