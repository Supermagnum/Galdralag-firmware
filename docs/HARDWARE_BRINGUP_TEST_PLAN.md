# Galdralag Hardware Bring-up Test Plan

Hardware: Baochip-1x (Dabao evaluation board)  
Firmware: Galdralag (`ccid-openpgp` feature, `usb-bao1x`)  
Prerequisites: `pcscd`, `gpg` (GnuPG 2.x), `pcsc-tools`, Nitrokey attached with existing keys

This plan assumes the board already runs a **bootable Xous** image that includes **`ccid-openpgp`** / **`usb-bao1x`**. If you still need to program the chip, start with **Flash firmware** and **Sign firmware** below.

---

## Flash firmware (Dabao / Baochip-1x)

Programming is platform-defined. For **eval hardware**, follow the **dabao** board repo ([baochip/dabao](https://github.com/baochip/dabao)) and silicon/integration notes ([Supermagnum/Baochip-1x-firmware](https://github.com/Supermagnum/Baochip-1x-firmware)).

### UF2 via boot1 (usual Xous path)

Authoritative steps and pin names are in **[Getting Started with Baochip Targets](https://github.com/betrusted-io/xous-core/blob/dev/README-baochip.md)** (`README-baochip.md` in **xous-core**). Summary:

1. **Build or obtain** three UF2 artifacts **`loader.uf2`**, **`xous.uf2`**, and **`apps.uf2`** from an **in-tree** `cargo xtask ...` build for your target (e.g. `dabao`). Paths are under `target/riscv32imac-unknown-xous-elf/release/` (or the **none**-elf variant your recipe uses); see upstream for the exact `xtask` invocation.
2. **Hold `PROG`** (button closest to the USB connector on **dabao**) **while** connecting USB so the device enumerates as a mass-storage volume labelled **`BAOCHIP`**. If your board revision uses a different switch label (e.g. **SW2**), match the **dabao** schematic.
3. Copy **`loader.uf2`**, **`xous.uf2`**, and **`apps.uf2`** onto the volume. For a **first** full programming, keep all three at the **same revision**. Later, if loader and kernel are unchanged, many workflows only replace **`apps.uf2`**.
4. Run **`sync`** or cleanly **unmount/eject** the volume so writes complete.
5. Press **`PROG`** again to exit the bootloader and run the flashed image.

**Committing staged UF2 without the physical boot button:** After the three files are on **`BAOCHIP`**, you can press the physical **boot** button **or** type **`boot`** on the **boot1** USB serial console (**1 000 000 baud**, 8N1). The console session drops when the device reboots; that is expected. This is separate from **PROG** + power-up for mass-storage mode. Details: [Flashing](../README.md#flashing) in the repo README.

**Bootloader-only updates** (e.g. `boot1-alt` then `boot1`) use the **`ALTCHIP`** flow documented in `README-baochip.md`; follow that section exactly when updating **boot1**.

### Relation to this repository

- **`cargo run -p xtask -- build-fw`** here builds **library** crates for `riscv32imac-unknown-none-elf`; it does **not** emit a single ready-to-flash system UF2 by itself.
- A full token image is produced in your **xous-core** checkout when you build the **`dabao`** (or product) target with **`ccid-openpgp`** enabled as required for this test plan.
- To register **`galdralag-service`** artifacts with **baosec** after you have a build: **`cargo run -p xtask -- build-and-register release`** (see [services/galdralag/README.md](../services/galdralag/README.md)).

---

## Sign firmware (Ed25519, boot0 / boot1)

Shippable **Baochip-1x** stages carry **Ed25519** signatures and a **key manifest** inside the image. **boot0** (ROM) verifies **boot1** before it runs; downstream UF2 application loading continues that signed-chain model. Full security-model text: [README-baochip.md security model](https://github.com/betrusted-io/xous-core/blob/dev/README-baochip.md#security-model).

**What operators usually do**

- Use an **in-tree** **`cargo xtask`** build in **[betrusted-io/xous-core](https://github.com/betrusted-io/xous-core)** so signing and header layout match what the ROM and **boot1** expect. The build pipeline embeds signatures in the firmware blob; you do not normally attach a separate OpenPGP **`.asc`** file next to a **`.uf2`** unless your distribution tooling explicitly defines that format.
- For **lab / developer** images, parts ship with a **developer** key slot whose public half is published under **`devkey/`** in xous-core ([`devkey/README.md`](https://github.com/betrusted-io/xous-core/blob/dev/devkey/README.md)). The corresponding private key is intentionally public for development; using it triggers **developer** device handling (factory secrets cleared per upstream policy). **Do not** treat developer-signed images as shipping candidates.
- **Production** signing uses **code deployment** / **beta** (or your **third-party**) keys burned or manifested for your lot; those private keys are **not** in this repo. Coordinate key roles with Baochip / your supply process.

**GnuPG / OpenPGP**

Host **GnuPG** with an **Ed25519** signing subkey can still be part of a **release process** (checksum manifests, tarball signing, CI attestation). The on-chip verifier, however, checks **Ed25519** over the **Baochip image layout**, not OpenPGP packets. Conceptual overview: [Signed firmware (Ed25519, boot0)](../README.md#signed-firmware-ed25519-boot0).

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

## 10. Manual PIN lockout verification

This section verifies that failed User PIN attempts are counted **before** the
PIN comparison, that the counter **persists across power loss** (RRAM flush via
the Xous PDDB layer), that lockout fires at the configured threshold, that key
material is **destroyed** (not merely blocked), and that the device can be
returned to a clean state after the test.

**This test is not automatable without physical hardware.** It must be performed
manually on a real flashed Baochip-1x device. Simulation and host-side unit
tests do not substitute for it.

**Warning:** This test **permanently destroys** on-device key material. Use
**test keys only** — never keys protecting real data.

**Power-cycle between attempts is essential.** After each deliberate wrong PIN,
unplug and replug the device (full USB power removal) before the next attempt.
This specifically exercises RRAM write durability through the Xous PDDB layer,
not only the in-memory firmware logic. If the retry counter **resets** after
power-cycle, that indicates a **Xous PDDB write ordering** issue, not necessarily
a bug in Galdralag firmware itself. Report such failures to the **xous-core**
team at [betrusted-io/xous-core](https://github.com/betrusted-io/xous-core).

Repeat the full sequence below for **each** configured PIN attempt threshold:
**3**, **5**, **7**, and **10**. Each run requires a **fresh** flash and
first-boot provision so the threshold is written at provision time (default
**3** when using `galdralag-provision` alone; for **5**, **7**, or **10**, use
the provision path that persists `max_pin_attempts` — see
[PIN attempt policy](GALDRA-TOOL.md#pin-attempt-policy) in `docs/GALDRA-TOOL.md`).

### 10.1. Provision and baseline crypto check

1. Flash firmware per **Flash firmware** above.
2. Complete first-boot PIN provisioning via `galdralag-provision` (section 3):

   ```bash
   cargo run -p host-tools --bin galdralag-provision -- \
     --port /dev/ttyACM0 \
     --user-pin 'your-test-user-pin' \
     --admin-pin 'your-test-admin-pin'
   ```

3. Confirm CCID enumeration (`gpg --card-status`).
4. Generate on-device keys (section 4).
5. Encrypt a test payload and decrypt it successfully (section 6) to confirm
   the device is working **before** lockout testing. Retain the encrypted file
   (e.g. `/tmp/galdralag_lockout_test.gpg`) for step 10.4.

Record the User PIN retry count from `gpg --card-status` (PW1 retries remaining).

### 10.2. Wrong PIN with power-cycle persistence

For each wrong attempt (one at a time, up to threshold − 1):

1. Trigger a User PIN prompt with a deliberate wrong PIN, for example:

   ```bash
   gpg --decrypt /tmp/galdralag_lockout_test.gpg
   # Enter an incorrect User PIN when prompted
   ```

2. Confirm the operation fails and note the **retries remaining** in
   `gpg --card-status` (should decrease by one compared to the previous step).
3. **Power-cycle:** unplug USB, wait several seconds, replug.
4. Run `gpg --card-status` again and confirm retries remaining **did not reset**
   to the provisioned maximum.

If the counter resets after step 3, **stop** and file an issue against
**xous-core** (see note above); do not treat it as a Galdralag-only defect
without that triage.

### 10.3. Lockout at threshold

1. Submit one more wrong User PIN (the Nth failed attempt for threshold N).
2. Confirm lockout / zeroisation: `gpg --card-status` should report blocked
   PIN state and all key slots `[none]` (or equivalent termination).
3. Compare behaviour against the configured threshold (3, 5, 7, or 10) —
   lockout must occur on the **Nth** consecutive wrong attempt, not before or
   after.

### 10.4. Verify key destruction

Attempt to decrypt the ciphertext from step 10.1:

```bash
gpg --decrypt /tmp/galdralag_lockout_test.gpg
```

Expected: decryption **fails** even if the correct User PIN were known — key
material was zeroised, not merely access-blocked.

### 10.5. Re-provision to clean state

1. Re-flash or follow the product recovery path so the device accepts
   first-boot provisioning again.
2. Run `galdralag-provision` as in step 10.1.
3. Confirm `gpg --card-status` shows a consistent fresh card (no stale key
   fingerprints, PIN retries at provisioned maximum, no blocked state).

Sign off in `docs/HARDWARE_VERIFICATION.md` under **PIN counter ordering** when
this procedure passes for all four thresholds.

---

## 11. Zeroisation (hardware) — quick check

For a shorter smoke test (threshold **3** only), trigger zeroisation with wrong
User PINs and confirm blocked state. The full procedure — including power-cycle
counter persistence and decrypt-after-lockout — is **section 10**.

See also `docs/HARDWARE_VERIFICATION.md`.

```bash
# Attempt PIN block (enter wrong User PIN 3 times)
# Then verify the device reports blocked state
gpg --card-status
```

Expected: `PIN blocked` or equivalent in card status output.
After zeroisation, all key slots should report `[none]`.

---

## 12. Results record

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
- **PIN lockout / zeroisation:** Full manual verification (section 10) supersedes
  simulation and `docs/TEST_RESULTS.md` section 11; section 11 is a quick smoke
  test only.
- **Optional dudect integrations:** `challenge-response HMAC`, `PSRAM tag check`,
  `XMSS/LMS verify` remain `[MISSING]` until those paths are wired.
