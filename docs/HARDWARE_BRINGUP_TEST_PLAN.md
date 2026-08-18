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
- For **Dabao CCID + OpenPGP APDUs**, build with **`scripts/build_dabao_ccid_image.sh`** (or `cargo xtask dabao-ccid <galdralag cratespec>` in the sibling xous-core on **`feature/usb-bao1x-ccid-openpgp`**). Plain **`dabao-ccid`** without a cratespec is **transport-only**.
- Confirm the nested/sibling xous-core trees match before compiling path deps: **`cargo run -p xtask -- check-xous-core`**. On failure the script prints a copy-pasteable `ln -sfn <sibling> ./xous-core`.
- **Fail-fast image build:** `scripts/build_dabao_ccid_image.sh` runs that preflight *before* any cargo build (unless `--skip-preflight`). To confirm: with `./xous-core` as a stale real checkout (not a symlink), the script must exit at “xous-core preflight” and must **not** print “Build galdralag-service”.
- BaoSec + PDDB path: **`cargo run -p xtask -- build-and-register release --xous-core …`** (see [services/galdralag/README.md](../services/galdralag/README.md)).

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

### Host CCID driver (required for Baochip VID:PID)

`usb-bao1x` on Dabao enumerates as **USB VID:PID `1D50:6197`**. Stock **libccid** often
does **not** list that ID. Until it does, add an entry to the driver bundle Info.plist
(example approach from xous-core PR #937 discussion):

- Path (Debian/Ubuntu typical): `/usr/lib/pcsc/drivers/ifd-ccid.bundle/Contents/Info.plist`
- Append `0x1D50` / `0x6197` / friendly name to `ifdVendorID` / `ifdProductID` / `ifdFriendlyName`
- Restart `pcscd`

Without this step, `pcsc_scan` / `gpg --card-status` may never see the reader.

### Firmware image must include `galdralag-service`

Plain **`cargo xtask dabao-ccid`** (no cratespec) is **transport-only**: inline ATR /
GetSlotStatus from `usb-bao1x`. It will **not** answer OpenPGP **XfrBlock** APDUs.

Build a Dabao image that registers Galdralag (Galdralag-side script; does not edit xous-core):

```bash
# Sibling xous-core on feature/usb-bao1x-ccid-openpgp
cargo run -p xtask -- check-xous-core
scripts/build_dabao_ccid_image.sh
```

See [services/galdralag/README.md](../services/galdralag/README.md).

Record the key fingerprints from `--list-keys` output. You will use these
as encrypt-to targets in step 5.

---

## 1. Device enumeration

Connect the Galdralag device via USB.

```bash
lsusb | grep -i 1d50   # expect 1d50:6197 after boot
dmesg --follow         # optional: watch re-enumeration
```

Confirm the host sees a CCID interface (bInterfaceClass 11) once configured.

---

## 2. PC/SC ATR (transport) then OpenPGP APDUs (Galdralag)

### 2a. Framing / ATR (usb-bao1x)

```bash
# Confirm pcscd sees the card reader
pcsc_scan
```

Expect a reader name and an ATR consistent with the OpenPGP T=1 ATR used by the
stack (transport may answer IccPowerOn inline). Kill `pcsc_scan` with Ctrl+C when
confirmed.

**Note:** xous-core `tools/ccid_hil/` Python tests exercise **framing / echo** only.
They are **not** a substitute for GnuPG APDU bring-up.

### 2b. Real card application (`gpg --card-status`)

Requires **`galdralag-service`** in the image so `OpenPgpCcidDispatcher` answers
**XfrBlock** APDUs (SELECT, GET DATA, …). Transport-only images stop at ATR.

```bash
gpg --card-status
```

Expected on a fresh Galdralag-backed image (fields may vary by firmware revision):

- Application ID / OpenPGP version present
- Key slots may show `[none]` until keygen
- PIN retries present

If ATR is visible in `pcsc_scan` but `gpg --card-status` hangs or fails with no
application, the image likely lacks `galdralag-service` (transport-only `dabao-ccid`).

If any field is missing or the AID is wrong, record the actual output and cross-check
against OpenPGP AID construction (`build_aid` / manufacturer ID — see
[OPENPGP_CARD.md](OPENPGP_CARD.md); `0x20A0` is a USB VID placeholder, not an FSFE ID).

---

## 3. PIN verification (Persona A / Dabao CCID)

**Dabao `dabao-ccid` images have no USB CDC provisioning serial and no PDDB.**
Do **not** expect `galdralag-provision` over `/dev/ttyACM0` on that recipe.

**Lab defaults** (when PDDB `OKV1` is never seen): User PIN **`12345`**, Admin PIN
**`12345678`** (see `services/galdralag` Dabao wait path). Change them promptly:

```bash
gpg --card-edit
# admin / passwd — set known User and Admin PINs
quit
```

**Development shortcut:** build with **`dev-provisioning`** and set **`CCID_USER_PIN`** /
**`CCID_ADMIN_PIN`** in the environment before first vault open (lab only).

**Legacy / baosec path (not Dabao CCID):** if the image has PDDB + optional CDC /
`ccid-pddb` factory seed, PINs may arrive via PDDB `usb.ccid` (`OKV1`,
`user_pin_line`, `admin_pin_line`) and `galdralag-provision` — see root README
“Known limitations”. Prefer documenting that path only for baosec-class images.

Confirm:

```bash
gpg --card-status
```

Record any new PINs securely. All subsequent steps require the User PIN.

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
**3**, **5**, **7**, and **10**. Each run requires a **fresh** flash and a known
PIN state so the threshold is written at provision / vault-open time (default
**3** for Dabao lab defaults; for **5**, **7**, or **10**, use the path that
persists `max_pin_attempts` — see
[PIN attempt policy](GALDRA-TOOL.md#pin-attempt-policy) in `docs/GALDRA-TOOL.md`).

**Note:** Dabao CCID has **no** `galdralag-provision` CDC path. Use section 3
defaults / `dev-provisioning`, or a baosec PDDB seed if that is your image.

### 10.1. Provision and baseline crypto check

1. Flash firmware per **Flash firmware** above (image **with** `galdralag-service`).
2. Establish known User/Admin PINs per **section 3** (Dabao defaults, change via
   `gpg --card-edit` → `passwd`, or `dev-provisioning` env vars). Do **not**
   expect CDC `galdralag-provision` on `dabao-ccid`.
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

1. Re-flash or follow the product recovery path so the device accepts a fresh
   vault / PIN state again (Dabao: re-flash image with `galdralag-service`).
2. Re-establish PINs as in section 3 / step 10.1 (defaults or `dev-provisioning`;
   baosec may still use PDDB / legacy CDC if that image provides them).
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

- **Plain `dabao-ccid` without cratespec:** transport-only; ATR may work, GnuPG APDUs will not until `galdralag-service` is in the image (`scripts/build_dabao_ccid_image.sh`).
- **libccid VID:PID:** host may need `1D50:6197` in Info.plist (section 0).
- **OpenPGP manufacturer ID:** AID uses USB VID `0x20A0` as a placeholder; see [OPENPGP_CARD.md](OPENPGP_CARD.md) and [XOUS_CORE_UPSTREAM_REQUESTS.md](XOUS_CORE_UPSTREAM_REQUESTS.md) §6.
- **Operator PIN UX:** Dabao uses lab defaults or `dev-provisioning`; change with `gpg --card-edit` → `passwd`. TRNG first-boot PINs (where enabled) are not displayed on device. See `docs/future-todo.md` section 0.
- **PIN lockout / zeroisation:** Full manual verification (section 10) supersedes
  simulation and `docs/TEST_RESULTS.md` section 11; section 11 is a quick smoke
  test only.
- **Optional dudect integrations:** `challenge-response HMAC`, `PSRAM tag check`,
  `XMSS/LMS verify` remain `[MISSING]` until those paths are wired.
