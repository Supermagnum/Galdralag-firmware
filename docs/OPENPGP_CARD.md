# OpenPGP Card Application

Galdralag implements the OpenPGP card application version 3.4.1. This makes it compatible with GnuPG and any software that uses GnuPG as its crypto backend, without any host-side driver or software changes beyond a standard CCID/USB smart card stack.

## Automatic compatibility

Once the USB CCID device is recognised by the host:

### File encryption and decryption

```bash
gpg --encrypt --recipient you@example.com file.txt
gpg --decrypt file.txt.gpg
```

### SSH authentication

Add to `~/.gnupg/gpg-agent.conf`:

```
enable-ssh-support
```

Add to `~/.bashrc`:

```bash
export SSH_AUTH_SOCK="$(gpgconf --list-dirs agent-ssh-socket)"
```

Export your SSH public key:

```bash
gpg --export-ssh-key YOUR_KEY_ID >> ~/.ssh/authorized_keys
```

### LUKS unlock at boot

Use the smartcard-key-luks script:

https://github.com/daringer/smartcard-key-luks

### Email encryption

Works out of the box with Thunderbird (Enigmail / built-in OpenPGP), Evolution, Kleopatra, and any GnuPG-backed email client.

## Key slots

| Slot | Purpose | Default algorithm |
|------|---------|-------------------|
| SIG | Signing | BrainpoolP256r1 ECDSA |
| DEC | Decryption | BrainpoolP256r1 ECDH |
| AUT | Authentication (SSH) | BrainpoolP256r1 ECDSA |

Algorithm can be changed per slot via:

`gpg --card-edit` then admin, then `key-attr`.

Supported algorithms: BrainpoolP256r1, BrainpoolP384r1, NIST P-256, NIST P-384, Ed25519/Curve25519, RSA-2048, RSA-3072, RSA-4096.

BrainpoolP512r1 was removed from the supported set; see [CHANGELOG.md](../CHANGELOG.md).

### Stale P-512 algorithm attributes (older firmware)

Tokens provisioned under firmware that still offered BrainpoolP512r1 may retain P-512 algorithm attributes in data objects **C1** (SIG), **C2** (DEC), or **C3** (AUT). **GET DATA** on those objects still returns the stored OID; the card does not rewrite them on upgrade.

GnuPG sign, decrypt, or SSH authentication against such a slot fails with a generic ISO 7816 status word (`ReferenceDataNotFound`, `ExecutionError`, `ConditionsNotSatisfied`, and similar). The card protocol carries no explanatory text for those failures.

Host-side detection (read-only; does not modify card state):

```bash
galdra device status
```

When a PC/SC reader can access the OpenPGP application, this command reports whether any slot still names BrainpoolP512r1 and prints the explicit removal message from `galdr_core::legacy_removed`. The same scan is exposed as `openpgp_card` in JSON output and in `galdrad` `GET /device/status`.

`galdra identity fingerprint` and `galdra encrypt` (when the selected profile does not use ephemeral ECDH) check the SIG slot before reading the public key and return `RemovedLegacyCrypto` with the same message instead of a generic PC/SC failure.

To replace stale attributes, use `gpg --card-edit` then `admin` and `key-attr` to select a supported curve and regenerate the slot key. New PUT DATA requests that name P-512 are rejected with `0x6A80` (Incorrect parameters).

See also [CHANGELOG.md](../CHANGELOG.md) (BrainpoolP512r1 / `high-assurance` removal).

### PC/SC scan scope (no Galdralag vendor filter yet)

`galdra device status` and `galdrad` `GET /device/status` probe the **first available PC/SC reader** (or the reader named in `GALDRA_PCSC_READER`). After a successful OpenPGP application SELECT, they read C1/C2/C3 with **GET DATA only** (no writes, no PIN commands).

There is **no check yet** that the card is a Galdralag/Baochip-1x token. On a host with another OpenPGP card in that reader (YubiKey, Nitrokey, a colleague's token on a shared reader), stale-P512 warnings and `card_present: true` may refer to **that** card, not yours.

Baochip-1x hardware is not generally available yet ([README.md](../README.md); [xous-core#875](https://github.com/betrusted-io/xous-core/issues/875) tracks CCID/usb-bao1x bring-up). A filter needs the **registered OpenPGP card manufacturer ID** (two bytes in the 16-byte Application Identifier returned by GET DATA tag **0x004F**, bytes 7-8 per the OpenPGP card spec), assigned by FSFE/GnuPG — not the USB vendor ID.

Firmware today builds the in-card AID with `build_aid(0x20A0, serial)` in `services/galdralag` (see `crates/usb-personality/src/openpgp/aid.rs`). **`0x20A0` is the project's USB VID** (`USB_VID_GALDRALAG`); it is **not** listed in the public OpenPGP manufacturer registry (for example Nitrokey's registered OpenPGP ID is `0x000F`, separate from its USB VID). Do not use `0x20A0` as a stand-in filter until a real OpenPGP manufacturer ID is assigned for Galdralag/Baochip.

**Tracked TODO (independent of CCID/USB transport):** request/obtain an FSFE/GnuPG-registered manufacturer ID; then filter `galdra device status` on AID bytes 7-8 and replace the `build_aid(0x20A0, …)` placeholder. See [future-todo.md](future-todo.md) and [XOUS_CORE_UPSTREAM_REQUESTS.md](XOUS_CORE_UPSTREAM_REQUESTS.md) §6 (Galdralag-only).

Once that ID exists, host tooling should read tag `0x004F` after SELECT, compare bytes 7-8, and skip C1/C2/C3 stale-P512 scans for foreign cards. Tracked in [docs/future-todo.md](future-todo.md).

## PIN policy

| PIN | Minimum length | Maximum retries | Blocks on |
|-----|----------------|-----------------|-----------|
| User PIN (PW1) | 5 characters | 3 | Hardware zeroisation |
| Admin PIN (PW3) | 5 characters | 3 | Hardware zeroisation |

## Linux udev rule

Create `/etc/udev/rules.d/99-galdralag.rules`:

```
SUBSYSTEM=="usb", ATTRS{idVendor}=="20a0", ATTRS{idProduct}=="42b3", \
  GROUP="plugdev", TAG+="uaccess"
```

Then run:

```
sudo udevadm control --reload-rules && sudo udevadm trigger
```

This allows non-root users to access the device. `pcscd` and GnuPG's `scdaemon` will then find it automatically.

## What is NOT supported

Website authentication (WebAuthn/FIDO2) is a separate protocol not covered by the OpenPGP card standard. It requires a separate FIDO2 application and is not implemented in this version.
