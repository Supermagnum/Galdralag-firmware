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

Supported algorithms: BrainpoolP256r1, BrainpoolP384r1, BrainpoolP512r1, NIST P-256, NIST P-384, Ed25519/Curve25519, RSA-2048, RSA-3072, RSA-4096.

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
