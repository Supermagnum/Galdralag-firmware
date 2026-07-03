# Galdralag — Capabilities and Future Expansion

This document describes what the Galdralag firmware already supports, and
identifies realistic future additions with suitable Rust crates for each.

The same standard applied to the current dependency tree applies to all future
additions: preference for audited, `no_std`-compatible crates from the RustCrypto
ecosystem or equivalently well-reviewed projects. Crates marked "not yet audited"
should not be integrated until independent audits are available.

---

## Current Capabilities

The device is already an OpenPGP card compatible security token. This is not a
minor detail — OpenPGP card compatibility gives the device immediate, out-of-the-box
support for a wide range of serious use cases through existing host-side tooling,
with no further firmware work required.

What this means in practice:

- **GnuPG integration** — signing, encryption, and authentication operations via
  GnuPG's OpenPGP card driver. Works on Linux, macOS, and Windows today.

- **SSH authentication** — via `gpg-agent` with `enable-ssh-support`. The device
  appears as an SSH authentication token to any SSH client that uses `gpg-agent`.
  No additional firmware required.

- **Git commit signing** — via `gpg.program=gpg` or `gpg.format=openpgp`.
  Signed commits and tags using a hardware-bound key.

- **S/MIME email signing and encryption** — through GnuPG's S/MIME support
  (`gpgsm`) and compatible mail clients such as Thunderbird and Evolution.

- **Code and artifact signing** — any tool that calls GnuPG for signing operations
  benefits immediately, including release scripts, package managers, and CI pipelines.

- **Document signing and notarisation** — signing arbitrary files with a
  hardware-bound key whose private material never leaves the device.

- **Offline CA operations** — the device can hold a CA signing key and issue
  certificates through GnuPG's certificate tooling or OpenSC's PKCS#11 interface.

On top of standard OpenPGP card behaviour, this repository adds or specifies the
following (with the implementation boundaries called out where they matter):

- **Authenticated ephemeral ECDH (forward secrecy design).** The `ephemeral-session`
  crate implements the handshake and session key derivation (Brainpool curves,
  HKDF); see [EPHEMERAL_SESSION.md](EPHEMERAL_SESSION.md). Host tooling links that
  crate (`galdra-core-host`). Device firmware implements OpenPGP-side ECDH and
  related primitives in `usb-personality` / `vault` but does **not** depend on
  `ephemeral-session` directly. Strong forward-secrecy guarantees still depend on
  product integration and on-device zeroisation behaviour; the same document notes
  limits of hardware verification to date.
- **Shamir K-of-N (split/recover math in `vault`).** GF(256) Shamir split and
  recovery live in `crates/vault`. Today's **host-orchestrated** flows export the
  signing key from the token (when connected), run `vault::shamir::*` on the
  **host** to build or combine shares, then re-import the recovered material —
  see [API_REFERENCE.md](API_REFERENCE.md) and `galdra-core-host/src/shamir_ops.rs`.
  That is multi-party **custody of shares**, not "the full Shamir lifecycle only
  inside the MCU RAM."
- **Cipher-agnostic named profiles** with cascade support and audit metadata
  (`cipher-profile` and related docs) — implemented in tree.
- **Optional bulk decoy storage (microSD or PSRAM)** — specified in
  [Psram.md](Psram.md) (and SD integration notes); **no working decoy volume stack
  is implemented in this repository yet.** `usb-personality` models a
  `MassStorageDecoy` persona and tests that secrets are not exposed on that path;
  product behaviour remains future work aligned with the design spec.
- **Fully open stack** (where the hardware and tooling ship that way): CERN-OHL-W-2.0
  RTL, open schematics, reproducible bootloader, Rust/Xous OS, IRIS-inspectable
  silicon — positioning for the Dabao/Baochip platform, not something this doc
  proves line-by-line in source.

This combination makes Galdralag a compelling device for journalism and source
protection, whistleblower infrastructure, scientific data provenance, enterprise
key custody, and software supply chain integrity — all without changes to
existing host-side tooling.

---

## Planned Additions

### When hardware arrives — bring-up sequence

Hardware bring-up sequence (Q2)

Run in this order on first hardware:

- gpg --card-status — confirms CCID enumeration, AID, and key slots
- Request / record the **FSFE/GnuPG OpenPGP card manufacturer ID** for Galdralag/Baochip when silicon is real (two-byte code for AID bytes 7-8; GET DATA tag `0x004F`). Until assigned, do not filter host PC/SC scans on USB VID `0x20A0` — that is a different namespace. See [OPENPGP_CARD.md](OPENPGP_CARD.md) and [xous-core#875](https://github.com/betrusted-io/xous-core/issues/875).
- On first boot only (PIN verifier digests unprovisioned), run **`galdralag-provision`** from [host-tools](../crates/host-tools/) — `cargo run -p host-tools --bin galdralag-provision -- --port /dev/ttyACM0` (PINs via `--user-pin` / `--admin-pin` or **`rpassword`** prompts). The host sends **two newline-terminated lines** (user PIN, admin PIN) matching **xous-core** **`usb-bao1x`** CDC provisioning; the device records **PDDB** **`usb.ccid`** / **`OKV1`** and PIN lines, then re-enumerates for **CCID**. With **`galdralag-service`** in the image, that process bridges **PDDB** into **RRAM** for OpenPGP (see [services/galdralag/README.md](../services/galdralag/README.md)).
- gpg --card-edit → passwd — exercises PIN change **after** you know the User and Admin PIN from provisioning (or dev-only env paths).
- RRAM map sign-off — manual review of the authoritative Baochip-1x memory map against the layout in docs/RRAM_LAYOUT.md; gate for production

---

### Xous multi-server IPC (`vaultd` / `pind` / `usbd`)

**Status:** Design in [ARCHITECTURE.md](ARCHITECTURE.md); **not implemented**. Today `galdralag-service` links `galdr-vault`, `pin-policy`, and `usb-personality` in one process.

**When to implement:** After Baochip bring-up stabilises CCID and vault open paths; replace `VaultService::dispatch` stub and `set_personality_stub` with real `xous::create_server` loops and the message types listed in ARCHITECTURE sections 3–5.

**Code markers:** `crates/vault/src/service.rs` (stub), `crates/usb-personality/src/lib.rs` (`set_personality_stub`), `galdr-core/src/scaffold_todos.rs` (`todo!` contract test).

---

### Host OpenPGP PC/SC vendor filter (`galdra device status`)

**Status:** Documented; implementation blocked on hardware and manufacturer ID assignment.

**Problem:** `galdra device status` / `galdrad` `GET /device/status` scan the first PC/SC reader for any OpenPGP application and read C1/C2/C3 (stale BrainpoolP512r1 detection). Third-party OpenPGP cards in that reader can produce misleading `card_present` / stale-P512 output.

**Blocked on:**

1. Baochip-1x tokens in hand ([xous-core#875](https://github.com/betrusted-io/xous-core/issues/875), [HARDWARE_BRINGUP_TEST_PLAN.md](HARDWARE_BRINGUP_TEST_PLAN.md)).
2. An **FSFE/GnuPG-registered OpenPGP manufacturer ID** for Galdralag/Baochip (not USB VID `0x20A0`). Firmware today calls `build_aid(0x20A0, serial)` in `services/galdralag` — treat as bring-up placeholder until registry assignment.

**Implementation sketch (when unblocked):**

- After OpenPGP SELECT in `galdra-core-host/src/openpgp_pcsc.rs` (`scan_openpgp_card_via_pcsc`), GET DATA tag `0x004F`, compare AID bytes 7-8 to the assigned ID.
- Extend `OpenPgpCardScan` with `is_galdralag_token: bool` (or equivalent); foreign cards: `card_present: true`, skip C1/C2/C3 GET DATA, CLI line such as `OpenPGP: Card present (not a Galdralag token)`.
- Centralize the manufacturer constant beside `crates/usb-personality/src/openpgp/aid.rs` once known.

**Code marker:** `TODO(openpgp-vendor-filter)` in `openpgp_pcsc.rs`.

---

### 0. First-boot operator PIN UX (resolved — USB CDC provisioning)

**Status:** Addressed in-tree via host tool **`galdralag-provision`** (`crates/host-tools/src/provision.rs`): **two newline-terminated lines** (user PIN, admin PIN) on the CDC serial, matching **xous-core** **`usb-bao1x`**, which persists **`OKV1`** / PIN lines in **PDDB** **`usb.ccid`**. Optional **`galdralag-service`** (`services/galdralag`) bridges **PDDB** into **RRAM** and handles **CCID** IPC with **`usb-bao1x`**. Separately, **`usb-personality`** **`ProvisioningClass`** (STATUS / SET_USER_PIN / COMMIT) remains for non-Xous or test layouts.

**Initial PIN delivery:** Operator-chosen PINs (1–32 bytes each) reach **RRAM** **`PNU1` / `PNA1`** either via that PDDB bridge and **`write_provisioning_pins`** or via **`usb-bao1x`**-local handling, then **`OpenPgpVaultBackend` / `open_or_provision_backend`** consumes them on first successful open (provision band cleared afterward). After the vault exists, PIN updates use **OpenPGP CHANGE REFERENCE DATA** over CCID, not raw provision-slot writes.

**PIN cap:** 32 bytes (firmware limit; OpenPGP spec allows 127). See `CCID_PIN_PROVISION_PAYLOAD_MAX_BYTES` in `crates/baochip-openpgp/src/xous_impl.rs`.

**Lab / CI fallbacks (not for production tokens):** Feature **`dev-provisioning`** (`CCID_USER_PIN` / `CCID_ADMIN_PIN` env); optional **`trng-pin-fallback`** (silent TRNG PIN — unrecoverable without out-of-band capture; **forbidden** with **`board-dabao`** via `compile_error!` in `baochip-openpgp`).

---

### 1. Password Vault

Store per-site credentials encrypted in RRAM behind the existing PIN policy.
Retrieval via the authenticated host-tools interface only — no USB keyboard
personality, no HID emulation.

| Crate | Role | Notes |
|-------|------|-------|
| `postcard` | Compact binary serialisation of credential records | `no_std`, deterministic output, used in production embedded Rust. Not a cryptographic crate — encryption handled by existing deps. No formal security audit; assess suitability carefully. |
| `serde` | Derive `Serialize`/`Deserialize` on credential entry types | Paired with `postcard`. |
| `zeroize` | Zeroise credential structs on drop | Already in the dependency tree. |

Cryptographic protection of vault entries uses `aes-gcm` or `chacha20poly1305`
plus `hkdf` with a new `KeyPurpose::PasswordEntry` domain label — all already
in tree. No new cryptographic crates required.

---

### 2. Kerberos / PKINIT Enterprise Authentication

Authenticate to Active Directory, FreeIPA, or MIT Kerberos infrastructure using
PKINIT (RFC 4556). The token presents a certificate-backed identity to a KDC
instead of a password, via the existing CCID interface and OpenSC or PKCS#11
middleware on the host.

| Crate | Role | Notes |
|-------|------|-------|
| `x509-cert` | X.509 certificate parsing and encoding (RFC 5280) | Pure Rust, RustCrypto project, `no_std` compatible. Not yet independently audited. |
| `cms` | PKINIT AuthPack signing (DER-encoded CMS SignedData) | Pure Rust, RustCrypto project, `no_std` compatible. Not yet independently audited. |
| `der` | ASN.1 DER encoding/decoding — required by `cms` and `x509-cert` | Pure Rust, RustCrypto project, `no_std` with heapless support. |
| `pkcs8` | Private key encoding/decoding (RFC 5208, RFC 5958) | RustCrypto project, `no_std` compatible. |
| `spki` | X.509 Subject Public Key Info encoding | RustCrypto project, `no_std` compatible. |

No standalone Rust PKINIT client crate suitable for `no_std` embedded use exists
at time of writing. The firmware only performs the signing operation; PKINIT
protocol handling lives entirely in host-side tooling.

Planned: after Q2 bring-up and CCID smoke test. Defer x509-cert / cms integration until independent audits are available; these crates handle untrusted input.

---

### 3. Post-Quantum Cryptography Profile Additions

Add ML-KEM, ML-DSA, and SLH-DSA algorithm entries to the existing cipher-agnostic
profile system once independently audited crates are available.

| Crate | Notes |
|-------|-------|
| `ml-kem` (RustCrypto) | `no_std` compatible, tested against NIST KAT vectors. No independent audit as of 2025 — RustCrypto README explicitly states this. Do not integrate before audit. |
| `ml-dsa` (RustCrypto) | `no_std` compatible, tested against NIST KAT vectors. No independent audit as of 2025. Same caveat. |
| `slh-dsa` (RustCrypto) | `no_std` compatible, tested against NIST KAT vectors. No independent audit as of 2025. Same caveat. |
| `libcrux-ml-kem` (Cryspen) | Formally verified using hax/F* framework; used in production by Mozilla. Most rigorous verification story currently available. Uncovered the KyberSlash timing bug in other implementations. Watch for formal audit availability. |

For first deployment, prefer libcrux-ml-kem over ml-kem (RustCrypto); Cryspen's formal verification uncovered the KyberSlash timing vulnerability in other implementations.

Hybrid classical+PQC profiles (e.g. X25519 + ML-KEM-768) should be the first
deployment target. The existing cipher-agnostic profile system accommodates this
without architectural changes.

Integration is intentionally deferred until at least one crate covering ML-KEM
and ML-DSA has completed an independent security audit.

---

### 4. Biometric pre-gate (design)

See [BIOMETRIC_API.md](BIOMETRIC_API.md) for the on-token template storage and
`galdrad` relay model. Before any **deployment** claim for that path:

- **PAD testing** must follow **ISO/IEC 30107-3** methodology; informal spoof
  tests are not enough for product or security positioning.
- **Matching accuracy** must be benchmarked against the **datasets published
  alongside the sweet platform (CandyFV)** and the **datasets associated with the
  ESP32-CAM device paper**, so numbers stay aligned with those public baselines.

**Rust integration tests** follow the existing **`test-hal` / `dudect` /
`cargo-fuzz`** pattern already in the workspace (same as other crates: **`test-hal`**
fakes, **`dudect`** for timing-critical paths, **`cargo-fuzz`** under `fuzz/`;
see [Psram.md](Psram.md) for the consolidated description).

---

### 5. LUKS Volume Unlock via Token (`galdra-unlock`)

Token-assisted unlock of LUKS2 encrypted volumes on Linux, including the OS
root volume. This is entirely a **host-side** addition — no firmware changes are
required. The feature is implemented as a new `galdra-unlock` binary crate in
the workspace that reuses existing host-side crates and bridges to `libcryptsetup`
via the `libcryptsetup-rs` crate.

#### Design rationale

Rather than reimplementing LUKS2 header parsing, keyslot management, or device
activation in Rust from scratch, `galdra-unlock` bridges to `libcryptsetup` —
the same library used by every major Linux distribution for LUKS operations.
This library has over a decade of production use and extensive testing. The
approach minimises new code surface: the interesting and security-sensitive parts
(key unwrapping, token communication) reuse already-tested workspace crates; the
activation call delegates to `libcryptsetup`.

This mirrors how `galdra-gtk` introduces a system library dependency
(`libgtk-4`) for host-only functionality without affecting the firmware or the
core cryptographic crates.

#### Key unwrapping paths

Two paths are supported, selectable at provisioning time:

**Path A — GnuPG / OpenPGP card key**

The LUKS key-slot secret is encrypted to the token's DEC key using standard
OpenPGP. At unlock time `galdra-unlock` instructs `gpg-agent` (via `scdaemon`)
to decrypt it using the on-card key, then feeds the result to `libcryptsetup-rs`.
No new cryptographic code is required on the host; the entire unwrap path goes
through GnuPG's existing OpenPGP card driver.

**Path B — Cipher profile cascade**

The LUKS key-slot secret is wrapped using a Galdralag cipher profile (for
example the `conservative` profile: ChaCha20-Poly1305 then Serpent-256, each
with independently HKDF-derived keys). At unlock time `galdra-unlock`:

1. Opens an authenticated ephemeral ECDH session with the token (reusing the
   existing `ephemeral-session` crate).
2. Verifies PIN on-device; the token returns the per-profile key material over
   the encrypted session channel.
3. Unwraps the volume key through the cascade layers in reverse using the
   existing `cipher-profile` and `cess` crates.
4. Passes the recovered key to `libcryptsetup-rs` to activate the volume.
5. Zeroes all key material from host memory immediately after activation using
   `zeroize`.

Path B can be combined with Shamir K-of-N: the volume key is reconstructed
on-device from K shares before being returned over the session channel, meaning
no single share holder can unlock the volume alone. This gives quorum-controlled
full-disk encryption, which is unusual in the LUKS ecosystem.

#### Crates

| Crate | Role | Notes |
|-------|------|-------|
| `libcryptsetup-rs` | FFI bridge to `libcryptsetup` for LUKS2 volume activation | Maintained by the Stratis project. Thin safe wrapper over the well-tested `libcryptsetup` C library. Requires `libcryptsetup-dev` on the build host and `libcryptsetup` at runtime. No independent Rust audit; cryptographic work is delegated to `libcryptsetup` itself. |
| `ephemeral-session` | Authenticated ephemeral ECDH session with the token | Already in workspace. |
| `cipher-profile` | Cascade key unwrapping (Path B) | Already in workspace. |
| `cess` | HKDF-BLAKE3 outer envelope unwrap (Path B) | Already in workspace. |
| `zeroize` | Zeroise key material after `crypt_activate_by_volume_key()` returns | Already in workspace. |

No new cryptographic crates are introduced. The `libcryptsetup-rs` dependency
is gated behind a `luks` feature flag on the `galdra-unlock` crate so it does
not affect other workspace members.

#### New code surface

The `galdra-unlock` crate itself is glue logic only:

1. Parse command-line arguments (device path, key path or profile name,
   optional Shamir parameters).
2. Open session and retrieve or unwrap key material (delegates entirely to
   existing crates).
3. Call `libcryptsetup_rs::CryptDevice::activate_by_volume_key()` (or the
   passphrase variant for Path A).
4. Zeroize the **host-side copy** of the key material (see Security notes).
5. Exit.

No cryptographic primitives are implemented in `galdra-unlock` itself.

#### Workspace layout addition

```
galdra-unlock/
  Cargo.toml          # [features] luks = ["libcryptsetup-rs"]
  src/
    main.rs           # argument parsing, orchestration, zeroize on exit
    session.rs        # thin wrapper around ephemeral-session for unlock flows
    luks.rs           # libcryptsetup-rs activation call, behind feature flag
```

Add to the root workspace `Cargo.toml`:

```toml
[workspace]
members = [
  # ... existing members ...
  "galdra-unlock",
]
```

#### Early-boot (initramfs) integration

For OS root volume unlock, `galdra-unlock` must run from the initramfs before
the root filesystem is mounted. The recommended approach:

**Build a statically linked binary** using the `x86_64-unknown-linux-musl`
target (or the equivalent for the host architecture). Static linking avoids
shared library resolution problems inside a minimal initramfs. `libcryptsetup`
must also be built statically or the binary must carry the shared library into
the initramfs.

```bash
# Install musl target
rustup target add x86_64-unknown-linux-musl

# Build statically linked release binary
RUSTFLAGS="-C target-feature=+crt-static" \
  cargo build --release --features luks -p galdra-unlock \
  --target x86_64-unknown-linux-musl
```

**dracut hook** (Fedora, RHEL, openSUSE, Arch with dracut):

Create `/etc/dracut.conf.d/galdra-unlock.conf`:

```bash
install_items+=" /usr/local/bin/galdra-unlock "
```

Create `/usr/lib/dracut/hooks/pre-mount/30-galdra-unlock.sh`:

```bash
#!/bin/bash
# Unlock the root LUKS volume using the Galdralag token.
# Adjust LUKS_DEV and KEY_PROFILE to match provisioning.
LUKS_DEV=/dev/disk/by-id/your-luks-device
KEY_PROFILE=conservative   # or "gnupg" for Path A

/usr/local/bin/galdra-unlock \
  --device "$LUKS_DEV" \
  --profile "$KEY_PROFILE" \
  --name root-luks

if [ $? -ne 0 ]; then
  echo "galdra-unlock: token unlock failed, falling back to passphrase"
  # dracut will fall through to its built-in cryptsetup prompt
fi
```

**mkinitcpio hook** (Arch Linux, Debian/Ubuntu with mkinitcpio):

Create `/etc/initcpio/install/galdra-unlock`:

```bash
#!/bin/bash
build() {
  add_binary /usr/local/bin/galdra-unlock
  add_runscript
}
```

Create `/etc/initcpio/hooks/galdra-unlock`:

```bash
run_hook() {
  /usr/local/bin/galdra-unlock \
    --device /dev/disk/by-id/your-luks-device \
    --profile conservative \
    --name root-luks \
  || echo "galdra-unlock: falling back to passphrase prompt"
}
```

Add `galdra-unlock` to the `HOOKS` array in `/etc/mkinitcpio.conf` before
`encrypt`.

#### Privileges

Activating a LUKS device requires `CAP_SYS_ADMIN` or root. In an initramfs
context the hook runs as root, so no special arrangement is needed. For
non-root data volume unlock in a running system, a small setuid or
`capabilities`-granted wrapper is required — the same constraint that applies
to `cryptsetup` itself.

#### Provisioning

A new `galdra device provision-luks` subcommand on the existing `galdra` host
tool handles initial setup:

```bash
# Path A: wrap the LUKS key-slot secret to the token's OpenPGP DEC key
galdra device provision-luks \
  --device /dev/sdX \
  --path gnupg \
  --key-slot 1

# Path B: wrap using the conservative cipher profile
galdra device provision-luks \
  --device /dev/sdX \
  --path profile \
  --profile conservative \
  --key-slot 1

# Path B with Shamir 2-of-3: requires 2 tokens to unlock
galdra device provision-luks \
  --device /dev/sdX \
  --path profile \
  --profile conservative \
  --shamir-n 3 \
  --shamir-k 2 \
  --key-slot 1
```

The provisioning subcommand: reads the LUKS key-slot secret from
`libcryptsetup-rs`, wraps it via the chosen path, stores the wrapped blob in
the token vault, and writes metadata (profile name, Shamir parameters if any)
to a small header file that `galdra-unlock` reads at boot time.

#### Security notes

**Host-side zeroisation scope — what is and is not zeroed**

The `zeroize` calls in `galdra-unlock` apply exclusively to the **ephemeral
host-side copy** of key material: the bytes returned over the authenticated
session channel and held temporarily in the Linux host process's RAM during the
unlock operation. Once `crypt_activate_by_volume_key()` returns, those bytes
are overwritten using `zeroize` before the buffer is freed or goes out of scope.
This closes the window during which the key material could be recovered from a
swap file, crash dump, or cold-boot attack against host RAM.

**`galdra-unlock` does not and cannot zeroise keys stored on the token.**
The keys held in the token's on-chip RRAM are entirely separate from the
host-side copy. They are protected by the token's own vault and PIN policy.
The only firmware paths that trigger on-device zeroisation are deliberate ones:

- The PIN attempt threshold being exceeded (after 3–10 consecutive wrong PINs,
  configurable at provisioning).
- An explicit authenticated wipe command sent through the management interface.

Nothing in `galdra-unlock` sends any command that would trigger on-device
zeroisation. The session channel is read-only with respect to vault contents:
`galdra-unlock` retrieves key material; it does not write to, modify, or delete
anything stored in the vault.

This boundary means a bug or crash in `galdra-unlock` cannot accidentally
destroy the keys on the token. The worst outcome of a `galdra-unlock` failure
is a failed volume activation that falls back to the passphrase prompt — not
loss of token key material.

**Other security notes**

- Host-side key material exists in RAM only between the session channel read
  and the `zeroize` call immediately following activation. The window is as
  short as the implementation allows.
- The wrapped key blob stored in the token vault is protected by the vault PIN
  policy; failed PIN attempts trigger the same on-device zeroisation path as
  all other vault secrets — but this is initiated by the token's own firmware,
  not by anything the host tool does.
- For Path B with Shamir, no single token holds enough shares to reconstruct
  the volume key without the quorum of other tokens or share holders.
- A fallback LUKS passphrase key slot should always be provisioned and stored
  offline (e.g. on paper in a physically secure location) in case the token is
  lost, damaged, or the `galdra-unlock` binary is unavailable at boot time.
  This is also the recovery path if the token is ever wiped due to PIN threshold
  exhaustion.

---

## Crates Explicitly Excluded

| Crate | Reason |
|-------|--------|
| `pqcrypto-*` family | FFI bindings to C reference implementations — not suitable for `no_std` embedded target |
| `openssl` | Does not support `no_std`; C dependency |
| Any TOTP/HOTP crate | No RTC; protocol mismatch for this device class |
| Any FIDO2/CTAP2 crate | No user-presence button; fundamental incompatibility |

---

## Audit Status Summary

The "Yes" entries below record **dependency policy** (commonly cited independent
audits for those crates). They are **not** assertions proven inside this
repository; confirm against each upstream project before production sign-off.

| Crate | Independently Audited |
|-------|----------------------|
| `aes-gcm`, `chacha20poly1305`, `ed25519-dalek`, `x25519-dalek`, `hkdf`, `pbkdf2`, `hmac`, `sha2`, `sha3`, `blake2`, `blake3`, `zeroize`, `subtle`, `p256`, `p384` | Yes (per upstream; existing deps) |
| `vsss-rs` | Yes (per upstream; existing dep) |
| `der`, `cms`, `x509-cert`, `pkcs8`, `spki` | No |
| `ml-kem`, `ml-dsa`, `slh-dsa` | No |
| `postcard` | No |
| `libcryptsetup-rs` | No (bridges to audited `libcryptsetup` C library) |
