# Galdr — Galdralag Firmware

> **Status:** Ready for testing by humans — no production-ready release exists.
> Its written in rust using validated and audited crypto crates. 
> Cryptographic primitives are drawn exclusively from audited workspace
> dependencies. Post-quantum algorithms are feature-gated and marked
> **PENDING INDEPENDENT AUDIT**. See [Post-quantum status](#post-quantum-status).

> **Note:** Parts of this project were developed with AI assistance (Claude, Anthropic).
> The design, cryptographic choices, and security decisions have not been reviewed
> by a professional cryptographer. Treat this as an experimental project and apply
> your own critical judgement. Independent expert review is strongly recommended
> before any production deployment.

It is ready for testing by humans; using a **virtual machine** for that is suggested. There may be bugs that automated tests have not discovered.

## Table of contents

- [About the name](#about-the-name)
- [What this is](#what-this-is)
- [Documentation](#documentation)
- [OpenPGP and GnuPG compatibility](#openpgp-and-gnupg-compatibility)
- [Standards vs. firmware-specific features](#standards-vs-firmware-specific-features)
- [Shamir secret sharing and drive encryption](#shamir-secret-sharing-and-drive-encryption)
- [Standards process: Shamir and ephemeral key exchange](#standards-process-shamir-and-ephemeral-key-exchange)
- [Sequoia PGP (if this repository is unresponsive)](#sequoia-pgp-if-this-repository-is-unresponsive)
- [Build, install, and uninstall](#build-install-and-uninstall)
  - [Compile firmware](#compile-firmware)
  - [Flashing](#flashing)
  - [Compile and install host tools (`galdra`, `galdrad`, `galdra-gtk`)](#compile-and-install-host-tools-galdra-galdrad-galdra-gtk)
  - [Uninstall host tools](#uninstall-host-tools)
- [Key capabilities](#key-capabilities)
  - [What makes this token unusual](#what-makes-this-token-unusual)
  - [Cryptographic capabilities](#cryptographic-capabilities)
    - [Asymmetric / key agreement](#asymmetric--key-agreement)
    - [Symmetric / AEAD](#symmetric--aead)
    - [Key derivation / MAC / digest](#key-derivation--mac--digest)
    - [Key management](#key-management)
  - [Security properties](#security-properties)
  - [PIN policy](#pin-policy)
- [Post-quantum status](#post-quantum-status)
  - [Implemented — unaudited crate (feature-gated)](#implemented--unaudited-crate-feature-gated)
  - [Pending independent audit — not yet implemented](#pending-independent-audit--not-yet-implemented)
  - [Will not be implemented](#will-not-be-implemented)
- [Zeroisation — hardware caveat](#zeroisation--hardware-caveat)
- [Test results](#test-results)
- [Workspace layout](#workspace-layout)
- [Cryptographic dependency policy](#cryptographic-dependency-policy)
- [Quick start](#quick-start)
- [License](#license)

---

## About the name

**Galdr** is the Old Norse practice of spoken or sung magic: incantations
used to bind, protect, or reveal. In the sagas it names the act of casting
the spell itself, not only the words. Sometimes also used to activate magic
rune inscriptions, as on the [Kragehul I lance shaft](https://en.wikipedia.org/wiki/Kragehul_I),
the [Lindholm amulet](https://en.wikipedia.org/wiki/Lindholm_amulet),
the [Vadstena bracteate](https://en.wikipedia.org/wiki/Vadstena_bracteate),
and other Elder Futhark finds.

**Galdralag** is the metrical form used for galdr: structured, precise,
rule-bound verse in which the pattern is part of the force of the spell.
The suffix *lag* is akin to "law" or "pattern."

**Runes** were literally secret, encoded knowledge — the shamanic usage
was only known to those who understood.

---

## What this is

Firmware for **Baochip-1x** (Dabao evaluation board) devices running the
**[Xous](https://github.com/betrusted-io/xous-core)** microkernel, built
for `riscv32imac-unknown-none-elf`.

It's located here:
https://www.baochip.com/

The device is a hardware security token in the same category as
Nitrokey-class devices, with OpenPGP smartcard-class behaviour and an
encrypted vault. The full hardware stack — RTL, schematics, bootloader,
OS — is open source and auditable.

Hardware specification, boot model, requirement tables, and ComboHash/PKE
usage are documented in the
**[Baochip-1x firmware design README](https://raw.githubusercontent.com/Supermagnum/Baochip-1x-firmware/refs/heads/main/README.md)**.
Architecture notes for this repository: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

The only remaining work before physical hardware works is the Xous USB service wiring — and that is documented in [docs/XOUS_CCID_INTEGRATION.md](docs/XOUS_CCID_INTEGRATION.md), waiting for the BSP crates to be available.

At that point the project will be a complete, tested, open-source hardware security token firmware: **OpenPGP card–style behaviour** for GnuPG over CCID (see [OpenPGP and GnuPG compatibility](#openpgp-and-gnupg-compatibility)), plus **additional on-device features** not currently defined by the OpenPGP card standard — ephemeral ECDH with forward secrecy, Shamir K-of-N, cipher-agnostic profiles, PSRAM decoy volume — as summarised in [Standards vs. firmware-specific features](#standards-vs-firmware-specific-features). All on open RTL with a reproducible bootloader.

---

## Documentation

- **[Galdra — Token Management Tool Specification](https://github.com/Supermagnum/Galdralag-firmware/blob/main/docs/GALDRA-TOOL.md)** — host tools (`galdra` CLI, `galdrad` daemon, `galdra-gtk`), contacts, groups, OpenPGP workflows, and operational behaviour.
- **[Glossary](https://github.com/Supermagnum/Galdralag-firmware/blob/main/docs/GLOSSARY.md)** — short definitions of terms used across this repository.

Same files in a local clone: [docs/GALDRA-TOOL.md](docs/GALDRA-TOOL.md), [docs/GLOSSARY.md](docs/GLOSSARY.md).

- **[OpenPGP card application and GnuPG](docs/OPENPGP_CARD.md)** — host compatibility (`gpg`, `scdaemon`, CCID), key slots, algorithms, udev, PIN policy, and unsupported features.

---

## OpenPGP and GnuPG compatibility

The firmware implements the **OpenPGP card application** (documented as version **3.4.1** in [docs/OPENPGP_CARD.md](docs/OPENPGP_CARD.md)). That is the same class of device GnuPG drives for **OpenPGP smart cards** over **CCID/USB**: the host needs a normal smart card stack (`pcscd`, `ccid` drivers, GnuPG’s `scdaemon`). **No custom host-side cryptographic driver** is required beyond what you would use for any OpenPGP card.

**What this enables on the host (once the device is visible as a CCID reader):**

| Area | Notes |
|------|--------|
| **GnuPG workflows** | `gpg --card-status`, `gpg --card-edit`, encrypt/decrypt and sign using keys on the card |
| **SSH** | `gpg-agent` with `enable-ssh-support` and the usual `SSH_AUTH_SOCK` setup |
| **Mail and files** | Clients that use GnuPG (e.g. Thunderbird, Evolution, Kleopatra) and standard `gpg` file encryption |
| **Other tools** | Anything that talks OpenPGP card + CCID the same way GnuPG does |

**Key slots (typical defaults):** **SIG** (signing), **DEC** (decryption / ECDH), **AUT** (authentication, e.g. SSH). Algorithms are selectable per slot (Brainpool curves, NIST P-256/P-384, Ed25519 / X25519, RSA). The full table and `key-attr` behaviour are in [docs/OPENPGP_CARD.md](docs/OPENPGP_CARD.md).

**Not covered by OpenPGP card / GnuPG here:** **WebAuthn / FIDO2** is a different protocol and is out of scope for this card application (see the same doc).

**OpenPGP card vs. OpenPGP messages:** The **card** specification defines how the token exposes PINs, key slots, and on-card operations over CCID. **GnuPG** uses that through `scdaemon`. The **OpenPGP message format** for files and mail (RFC 4880 and successors) is a **host-side** layer: the card supplies keys; GnuPG still applies the message format on the PC. Neither the card spec nor RFC 4880 defines **Shamir splitting**, **ephemeral ECDH sessions**, or **cipher profiles** — those are [firmware-specific](#standards-vs-firmware-specific-features).

**Integration status:** The OpenPGP and CCID logic lives in **`usb-personality`** and is covered by unit tests, integration tests, and the **`openpgp_dispatch`** fuzz target (see [docs/TEST_RESULTS.md](docs/TEST_RESULTS.md)). Wiring the USB **CCID** service into the running **Xous** image is still **integration work**; follow [docs/XOUS_CCID_INTEGRATION.md](docs/XOUS_CCID_INTEGRATION.md). Until that is done, **end-to-end GnuPG against real hardware** is not available, even though the card application behaviour is implemented in firmware sources.

---

## Standards vs. firmware-specific features

Different parts of this project align with different standards. **GnuPG interoperability** is limited to what the **OpenPGP card application** and **CCID** define. Other features are implemented in firmware (and sometimes in **Galdra** host tools) but are **not** something you can invoke through standard `gpg` card workflows.

| Scope | Typical standard / document | Exposed as standard OpenPGP card + GnuPG? |
|-------|------------------------------|-------------------------------------------|
| **OpenPGP card application** — APDUs, PINs, SIG/DEC/AUT slots, generate/sign/decipher on card | OpenPGP card specification (see [docs/OPENPGP_CARD.md](docs/OPENPGP_CARD.md)) | **Yes** — same host stack as other OpenPGP smart cards (`gpg`, `scdaemon`, CCID) |
| **USB CCID** — talking to the device as a smart card reader | USB CCID device class | **Yes** — class drivers |
| **OpenPGP message format** — encrypted files, mail, key packets | RFC 4880 (and updates) | **Yes on the host** — GnuPG uses this; the card does not parse mail |
| **Shamir K-of-N** — split / recover long-term key material in the vault | Not in OpenPGP card spec; not in GnuPG | **No** — firmware and provisioning tools only; not a `gpg --card-edit` operation (see [Shamir and full-disk encryption](#shamir-secret-sharing-and-drive-encryption)) |
| **Authenticated ephemeral ECDH** — forward-secret session protocol on the token | Not in OpenPGP card spec | **No** — token-specific; not a GnuPG card command |
| **Cipher profile system** — named cipher cascades and related policy | Not in OpenPGP card spec | **No** — firmware / host token tools |
| **PSRAM decoy / mass-storage personas** — uninformed-host USB behaviour | Not in OpenPGP card spec | **No** — separate USB personality code paths |
| **WebAuthn / FIDO2** | CTAP / WebAuthn | **Not implemented** — different standard from OpenPGP card |

For day-to-day **card** behaviour, rely on [docs/OPENPGP_CARD.md](docs/OPENPGP_CARD.md). For **vault-only** or **token-unique** features, use this repository’s firmware and [Galdra tool](docs/GALDRA-TOOL.md) documentation.

---

## Shamir secret sharing and drive encryption

The **OpenPGP card** and **GnuPG** stacks do **not** define Shamir’s Secret Sharing (SSS) for keys or for disk unlock. SSS is still useful **alongside** normal encryption: it almost never replaces the symmetric cipher on the disk — it **protects the small secret** (master key or passphrase) that unlocks that encryption.

**Pattern (always the same idea):**

| Layer | Role |
|-------|------|
| Drive | Encrypted with a **master key** (e.g. AES-256 via LUKS, VeraCrypt, or a raw block layer) |
| Master key | Split with SSS into **N** shares, threshold **K-of-N** |
| Shares | Held by people, devices, or offline storage; **K** shares together reconstruct the master key |
| Unlock | Reconstruct key, then pass it to `cryptsetup`, `veracrypt`, or your stack |

### Common real-world approaches

**1. LUKS (Linux) and external SSS**

[LUKS](https://gitlab.com/cryptsetup/cryptsetup) encrypts the volume with a master key. You can extract that key (or a key-slot secret, depending on your procedure), split it with an SSS tool, and store shares separately. At unlock time, combine **K** shares, reconstruct the key material, and supply it to `cryptsetup` (see your distribution’s documentation; mishandling keys can brick access).

Example shape using the `ssss` (“Shamir’s Secret Sharing Scheme”) utilities (names and packaging vary by OS):

```bash
# Example: 3-of-5 split of a file containing key material (illustrative only)
ssss-split -t 3 -n 5 < luks_master.key

# Later: combine shares, then unlock (adapt device path and cryptsetup flow)
ssss-combine -t 3 | cryptsetup luksOpen /dev/sdX vault
```

**2. HashiCorp Vault**

[Vault](https://www.hashicorp.com/products/vault) uses Shamir for **unseal**: the storage encryption key is split at init (e.g. 3-of-5 operators each hold a share). After restart, **K** shares must be entered to unseal. Same **K-of-N on a master secret** pattern as LUKS, applied to a secrets engine rather than a block device.

**3. Galdralag firmware (`vsss-rs`)**

This repository uses [`vsss-rs`](https://crates.io/crates/vsss-rs) (RustCrypto ecosystem) for on-device Shamir. The same **layering** applies if you align it with bulk encryption:

- Generate a random 256-bit (or appropriate) master key.
- Encrypt the drive or bulk store with **AES-GCM** or **ChaCha20-Poly1305** using that key (this matches the workspace’s audited symmetric crates).
- Use `vsss-rs` to split the master key into **N** shares with threshold **K**.
- Store shares in vault slots, other devices, or with key holders.
- On boot or recovery, collect **K** shares, reconstruct, then use **HKDF** (or your policy) for domain-separated subkeys if needed.

**4. VeraCrypt**

VeraCrypt does not implement SSS internally. The same **external** pattern applies: split the **passphrase or keyfile material** with an SSS tool; do not try to Shamir-split the volume’s ciphertext.

### Hybrid pattern (large data)

SSS is for **small secrets** (key size). You **do not** apply Shamir to multi-gigabyte ciphertext. The usual layering:

```text
[Drive data]
    encrypted by
[Symmetric master key, e.g. 32-byte AES-256]
    split by SSS into
[Share 1] [Share 2] ... [Share N]
    (each share may be wrapped with a recipient’s PGP key, HSM, or offline media)
```

That lines up with what this project already stacks: **aes-gcm** / **chacha20poly1305** for data at rest, **vsss-rs** for splitting the master secret, **hkdf** for derivation after reconstruction.

### Key practical decisions

| Decision | Typical options |
|----------|-------------------|
| **Threshold** | 2-of-3 (small team, some redundancy); 3-of-5 (common in organisations) |
| **Share storage** | Hardware tokens, separate machines, paper, geographically split sites |
| **Share protection** | Encrypt each share for a specific recipient (e.g. with their OpenPGP key) before distribution |
| **Where to reconstruct** | Air-gapped machine, HSM policy, or controlled environment — not on untrusted shared hosts |

Operational key handling for LUKS and full-disk encryption is security-sensitive; follow vendor and distribution guidance and threat models for your environment.

### Shamir plus Brainpool: example and institutional fit

One concrete pattern is a **drive or volume** encrypted using **Brainpool** curves where your stack requires them (for example ECDH/ECDSA around a **master secret**), combined with **Shamir’s Secret Sharing** on the **key material** that unlocks that encryption (the same [small-secret layering](#hybrid-pattern-large-data) as above: SSS protects the key, not multi-gigabyte ciphertext). If and when **firmware and host software** implementing that workflow have been **independently audited**, such a combination can be valuable to organisations that must meet **quorum** policies and **national crypto** profiles at the same time.

**Why Brainpool curves (e.g. BrainpoolP256r1, BrainpoolP384r1, BrainpoolP512r1) are often discussed in that context:**

- **BSI** (Germany’s federal cybersecurity authority) mandates Brainpool in many deployment profiles; requirements appear in **EU government** and **NATO** procurement and policy settings.
- Parameters are **fully specified and verifiable** in [RFC 5639](https://datatracker.ietf.org/doc/html/rfc5639), which reduces “nothing up my sleeve” concerns compared with older debates around some NIST curve generation methods.
- **IETF precedent:** RFC 5639 is already on the standards track for these curves.

**Scenarios where combining SSS with Brainpool-class cryptography addresses institutional needs** (illustrative; not legal or compliance advice):

| Scenario | Why SSS plus strong, policy-aligned curves matter |
|----------|---------------------------------------------------|
| Employee leaves or dies | Recovery remains possible **without** that person’s exclusive secret |
| Lawful access under due process | A **quorum** can be required — no single party holds the full unlocking secret |
| Corporate key escrow | **Auditable** split; no single administrator has complete access |
| Hardware seizure | Media may be captured without capturing **K** of **N** shares |
| Regulatory alignment (EU / BSI) | Brainpool satisfies many **German and EU** government cryptography requirements |

---

## Standards process: Shamir and ephemeral key exchange

When and if the hardware reaches a **consumer-ready** state, people who want **Shamir’s Secret Sharing** and **authenticated ephemeral key exchange** to become part of interoperable **OpenPGP / GnuPG** behaviour (instead of only firmware-specific features) would need to drive **standards and implementation** change elsewhere. This repository does not speak for the IETF or GnuPG; the venues below are where such amendments are normally pursued.

### IETF (primary venue)

The OpenPGP protocol standard is developed at the **IETF**. The relevant working group:

| Resource | Link or address |
|----------|-----------------|
| Working group (charter, chairs) | [OpenPGP WG — datatracker](https://datatracker.ietf.org/wg/openpgp/about/) |
| Public mailing list | `openpgp@ietf.org` |
| List archive and subscription | [mailarchive.ietf.org — openpgp](https://mailarchive.ietf.org/arch/browse/openpgp/) |

**Internet-Drafts** are the usual way to propose new functionality: publish a draft, then post to the list with the problem statement and a link to the draft. Working group chairs and participants decide whether a document becomes a **working group item** and eventually an RFC. An email that explains the need and points at a draft is the typical opening step.

### GnuPG

[GnuPG](https://gnupg.org/) maintainers and developers have strong influence on what operators deploy and what gets discussed in the OpenPGP WG.

| Resource | Link or address |
|----------|-----------------|
| Developer list | `gnupg-devel@gnupg.org` |
| Issue tracker / proposals | [dev.gnupg.org](https://dev.gnupg.org) |
| Project lead | Werner Koch remains the primary author; contact addresses are listed on [gnupg.org](https://gnupg.org/) (e.g. `wk@gnupg.org`). |

### Other OpenPGP implementations

Engaging **multiple** implementations at the same time **strengthens a proposal considerably**: the OpenPGP ecosystem is not only GnuPG, and implementors often share IETF and de facto interoperability work.

| Implementation | Notes |
|----------------|--------|
| [OpenPGP.js](https://github.com/openpgpjs/openpgpjs) | Widely deployed in browsers and application stacks |
| [Sequoia PGP](https://sequoia-pgp.org) | Modern Rust implementation; often sympathetic to Rust-heavy stacks and cross-implementation work |

### Sequoia PGP (if this repository is unresponsive)

If **maintainers of this GitHub repository** do not answer issues, pull requests, or mail, you can still advance **new ciphers**, **OpenPGP behaviour**, and **standards-related work** in the wider ecosystem. **[Sequoia PGP](https://sequoia-pgp.org/)** is an independent, Rust-based OpenPGP stack (memory safety, library-first design, active IETF/ecosystem participation) where much public development happens. It is **not** this project; it is documented here as a **practical alternate path** when upstream here is silent.

| Goal | Where to start |
|------|----------------|
| Project overview, news, community | [sequoia-pgp.org](https://sequoia-pgp.org/) |
| **Contribute** (issues, fixes, features, documentation); **contact before large work** | [Contribute](https://sequoia-pgp.org/contribute/), [Contact](https://sequoia-pgp.org/contact) |
| **Developer docs** — API surface for extending the implementation (`sequoia-openpgp` and related crates) | [Docs](https://sequoia-pgp.org/docs/) — e.g. [sequoia-openpgp on docs.rs](https://docs.rs/sequoia-openpgp/latest/sequoia_openpgp/) |
| **Source and trackers** | [gitlab.com/sequoia-pgp](https://gitlab.com/sequoia-pgp) (core library and tools); [github.com/sequoia-pgp](https://github.com/sequoia-pgp) (mirrors / selected repos); [Projects](https://sequoia-pgp.org/projects) |
| **New algorithms in the OpenPGP standard** | Still go through the **[IETF OpenPGP working group](#ietf-primary-venue)**. Sequoia and other implementations implement drafts and RFCs; propose protocol changes there, and coordinate with implementors (including Sequoia) so behaviour matches the spec. |

The [Contribute](https://sequoia-pgp.org/contribute/) page describes licensing (LGPL 2.0 or later for most projects), the Developer Certificate of Origin, and that **larger commercial features** may require prior agreement and long-term maintenance arrangements — read that page before investing significant effort.

---

## Build, install, and uninstall

Use a **stable Rust** toolchain as pinned in [rust-toolchain.toml](rust-toolchain.toml). Firmware uses the `riscv32imac-unknown-none-elf` target; host tools use the host triple.

### Compile firmware

1. Install the embedded target:

   ```bash
   rustup target add riscv32imac-unknown-none-elf
   ```

2. Type-check firmware crates (fails if `test-hal` would leak into production builds):

   ```bash
   cargo run -p xtask -- check-fw
   ```

3. Build firmware crates in release mode:

   ```bash
   cargo run -p xtask -- build-fw
   ```

   Object code and archives land under `target/riscv32imac-unknown-none-elf/release/`. A full bootable **Xous** system image for a specific board is produced by the wider Baochip / Xous integration flow when you follow that product’s build; `xtask` here runs `cargo build` for the firmware library crates listed in `xtask` (not a single ready-to-flash file by itself).

### Flashing

This repository does **not** ship a one-command flasher. Programming the **Baochip-1x** (JTAG, ROM/USB boot, or vendor tools) follows the board and silicon documentation. Start from the **[Baochip-1x firmware design README](https://raw.githubusercontent.com/Supermagnum/Baochip-1x-firmware/refs/heads/main/README.md)** and your board’s flashing guide.

### Compile and install host tools (`galdra`, `galdrad`, `galdra-gtk`)

Host crates live at the workspace root: `galdra/`, `galdrad/`, `galdra-gtk/`.

**GTK 4 (required for `galdra-gtk` only):** install development packages so `pkg-config` can find `gtk4` (crate `gtk4` 0.9). Examples: Debian/Ubuntu — `libgtk-4-dev`; Fedora — `gtk4-devel`; Arch — `gtk4`.

Build release binaries from the repository root:

```bash
cargo build --release -p galdra -p galdrad -p galdra-gtk
```

Executables: `target/release/galdra`, `target/release/galdrad`, `target/release/galdra-gtk`.

**Install** into `~/.cargo/bin` (adjust `--path` if you are not in the repo root):

```bash
cargo install --locked --path galdra
cargo install --locked --path galdrad
cargo install --locked --path galdra-gtk
```

You can instead copy those three binaries to any directory on your `PATH`.

### Uninstall host tools

If you used `cargo install --path` as above:

```bash
cargo uninstall galdra
cargo uninstall galdrad
cargo uninstall galdra-gtk
```

If you copied binaries manually, remove the files you added. Firmware is not “installed” on the host; erasing or reflashing the device is covered by your hardware documentation.

---

## Key capabilities

### What makes this token unusual

The items below are **Galdralag firmware capabilities**, not requirements of the [OpenPGP card application](#standards-vs-firmware-specific-features) or GnuPG.

- **Authenticated ephemeral ECDH on-device** — true cryptographic forward
  secrecy. Each session generates a fresh ephemeral key pair on the token's
  hardware TRNG. The long-term key signs the ephemeral offer but never
  participates in key agreement. Past sessions cannot be decrypted even from
  a fully compromised long-term key. To the project authors' knowledge, no
  commercial hardware security token provides this as a first-class feature.

- **Shamir K-of-N secret sharing on-device** — the long-term key can be
  split into N shares requiring K to reconstruct, with no single holder able
  to recover the key alone. To the project authors' knowledge, no commercial
  token provides this as a first-class feature either.

- **Cipher-agnostic profile system** — symmetric ciphers, ECDHE curves, and
  Shamir configuration are combined into named, auditable profiles. A cascade
  of multiple independent ciphers (e.g. Serpent-256 + ChaCha20-Poly1305) can
  be selected per session. Every profile selection is logged in the audit trail.

- **Optional PSRAM decoy volume** — if a PSRAM chip is fitted, an extra bulk
  decoy LUN can appear after unlock. **If no PSRAM is fitted, the device is
  still a hardware security token** (vault, PIN policy, OpenPGP/CCID, and other
  token functions are unchanged); only that optional bulk volume is absent. For
  uninformed hosts, the device still presents the usual on-chip mass-storage
  decoy persona where configured. PSRAM content, when present, is intentionally
  unencrypted and unremarkable. Real key material lives in on-chip RRAM behind
  the vault and PIN policy.

- **Fully open stack** — CERN-OHL-W-2.0 RTL, open schematics, reproducible
  bootloader, Rust/Xous OS, IRIS-inspectable silicon.

### Cryptographic capabilities

All primitives come from independently audited workspace dependencies.
Nothing is implemented in-tree.

#### Asymmetric / key agreement

| Algorithm | Standard | Notes |
|-----------|----------|-------|
| BrainpoolP256r1 ECDH + ECDSA | RFC 5639, BSI TR-03111 | BSI-standardised, no NSA involvement |
| BrainpoolP384r1 ECDH + ECDSA | RFC 5639, BSI TR-03111 | ~192-bit security |
| BrainpoolP512r1 ECDH + ECDSA | RFC 5639, BSI TR-03111 | ~256-bit security |
| X25519 ECDH | RFC 7748 | |
| Ed25519 sign / verify | RFC 8032 | |
| RSA-2048 / 3072 / 4096 OAEP, PSS | RFC 8017 | Minimum 2048-bit enforced |
| P-256, P-384 | NIST | Via `p256` / `p384` workspace deps |

#### Symmetric / AEAD

| Algorithm | Standard | Notes |
|-----------|----------|-------|
| AES-256-GCM | FIPS 197, NIST SP 800-38D | Hardware AES on Baochip-1x |
| ChaCha20-Poly1305 | RFC 8439 | No NSA involvement |
| Twofish-256 | Schneier et al. 1998 | AES finalist, no NSA involvement |
| Serpent-256 | Anderson / Biham / Knudsen 1998 | AES finalist, 32 rounds, conservative margin |

#### Key derivation / MAC / digest

| Algorithm | Standard |
|-----------|----------|
| HKDF (SHA-256 / SHA-512) | RFC 5869 |
| HMAC (SHA-256 / SHA-512) | RFC 2104 |
| PBKDF2 | RFC 8018 |
| SHA-2 (224 / 256 / 384 / 512) | FIPS 180-4 |
| SHA-3 family | FIPS 202 |
| BLAKE2b / BLAKE2s | RFC 7693 |
| BLAKE3 | BLAKE3 specification |

#### Key management

| Feature | Notes |
|---------|-------|
| Shamir K-of-N secret sharing | `vsss-rs` — on-device split and recovery |
| Authenticated ephemeral ECDH | Forward-secret session protocol — `ephemeral-session` crate |
| Cipher profile system | User-configurable cipher cascade — `cipher-profile` crate |

### Security properties

| Property | Implementation |
|----------|---------------|
| Forward secrecy | Ephemeral ECDH: long-term key signs only, never agrees |
| PIN counter before compare | Counter flushed to RRAM before `subtle::ConstantTimeEq` — no exceptions |
| Hardware zeroisation | TRNG-sourced multi-pass overwrite; boot0 zeroises before USB enumeration |
| No secret on USB bus | Uninformed host sees only standard mass-storage; no fingerprint possible |
| Monotonic tamper evidence | Hardware one-way counters in always-on domain |
| Constant-time operations | All secret comparisons via `subtle`; verified by dudect harnesses |
| test-hal never in production | Enforced by `check-fw` xtask |

### PIN policy

- Minimum length: **5 alphanumeric characters** — enforced at parser boundary,
  before `pin-policy` is called. Short inputs do not increment the counter.
- Default attempt threshold: **3** (configurable 3–10 at provisioning).
  Matches hardware token industry standard (Nitrokey, YubiKey, ISO 7816).
- On threshold: full hardware zeroisation triggered.
- Challenge/response passphrase (USB informed-host path): minimum 5 characters,
  transmitted only as `HMAC-SHA256(HostChallengeKey, nonce || passphrase)`.

---

## Post-quantum status

### Implemented — unaudited crate (feature-gated)

XMSS (RFC 8391, NIST SP 800-208) and LMS/HSS (RFC 8554, NIST SP 800-208)
are implemented behind `--features pq-signatures`. The underlying Rust crates
have not been independently audited. See
[docs/PQ_SIGNATURES.md](docs/PQ_SIGNATURES.md) and
[docs/STATEFUL_SIG_STATE.md](docs/STATEFUL_SIG_STATE.md).

### Pending independent audit — not yet implemented

These algorithms are NIST-standardised. Implementation is blocked on an
independently audited `no_std` Rust crate becoming available.

| Algorithm | Standard | Awaiting |
|-----------|----------|---------|
| ML-KEM | FIPS 203 | Audited `no_std` Rust crate |
| ML-DSA | FIPS 204 | Audited `no_std` Rust crate |
| SLH-DSA | FIPS 205 | Audited `no_std` Rust crate |
| FN-DSA (FALCON) | FIPS 206 draft | Standard finalisation + audited crate |
| HQC | Draft ~2027 | Standard finalisation + audited crate |

**Note on libcrux:** A 2026 academic paper identified specification-level bugs
in libcrux's formally verified ML-KEM and ML-DSA implementations including
proofs rendered unsound. Check the libcrux changelog before evaluating it.

### Will not be implemented

**BIKE** was eliminated from NIST standardisation in March 2025 in favour of
HQC. **NTRU** encryption was eliminated in July 2022. Neither has a path to a
NIST standard.

---

## Zeroisation — hardware caveat

The zeroisation implementation is **software-correct but hardware-unverified**.
It has been tested using `test-hal` simulation only. Physical verification on
Baochip-1x silicon (JTAG memory inspection, power-cycle resilience, side-channel
confirmation) has not yet been performed. See
[docs/HARDWARE_VERIFICATION.md](docs/HARDWARE_VERIFICATION.md).

---

## Test results

Full vector coverage, dudect t-statistics, RFC / BSI / NIST CAVP pass/fail
tables, fuzzing (including **openpgp_dispatch** libFuzzer notes), and key lifecycle results:
**[docs/TEST_RESULTS.md](docs/TEST_RESULTS.md)** — see **Section 10** for cargo-fuzz matrices and the recorded **`openpgp_dispatch`** long-run interpretation.

```
cargo run -p xtask -- test-all
```

---

## Workspace layout

| Crate | Role |
|-------|------|
| `galdr-core` | HAL traits (`MonotonicCounter`, `HardwareTrng`, `ZeroiseController`, `VaultStorage`), shared errors, `test-hal` fakes |
| `vault` | RRAM vault contracts, HKDF `KeyPurpose` labels, key material types (`zeroize`, no `Clone`/`Copy`) |
| `pin-policy` | PIN state machine; counter increment before `subtle::ConstantTimeEq`; threshold zeroisation |
| `usb-personality` | Mass-storage vs authenticated-unlock personas; challenge/response; OpenPGP/CCID card application; USB disconnect-on-lock |
| `psram-store` | Optional PSRAM block device; probe-absent short-circuit; mount/unmount access gate |
| `ephemeral-session` | Authenticated ephemeral ECDH session protocol; forward secrecy |
| `cipher-profile` | User-configurable cipher cascade profiles; built-in and user-defined |
| `security-tests` | dudect timing harnesses for all cryptographic paths |
| `host-tools` | Host manifest hashing, update verification, `psram-unlock` binary |
| `xtask` | Build, check, test, fuzz, timing-test orchestration |

---

## Cryptographic dependency policy

Primitives are **not implemented in-tree**. All cryptographic work uses
audited workspace dependencies from the RustCrypto project (except `vsss-rs`
and the dalek family, which have had independent review):

```
aes-gcm  chacha20poly1305  ed25519-dalek  x25519-dalek
hkdf  pbkdf2  hmac  sha2  sha3  blake2  blake3
vsss-rs  zeroize  subtle  p256  p384
```

Using audited crates means this project inherits their audit history rather
than introducing unreviewed cryptographic code.

---

## Quick start

Firmware build prerequisites and install paths are in [Build, install, and uninstall](#build-install-and-uninstall) above.

```bash
rustup target add riscv32imac-unknown-none-elf
cargo test --workspace --exclude xtask
cargo run -p xtask -- check-fw
cargo run -p xtask -- build-fw
cargo run -p xtask -- test-host
cargo run -p xtask -- test-all
cargo run -p xtask -- timing-test
```

**Fuzzing (libFuzzer):** install `cargo-fuzz`, use nightly, then e.g. `cargo run -p xtask -- fuzz chacha_roundtrip 60` or `cargo run -p xtask -- fuzz openpgp_dispatch 60` (OpenPGP APDU path). Target names, xtask aliases, and **recommended corpus seeds** per target are in [fuzz/README.md](fuzz/README.md).

Enable `galdr-core` feature `test-hal` **only** in tests or host tools.
Never enable it in production firmware images — enforced by `check-fw`.

---

## License

GNU General Public License v3.0 — see [LICENSE](LICENSE).
