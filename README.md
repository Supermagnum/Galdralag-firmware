# Galdr — Galdralag Firmware

## Open Invention Network

![Open Invention Network member](docs/oin-member-horiz.jpg)

This project is **registered with the [Open Invention Network (OIN)](https://openinventionnetwork.com/)**. OIN is a defensive patent pool: members cross-license Linux-related patents so participants can ship and use open-source software with reduced patent exposure.

## Skipped and ignored tests

Not every test runs in every command; that is intentional.

- **`xtask` not in the default workspace test:** The common recipe is `cargo test --workspace --exclude xtask` because `xtask` is a build-orchestration crate. Run `cargo test -p xtask` when you want its tests.
- **Tests marked `#[ignore]`:** These are skipped unless you pass `--ignored` (and any needed crate filters). Reasons include: coverage that is already exercised in focused unit tests (e.g. post-drop zeroization), **slow** cases (e.g. RSA key generation), and **hardware or token-dependent** flows in host tools such as `galdra` that need a connected device or fixtures.
- **`test-all --no-fuzz`:** Skips the **cargo-fuzz** step to keep CI or quick runs short and to avoid requiring a nightly toolchain for that step; run `cargo run -p xtask -- test-all` without `--no-fuzz`, or invoke fuzz targets separately (see [`fuzz/README.md`](fuzz/README.md)).
- **Conformance vector suites:** Some groups are not executed (for example certain AES-GCM Wycheproof cases); see [`docs/TEST_RESULTS.md`](docs/TEST_RESULTS.md) for what is in scope.

One can also check with this tool:
https://github.com/Supermagnum/crypto-verify


> **Status:** Ready for testing by humans — no production-ready release exists.
> It's written in Rust using validated and audited crypto crates. 
> Cryptographic primitives are drawn exclusively from audited workspace
> dependencies. Post-quantum algorithms are feature-gated and marked
> **PENDING INDEPENDENT AUDIT**. See [Post-quantum status](#post-quantum-status).

> **Note:** Parts of this project were developed with AI assistance (Claude, Anthropic).
> The design, cryptographic choices, and security decisions have not been reviewed
> by a professional cryptographer. Treat this as an experimental project and apply
> your own critical judgement. Independent expert review is strongly recommended
> before any production deployment.

It is ready for testing by humans. **You** decide whether to build or run any of this software; there may be bugs that **unit tests, fuzzing, and other checks** have not found. Using an **optional virtual machine** for experimentation **reduces risk** to your host system but does not eliminate it. Detailed results are in **[Test results](#test-results)** ([`docs/TEST_RESULTS.md#run-metadata`](docs/TEST_RESULTS.md#run-metadata)). **Plain-language definitions** (A–Z) of technical terms: **[Glossary](docs/GLOSSARY.md)**.

## Table of contents

- [Open Invention Network](#open-invention-network)
- [Skipped and ignored tests](#skipped-and-ignored-tests)
- [Why Rust?](#why-rust)
  - [Memory Safety](#memory-safety)
  - [System-level robustness (with limits)](#system-level-robustness-with-limits)
  - [Key material protection (project patterns)](#key-material-protection-project-patterns)
  - [Auditable by design](#auditable-by-design)
  - [What Rust does not prevent](#what-rust-does-not-prevent)
  - [Setting up a virtual machine for evaluation](#setting-up-a-virtual-machine-for-evaluation)
  - [Risk assessment and deployment](#risk-assessment-and-deployment)
- [About the name](#about-the-name)
- [What this is](#what-this-is)
  - [Signed firmware (Ed25519, boot0)](#signed-firmware-ed25519-boot0)
- [Documentation](#documentation)
- [Glossary (plain language)](docs/GLOSSARY.md)
- [OpenPGP and GnuPG compatibility](#openpgp-and-gnupg-compatibility)
- [Token session and key export](#token-session-and-key-export)
- [Standards vs. firmware-specific features](#standards-vs-firmware-specific-features)
- [Shamir secret sharing and drive encryption](#shamir-secret-sharing-and-drive-encryption)
- [Standards process: Shamir and ephemeral key exchange](#standards-process-shamir-and-ephemeral-key-exchange)
  - [CESS (related open standard)](#cess-related-open-standard)
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

## Why Rust?

This firmware is written in Rust, a systems programming language designed
to be as fast and low-level as C or C++, but with a fundamentally different
approach to safety.

### Memory Safety

A large share of security-relevant bugs in industry codebases come from **memory unsafety** (buffer overflows, use-after-free, null dereferences, and similar). Microsoft’s MSRC has **repeatedly reported** that roughly **70% of CVEs addressed in their own products** fall into this category; the **Chrome** team has published similar proportions for Chrome. Those figures describe **those vendors’ products**, not a universal law for all firmware, but they illustrate why memory-safe languages matter.

In **safe Rust** (the default), the **borrow checker** rules out data races and the usual undefined-behaviour memory errors at compile time **without** relying on garbage collection. **Unsafe Rust** and **FFI** to C can still introduce memory bugs; they must be kept small and reviewed.

### System-level robustness (with limits)

Rust’s **bounds checking** on slices and its **ownership rules** reduce several classes of failure modes common in C/C++ embedded code:

- **Buffer and stack smashes** that corrupt control flow are caught at compile time in safe code or via checked indexing at runtime instead of silent UB.
- **Data races** in concurrent safe Rust are rejected by the compiler (deadlocks are **not** eliminated — see below).
- **`unsafe` blocks** must be explicit; **MMIO** and raw pointers for registers live there, so reviewers can **grep** for the audit surface (unsafe does **not** make incorrect MMIO impossible, only easier to localize).

Rust does **not** by itself stop **logic bugs** such as a tight loop that wears **flash**, or choosing wrong register values. Those remain engineering and review concerns.

### Key material protection (project patterns)

This codebase applies common Rust patterns for secrets; they are **not** automatic for every type:

- Types like **`zeroize::Zeroize` / `ZeroizeOnDrop`** clear buffers on drop; callers opt in.
- **Secret comparisons** use **`subtle::ConstantTimeEq`** (and similar) where timing matters — ordinary `==` is not magically constant-time.
- **No `Copy` on secret wrappers** reduces accidental duplication; domain separation uses **distinct types** and **HKDF labels** ([Cryptographic dependency policy](#cryptographic-dependency-policy)).
- **Panic behaviour** and **drop order** follow Rust rules; use `catch_unwind` or `abort` strategies where your platform requires stronger guarantees.

### Auditable by design

**`unsafe`** must be **spelled out** in source, which narrows manual review. **Dependencies:** this project’s cryptographic policy favours **audited Rust crates** (RustCrypto and others); see the table in [Cryptographic dependency policy](#cryptographic-dependency-policy) — not every dependency is from a single umbrella project.

### What Rust does not prevent

Rust does **not** remove **deadlocks** (e.g. mis-ordered `Mutex` locks), **logic bugs**, **incorrect protocols**, **flash wear** from bad loops, **physical attacks** (glitching, power analysis), or risks from a **correct build of the wrong image**. It also does not guarantee constant-time execution on all hardware without careful coding. Those areas rely on **design, review, testing**, and the project’s **crypto and supply-chain** practices described elsewhere in this README.

**Verification (tests and fuzzing):** Beyond the language, this repository uses **unit tests**, **integration tests**, **dudect** timing harnesses, and **libFuzzer** (`cargo-fuzz`) targets. Summaries and matrices are in **[Test results](#test-results)**; the **recorded run metadata** starts at [`docs/TEST_RESULTS.md#run-metadata`](docs/TEST_RESULTS.md#run-metadata). **Passing tests do not** prove production readiness or absence of vulnerabilities — they narrow risk. **You** judge whether running builds or tests is acceptable for your environment; a **virtual machine** is optional but **limits blast radius** on your machine.

### Setting up a virtual machine for evaluation

Any major VM platform is suitable — **VirtualBox** (free, open source),
**QEMU** (free, open source, command-line), or **VMware**. A **Linux guest**
is recommended as the build environment is best supported there.

Quick start with QEMU and Ubuntu:

```bash
# Install QEMU
sudo apt install qemu-system-x86  # Debian/Ubuntu host
# or
brew install qemu                  # macOS host

# Download an Ubuntu Server ISO and boot it
qemu-system-x86_64 -m 2G -cdrom ubuntu-24.04-live-server-amd64.iso
```

Inside the VM, the standard build instructions apply. The VM can
be **snapshotted** before each experiment and **rolled back** cleanly if
anything goes wrong.

### Risk assessment and deployment

**Ultimately, whether this firmware is safe to deploy in your
environment is a decision only you can make**, based on your own
risk assessment, the sensitivity of what you are protecting, and
whether you choose to wait for an independent third-party audit
before deployment. This project aims to give you all the
information needed to make that decision for yourself.

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
usage are documented in **[Supermagnum/Baochip-1x-firmware](https://github.com/Supermagnum/Baochip-1x-firmware)**.
The **Dabao** evaluation board (KiCad, schematics, switches, pinout) is **[baochip/dabao](https://github.com/baochip/dabao)**. To enter **bootloader mode** for flashing, **press SW2** to toggle it (see that repo’s schematic).
Architecture notes for this repository: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

**CESS:** This firmware **conforms to CESS** for the normative constructions implemented in-tree (including **Mode A** outer AEAD, **HKDF-BLAKE3** for **`K_outer`**, and byte-wise GF(2^8) Shamir splitting). The full alignment statement, deviation register, and **certification level** (for example **CESS-CORE** for the full fixed layer) are documented in [docs/CESS_CONFORMANCE.md](docs/CESS_CONFORMANCE.md) and [CESS (related open standard)](#cess-related-open-standard) below.

The only remaining work before physical hardware works is the Xous USB service wiring — and that is documented in [docs/XOUS_CCID_INTEGRATION.md](docs/XOUS_CCID_INTEGRATION.md), waiting for the BSP crates to be available.

At that point the project will be a complete, tested, open-source hardware security token firmware: **OpenPGP card–style behaviour** for GnuPG over CCID (see [OpenPGP and GnuPG compatibility](#openpgp-and-gnupg-compatibility)), plus **additional on-device features** not currently defined by the OpenPGP card standard — ephemeral ECDH with forward secrecy, Shamir K-of-N, cipher-agnostic profiles, microSD decoy volume — as summarised in [Standards vs. firmware-specific features](#standards-vs-firmware-specific-features). All on open RTL with a reproducible bootloader.

### Signed firmware (Ed25519, boot0)

Shippable firmware for **Baochip-1x** is **signed** with **Ed25519**. You sign the firmware image with an **Ed25519** private key; **GnuPG** can do this with **`gpg --sign`** using an **Ed25519 signing subkey** (the usual OpenPGP detached-signature workflow, adapted to whatever packaging your build emits). The immutable **boot0** ROM in the SoC **verifies** that signature against the **corresponding public keys burned into the device** (and the wider **key manifest** for the boot chain) **before** the next stage — **boot1** — is allowed to run. **boot1** then loads signed application images (for example **UF2** blobs delivered over USB mass storage in bootloader mode). Default parts carry **four** on-chip Ed25519 public keys (roles such as code deployment, beta, and developer); **boot0** / **boot1** enforce a **mutual-distrust** policy between Baochip and third-party signing keys. Full boot flow, **UF2** delivery, console, **boot1** updates, and security model: **[Getting Started with Baochip Targets](https://github.com/betrusted-io/xous-core/blob/dev/README-baochip.md)** in **xous-core**.

---

## Documentation

**Glossary:** [docs/GLOSSARY.md](docs/GLOSSARY.md) — terms explained in **plain language** (sorted A–Z). Start here if the README or other docs feel jargon-heavy.

**AI assistants (Claude, Cursor):** [CLAUDE.md](CLAUDE.md) — project instructions for coding agents. Cursor-specific rules: [`.cursor/rules/`](.cursor/rules/).

**Browse all files:** [github.com/Supermagnum/Galdralag-firmware — `docs/`](https://github.com/Supermagnum/Galdralag-firmware/tree/main/docs)

**Hardware (USB dongle and related):** [Hardware/](Hardware/) — KiCad project (`dabao_v3c`), gerbers, BOM, production outputs, and [pinout docs](Hardware/docs/pinout/README.md). The USB-A dongle PCB layout (minimal token vs Pico-format eval) is described in [docs/USB_DONGLE_PCB.md](docs/USB_DONGLE_PCB.md).

| Document | Description |
|----------|-------------|
| [Hardware/](Hardware/) | **USB dongle** design files and related outputs: KiCad, gerbers, BOM, pinout; complements [USB_DONGLE_PCB.md](docs/USB_DONGLE_PCB.md) |
| [docs/API_REFERENCE.md](docs/API_REFERENCE.md) | Code map + **annex** for IETF/I-D/GnuPG/Sequoia: Shamir GF(256) construction, GALDRA SHARE armour, ephemeral ECDH wire format, HKDF labels, preimages; `galdrad` routes; rustdoc hints |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | High-level firmware architecture and major subsystems |
| [docs/GALDRA-TOOL.md](docs/GALDRA-TOOL.md) | Host tools (`galdra`, `galdrad`, `galdra-gtk`): workflows, provisioning, PIN policy, operational behaviour |
| [docs/GLOSSARY.md](docs/GLOSSARY.md) | **Plain-language glossary** (A–Z) for non-technical readers; technical detail remains in linked docs |
| [CLAUDE.md](CLAUDE.md) | Instructions for **Claude** / AI coding agents; points to [`.cursor/rules/`](.cursor/rules/) for **Cursor** |
| [docs/GALDRALAG_DEV_REFERENCE.md](docs/GALDRALAG_DEV_REFERENCE.md) | Toolchain, `xtask` commands, fuzzing and crypto test entry points |
| [docs/dev-ref.md](docs/dev-ref.md) | Workspace layout, crates, HAL traits, USB/PSRAM behaviour, security invariants |
| [docs/OPENPGP_CARD.md](docs/OPENPGP_CARD.md) | OpenPGP card application, GnuPG/CCID host setup, key slots, algorithms, udev |
| [docs/XOUS_CCID_INTEGRATION.md](docs/XOUS_CCID_INTEGRATION.md) | Wiring CCID/OpenPGP USB into Xous on Baochip |
| [docs/CIPHER_PROFILES.md](docs/CIPHER_PROFILES.md) | Cipher profile system and configuration |
| [docs/CIPHER_PROFILE_SECURITY.md](docs/CIPHER_PROFILE_SECURITY.md) | Security considerations: cleartext profile identifiers, traffic analysis, BrainpoolP384r1 outer-wrapper rationale, encrypted identifiers, wildcard property |
| [docs/CESS_CONFORMANCE.md](docs/CESS_CONFORMANCE.md) | [CESS](https://github.com/Supermagnum/CESS/tree/main) alignment: Mode A wire layout, `suite_id` from [ALGORITHM-REGISTRY.md — lookup table](https://github.com/Supermagnum/CESS/blob/main/ALGORITHM-REGISTRY.md#cipher-suite-identifier-lookup-table), deviation register (retained AES/SHA-2 vs CESS-CORE), roadmap |
| [crates/cess](crates/cess) | CESS Mode A: HKDF-BLAKE3 (`derive_k_outer`, `hkdf_blake3`), ChaCha outer seal/open, `suite_id \|\| inner_blob` layout; see [CESS_CONFORMANCE.md](docs/CESS_CONFORMANCE.md) |
| [docs/EPHEMERAL_SESSION.md](docs/EPHEMERAL_SESSION.md) | Authenticated ephemeral ECDH session protocol |
| [Supermagnum/CESS](https://github.com/Supermagnum/CESS) | **CESS** (*Cryptologically Enchanted Shamir's Secret*) — open specification (normative text and test vectors) for threshold secret sharing with authenticated encryption, password-based share wrapping, and optional post-quantum hybrid key exchange; separate from this firmware but in the same design space as Shamir and cipher profiles here |
| [docs/PQ_SIGNATURES.md](docs/PQ_SIGNATURES.md) | Post-quantum stateful signatures (XMSS, LMS/HSS), feature gating |
| [docs/Psram.md](docs/Psram.md) | Optional microSD decoy volume and related behaviour |
| [docs/TEST_RESULTS.md](docs/TEST_RESULTS.md#run-metadata) | Opens at **Run metadata**; pipeline summary, vectors, dudect, cargo-fuzz ([Section 6](docs/TEST_RESULTS.md#6-cargo-fuzz-libfuzzer)), key lifecycle |
| [docs/PERFORMANCE.md](docs/PERFORMANCE.md) | Performance notes |
| [docs/HARDWARE_VERIFICATION.md](docs/HARDWARE_VERIFICATION.md) | Hardware zeroisation: simulation vs silicon verification |
| [docs/HARDWARE_TEST.md](docs/HARDWARE_TEST.md) | Hardware-oriented testing notes |
| [docs/NFC_PN532_INTEGRATION.md](docs/NFC_PN532_INTEGRATION.md) | PN532 / NFC: libnfc, Rust options, door passive vs USB panel, quorum with Shamir and PIN |
| [docs/SDMMC_STORAGE_INTEGRATION.md](docs/SDMMC_STORAGE_INTEGRATION.md) | `embedded-sdmmc` + SPI microSD as optional bulk storage; BOM alternative to PSRAM |
| [docs/USB_DONGLE_PCB.md](docs/USB_DONGLE_PCB.md) | How to make a USB-A dongle PCB from the Dabao reference: Pico-format eval is for firmware bring-up; this strips GPIO header for a minimal token; KiCad, FreeCAD, 5 V / 500 mA vs USB-C PD, QSPI PSRAM routing |

The same paths resolve on GitHub under [`tree/main/docs`](https://github.com/Supermagnum/Galdralag-firmware/tree/main/docs) and [`tree/main/Hardware`](https://github.com/Supermagnum/Galdralag-firmware/tree/main/Hardware).

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

**Integration status:** The OpenPGP and CCID logic lives in **`usb-personality`** and is covered by unit tests, integration tests, and the **`openpgp_dispatch`** fuzz target (see [TEST_RESULTS — Section 6](docs/TEST_RESULTS.md#6-cargo-fuzz-libfuzzer)). Wiring the USB **CCID** service into the running **Xous** image is still **integration work**; follow [docs/XOUS_CCID_INTEGRATION.md](docs/XOUS_CCID_INTEGRATION.md). Until that is done, **end-to-end GnuPG against real hardware** is not available, even though the card application behaviour is implemented in firmware sources.

## Token session and key export

**Physical disconnect (unplug):** The host loses the USB device; any in-flight operation fails until the token is connected again and re-enumerated. On the device, the OpenPGP **card session** is cleared: **PIN verification state** does not survive power-off or removal, so **signing, decryption, and other protected operations require VERIFY PIN again** after reconnect, like other OpenPGP smart cards. **Private key material remains stored on the token** in sealed vault storage; unplugging does not erase it unless a separate **zeroisation** or wipe path runs.

**What may leave the device:** By design, **only public key material** is permitted to cross the USB link (for example OpenPGP **public** key packets and related data the card specification exposes to the host). **Private** keys, raw secret scalars, and sealed key blobs **do not** leave the device through normal firmware paths; private-key operations run **on the token**. The host receives **cryptographic results** (signatures, decrypted plaintext for card-assisted decrypt workflows) where the standard commands require it, not a portable copy of the private key.

**Importing keys onto the device:** It is also possible to **import public keys** into the token (for example trust anchors, peer certificates, or OpenPGP public packets for on-device verification). The firmware **vault** provides **public-key slots** for non-secret material (`crates/vault/src/public_key_vault.rs`). Host tooling for loading those slots is described in [docs/GALDRA-TOOL.md](docs/GALDRA-TOOL.md) as integration matures.

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
| **microSD decoy / mass-storage personas** — uninformed-host USB behaviour | Not in OpenPGP card spec | **No** — separate USB personality code paths |
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

### CESS (related open standard)

**[CESS](https://github.com/Supermagnum/CESS)** — *Cryptologically Enchanted Shamir's Secret* — is an open cryptographic standard for **threshold secret sharing** together with **cipher-agnostic authenticated encryption**, **password-based share wrapping**, and optional **post-quantum hybrid key exchange**. The [CESS repository](https://github.com/Supermagnum/CESS) holds the normative specification, algorithm registry, test vectors, and conformance runner.

**This firmware conforms to CESS** for the constructions implemented here: the specification’s interoperable share and envelope rules sit alongside the same **Shamir**, **Brainpool**, and **cipher-profile** themes described elsewhere in this README. The normative text is separate from this repository; **conformance posture** (what matches the spec, what differs while **retaining** algorithms such as AES and SHA-256 in profiles, and roadmap toward stronger interoperability): [docs/CESS_CONFORMANCE.md](docs/CESS_CONFORMANCE.md).

### Sequoia PGP (if this repository is unresponsive)

If **maintainers of this GitHub repository** do not answer issues, pull requests, or mail, you can still advance **new ciphers**, **OpenPGP behaviour**, and **standards-related work** in the wider ecosystem. **[Sequoia PGP](https://sequoia-pgp.org/)** is an independent, Rust-based OpenPGP stack (memory safety, library-first design, active IETF/ecosystem participation) where much public development happens. It is **not** this project; it is documented here as a **practical alternate path** when upstream here is silent.

| Goal | Where to start |
|------|----------------|
| Project overview, news, community | [sequoia-pgp.org](https://sequoia-pgp.org/) |
| **Contribute** (issues, fixes, features, documentation); **contact before large work** | [Contribute](https://sequoia-pgp.org/contribute/), [Contact](https://sequoia-pgp.org/contact) |
| **Developer docs** — API surface for extending the implementation (`sequoia-openpgp` and related crates) | [Docs](https://sequoia-pgp.org/docs/) — e.g. [sequoia-openpgp on docs.rs](https://docs.rs/sequoia-openpgp/latest/sequoia_openpgp/) |
| **Source and trackers** | [gitlab.com/sequoia-pgp](https://gitlab.com/sequoia-pgp) (core library and tools); [github.com/sequoia-pgp](https://github.com/sequoia-pgp) (mirrors / selected repos); [Projects](https://sequoia-pgp.org/projects) |
| **New algorithms in the OpenPGP standard** | Still go through the **[IETF OpenPGP working group](https://datatracker.ietf.org/wg/openpgp/about/)**. Sequoia and other implementations implement drafts and RFCs; propose protocol changes there, and coordinate with implementors (including Sequoia) so behaviour matches the spec. |

The [Contribute](https://sequoia-pgp.org/contribute/) page describes licensing (LGPL 2.0 or later for most projects), the Developer Certificate of Origin, and that **larger commercial features** may require prior agreement and long-term maintenance arrangements — read that page before investing significant effort.

Its also wort keeping a eye on https://autocrypt2.org/#/

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

This repository does **not** ship a one-command flasher yet. Programming the **Baochip-1x** (JTAG, ROM/USB boot, or vendor tools) follows the board and silicon documentation. Start from **[Supermagnum/Baochip-1x-firmware](https://github.com/Supermagnum/Baochip-1x-firmware)**; **eval board hardware** is in **[baochip/dabao](https://github.com/baochip/dabao)** — on the Dabao board, **SW2** toggles **bootloader mode** (see that schematic).

**Committing UF2 without the physical boot button:** After copying **`loader.uf2`**, **`xous.uf2`**, and **`apps.uf2`** to the **BAOCHIP** volume, you can either press the physical **boot** button **or** type **`boot`** in the **boot1** USB serial console (1 000 000 baud, e.g. `screen /dev/ttyACM0 1000000`). That avoids relying on the **boot** button for this step only. The console **disconnects** when you type **`boot`**; that is **expected** (the system reboots into the next stage). On Linux, `dmesg --follow` helps confirm USB re-enumeration. This is distinct from **PROG** (hold while connecting USB to enter the **BAOCHIP** mass-storage bootloader). See **[baochip/dabao#2](https://github.com/baochip/dabao/issues/2)** (closed).

**Xous / Baochip flow:** Images are **Ed25519-signed** and verified by **boot0** before execution; see [Signed firmware (Ed25519, boot0)](#signed-firmware-ed25519-boot0). For **dabao**, **UF2** layout, holding **PROG** while plugging USB to enter mass-storage mode, and **boot1** update steps, see **[Getting Started with Baochip Targets](https://github.com/betrusted-io/xous-core/blob/dev/README-baochip.md)**.

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
  of multiple independent ciphers (e.g. ChaCha20-Poly1305 + Serpent-256 per CESS cascade rows) can
  be selected per session. Every profile selection is logged in the audit trail.

- **Optional microSD decoy volume** — if a PSRAM chip is fitted, an extra bulk
  decoy LUN can appear after unlock. **If no microSD is fitted, the device is
  still a hardware security token** (vault, PIN policy, OpenPGP/CCID, and other
  token functions are unchanged); only that optional bulk volume is absent. For
  uninformed hosts, the device still presents the usual on-chip mass-storage
  decoy persona where configured. MicroSD content, when present, is intentionally
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
- Default attempt threshold: **3** (configurable **3–10** at provisioning).
  Matches hardware token industry standard (Nitrokey, YubiKey, ISO 7816).
- On threshold: full hardware zeroisation triggered.
- Challenge/response passphrase (USB informed-host path): minimum 5 characters,
  transmitted only as `HMAC-SHA256(HostChallengeKey, nonce || passphrase)`.

**Setting or adjusting the attempt threshold:** The counter limit is written when the token is **first provisioned**; it is **not** a runtime `gpg` setting. Use the **`galdra`** host tool after [building](#compile-and-install-host-tools-galdra-galdrad-galdra-gtk) it:

```bash
galdra device provision --pin-attempts 5
```

| Flag | Range | Default | Meaning |
|------|--------|---------|---------|
| `--pin-attempts` | 3–10 | **3** | Failed PIN attempts allowed before lockout / zeroisation |
| `--min-pin-length` | 5–32 | **5** | Minimum user PIN length (alphanumeric) stored in policy |

Omit both flags to keep defaults (`3` attempts, `5` character minimum). Example with both: `galdra device provision --pin-attempts 7 --min-pin-length 8`.

The policy is **stored on the token** (vault policy). The host tool cannot raise or lower the threshold **after** provisioning without going through the device’s own authenticated management flow; treat provisioning as the moment to choose **3–10** for your threat model. Rationale (defaults vs higher limits) is spelled out in [docs/GALDRA-TOOL.md](docs/GALDRA-TOOL.md) under the PIN policy section.

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

Authoritative write-up: **[`docs/TEST_RESULTS.md#run-metadata`](docs/TEST_RESULTS.md#run-metadata)** (commit, scope, and how sections are organised). That page includes the **pipeline summary** table, unit test totals, vector coverage (Wycheproof, RFC, BSI, NIST CAVP), **dudect** timing table, key lifecycle checks, and **[Section 6 — cargo-fuzz](docs/TEST_RESULTS.md#6-cargo-fuzz-libfuzzer)** (matrices, **`chacha_roundtrip`**, recorded **`openpgp_dispatch`** long run). **You** decide whether those results are enough to try building or running this project; a **virtual machine** remains optional but **reduces** host risk.

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
| `psram-store` | Optional microSD bulk block device (decoy volume); probe-absent short-circuit; mount/unmount access gate |
| `ephemeral-session` | Authenticated ephemeral ECDH session protocol; forward secrecy |
| `cipher-profile` | User-configurable cipher cascade profiles; built-in and user-defined |
| `cess` | HKDF-BLAKE3 `K_outer`, ChaCha outer AEAD, `suite_id \|\| inner_blob`; see [CESS_CONFORMANCE.md](docs/CESS_CONFORMANCE.md) |
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
