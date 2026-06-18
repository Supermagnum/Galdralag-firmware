# Galdr — Galdralag Firmware

## Open Invention Network

![Open Invention Network member](docs/oin-member-horiz.jpg)

This project is **registered with the [Open Invention Network (OIN)](https://openinventionnetwork.com/)**. OIN is a defensive patent pool: members cross-license Linux-related patents so participants can ship and use open-source software with reduced patent exposure.

## Table of contents

- [Open Invention Network](#open-invention-network)
- [What this is](#what-this-is)
  - [Galdra contact metadata](#galdra-contact-metadata)
  - [What this firmware is (and is not)](#what-this-firmware-is-and-is-not)
  - [Signed firmware (Ed25519, boot0)](#signed-firmware-ed25519-boot0)
- [Is this AI slop?](#is-this-ai-slop)
- [Test results](#test-results)
- [Why Rust?](#why-rust)
  - [Memory Safety](#memory-safety)
  - [System-level robustness (with limits)](#system-level-robustness-with-limits)
  - [Key material protection (project patterns)](#key-material-protection-project-patterns)
  - [Auditable by design](#auditable-by-design)
  - [What Rust does not prevent](#what-rust-does-not-prevent)
  - [Setting up a virtual machine for evaluation](#setting-up-a-virtual-machine-for-evaluation)
  - [Risk assessment and deployment](#risk-assessment-and-deployment)
- [Galdralag for dummies](#galdralag-for-dummies)
  - [What is GnuPG?](#what-is-gnupg)
- [GnuPG / OpenPGP keys and Galdra keys](#gnupg--openpgp-keys-and-galdra-keys)
  - [Metadata comparison (GnuPG vs Galdra)](#metadata-comparison-gnupg-vs-galdra)
- [Skipped and ignored tests](#skipped-and-ignored-tests)
- [About the name](#about-the-name)
- [Documentation](#documentation)
- [Code map (function and module index)](docs/CODE_MAP.md)
- [Debugging instructions](docs/DEBUG_INSTRUCTIONS.md)
- [docs/AUDIT_LOG.md](docs/AUDIT_LOG.md)
- [docs/BIOMETRIC_API.md](docs/BIOMETRIC_API.md)
- [docs/HARDWARE_BRINGUP_TEST_PLAN.md](docs/HARDWARE_BRINGUP_TEST_PLAN.md)
- [docs/KEY_LIFECYCLE.md](docs/KEY_LIFECYCLE.md)
- [docs/RRAM_LAYOUT.md](docs/RRAM_LAYOUT.md)
- [docs/THREE_FACTOR_AUTH.md](docs/THREE_FACTOR_AUTH.md)
- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)
- [Glossary (plain language)](docs/GLOSSARY.md)
- [OpenPGP and GnuPG compatibility](#openpgp-and-gnupg-compatibility)
- [Token session and key export](#token-session-and-key-export)
- [Web of Trust and Key Signing Parties](#web-of-trust-and-key-signing-parties)
  - [Obtaining your Galdralag fingerprint](#obtaining-your-galdralag-fingerprint)
  - [What is the web of trust?](#what-is-the-web-of-trust)
  - [How it works](#how-it-works)
  - [Key signing parties](#key-signing-parties)
  - [Typical workflow at a key signing party](#typical-workflow-at-a-key-signing-party)
  - [Fingerprints instead of full keys at the event](#fingerprints-instead-of-full-keys-at-the-event)
  - [Keyservers](#keyservers)
  - [Using keyservers](#using-keyservers)
  - [Common keyservers](#common-keyservers)
  - [Best practices and caveats](#best-practices-and-caveats)
  - [Fulla (WoT registry server)](https://github.com/Supermagnum/Fulla)
- [Standards vs. firmware-specific features](#standards-vs-firmware-specific-features)
- [Shamir secret sharing and drive encryption](#shamir-secret-sharing-and-drive-encryption)
- [German eID and Governikus as a trust anchor for public keys](#german-eid-and-governikus-as-a-trust-anchor-for-public-keys)
- [Standards process: Shamir and ephemeral key exchange](#standards-process-shamir-and-ephemeral-key-exchange)
  - [CESS (related open standard)](#cess-related-open-standard)
- [Sequoia PGP (if this repository is unresponsive)](#sequoia-pgp-if-this-repository-is-unresponsive)
- [Build, install, and uninstall](#build-install-and-uninstall)
  - [Compile firmware](#compile-firmware)
  - [Flashing](#flashing)
  - [Compile and install host tools (`galdra`, `galdrad`, `galdra-gtk`)](#compile-and-install-host-tools-galdra-galdrad-galdra-gtk)
  - [Run `galdrad` and the desktop GUI (`galdra-gtk`)](#run-galdrad-and-the-desktop-gui-galdra-gtk)
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
- [Workspace layout](#workspace-layout)
- [Cryptographic dependency policy](#cryptographic-dependency-policy)
- [Quick start](#quick-start)
- [Known limitations / open work](#known-limitations--open-work)
  - [CCID initial PIN: first-boot provisioning (USB CDC)](#ccid-initial-pin-first-boot-provisioning-usb-cdc)
- [License](#license)

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
The **Dabao** evaluation board (KiCad, schematics, switches, pinout) is **[baochip/dabao](https://github.com/baochip/dabao)**. To enter **bootloader mode** for flashing, **press SW2** to toggle it (see that repo's schematic).
Architecture notes for this repository: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

### Galdra contact metadata

The **Galdra** host tool keeps a **local SQLite** directory of recipients (contacts). Each stored identity includes public key material plus optional **sidecar labels** (see the table below). These tags live in the host database and, for **Galdra keys**, in the on-chip **contact store** (`crates/contact-store`). They are **not** magically bound to OpenPGP User IDs unless you align them yourself, and they are **not** cryptographically asserted unless you check them **out of band**. Optional **`galdra keyserver push`** can send overlapping fields to a project registry as JSON alongside the exported public key. Per-field provenance on the token uses **SelfAttested**, **HostVerified**, **RegistrySync**, and **OobVerified** (see [Metadata comparison (GnuPG vs Galdra)](#metadata-comparison-gnupg-vs-galdra) and the contact-store layout in [docs/RRAM_LAYOUT.md](docs/RRAM_LAYOUT.md)).

| Field | Purpose | Host (`galdra` SQLite) | On-chip contact store | Format / limit |
|-------|---------|--------------------------|------------------------|----------------|
| **Contact id** | Stable host primary key | Yes | No | Text (`id` in SQLite) |
| **Display name** | Human-readable label | Yes | Yes | UTF-8 string; **240 bytes** max per heap field on chip |
| **E-mail** | Primary mail address | Yes | Yes | UTF-8 string; lookup on chip by e-mail scan |
| **Callsign** | Amateur-radio callsign | Yes | Yes | **12 bytes**, NUL-padded; lookup on chip |
| **DMR subscriber ID** | DMR radio ID | Yes | Yes | **32-bit** unsigned (`0` = absent); lookup on chip |
| **Badge number** | Employee or badge ID | Yes | Yes | UTF-8 string |
| **Organisation** | Agency or employer | Yes | Yes | UTF-8 string |
| **Department** | Team or unit | Yes | Yes | UTF-8 string |
| **Role** | Job or function label | Yes | Yes | UTF-8 string |
| **Note** | Free-form comment | Yes | Yes | UTF-8 string |
| **Radio affiliation** | Club, net, or alliance label | Yes | Yes | UTF-8 string |
| **Street** | Street address line | Yes | Yes | UTF-8 string |
| **Country** | Country name or code | Yes | Yes | UTF-8 string |
| **Postal code** | ZIP or postal code | Yes | Yes | UTF-8 string |
| **Region** | State, county, or region | Yes | Yes | UTF-8 string |
| **Fluxer ID** | Fluxer handle or id | Yes | Yes | UTF-8 string |
| **Discord ID** | Discord user id | Yes | Yes | UTF-8 string |
| **IRC id** | IRC nick or similar | Yes | Yes | UTF-8 string |
| **Fingerprint** | Key anchor (lookup, sync) | Yes (`pgp_fingerprint`) | Yes | **32 bytes**; OpenPGP v4 style on wire; **not** the same as a **`G:`** device fingerprint |
| **Public key** | Encryption / verify material | Yes (`pgp_pubkey`) | Yes (key region) | Algorithm: Ed25519, X25519, Brainpool P-256/P-384/P-512, NIST P-256/P-384, RSA-2048/3072/4096; up to **768 bytes** blob on chip |
| **PIN-protected key** | Key requires PIN unlock | Host stores OpenPGP keys separately | Yes | PIN verifier digest + AES-GCM wrap metadata on chip |
| **Last fetched** | When key material was refreshed | Yes (`fetched_at`) | Yes (`last_fetched`) | UTC on host; **32-bit** timestamp on chip |
| **Expires at** | Key expiry time | Yes | No | UTC datetime in SQLite only |
| **Key source** | How the host record was created | Yes (`source`) | No | e.g. manual, keyserver, WKD, LDAP, file, peer |
| **Field provenance** | Trust label per metadata field | No | Yes (`source_map`) | Two bits per field: SelfAttested, HostVerified, RegistrySync, OobVerified |
| **Record flags** | Active, stale, own-identity, revoked | Partially (host logic) | Yes | e.g. **STALE**, **SELF_KEY** on chip |

Host-side details and CLI behaviour: [docs/GALDRA-TOOL.md](docs/GALDRA-TOOL.md). Wire layout and slot counts: `crates/contact-store/src/layout.rs` and [docs/RRAM_LAYOUT.md](docs/RRAM_LAYOUT.md).

### What this firmware is (and is not)

**This firmware is** a **hardware security token** for **Baochip-1x**: an **OpenPGP card application** over **USB CCID**, with an on-device **vault**, **PIN policy**, and repository-specific features (**cipher profiles** — you can **stack** **up to four** different symmetric ciphers in one cascade, each with its own derived key; see [Key capabilities](#key-capabilities)), Shamir-related flows, authenticated ephemeral ECDH where implemented, and **Galdra** host tools). The primary interoperability target is **GnuPG-style** OpenPGP card usage, not every token protocol on the market.

**This firmware is not:**

- **FIDO2 / CTAP2 / WebAuthn** — different standards; no CTAP **user-presence** button model and no planned CTAP stack. Use a FIDO security key if you need WebAuthn. (See also [OpenPGP and GnuPG compatibility](#openpgp-and-gnupg-compatibility) and the standards table under [Standards vs. firmware-specific features](#standards-vs-firmware-specific-features).)
- **TOTP / HOTP (OATH one-time passwords)** — those protocols expect a **real-time clock** (TOTP) or an OATH-oriented counter workflow and UX; this device is **not** built as a dedicated OTP token.
- **USB HID keyboard "password typer"** — there is no USB keyboard personality to inject keystrokes into the host. Planned credential storage (see [docs/future-todo.md](docs/future-todo.md)) is described as retrieval through **authenticated host tooling**, not HID typing.
- **A general multi-applet Java Card platform** — scope is this **Galdr** firmware and its documented surfaces, not arbitrary third-party smart-card applets.

Crate-level exclusions aligned with the same constraints are listed under **[Crates Explicitly Excluded](docs/future-todo.md#crates-explicitly-excluded)** in [docs/future-todo.md](docs/future-todo.md).

**CESS:** This firmware **conforms to CESS** for the normative constructions implemented in-tree (including **Mode A** outer AEAD, **HKDF-BLAKE3** for **`K_outer`**, and byte-wise GF(2^8) Shamir splitting). The full alignment statement, deviation register, and **certification level** (for example **CESS-CORE** for the full fixed layer) are documented in [docs/CESS_CONFORMANCE.md](docs/CESS_CONFORMANCE.md) and [CESS (related open standard)](#cess-related-open-standard) below.

The **OpenPGP / CCID** application logic is in **`crates/usb-personality`**. On **Xous**, the USB service that exposes CCID is **`usb-bao1x`** (in your **xous-core** checkout), built with feature **`ccid-openpgp`**, using **`crates/baochip-openpgp`** for the OpenPGP RRAM window and provisioning. Layout: [docs/RRAM_LAYOUT.md](docs/RRAM_LAYOUT.md). Pre-production gaps (operator PIN UX, platform map sign-off): [Known limitations / open work](#known-limitations--open-work).

The overall goal remains a complete, tested, open-source hardware security token firmware: **OpenPGP card–style behaviour** for GnuPG over CCID (see [OpenPGP and GnuPG compatibility](#openpgp-and-gnupg-compatibility)), plus **additional on-device features** not currently defined by the OpenPGP card standard — ephemeral ECDH with forward secrecy, Shamir K-of-N, cipher-agnostic profiles, microSD decoy volume — as summarised in [Standards vs. firmware-specific features](#standards-vs-firmware-specific-features). All on open RTL with a reproducible bootloader.

### Signed firmware (Ed25519, boot0)

Shippable firmware for **Baochip-1x** is **signed** with **Ed25519**. You sign the firmware image with an **Ed25519** private key; **GnuPG** can do this with **`gpg --sign`** using an **Ed25519 signing subkey** (the usual OpenPGP detached-signature workflow, adapted to whatever packaging your build emits). The immutable **boot0** ROM in the SoC **verifies** that signature against the **corresponding public keys burned into the device** (and the wider **key manifest** for the boot chain) **before** the next stage — **boot1** — is allowed to run. **boot1** then loads signed application images (for example **UF2** blobs delivered over USB mass storage in bootloader mode). Default parts carry **four** on-chip Ed25519 public keys (roles such as code deployment, beta, and developer); **boot0** / **boot1** enforce a **mutual-distrust** policy between Baochip and third-party signing keys. Full boot flow, **UF2** delivery, console, **boot1** updates, and security model: **[Getting Started with Baochip Targets](https://github.com/betrusted-io/xous-core/blob/dev/README-baochip.md)** in **xous-core**.

## Skipped and ignored tests

Not every test runs in every command; that is intentional.

- **`xtask` not in the default workspace test:** The common recipe is `cargo test --workspace --exclude xtask` because `xtask` is a build-orchestration crate. Run `cargo test -p xtask` when you want its tests.
- **Tests marked `#[ignore]`:** These are skipped unless you pass `--ignored` (and any needed crate filters). Reasons include: coverage that is already exercised in focused unit tests (e.g. post-drop zeroization), **slow** cases (e.g. RSA key generation), and **hardware or token-dependent** flows in host tools such as `galdra` that need a connected device or fixtures.
- **`test-all --no-fuzz`:** Skips the **cargo-fuzz** step to keep CI or quick runs short and to avoid requiring a nightly toolchain for that step; run `cargo run -p xtask -- test-all` without `--no-fuzz`, or invoke fuzz targets separately (see [`fuzz/README.md`](fuzz/README.md)).
- **Conformance vector suites:** Some groups are not executed (for example certain AES-GCM Wycheproof cases); see [`docs/TEST_RESULTS.md`](docs/TEST_RESULTS.md) for what is in scope.

One can also check integrity of crates with this when the pr is closed:
https://github.com/rust-lang/cargo/issues/16850


> **Status:** Ready for testing by humans, on real hardware — no production-ready release exists.
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

## Is this AI slop?

The primary developer has a **neurological condition related to dyscalculia**. Dyscalculia affects number sense and related symbolic processing in ways that, for them, make **traditional programming** — hand-authored code editing as the sole workflow — **not workable** without assisted tooling (for example conversational AI editors). That constraint is distinct from correctness: reviewers should still weigh tests, fuzzing, and independent audit as documented elsewhere on this page.

A cryptographer or serious implementer reviewing Galdralag will typically open `crates/vault/tests/` and `crates/cipher-profile/tests/` before reading prose. The test suite is the proof of work: it encodes domain knowledge that cannot be substituted with narrative alone.

That is not a reason to hide the point from everyone else. People evaluating the project for procurement, deciding whether to contribute, or shipping code without deep training in cryptographic testing methodology still deserve a pointer to the concrete evidence. 

**What to look at:** Conformance material includes RFC 8439 worked examples for ChaCha20-Poly1305 under `crates/vault/tests/rfc_vectors/`, vendored Wycheproof JSON for ChaCha20-Poly1305 and Brainpool ECDH/ECDSA edge cases under `crates/vault/tests/data/wycheproof/`, BSI TR-03111 vectors for BrainpoolP256r1, P384r1, and P512r1 under `crates/vault/tests/bsi_vectors/`, official BLAKE3 reference vectors (all 35 input lengths, all three modes) under `crates/vault/tests/blake3_vectors.json`, Twofish specification vectors (1203 cases including Monte Carlo) under `crates/vault/tests/twofish_vectors.json`, and the project's own CESS cascade KAT fixture with independently verified intermediates under `crates/cipher-profile/tests/fixtures/cascade_cess_kat.json`. Together these are the ground truth the runner and reviewers can exercise with `cargo test --workspace` and `python3 scripts/verify_cascade_kats.py`.

**RFC 8439** is published by the Internet Engineering Task Force (IETF), the organisation that standardises much of how the internet interoperates. RFCs (Request for Comments) are the usual form for protocol and many cryptographic specifications. RFC 8439 defines ChaCha20-Poly1305 authenticated encryption (building on Daniel Bernstein's designs) and includes concrete worked examples with specific inputs and expected outputs so independent implementations can check they match the standard byte-for-byte. The widely reproduced plaintext beginning with *Ladies and Gentlemen of the class of '99: wear sunscreen* appears in the RFC's appendix examples: if your code reproduces the AEAD output exactly, you have a strong check that you implemented the construction correctly. It is the cryptographic analogue of an official answer key. ChaCha20-Poly1305 is the inner layer of every multi-layer cascade profile in this firmware, so this check sits at the foundation of the entire cipher stack.

**Wycheproof** is a test corpus released by Google's security team (2017). The name refers to Mount Wycheproof in Australia — often cited as the world's smallest mountain — because the project focuses on clearing small but fatal hurdles: integer overflows, boundary cases, malformed inputs, and tampered authentication tags; failures that show up repeatedly in real deployed crypto. It complements RFC-style vectors: RFC 8439-style examples demonstrate correctness against the published AEAD; Wycheproof stresses robustness where implementations historically break. In this repository Wycheproof JSON covers ChaCha20-Poly1305, AES-GCM, HMAC, HKDF, X25519, Ed25519, RSA, and Brainpool ECDH/ECDSA variants.

**BSI TR-03111** is the technical guideline for elliptic curve cryptography published by the German Federal Office for Information Security (Bundesamt fur Sicherheit in der Informationstechnik). Version 2.10 is the current revision. The three Brainpool curves used in this firmware — P256r1, P384r1, P512r1 — are specified in BSI standards, making TR-03111 the natural reference for their test vectors. Each curve has ECDH and ECDSA coverage; ECDSA signatures were additionally cross-checked against an independent Python implementation using the `cryptography` library.

**BLAKE3 reference vectors** are the official test corpus published alongside the BLAKE3 specification by its authors. They cover 35 input lengths from 0 to 102400 bytes, specifically chosen to exercise all internal chunk and tree-hashing boundary conditions that are invisible to short-input tests. All three BLAKE3 modes — default hash, keyed hash, and derive-key — are covered. BLAKE3 is used throughout this firmware for HKDF key derivation and inter-layer integrity checks in the cascade cipher profiles; the boundary coverage matters because BLAKE3's tree construction only activates above 1024 bytes.


**The test suite is also tamper detection for the supply chain.** All cryptographic primitives in this firmware come from audited RustCrypto crates — no cryptography is implemented in-tree. Because the conformance vectors above are run against those crates on every `cargo test --workspace`, any dependency that has been tampered with or substituted will produce a known-answer test failure before the compromised code reaches a deployed system. `python3 scripts/verify_cascade_kats.py` adds a second independent path: a Python implementation checks the same intermediate values in the cascade KAT fixture, so even a compromised Rust toolchain producing wrong output is caught by the cross-check. This is a meaningfully stronger supply chain integrity story than binding to a C library, where equivalent verification of every internal operation requires significantly more effort and specialist tooling.

It is now up to the reader to judge whether these claims are false or not.

## Galdralag for dummies

You plug it into a USB port. From the host's perspective the firmware can present **crypto mode** or **camouflage mode**. In crypto mode your computer sees a smart card: you use **GnuPG** or a compatible OpenPGP stack ([What is GnuPG?](#what-is-gnupg)) the same way you would any other hardware security token — the token handles the sensitive cryptographic operations so your private keys never exist unprotected on your computer. In camouflage mode it can enumerate as ordinary removable storage with innocuous-looking files so a quick look does not reveal its real role; see **Storage camouflage** below.

### What is GnuPG?

**GnuPG** stands for **GNU Privacy Guard**. It is the GNU project's implementation of **OpenPGP**, the open standard for key management and cryptographically protected messages (the same conceptual family as PGP, but specified in documents such as RFC 4880 and community updates). You normally run it as the **`gpg`** command on Linux, BSD, macOS, or Windows; many graphical mail and key utilities wrap this underneath.

People use GnuPG to:

- **Encrypt and decrypt** files or backups so only chosen recipients can read them.
- **Sign data** so others can check authenticity and integrity — common for software releases, distribution mirrors, and personal documents.
- **Protect email** end-to-end when paired with a suitable mail client (GnuPG handles the cryptography; the message format on the wire is OpenPGP).
- **Authenticate**, notably **SSH** logins when **`gpg-agent`** exposes authentication keys from a smart card or local keystore.

By default GnuPG stores keys under **`~/.gnupg`**. With an **OpenPGP smart card**, sensitive **private** keys live on the card; **`scdaemon`** (part of the GnuPG suite) talks **CCID**/**USB** to the card while **`gpg`** still assembles OpenPGP packets on the host.

**What you can use it for.** In **crypto mode** the token is meant for the same work as other OpenPGP smart cards: **signing and decrypting** mail and files, **authenticating** (for example SSH when you use `gpg-agent` as usual), and keeping **long-term private keys** off the machine you type on. Organisations can combine that with **Shamir shares** on the token so no single person holds the entire secret (described further below). **GnuPG** is the primary interoperability target on the host: this firmware implements the **OpenPGP card application** over **CCID**, which `scdaemon` drives (`gpg --card-status`, `gpg --card-edit`, and normal encrypt/sign/decrypt with keys on the card). Other software that speaks the same smart-card protocols may work too; commands, slots, algorithms, and current integration limits are in [OpenPGP and GnuPG compatibility](#openpgp-and-gnupg-compatibility). When **NFC** is brought up on the hardware (**planned** integration — **not** in firmware yet), the same device class can support **physical access**: tapping an NFC reader at a **door, gate, or lock panel** can take part in a policy that only releases the lock after cryptographic checks (often combined with PIN, biometrics, or Shamir-style quorum depending on the deployment). The PN532-oriented sketch for readers and panels is in [docs/NFC_PN532_INTEGRATION.md](docs/NFC_PN532_INTEGRATION.md).

That is the short version. Here is what makes it different from other tokens you may have encountered.

**Storage camouflage.** The device can act as ordinary removable storage so its real role is not obvious from a quick look. When you plug it into a typical computer, it can show up like a normal USB drive or SD-backed volume; you can fill the visible filesystem with plausible everyday files (for example vacation photos) so casual browsing reinforces the impression that it is only storage. That frustrates superficial inspection at a desk or checkpoint. Figuring out that it is actually a security token usually means taking the housing apart, not just plugging it in.

**Your keys stay on the device.** When you sign an email or decrypt a file, the private key never leaves the token. The computer sends the data in, the token does the work, the result comes back out. An attacker who compromises your computer gets nothing useful.

**Past sessions stay safe even if the token is stolen.** Most hardware tokens use a long-term private key directly for key agreement. This one generates a fresh throwaway key pair for every session, signs it with the long-term key to prove it is genuine, and then uses the throwaway pair for the actual exchange. If someone steals the token years from now and somehow extracts the long-term key, they still cannot decrypt anything from past sessions. This property is called forward secrecy, and it is unusual in hardware tokens.

**You can split the key between multiple people.** The token can divide the long-term key into N shares so that any K of those shares are needed to reconstruct it — but no single share holder can do anything alone. This is called Shamir secret sharing. It is useful for organisational keys where no single person should have unilateral access, or as a backup strategy where shares are stored in separate locations. This is also unusual in hardware tokens.

**The encryption is layered.** Rather than encrypting your data with a single cipher, the token can run it through multiple independent ciphers in sequence — for example ChaCha20, then Serpent, then Twofish — each using a separately derived key. A future breakthrough that breaks one cipher does not break the others. The specific combination is called a cipher profile, and you can choose from several built-in ones depending on how much caution your situation requires.

My personal recommendation is **BrainpoolP256r1 + ChaCha20-Poly1305 + BLAKE3**. This is the built-in `standard` profile. It uses the BSI Brainpool P-256 curve for ephemeral key agreement, ChaCha20-Poly1305 for symmetric encryption, and BLAKE3 for key derivation and inter-layer integrity. It is fast, well-tested, battery friendly (ChaCha20-Poly1305 was designed to be efficient on hardware without AES acceleration, reducing CPU time and host power draw; P-256 is the smallest of the three Brainpool curves in this firmware), and does not depend on any NIST-designed primitive. If you need a higher margin against a future cryptanalytic break against a single cipher, the `conservative` profile adds a Serpent-256 layer on top.

**The algorithm choices are deliberate.** The ciphers used — ChaCha20-Poly1305, Serpent, Twofish, Camellia — were all designed independently of government standards bodies. AES and the NIST suite are intentionally excluded. This is a conscious choice for users and organisations who want cryptographic independence from any single country's standards process. Camellia was evaluated independently by the EU NESSIE project and Japan's CRYPTREC programme, and is specified in RFC 3713 and ISO/IEC 18033-3.

**A wrong PIN locks you out properly.** The token counts failed PIN attempts before it checks whether the PIN is correct, not after. This means a crash or power loss mid-attempt cannot be exploited to reset the counter. After too many wrong attempts the token zeroises sensitive material.

**What it does not do yet.** There is no hardware available yet — this is firmware under active development. End-to-end testing with real USB hardware and GnuPG is a future milestone. **NFC** transport and **door-style access readers** are described in the documentation as **integration targets**, not shipped behaviour yet. The biometric third factor described in the documentation is not yet implemented. Some timing side-channel tests that require real hardware cannot be completed until a device exists.

---

## GnuPG / OpenPGP keys and Galdra keys

Galdralag can work with two different kinds of asymmetric key at once. They answer different questions on the device and on the host, and they are not interchangeable even when they belong to the same person. The sections **OpenPGP and GnuPG compatibility**, **Web of Trust and Key Signing Parties**, [Galdra contact metadata](#galdra-contact-metadata), and [Metadata comparison (GnuPG vs Galdra)](#metadata-comparison-gnupg-vs-galdra) describe each stack in more detail; here is how they differ in everyday terms.

An **OpenPGP key**, in the sense GnuPG generates and uses, is a structured packet, not a bare public number. It bundles the primary key, subkeys for signing and encryption, and one or more **User IDs** — usually a display name and an email address such as `Alice Example <alice@example.org>`. Other people can sign those User IDs to say they believe the identity claim is genuine; that social graph is the basis of the web of trust described in **Web of Trust and Key Signing Parties** later in this README. When Galdralag acts as an OpenPGP smartcard, it holds the **private** key material on chip and performs signing and decryption there. The **public** key, the User IDs, and the signatures from others live on the host and are managed by GnuPG in the usual way. The token does not change the OpenPGP message format on the wire; GnuPG treats it like any other OpenPGP card.

A **Galdra key** is a bare asymmetric keypair — Ed25519, X25519, or one of the Brainpool or NIST curves the firmware supports. The key bytes themselves carry **no** identity claims: no User ID packets, no email baked in, no web-of-trust signatures attached to the key structure. Identity for a Galdra key comes from the **contact record** stored next to it in the host SQLite database and the on-chip **contact store**, tied to the key by its fingerprint.

### Metadata comparison (GnuPG vs Galdra)

The table below compares **identity and contact metadata** field by field. **OpenPGP / GnuPG** columns describe what you get from a normal certificate and User ID (plus optional host-side contact rows in **Galdra** when you store an OpenPGP public key in the same directory). **Galdra key** columns describe structured sidecar fields for operational contacts (full host and on-chip detail in [Galdra contact metadata](#galdra-contact-metadata)). A dash means that stack has no standard, separate field for that item.

| Metadata field | OpenPGP / GnuPG | Galdra key (host + contact store) |
|----------------|-----------------|-----------------------------------|
| **Contact / record id** | No (use key ID or fingerprint) | Yes (SQLite `id` on host; not on chip) |
| **Display name** | Only inside **User ID** text (`Name <email>`) | Yes (separate UTF-8 field) |
| **E-mail** | Only inside **User ID** text | Yes (separate field; lookup by e-mail on chip) |
| **Street address** | No standard field | Yes |
| **Country** | No standard field | Yes |
| **Postal / ZIP code** | No standard field | Yes |
| **Region / state** | No standard field | Yes |
| **Organisation** | No standard field | Yes |
| **Department** | No standard field | Yes |
| **Role / job title** | No standard field | Yes |
| **Badge / employee id** | No standard field | Yes |
| **Callsign** | No standard field | Yes (**12** bytes, NUL-padded on chip) |
| **DMR subscriber ID** | No standard field | Yes (**32-bit**; lookup on chip) |
| **Radio affiliation** | No standard field | Yes |
| **Fluxer ID** | No standard field | Yes |
| **Discord ID** | No standard field | Yes |
| **IRC id** | No standard field | Yes |
| **Free-form note** | No standard field | Yes |
| **OpenPGP v4 fingerprint** | Yes (**40** hex chars) | Optional on host row when linking a cert (`pgp_fingerprint`); **32** bytes on chip for Galdra keys |
| **`G:` device fingerprint** | No | Yes (BLAKE3-160 over SIG public key; host tool; **not** the OpenPGP v4 value) |
| **OpenPGP key ID** | Yes (short / long form) | No |
| **Trust / provenance** | **WoT** signatures on User IDs | Per-field labels: SelfAttested, HostVerified, RegistrySync, OobVerified (on chip) |
| **Key expiry** | Yes (certificate / subkey) | Host only (`expires_at` in SQLite) |
| **Last key fetch time** | Host tooling dependent | Yes (`fetched_at` / `last_fetched`) |
| **Private key on token** | **SIG**, **DEC**, **AUT** card slots | Separate **Galdra** key region (not User ID packets) |
| **PIN to use private key** | PW1 / PW3 (OpenPGP card) | Optional PIN wrap per Galdra contact record |

OpenPGP puts **name and e-mail in one User ID string**; it does not give you separate, machine-readable callsign, DMR, or postal fields. **Galdra** keeps those as named columns so radio and operations teams can search and display them without parsing certificate text.

| OpenPGP card object (not in table above) | Host (GnuPG) | On token |
|------------------------------------------|--------------|----------|
| Primary + **SIG** / **DEC** / **AUT** subkeys | Public in keyring | Private in sealed slots |
| **Certification signatures** (WoT) | Yes | No |
| **Revocation certificate** | Yes | No |
| **Algorithm attributes** (DO **0xC1** / **0xC2** / **0xC3**) | `gpg --card-edit` | Yes |
| **PW1** / **PW3** | Never stored | Verifier on chip (min **5** chars, **3** tries default) |
| **Cardholder DOs** (login, language, URL, …) | Cached by GnuPG | Optional (**254** bytes max per DO) |

Card application **3.4.1**, CCID, and GnuPG workflows: [docs/OPENPGP_CARD.md](docs/OPENPGP_CARD.md) and [OpenPGP and GnuPG compatibility](#openpgp-and-gnupg-compatibility).

The split exists because the identity information that matters in the communities Galdralag targets — callsign, DMR ID, radio network affiliation — has no natural home in an OpenPGP User ID. A User ID is meant for name and email. Writing something like `LA5XYZ <la5xyz@example.org> DMR:2345678` into a User ID string is informal, unstructured, and not machine-readable in any standard way. Galdra keys keep the cryptographic material clean and put operational identity in a record format the host tool and on-chip store understand natively.

In practice, a single device can hold **both** kinds of key without conflict. The OpenPGP card application serves GnuPG through the standard SIG, DEC, and AUT slots. The contact store holds Galdra keys for operational work — for example encrypting to a radio contact by callsign, checking a message against a DMR subscriber ID, or looking up a colleague by badge number. The two paths do not step on each other.

If someone has an OpenPGP certificate managed by GnuPG on the host **and** a Galdra key in the on-chip contact store, those are **two separate keys** with **two separate fingerprints**. The Galdra fingerprint — prefixed `G:` and derived with BLAKE3 from the raw public key bytes — is **not** the same value as the OpenPGP v4 fingerprint of that person's GnuPG certificate. The host tool and the device treat them as independent identities. Do not assume one fingerprint implies the other without checking both.

Neither key type automatically vouches for the labels around it. An OpenPGP User ID is self-asserted until someone else signs it. A callsign or DMR field in a Galdra contact record is only as trustworthy as its source — a keyserver fetch, a manual entry, or an out-of-band check you performed yourself. The provenance labels (SelfAttested, HostVerified, RegistrySync, OobVerified) record **how** a field arrived; they do not replace the work of actually verifying the identity you care about.

---

## Why Rust?

This firmware is written in Rust, a systems programming language designed
to be as fast and low-level as C or C++, but with a fundamentally different
approach to safety.

### Memory Safety

A large share of security-relevant bugs in industry codebases come from **memory unsafety** (buffer overflows, use-after-free, null dereferences, and similar). Microsoft's MSRC has **repeatedly reported** that roughly **70% of CVEs addressed in their own products** fall into this category; the **Chrome** team has published similar proportions for Chrome. Those figures describe **those vendors' products**, not a universal law for all firmware, but they illustrate why memory-safe languages matter.

In **safe Rust** (the default), the **borrow checker** rules out data races and the usual undefined-behaviour memory errors at compile time **without** relying on garbage collection. **Unsafe Rust** and **FFI** to C can still introduce memory bugs; they must be kept small and reviewed.

### System-level robustness (with limits)

Rust's **bounds checking** on slices and its **ownership rules** reduce several classes of failure modes common in C/C++ embedded code:

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

**`unsafe`** must be **spelled out** in source, which narrows manual review. **Dependencies:** this project's cryptographic policy favours **audited Rust crates** (RustCrypto and others); see the table in [Cryptographic dependency policy](#cryptographic-dependency-policy) — not every dependency is from a single umbrella project.

### What Rust does not prevent

Rust does **not** remove **deadlocks** (e.g. mis-ordered `Mutex` locks), **logic bugs**, **incorrect protocols**, **flash wear** from bad loops, **physical attacks** (glitching, power analysis), or risks from a **correct build of the wrong image**. It also does not guarantee constant-time execution on all hardware without careful coding. Those areas rely on **design, review, testing**, and the project's **crypto and supply-chain** practices described elsewhere in this README.

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

A structured list of assets, threats **T1–T14**, explicit non-goals, and Q2 verification gaps is in **[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)**.

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

## Documentation

**Glossary:** [docs/GLOSSARY.md](docs/GLOSSARY.md) — terms explained in **plain language** (sorted A–Z). Start here if the README or other docs feel jargon-heavy.

**Debugging:** [docs/DEBUG_INSTRUCTIONS.md](docs/DEBUG_INSTRUCTIONS.md) — backtraces, narrowing `cargo test`, `xtask` shortcuts, firmware triple checks, fuzzing, and what to collect before reporting an issue.

**AI assistants (Claude, Cursor):** [CLAUDE.md](CLAUDE.md) — project instructions for coding agents. Cursor-specific rules: [`.cursor/rules/`](.cursor/rules/).

**Browse all files:** [github.com/Supermagnum/Galdralag-firmware — `docs/`](https://github.com/Supermagnum/Galdralag-firmware/tree/main/docs)

**Hardware (USB dongle and related):** Two KiCad trees: [Hardware/kicad-files-usb/](Hardware/kicad-files-usb/) — `dabao_v3c` (USB-A token **without** micro-SD); and [Hardware/kicad-sd-card/](Hardware/kicad-sd-card/) — `dabao_v3c_sdcard` (same base layout **with** micro-SD holder), gerbers, BOM, production outputs, and [pinout docs](Hardware/kicad-sd-card/docs/pinout/README.md). The USB-A dongle PCB layout (minimal token vs Pico-format eval) is described in [docs/USB_DONGLE_PCB.md](docs/USB_DONGLE_PCB.md).

| Document | Description |
|----------|-------------|
| [Hardware/kicad-files-usb/](Hardware/kicad-files-usb/) | **USB dongle** KiCad project `dabao_v3c` (no micro-SD); gerbers, BOM, production outputs; complements [USB_DONGLE_PCB.md](docs/USB_DONGLE_PCB.md) |
| [Hardware/kicad-sd-card/](Hardware/kicad-sd-card/) | **USB dongle** KiCad project `dabao_v3c_sdcard` (micro-SD holder); gerbers, BOM, pinout under [docs/pinout](Hardware/kicad-sd-card/docs/pinout/README.md); complements [USB_DONGLE_PCB.md](docs/USB_DONGLE_PCB.md) |
| [docs/CODE_MAP.md](docs/CODE_MAP.md) | Workspace **function and module index** (per-file `pub fn` / types with line anchors) |
| [docs/API_REFERENCE.md](docs/API_REFERENCE.md) | Code map + **annex** for IETF/I-D/GnuPG/Sequoia: Shamir GF(256) construction, GALDRA SHARE armour, ephemeral ECDH wire format, HKDF labels, preimages; `galdrad` routes; rustdoc hints |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | High-level firmware architecture and major subsystems |
| [docs/AUDIT_LOG.md](docs/AUDIT_LOG.md) | Profile audit records (`cipher-profile`), OpenPGP `OpenPgpAudit` hook; **no** append-only RRAM log implemented yet |
| [docs/BIOMETRIC_API.md](docs/BIOMETRIC_API.md) | Biometric pre-gate: architecture, wire format, vault layout; integration partially implemented |
| [docs/BIOMETRIC_DEVICE_GUIDE.md](docs/BIOMETRIC_DEVICE_GUIDE.md) | How to add support for a new biometric hardware backend |
| [docs/BIOMETRIC_TESTING.md](docs/BIOMETRIC_TESTING.md) | Test methodology: ISO/IEC 30107-3 PAD metrics, datasets, how to run |
| [docs/FINGERVEIN_DEVICE.md](docs/FINGERVEIN_DEVICE.md) | ESP32-CAM open finger vein device: hardware, protocol sketch, liveness |
| [docs/SWEET_PLATFORM_INTEGRATION.md](docs/SWEET_PLATFORM_INTEGRATION.md) | sweet platform hand scanner: hardware, integration, liveness, dataset |
| [docs/GALDRA-TOOL.md](docs/GALDRA-TOOL.md) | Host tools (`galdra`, `galdrad`, `galdra-gtk`): workflows, provisioning, PIN policy, operational behaviour |
| [Supermagnum/Fulla](https://github.com/Supermagnum/Fulla) | **Fulla**: WoT-oriented OpenPGP public-key registry (server repository and implementation). **No public registry instance is running yet**; one is planned. **`galdra keyserver push`** / **`galdra keyserver fetch`** and optional **`[keyserver]`** config target this ecosystem—see also [Web of Trust and Key Signing Parties](#web-of-trust-and-key-signing-parties). Supplementary design notes remain in [docs/server.md](docs/server.md). |
| [docs/GLOSSARY.md](docs/GLOSSARY.md) | **Plain-language glossary** (A–Z) for non-technical readers; technical detail remains in linked docs |
| [CLAUDE.md](CLAUDE.md) | Instructions for **Claude** / AI coding agents; points to [`.cursor/rules/`](.cursor/rules/) for **Cursor** |
| [docs/GALDRALAG_DEV_REFERENCE.md](docs/GALDRALAG_DEV_REFERENCE.md) | Toolchain, `xtask` commands, fuzzing and crypto test entry points |
| [docs/dev-ref.md](docs/dev-ref.md) | Workspace layout, crates, HAL traits, USB/PSRAM behaviour, security invariants |
| [docs/DEBUG_INSTRUCTIONS.md](docs/DEBUG_INSTRUCTIONS.md) | Debugging: `RUST_BACKTRACE`, verbose builds, scoped tests, `xtask` recipes, embedded target checks, fuzzing pointers, OpenPGP host checks |
| [docs/KEY_LIFECYCLE.md](docs/KEY_LIFECYCLE.md) | Key generation, import, export policy, rotation, zeroisation, Shamir (as reflected in `vault` / OpenPGP) |
| [docs/OPENPGP_CARD.md](docs/OPENPGP_CARD.md) | OpenPGP card application, GnuPG/CCID host setup, key slots, algorithms, udev |
| [docs/CIPHER_PROFILES.md](docs/CIPHER_PROFILES.md) | Cipher profile system and configuration |
| [docs/CIPHER_PROFILE_SECURITY.md](docs/CIPHER_PROFILE_SECURITY.md) | Security considerations: cleartext profile identifiers, traffic analysis, BrainpoolP384r1 outer-wrapper rationale, encrypted identifiers, wildcard property |
| [docs/CESS_CONFORMANCE.md](docs/CESS_CONFORMANCE.md) | [CESS](https://github.com/Supermagnum/CESS/tree/main) alignment: Mode A wire layout, `suite_id` from [ALGORITHM-REGISTRY.md — lookup table](https://github.com/Supermagnum/CESS/blob/main/ALGORITHM-REGISTRY.md#cipher-suite-identifier-lookup-table), deviation register (retained AES/SHA-2 vs CESS-CORE), roadmap |
| [crates/cess](crates/cess) | CESS Mode A: HKDF-BLAKE3 (`derive_k_outer`, `hkdf_blake3`), ChaCha outer seal/open, `suite_id \|\| inner_blob` layout; see [CESS_CONFORMANCE.md](docs/CESS_CONFORMANCE.md) |
| [docs/EPHEMERAL_SESSION.md](docs/EPHEMERAL_SESSION.md) | Authenticated ephemeral ECDH session protocol |
| [Supermagnum/CESS](https://github.com/Supermagnum/CESS) | **CESS** (*Cryptologically Enchanted Shamir's Secret*) — open specification (normative text and test vectors) for threshold secret sharing with authenticated encryption, password-based share wrapping, and optional post-quantum hybrid key exchange; separate from this firmware but in the same design space as Shamir and cipher profiles here |
| [docs/PQ_SIGNATURES.md](docs/PQ_SIGNATURES.md) | Post-quantum stateful signatures (XMSS, LMS/HSS), feature gating |
| [docs/Psram.md](docs/Psram.md) | Optional microSD decoy volume and related behaviour |
| [docs/RRAM_LAYOUT.md](docs/RRAM_LAYOUT.md) | **4,194,304 byte** on-chip RRAM: vault offsets from source, HAL mapping, wear / zeroisation notes |
| [docs/TEST_RESULTS.md](docs/TEST_RESULTS.md#run-metadata) | Opens at **Run metadata**; pipeline summary, vectors, dudect, cargo-fuzz ([Section 6](docs/TEST_RESULTS.md#6-cargo-fuzz-libfuzzer)), key lifecycle |
| [docs/THREE_FACTOR_AUTH.md](docs/THREE_FACTOR_AUTH.md) | Token + PIN + optional biometric: what this repo implements vs placeholder; threat sketch |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Threat model: assets, threats T1–T14, what is and is not defended, unverified items pending Q2 hardware, audit status |
| [docs/PERFORMANCE.md](docs/PERFORMANCE.md) | Performance notes |
| [docs/HARDWARE_BRINGUP_TEST_PLAN.md](docs/HARDWARE_BRINGUP_TEST_PLAN.md) | Q2 first-hardware bring-up: CCID enumeration, `gpg --card-status`, USB CDC `galdralag-provision` for first-boot PINs, then `gpg --card-edit` / crypto smoke tests |
| [docs/HARDWARE_VERIFICATION.md](docs/HARDWARE_VERIFICATION.md) | Hardware zeroisation: simulation vs silicon verification |
| [docs/HARDWARE_TEST.md](docs/HARDWARE_TEST.md) | Hardware-oriented testing notes |
| [docs/NFC_PN532_INTEGRATION.md](docs/NFC_PN532_INTEGRATION.md) | PN532 / NFC: libnfc, Rust options, door passive vs USB panel, quorum with Shamir and PIN |
| [docs/SDMMC_STORAGE_INTEGRATION.md](docs/SDMMC_STORAGE_INTEGRATION.md) | `embedded-sdmmc` + SPI microSD as optional bulk storage; BOM alternative to PSRAM |
| [docs/USB_DONGLE_PCB.md](docs/USB_DONGLE_PCB.md) | How to make a USB-A dongle PCB from the Dabao reference: Pico-format eval is for firmware bring-up; this strips GPIO header for a minimal token; KiCad, FreeCAD, 5 V / 500 mA vs USB-C PD, QSPI PSRAM routing |

The same paths resolve on GitHub under [`tree/main/docs`](https://github.com/Supermagnum/Galdralag-firmware/tree/main/docs) and [`tree/main/Hardware`](https://github.com/Supermagnum/Galdralag-firmware/tree/main/Hardware).

---

## OpenPGP and GnuPG compatibility

The firmware implements the **OpenPGP card application** (documented as version **3.4.1** in [docs/OPENPGP_CARD.md](docs/OPENPGP_CARD.md)). That is the same class of device GnuPG drives for **OpenPGP smart cards** over **CCID/USB**: the host needs a normal smart card stack (`pcscd`, `ccid` drivers, GnuPG's `scdaemon`). **No custom host-side cryptographic driver** is required beyond what you would use for any OpenPGP card.

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

**Integration status:** The OpenPGP and CCID logic lives in **`usb-personality`**, **`baochip-openpgp`**, and the **Xous** **`usb-bao1x`** service (see **xous-core**). Optional **`galdralag-service`** (`services/galdralag`) runs as a separate Xous process, connects to **`usb-bao1x`** for **CCID** IPC, and bridges **PDDB** provisioning data into **RRAM**; build and **`baosec`** registration: [services/galdralag/README.md](services/galdralag/README.md) and **`cargo run -p xtask -- build-and-register`**. Memory layout: [docs/RRAM_LAYOUT.md](docs/RRAM_LAYOUT.md). **End-to-end GnuPG on real hardware** still needs a full Xous image (with **`ccid-openpgp`**), a working host CCID stack (`pcscd`, driver), and items under [Known limitations / open work](#known-limitations--open-work) addressed where they apply to your ship target.

## Token session and key export

**Physical disconnect (unplug):** The host loses the USB device; any in-flight operation fails until the token is connected again and re-enumerated. On the device, the OpenPGP **card session** is cleared: **PIN verification state** does not survive power-off or removal, so **signing, decryption, and other protected operations require VERIFY PIN again** after reconnect, like other OpenPGP smart cards. **Private key material remains stored on the token** in sealed vault storage; unplugging does not erase it unless a separate **zeroisation** or wipe path runs.

**What may leave the device:** By design, **only public key material** is permitted to cross the USB link (for example OpenPGP **public** key packets and related data the card specification exposes to the host). **Private** keys, raw secret scalars, and sealed key blobs **do not** leave the device through normal firmware paths; private-key operations run **on the token**. The host receives **cryptographic results** (signatures, decrypted plaintext for card-assisted decrypt workflows) where the standard commands require it, not a portable copy of the private key.

**Importing keys onto the device:** It is also possible to **import public keys** into the token (for example trust anchors, peer certificates, or OpenPGP public packets for on-device verification). The firmware **vault** provides **public-key slots** for non-secret material (`crates/vault/src/public_key_vault.rs`). Host tooling for loading those slots is described in [docs/GALDRA-TOOL.md](docs/GALDRA-TOOL.md) as integration matures.

---

## Web of Trust and Key Signing Parties

OpenPGP and **GnuPG** use a decentralised trust model—the **web of trust**—to help verify who owns which keys and whether to rely on a given **public key**. That model is entirely **host-side**. Where chip-backed attestations such as [German eID and Governikus](#german-eid-and-governikus-as-a-trust-anchor-for-public-keys) are unavailable or inappropriate, it is the usual decentralised alternative (**key signing parties**, signatures on certificates); where they **are** available, both approaches can coexist as complementary paths.

**Galdralag fingerprint (`G:`):** For in-person verification workflows, **Galdra** can show a **device-bound** fingerprint derived from the token’s **SIG** public key (**BLAKE3-160**, `G:` prefix). It is **not** an OpenPGP v4 certificate fingerprint. It is **only** available when the active **cipher profile** has **`ephemeral_ecdh: false`**; built-in profiles default **`ephemeral_ecdh: true`**, so you typically add a user profile with **`galdra profile add ... --no-ephemeral-ecdh`** for workflows that need this identifier alongside **WoT**-style host signing. Plain-language definition and format specification: [Galdralag fingerprint](docs/GLOSSARY.md#g). Lifecycle, rotation policy, and the ephemeral ECDH gate: [KEY_LIFECYCLE.md — Galdralag fingerprint](docs/KEY_LIFECYCLE.md#galdralag-fingerprint-host).

### Obtaining your Galdralag fingerprint

The host prints a string that **always starts with `G:`** (BLAKE3-160 over the SIG public key bytes, **40 lowercase hexadecimal characters** after the prefix in canonical form).

1. Install **[Galdra](docs/GALDRA-TOOL.md)** on the host and ensure **PC/SC** works (**`pcscd`**, **`libpcsclite`**) so the tool can speak CCID to the token (see [Compile and install host tools](#compile-and-install-host-tools-galdra-galdrad-galdra-gtk)).
2. Connect the token (unlock if your workflow requires it).
3. Select a **cipher profile** with **`ephemeral_ecdh: false`**. Confirm with **`galdra profile show <name>`** (`ephemeral_ecdh: off`). The default profile name **`standard`** usually has **`ephemeral_ecdh: on`**; create one with **`galdra profile add <name> ... --no-ephemeral-ecdh`** if needed.
4. Run:

```bash
galdra identity fingerprint
# If you use a non-default profile:
galdra identity fingerprint --profile <name>
```

Machine-readable output: **`galdra --emit json identity fingerprint`** (optionally **`--profile <name>`**).

### What is the web of trust?

OpenPGP-compliant implementations include a certificate vetting scheme to assist with verifying key ownership; its operation has been termed a web of trust. OpenPGP **certificates** (one or more public keys plus owner/user-ID material) can be **digitally signed** by other users who, by doing so, endorse the association between that **public key** and the person or entity named on the certificate.

### How it works

1. **Key distribution.** You publish or send your **public key** (for example one generated with `gpg --full-generate-key` on the host, or carried on an OpenPGP-capable token).
2. **Identity verification.** Others check that the **public key** really belongs to you—typically **in person** or through channels they already trust.
3. **Key signing.** Once satisfied, they **sign your certificate** with their own **private key**.
4. **Trust propagation.** Each signature adds evidence to the web; people who trust the **signer** may extend **partial trust** to your key according to their **GnuPG** trust settings.

### Key signing parties

A **key signing party** is an in-person meeting where participants exchange **key fingerprints** and verify each other's identity before signing certificates later.

Typical characteristics:

- Participants meet **face-to-face** and verify identity using government ID, organisational credentials, or other agreed proof.
- After verification, participants **sign each other's public keys** (usually **after** the event—see workflow below).

That yields a social graph: if Alice trusts Bob and Bob signed Charlie's key, Alice may choose to trust Charlie's key depending on trust depth and policy.

Why such events matter:

- **In-person verification** can be stronger than purely remote confirmation for linking a key to a human.
- **Trust network.** Evidence spreads beyond pairwise meetings for those who use ownertrust and signature chains.
- **Community norm.** Used in amateur radio circles, open-source projects, and cryptography conferences.
- **Operational hygiene.** Reduces uptake of wrong or substituted keys when procedures are followed.

### Typical workflow at a key signing party

Parties usually **avoid computers during identity exchange**, so attackers have fewer chances to slip in substituted keys or malware on shared machines.

**Before the event.** Compute and record your **fingerprint** (a hash-derived digest of the **public key**—short enough to compare reliably). Do **not** rely on exchanging full keys on paper at this stage unless your organisers specify otherwise.

```bash
# Key fingerprint for YOUR_KEY_ID (example)
gpg --fingerprint YOUR_KEY_ID
```

Bring the fingerprint on paper or another durable medium (example shape: `ABCD 1234 EFGH 5678 90AB CDEF 1234 5678 90AB CDEF`).

**At the event (fingerprints only).** Exchange **fingerprints**, verify IDs, and note which fingerprints belong to which verified person. Confirm each participant's claimed identity matches the documents checked.

**After the event.** Fetch full **public keys** from **keyservers** or direct distribution; confirm downloaded keys match the **fingerprints** recorded on paper; **sign** the keys you verified; optionally **upload** signatures so others can use them.

### Fingerprints instead of full keys at the event

- **Operational security.** Keeps substitution attacks tied to verified fingerprints rather than trusting arbitrary machines mid-event.
- **Simplicity.** Fingerprints fit on paper and are quick to read aloud or compare.
- **Verification.** After download, recomputing the fingerprint checks integrity end-to-end.

### Keyservers

**Keyservers** are networked repositories that store and replicate **public** OpenPGP keys (and updates such as signatures and revocations). They make keys discoverable by **User ID**, **key ID**, or **fingerprint** and underpin wide-area distribution for the web of trust.

How they behave in principle:

- **Distributed replication.** Uploading to one server participating in a sync mesh often propagates to peers (classic **SKS**-style pools worked this way).
- **Synchronisation.** New keys, signatures, and revocation certificates spread according to each server's policy and connectivity.
- **Public read access.** Only **public** material is intended for publication; **private keys** must never be uploaded.

**Privacy.** Published keys expose **User IDs** (often including mail addresses). Treat uploads as **public and long-lived** on many servers; upload **revocation certificates** when a key must be retired. Policy varies by operator ([keys.openpgp.org](https://keys.openpgp.org/) differs from legacy pools).

**Peer topology.** Graphs of server relationships appear at [spider.pgpkeys.eu/graphs/](https://spider.pgpkeys.eu/graphs/); SKS-oriented peer listings at [spider.pgpkeys.eu/sks-peers](https://spider.pgpkeys.eu/sks-peers).

### Using keyservers

```bash
# Upload your signed key (after local signing)
gpg --send-keys YOUR_KEY_ID

# Search by mail or name (behaviour depends on keyserver configured in gpg.conf)
gpg --search-keys email@example.com

# Refresh imported keys from configured keyservers
gpg --refresh-keys
```

### Common keyservers

| Server | Notes |
|--------|--------|
| [keys.openpgp.org](https://keys.openpgp.org/) | Widely used; consent-oriented verification for mail-linked User IDs |
| [pgp.mit.edu](https://pgp.mit.edu/) | MIT-hosted server historically tied to SKS-era meshes |
| pool.sks-keyservers.net | Legacy pool hostname associated with the former SKS ecosystem; connectivity today varies |

### Best practices and caveats

- Publish your **public key** (or signatures on others' keys) when your policy allows wider discovery.
- Run **`gpg --refresh-keys`** periodically so revocations and new signatures propagate locally.
- **Key signing asserts identity linkage**, not cipher strength—sign only after proportionate verification.
- A signature means: you attest this **public key** belonged to that verified identity **at signing time**; others still choose trust paths themselves.
- Before publishing a Galdralag fingerprint, confirm the active profile has `ephemeral_ecdh: false` with `galdra profile show <name>`.

For authoritative behaviour of **`gpg`**, trust models, and distribution options, see the **GnuPG** manual and upstream documentation.

The **Fulla** project (**[Supermagnum/Fulla on GitHub](https://github.com/Supermagnum/Fulla)**) hosts the WoT-aligned registry server work: implementation and evolving specification for storing contributor public keys plus optional amateur-radio labels, postal hints, **`organisation`** (JSON spelling), **`role`**, **`note`**, **`badge_number`**, and related columns aligned with Galdra contact metadata. **`galdra keyserver push`** submits **`POST /api/v1/keys`** JSON (including **`armored_public_key`**, **`email`**, and those optional fields when you pass CLI flags); **`galdra keyserver fetch`** and the **`[keyserver]`** config stanza are implemented in **`galdra`** / **`galdra-core-host`** against that direction. **No public Fulla registry is deployed yet**; a publicly operated service is expected in the future. Additional historical design prose lives in **[docs/server.md](docs/server.md)**.

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
| **Cipher profile system** — named symmetric **cascades** (stack independent ciphers on top of each other; **up to four** layers, **three** is a supported depth) and related policy | Not in OpenPGP card spec | **No** — firmware / host token tools |
| **microSD decoy / mass-storage personas** — uninformed-host USB behaviour | Not in OpenPGP card spec | **No** — separate USB personality code paths |
| **WebAuthn / FIDO2** | CTAP / WebAuthn | **Not implemented** — different standard from OpenPGP card |

For day-to-day **card** behaviour, rely on [docs/OPENPGP_CARD.md](docs/OPENPGP_CARD.md). For **vault-only** or **token-unique** features, use this repository's firmware and [Galdra tool](docs/GALDRA-TOOL.md) documentation.

---

## Shamir secret sharing and drive encryption

The **OpenPGP card** and **GnuPG** stacks do **not** define Shamir's Secret Sharing (SSS) for keys or for disk unlock. SSS is still useful **alongside** normal encryption: it almost never replaces the symmetric cipher on the disk — it **protects the small secret** (master key or passphrase) that unlocks that encryption.

**Pattern (always the same idea):**

| Layer | Role |
|-------|------|
| Drive | Encrypted with a **master key** (e.g. AES-256 via LUKS, VeraCrypt, or a raw block layer) |
| Master key | Split with SSS into **N** shares, threshold **K-of-N** |
| Shares | Held by people, devices, or offline storage; **K** shares together reconstruct the master key |
| Unlock | Reconstruct key, then pass it to `cryptsetup`, `veracrypt`, or your stack |

### Common real-world approaches

**1. LUKS (Linux) and external SSS**

[LUKS](https://gitlab.com/cryptsetup/cryptsetup) encrypts the volume with a master key. You can extract that key (or a key-slot secret, depending on your procedure), split it with an SSS tool, and store shares separately. At unlock time, combine **K** shares, reconstruct the key material, and supply it to `cryptsetup` (see your distribution's documentation; mishandling keys can brick access).

Example shape using the `ssss` ("Shamir's Secret Sharing Scheme") utilities (names and packaging vary by OS):

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
- Encrypt the drive or bulk store with **AES-GCM** or **ChaCha20-Poly1305** using that key (this matches the workspace's audited symmetric crates).
- Use `vsss-rs` to split the master key into **N** shares with threshold **K**.
- Store shares in vault slots, other devices, or with key holders.
- On boot or recovery, collect **K** shares, reconstruct, then use **HKDF** (or your policy) for domain-separated subkeys if needed.

**4. VeraCrypt**

VeraCrypt does not implement SSS internally. The same **external** pattern applies: split the **passphrase or keyfile material** with an SSS tool; do not try to Shamir-split the volume's ciphertext.

### Hybrid pattern (large data)

SSS is for **small secrets** (key size). You **do not** apply Shamir to multi-gigabyte ciphertext. The usual layering:

```text
[Drive data]
    encrypted by
[Symmetric master key, e.g. 32-byte AES-256]
    split by SSS into
[Share 1] [Share 2] ... [Share N]
    (each share may be wrapped with a recipient's PGP key, HSM, or offline media)
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

One concrete pattern is a **drive or volume** encrypted using **Brainpool** curves where your stack requires them (for example ECDH/ECDSA around a **master secret**), combined with **Shamir's Secret Sharing** on the **key material** that unlocks that encryption (the same [small-secret layering](#hybrid-pattern-large-data) as above: SSS protects the key, not multi-gigabyte ciphertext). If and when **firmware and host software** implementing that workflow have been **independently audited**, such a combination can be valuable to organisations that must meet **quorum** policies and **national crypto** profiles at the same time.

**Why Brainpool curves (e.g. BrainpoolP256r1, BrainpoolP384r1, BrainpoolP512r1) are often discussed in that context:**

- **BSI** (Germany's federal cybersecurity authority) mandates Brainpool in many deployment profiles; requirements appear in **EU government** and **NATO** procurement and policy settings.
- Parameters are **fully specified and verifiable** in [RFC 5639](https://datatracker.ietf.org/doc/html/rfc5639), which reduces "nothing up my sleeve" concerns compared with older debates around some NIST curve generation methods.
- **IETF precedent:** RFC 5639 is already on the standards track for these curves.

**Scenarios where combining SSS with Brainpool-class cryptography addresses institutional needs** (illustrative; not legal or compliance advice):

| Scenario | Why SSS plus strong, policy-aligned curves matter |
|----------|---------------------------------------------------|
| Employee leaves or dies | Recovery remains possible **without** that person's exclusive secret |
| Lawful access under due process | A **quorum** can be required — no single party holds the full unlocking secret |
| Corporate key escrow | **Auditable** split; no single administrator has complete access |
| Hardware seizure | Media may be captured without capturing **K** of **N** shares |
| Regulatory alignment (EU / BSI) | Brainpool satisfies many **German and EU** government cryptography requirements |

## German eID and Governikus as a trust anchor for public keys

If Governikus-style OpenPGP signing or comparable chip-backed national **eID** attestation is **not** available or practical for your jurisdiction or workflow, [Web of Trust and Key Signing Parties](#web-of-trust-and-key-signing-parties) describes an alternative host-side approach based on **in-person verification** and third-party signatures on certificates.

[Governikus OpenPGP key authentication](https://pgp.governikus.de/?lang=EN) is an online service run on behalf of the **BSI** (Germany's Federal Office for Information Security). After the submitter authenticates with a **German eID**-capable ID card, an EU **eID** card for EU citizens, or an **electronic residence permit**, the service checks that the authenticated **legal name** matches the OpenPGP **User ID** on the uploaded public key. If it matches, Governikus signs that public key with the service signing key so third parties can verify the attestation.

A practical workflow with this firmware: generate a **Brainpool** asymmetric key on the token (OpenPGP card generation as usual), export the **public** key or certificate to the host, complete the Governikus submission flow including **eID** authentication (typically AusweisApp and NFC card read), and use the signed public key returned by the service (for example from e-mail distribution). The private key stays on Galdralag throughout.

Neither path replaces the other. **eID** and the Governikus step bind the public key to **identity verified against the chip** at submission time; they do not supply **forward secrecy**, **Shamir K-of-N** for long-term key material, or **cipher profiles** for bulk data—those are [firmware-specific features](#standards-vs-firmware-specific-features) described elsewhere in this README. The **eID** chip and surrounding issuance process also do not, by themselves, implement the token's ephemeral ECDH and cascade behaviour. Conversely, a Brainpool OpenPGP key generated on-device aligns with the **BSI**/**EU** deployment context already discussed for [Brainpool institutional use](#shamir-plus-brainpool-example-and-institutional-fit), but without an external attestation step correspondents must rely on other means to connect a fingerprint to a **legal person**.

| Layer | Role |
|-------|------|
| OpenPGP public key (e.g. Brainpool on Galdralag) | Cryptographic structure and on-token private-key control; curve choices track **BSI TR-03111**-class expectations (see the [Brainpool capability rows](#asymmetric--key-agreement) and TR-03111 discussion in [Is this AI slop?](#is-this-ai-slop)) |
| Governikus signature | Confirms the **name** on the certificate matched chip-authenticated identity when the user completed the flow |

**Limitation:** Verification is **name-based**. If two people share the same legal name in the fields the service compares, the attestation does not distinguish them; it confirms **identity linkage to that name at attestation time**, not global **uniqueness**. Routine OpenPGP concerns (e-mail binding, key rollover, revocation) remain in force.

Policy alignment: the same **BSI** that defines Brainpool-related technical guidance (**BSI TR-03111**; conformance vectors under `crates/vault/tests/bsi_vectors/`) also stands behind the Governikus **eID** signing process, which often matters in **German and EU** settings where Brainpool is already required or preferred—see [Shamir plus Brainpool: example and institutional fit](#shamir-plus-brainpool-example-and-institutional-fit).

**Wider scope (research note, not a finished survey):** The same pattern—binding an OpenPGP public key to chip-verified identity—is applicable in principle wherever national **eID** exists; which providers offer a Governikus-like signing step, and under what rules, is a separate question worth investigating as deployments expand. Other **EU** member states run card-based **eID** ecosystems under **eIDAS** that might support comparable or stronger trust anchors than the German path alone; this README does not catalogue them.

| Jurisdiction | Status touched in this document |
|--------------|----------------------------------|
| Germany | Governikus/BSI flow described above |
| Estonia | Chip-based **eID**. Migrated from **RSA** to **NIST P-384** (**secp384r1**) **ECDSA** in 2017–2018 after the **ROCA** vulnerability forced abandonment of **RSA** entirely (the chip could not generate safe **RSA** keys and had no path to larger key sizes). Private key is hardware-bound and cannot be read from the card. No known Governikus-style OpenPGP signing service found. |
| Belgium | Chip-based **eID**. Older cards used **RSA** 1024-bit; newer cards (**applet** 1.8 onward) use **NIST P-384** **ECDSA**. Active open-source middleware ecosystem (**eid-mw**, **OpenSC**). No known Governikus-style OpenPGP signing service found. |
| Norway | The national ID card chip (issued since 2020) is **ICAO** 9303-compatible and implements a **travel-document** chip only; it carries no **eID** signing function. Signing **eID** is separate: accredited private providers (**Buypass**, **Commfides**) under **SEID**, historically **RSA** 2048-bit, moving to **RSA** 3072-bit with **ECC** introduced in **SEID 2.0**. No known Governikus-style OpenPGP signing service. The travel chip and the signing **eID** are distinct—relevant if someone tries to use only the card chip directly. |
| Austria | *Partially investigated.* **eID** uses **ECC** (confirmed); specific curve not confirmed in available sources. Multi-token **Bürgerkarte** model rather than a single card; largely migrated to a mobile app. Further investigation needed on curve details and any OpenPGP signing service. |
| USA | **PIV** card (**Personal Identity Verification**, **FIPS** 201 / **NIST SP** 800-78): issued only to **federal** employees and contractors—not a universal civilian card. Algorithms: **NIST P-256** mandatory for authentication keys; **P-256** or **P-384** for signing/key management; **RSA** 2048/3072 also permitted; **NIST** curves only, no **Brainpool**. Trust root is the **Federal Common Policy CA** (**FCPCAG2**), not included in standard commercial trust stores. No Governikus-style OpenPGP signing service found; **FPKI** is **X.509** infrastructure separate from OpenPGP. **PIV** being federal-only means it is not a civilian trust anchor like German **eID**. |
| Canada | No national chip-based identity card with on-chip signing keys. Digital identity is fragmented across provincial schemes (for example **BC Services Card**), mobile apps (for example **eID-Me**), and an evolving federal digital-credentials framework. No single card comparable to the German, Estonian, or Belgian model. *No equivalent card infrastructure found*—not a viable trust anchor in this sense. |
| Other countries | Not investigated |

Estonia and Belgium both adopted **NIST P-384** on-chip rather than **Brainpool**, whereas Germany's public-sector **BSI** profile centres on **Brainpool** (see above). Galdralag already supports **Brainpool**, **NIST** P-256/P-384, and **RSA** for OpenPGP-capable use ([Asymmetric / key agreement](#asymmetric--key-agreement)), so the same trust-anchor pattern does not depend on matching Germany's curve preference alone.

Outside the **EU**/**EEA**, the card-based trust-anchor pattern is harder to apply: the **USA** has a chip card (**PIV**) but it is restricted to federal personnel and sits in **X.509**/**FPKI**, not integrated with OpenPGP; **Canada** has no national on-chip signing card in the sense used above. That limits the pattern chiefly to jurisdictions with universally issued government chip credentials—the **EU eIDAS** area is where the model is currently strongest.

---

## Standards process: Shamir and ephemeral key exchange

When and if the hardware reaches a **consumer-ready** state, people who want **Shamir's Secret Sharing** and **authenticated ephemeral key exchange** to become part of interoperable **OpenPGP / GnuPG** behaviour (instead of only firmware-specific features) would need to drive **standards and implementation** change elsewhere. This repository does not speak for the IETF or GnuPG; the venues below are where such amendments are normally pursued.

### CESS (related open standard)

**[CESS](https://github.com/Supermagnum/CESS)** — *Cryptologically Enchanted Shamir's Secret* — is an open cryptographic standard for **threshold secret sharing** together with **cipher-agnostic authenticated encryption**, **password-based share wrapping**, and optional **post-quantum hybrid key exchange**. The [CESS repository](https://github.com/Supermagnum/CESS) holds the normative specification, algorithm registry, test vectors, and conformance runner.

**This firmware conforms to CESS** for the constructions implemented here: the specification's interoperable share and envelope rules sit alongside the same **Shamir**, **Brainpool**, and **cipher-profile** themes described elsewhere in this README. The normative text is separate from this repository; **conformance posture** (what matches the spec, what differs while **retaining** algorithms such as AES and SHA-256 in profiles, and roadmap toward stronger interoperability): [docs/CESS_CONFORMANCE.md](docs/CESS_CONFORMANCE.md).

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

   Object code and archives land under `target/riscv32imac-unknown-none-elf/release/`. A full bootable **Xous** system image for a specific board is produced by the wider Baochip / Xous integration flow when you follow that product's build; `xtask` here runs `cargo build` for the firmware library crates listed in `xtask` (not a single ready-to-flash file by itself).

4. **Xous CCID daemon (`galdralag-service`)** — needs the **`riscv32imac-unknown-xous-elf`** Xous toolchain (not the bare **`riscv32imac-unknown-none-elf`** firmware triple above). From repo root: **`cargo run -p xtask -- build-and-register release`**. That rebuilds the ELF, verifies it on disk, prints the **`baosec`** cratespec, and optionally runs **`cargo xtask baosec`** when given **`--xous-core /path/to/xous-core`**. Details: [services/galdralag/README.md](services/galdralag/README.md).

### Flashing

This repository does **not** ship a one-command flasher yet. Programming the **Baochip-1x** (JTAG, ROM/USB boot, or vendor tools) follows the board and silicon documentation. Start from **[Supermagnum/Baochip-1x-firmware](https://github.com/Supermagnum/Baochip-1x-firmware)**; **eval board hardware** is in **[baochip/dabao](https://github.com/baochip/dabao)** — on the Dabao board, **SW2** toggles **bootloader mode** (see that schematic).

**Committing UF2 without the physical boot button:** After copying **`loader.uf2`**, **`xous.uf2`**, and **`apps.uf2`** to the **BAOCHIP** volume, you can either press the physical **boot** button **or** type **`boot`** in the **boot1** USB serial console (1 000 000 baud, e.g. `screen /dev/ttyACM0 1000000`). That avoids relying on the **boot** button for this step only. The console **disconnects** when you type **`boot`**; that is **expected** (the system reboots into the next stage). On Linux, `dmesg --follow` helps confirm USB re-enumeration. This is distinct from **PROG** (hold while connecting USB to enter the **BAOCHIP** mass-storage bootloader). See **[baochip/dabao#2](https://github.com/baochip/dabao/issues/2)** (closed).

**Xous / Baochip flow:** Images are **Ed25519-signed** and verified by **boot0** before execution; see [Signed firmware (Ed25519, boot0)](#signed-firmware-ed25519-boot0). For **dabao**, **UF2** layout, holding **PROG** while plugging USB to enter mass-storage mode, and **boot1** update steps, see **[Getting Started with Baochip Targets](https://github.com/betrusted-io/xous-core/blob/dev/README-baochip.md)**.

### Compile and install host tools (`galdra`, `galdrad`, `galdra-gtk`)

Host crates live at the workspace root: `galdra/`, `galdrad/`, `galdra-gtk/`.

**Ubuntu / Debian** (install before `cargo build` / `cargo install`):

```bash
sudo apt update
sudo apt install build-essential pkg-config libpcsclite-dev pcscd libssl-dev
# required only for `galdra-gtk`:
sudo apt install libgtk-4-dev
```

`libpcsclite-dev` satisfies the **default** **`galdra`** **PC/SC** linking path; **`pcscd`** is the daemon that serves smart-card readers at runtime. **`libssl-dev`** is required so **openssl-sys** can link (**sequoia-net** keyserver lookups and **ldap3** TLS use **native-tls** today). Omit **`libgtk-4-dev`** if you never build **`galdra-gtk`**.

**GTK 4 (`galdra-gtk` only):** `pkg-config` must resolve **gtk4** (workspace crate **`gtk`** 0.9.x, package **`gtk4`**). On Fedora use **`gtk4-devel`**; on Arch **`gtk4`**.

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

### Run `galdrad` and the desktop GUI (`galdra-gtk`)

**`galdra-gtk`** is the GTK4 desktop binary (Cargo package **`galdra-gtk`**; there is no **`galdra-gui`**). It is a front-end to the **`galdrad`** REST API — run **`galdrad`** first.

**Daemon** — **`galdrad`** listens on **`127.0.0.1:8742`** by default (`--listen` overrides); see [`galdrad/src/main.rs`](galdrad/src/main.rs).

```bash
galdrad
```

Quick check: `curl -s http://127.0.0.1:8742/health` (interactive API docs: **`http://127.0.0.1:8742/swagger-ui/`**.)

**Desktop GUI** — **`galdra-gtk`** uses **`http://127.0.0.1:8742`** by default (`--base-url` or **`GALDRAD_URL`**); see [`galdra-gtk/src/main.rs`](galdra-gtk/src/main.rs).

```bash
galdra-gtk
galdra-gtk --base-url http://127.0.0.1:8742
GALDRAD_URL=http://127.0.0.1:8742 galdra-gtk
```

From a fresh **`cargo build --release`**, without installing: **`./target/release/galdrad`** then **`./target/release/galdra-gtk`** from the repo root.

**Host vs token:** **`galdra-gtk`** mirrors whatever **`galdrad`** exposes over HTTP; token **unlock**, **provision**, and other CCID flows stay on the **`galdra`** CLI (see **`galdra device`** in **[docs/GALDRA-TOOL.md](docs/GALDRA-TOOL.md)** and Tier **2c**).

**Contact directory (`galdra contact`, `galdrad` `/contacts`):** creating a contact **requires an e-mail** (CLI: `--email`; HTTP: JSON field `email`). Optional fields include **display name** (`--name` / `name`), **organisation** (**`--org`** / `org`), **role**, **badge** (**`--badge`** / `badge`), **note**, **callsign**, **Fluxer**, **Discord**, and **IRC** ids, plus **postal hints** (`street`, `country`, `postal_code`, `region`), amateur-radio **`dmr_id`**, and **`radio_affiliation`**. These values are stored only in local SQLite metadata (they are **not verified** against external services). **Looking up** a contact (for example `galdra contact show`, `PATCH`/`DELETE` paths, `galdrad` **`GET /contacts/{id}`**, group member ids, or **`POST /decrypt`** `recipient`) accepts the row **UUID**, **callsign**, **e-mail**, a full **40-hex OpenPGP v4 fingerprint** (spaces ignored), those social ids, or a **DMR subscriber id** in **1..16777215** when given as a decimal token. **`galdra keyserver push`** can mirror many of the same labels to a Fulla-style registry (**`organisation`**, **`role`**, **`note`**, **`badge_number`**, radio/social/postal fields, and names — see **`galdra keyserver push --help`**). Commands and field limits are summarized in **[docs/GALDRA-TOOL.md](docs/GALDRA-TOOL.md)** under **Contacts** and **Identity model**.

### Uninstall host tools

If you used `cargo install --path` as above:

```bash
cargo uninstall galdra
cargo uninstall galdrad
cargo uninstall galdra-gtk
```

If you copied binaries manually, remove the files you added. Firmware is not "installed" on the host; erasing or reflashing the device is covered by your hardware documentation.

---

## Key capabilities

### What makes this token unusual

The items below are **Galdralag firmware capabilities**, not requirements of the [OpenPGP card application](#standards-vs-firmware-specific-features) or GnuPG.

- **Three-factor-ready security model** — **Possession** of the USB token and **knowledge** of the PIN are enforced in firmware today; an optional **biometric** third factor is **not** implemented in this repository (placeholder: [docs/BIOMETRIC_API.md](docs/BIOMETRIC_API.md)). See [docs/THREE_FACTOR_AUTH.md](docs/THREE_FACTOR_AUTH.md) for scope and limits.

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
  Shamir configuration are combined into named, auditable profiles. For bulk
  data under a profile, plaintext is encrypted **from the inside out**: you can
  stack **up to four** **different** symmetric AEADs on top of each other — so
  you can use **three** independent ciphers in one profile (for example
  ChaCha20-Poly1305, then Serpent-256, then Twofish-256), or a fourth distinct
  layer where policy allows — with **no cipher repeated** in the same profile
  and **independent** HKDF-derived key and nonce material per layer. Built-in
  names such as `standard`, `conservative`, and `high-assurance` ship with **one
  or two** layers; deeper stacks are for advanced or custom profiles.
  Full rules and wire layout: [docs/CIPHER_PROFILES.md](docs/CIPHER_PROFILES.md).
  Every profile selection is logged in the audit trail.

- **Keyed BLAKE3 between cascade layers (CESS)** — In addition to each layer's
  own AEAD tag and to the **Mode A** outer ChaCha20-Poly1305 envelope, **CESS**
  defines **keyed BLAKE3**-style integrity **between** inner cascade stages. For
  **registry-mapped** profiles (`suite_id` via built-in names), **`cipher-profile`**
  appends a **32-byte HMAC-BLAKE3** over each inner layer's AEAD output before the
  next layer encrypts; keys are derived with **HKDF-BLAKE3** using
  `cess::cess_blake3_integrity_gap_info` ([`inner_info.rs`](crates/cess/src/inner_info.rs)).
  **Single-layer** built-ins skip extra tags; **custom** profiles (no `suite_id`)
  keep the legacy cascade without inter-layer MACs. See
  [docs/CIPHER_PROFILES.md](docs/CIPHER_PROFILES.md) and
  [docs/CESS_CONFORMANCE.md](docs/CESS_CONFORMANCE.md). **Combination counts**
  under `cipher-profile` cipher rules (**five** AEAD primitives, **no cipher
  repeated** in one profile, order matters); the BLAKE3 column is the CESS
  **design-space** count (independent on/off per gap), not a per-message host toggle:

  | Cascade length | Ordered distinct-cipher stacks | × optional BLAKE3 on/off at each of the **length−1** gaps between layers |
  |:--------------:|--------------------------------:|---------------------------------------------------------------------------:|
  | 1 layer | 5 | 5 × 2^0 = **5** |
  | 2 layers | 20 | 20 × 2^1 = **40** |
  | 3 layers | 60 | 60 × 2^2 = **240** |
  | 4 layers | 120 | 120 × 2^3 = **960** |
  | **Total** | **205** | **1245** |

  The **205** figure counts **cipher stacks only** (permutations of 1–4 distinct
  choices from AES-256-GCM, ChaCha20-Poly1305, Twofish-256, Serpent-256, Camellia-256). The
  **1245** figure is the same stacks multiplied by every **independent**
  on/off pattern for optional inter-layer BLAKE3 (**2^(k−1)** patterns for **k**
  layers). **This firmware** applies inter-layer MACs for **all** gaps when a
  built-in **`suite_id`** profile has **≥ 2** layers (not a per-gap toggle).
  Built-in profile names use a **small** subset of the 205.

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
| Cipher profile system | Symmetric **cascade**: **up to four** different AEADs stacked (e.g. **three** independent layers); per-layer keys — `cipher-profile` — [docs/CIPHER_PROFILES.md](docs/CIPHER_PROFILES.md) |

### Security properties

| Property | Implementation |
|----------|---------------|
| Forward secrecy | Ephemeral ECDH: long-term key signs only, never agrees |
| PIN counter before compare | Counter flushed to RRAM before `subtle::ConstantTimeEq` — no exceptions |
| Hardware zeroisation | TRNG-sourced multi-pass overwrite; boot0 zeroises before USB enumeration |
| No secret on USB bus | Uninformed host sees only standard mass-storage; no fingerprint possible |
| Monotonic tamper evidence | Hardware one-way counters in always-on domain |
| Three-factor authentication | **Possession:** USB token; **knowledge:** on-device PIN (`pin-policy`); optional **biometric** not implemented — [docs/THREE_FACTOR_AUTH.md](docs/THREE_FACTOR_AUTH.md) |
| RRAM counters and audit trail | Monotonic HAL for PIN (and future stateful PQ signatures); profile audit records and in-RAM OpenPGP audit hook — append-only NV audit log **not** implemented — [docs/AUDIT_LOG.md](docs/AUDIT_LOG.md), [docs/RRAM_LAYOUT.md](docs/RRAM_LAYOUT.md) |
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

The policy is **stored on the token** (vault policy). The host tool cannot raise or lower the threshold **after** provisioning without going through the device's own authenticated management flow; treat provisioning as the moment to choose **3–10** for your threat model. Rationale (defaults vs higher limits) is spelled out in [docs/GALDRA-TOOL.md](docs/GALDRA-TOOL.md) under the PIN policy section.

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
[docs/HARDWARE_VERIFICATION.md](docs/HARDWARE_VERIFICATION.md). Intended
**region order** and **layout anchors** for vault subsystems are summarised in
[docs/RRAM_LAYOUT.md](docs/RRAM_LAYOUT.md); **physical** wipe ordering remains
platform and **boot0** integration work.

---

## Test results

Authoritative write-up: **[`docs/TEST_RESULTS.md#run-metadata`](docs/TEST_RESULTS.md#run-metadata)** (commit, scope, and how sections are organised). That page includes the **pipeline summary** table, unit test totals, vector coverage (Wycheproof, RFC, BSI TR-03111 ECDH + ECDSA, NIST CAVP, BLAKE3 hash/keyed-hash/derive-key), **dudect** timing table, key lifecycle checks, and **[Section 6 — cargo-fuzz](docs/TEST_RESULTS.md#6-cargo-fuzz-libfuzzer)** (matrices, **`chacha_roundtrip`**, recorded **`openpgp_dispatch`** long run). **You** decide whether those results are enough to try building or running this project; a **virtual machine** remains optional but **reduces** host risk.

```
cargo run -p xtask -- test-all
```

---

## Workspace layout

Firmware-oriented crates under `crates/` and host binaries at the repo root (see root **`Cargo.toml`** `[workspace]` for the authoritative member list):

| Crate | Role |
|-------|------|
| `galdr-core` | HAL traits (`MonotonicCounter`, `HardwareTrng`, `ZeroiseController`, `VaultStorage`), shared errors, `test-hal` fakes |
| `vault` | RRAM vault contracts, HKDF `KeyPurpose` labels, key material types (`zeroize`, no `Clone`/`Copy`) |
| `pin-policy` | PIN state machine; counter increment before `subtle::ConstantTimeEq`; threshold zeroisation |
| `usb-personality` | Mass-storage vs authenticated-unlock personas (including decoy mass-storage role); challenge/response; OpenPGP/CCID card application; USB disconnect-on-lock |
| `ephemeral-session` | Authenticated ephemeral ECDH session protocol; forward secrecy |
| `cipher-profile` | User-configurable cipher cascade profiles; built-in and user-defined |
| `cess` | HKDF-BLAKE3 `K_outer`, ChaCha outer AEAD, `suite_id \|\| inner_blob`; see [CESS_CONFORMANCE.md](docs/CESS_CONFORMANCE.md) |
| `bp512` | Brainpool P-512 backend helper crate |
| `biometric-api` | Biometric pre-gate wire types (CBOR, `SignedMatchResult`), session token helpers |
| `biometric-vault` | Template sealing and vault-side integration pieces |
| `biometric-fingervein` / `biometric-sweet` | Pluggable biometric backend sketches |
| `security-tests` | dudect timing harnesses for cryptographic paths |
| `host-tools` | Host manifest hashing, update verification, `psram-unlock`, **`galdralag-provision`** (Xous two-line CDC PIN provisioning) |
| `xtask` | Build, check, test, fuzz, **`build-and-register`** (Xous `galdralag-service`), timing-test |
| `galdra-core-host` | SQLite schema, contacts/groups/audit/sync, HKP/WKD/LDAP fetch, device and OpenPGP host helpers |
| `galdra` | CLI over `galdra-core-host` |
| `galdrad` | Local REST daemon |
| `galdra-gtk` | GTK4 desktop UI |

**Not in this workspace table as separate crates:** `baochip-openpgp` and `services/galdralag` are built via **`--manifest-path`** (see root `Cargo.toml` `exclude` and [services/galdralag/README.md](services/galdralag/README.md)). Optional **bulk/decoy block storage** (`psram-store` in design docs) is **not** yet a workspace member; see [docs/Psram.md](docs/Psram.md), [docs/dev-ref.md](docs/dev-ref.md), and [docs/SDMMC_STORAGE_INTEGRATION.md](docs/SDMMC_STORAGE_INTEGRATION.md).

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

**Host desktop GUI (`galdra-gtk`):** after [building/installing](#compile-and-install-host-tools-galdra-galdrad-galdra-gtk) **`galdrad`** and **`galdra-gtk`**, start **`galdrad`** then **`galdra-gtk`** ([step-by-step](#run-galdrad-and-the-desktop-gui-galdra-gtk)).

```bash
rustup target add riscv32imac-unknown-none-elf
cargo test --workspace --exclude xtask
cargo run -p xtask -- check-fw
cargo run -p xtask -- build-fw
cargo run -p xtask -- test-host
cargo run -p xtask -- test-all
cargo run -p xtask -- test-biometric
cargo run -p xtask -- timing-test biometric
cargo run -p xtask -- fuzz biometric_dispatch 60
cargo run -p xtask -- timing-test
# Xous CCID daemon (separate triple; see [Build, install, and uninstall](#build-install-and-uninstall) step 4):
# cargo run -p xtask -- build-and-register release
```

**Fuzzing (libFuzzer):** install `cargo-fuzz`, use nightly, then e.g. `cargo run -p xtask -- fuzz chacha_roundtrip 60` or `cargo run -p xtask -- fuzz openpgp_dispatch 60` (OpenPGP APDU path) or `cargo run -p xtask -- fuzz biometric_dispatch 60` (biometric CBOR path). Target names, xtask aliases, and **recommended corpus seeds** per target are in [fuzz/README.md](fuzz/README.md).

Enable `galdr-core` feature `test-hal` **only** in tests or host tools.
Never enable it in production firmware images — enforced by `check-fw`.

---

## Known limitations / open work

### CCID initial PIN: first-boot provisioning (USB CDC)

On first boot (OpenPGP PIN verifier digests still zero), firmware must not silently pick **unknown** PINs. Production **Xous** **`usb-bao1x`** images (without `dev-provisioning` or `trng-pin-fallback`) expose a **USB CDC-ACM** provisioning serial and return **`HalError::NeedsProvisioning`** until the operator has supplied PINs.

1. The host runs **`galdralag-provision`** from this repo:  
   `cargo run -p host-tools --bin galdralag-provision -- --port /dev/ttyACM0`  
   Use **`--user-pin`** / **`--admin-pin`** or omit them for interactive prompts via **`rpassword`** (nothing is echoed; PINs are not stored in shell history).
2. The tool sends **exactly two newline-terminated lines**: **line 1 = user PIN** (raw bytes), **line 2 = admin PIN** — matching **xous-core** `usb-bao1x` provisioning (not `STATUS` / `SET_USER_PIN` / `COMMIT` framing). See `crates/host-tools/src/provision.rs`.
3. **Xous** stores provisioning state in **PDDB** under **`usb.ccid`** (sentinel **`OKV1`**, keys **`user_pin_line`**, **`admin_pin_line`** per **`ccid_store`** in xous-core). The device resets USB and re-enumerates for **CCID** / OpenPGP.

When **`galdralag-service`** is included in the image (**`build-and-register`** / **`baosec`** positional cratespec, [services/galdralag/README.md](services/galdralag/README.md)), it waits for **PDDB** **`OKV1`**, bridges those PIN lines into **RRAM** via **`write_provisioning_pins`**, opens the vault, then drives **CCID** against **`usb-bao1x`**. Without that daemon, **`usb-bao1x`** itself may own the full CCID stack depending on your xous-core configuration.

**Other builds:** `usb-personality` also provides **`ProvisioningClass`** (feature **`provisioning-personality`**) with a **line-oriented STATUS / SET_USER_PIN / … / COMMIT** protocol for non-Xous or test harnesses; **`galdralag-provision`** is aimed at the **Xous two-line** reader, not that class.

**Development / lab shortcuts:** feature **`dev-provisioning`** with **`CCID_USER_PIN`** / **`CCID_ADMIN_PIN`** in the process environment (see `baochip-openpgp`). Optional **`trng-pin-fallback`** generates **unrecoverable** random PINs unless captured out-of-band — it is **`compile_error!`-disallowed** together with **`board-dabao`**.

**After the vault exists**, changing PINs still uses **GnuPG** / **OpenPGP CHANGE REFERENCE DATA** over CCID (`gpg --card-edit` → `passwd`), not the CDC provision protocol.

**Sequencing:** RRAM provision slots **`PNU1` / `PNA1`** carry operator-chosen PINs **into** the first successful vault open, then clear; routine PIN updates are card-application commands, not raw provision-slot writes.

PIN cap: 32 bytes (firmware limit; OpenPGP spec allows 127). See
`CCID_PIN_PROVISION_PAYLOAD_MAX_BYTES` in
`crates/baochip-openpgp/src/xous_impl.rs`.

**Integration:** **`usb-bao1x`** lives in **xous-core** (not built in this workspace). Bring-up: [docs/HARDWARE_BRINGUP_TEST_PLAN.md](docs/HARDWARE_BRINGUP_TEST_PLAN.md). Historical tracking: [xous-core issue #875](https://github.com/betrusted-io/xous-core/issues/875).

---

## License

GNU General Public License v3.0 — see [LICENSE](LICENSE).
