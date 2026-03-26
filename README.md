# Galdr firmware (Galdralag)

**[Galdra — Token Management Tool Specification](docs/GALDRA-TOOL.md)** — authoritative document for the **Galdra** CLI, **galdrad** daemon, GTK client, REST API, contacts and groups, encryption, build/install, and operational workflows (including keys and Shamir). Start here when working with host-side tools.

Portions of this repository (including documentation, tests, and tooling) may have been drafted or refined with assistance from automated coding or language models. That assistance is not a substitute for human review, security analysis, or independent cryptographic audit. Recorded test vectors, suite summaries, and timing statistics are collected in [docs/TEST_RESULTS.md](docs/TEST_RESULTS.md). The same policy in full appears under [AI disclaimer](#ai-disclaimer) at the end of this README.

> **Status:** Ready for human review and testing. No production-ready release exists.
> Cryptographic primitives are drawn exclusively from audited workspace
> dependencies. Post-quantum algorithms are feature-gated and marked
> **PENDING INDEPENDENT AUDIT** — do not use in production until that
> status changes. See [Post-quantum status](#post-quantum-status) below.

## Table of contents

- [Galdra tool usage and specifications](docs/GALDRA-TOOL.md)
- [AI disclaimer](#ai-disclaimer)
- [Test results](#test-results)
- [Testing on a virtual machine](#testing-on-a-virtual-machine)
- [About the name](#about-the-name)
- [Project overview](#project-overview)
- [Introduction to cryptographic keys (OpenPGP and GnuPG)](#introduction-to-cryptographic-keys-openpgp-and-gnupg)
  - [What are OpenPGP and GnuPG keys?](#what-are-openpgp-and-gnupg-keys)
  - [Session key exchange (hybrid encryption)](#session-key-exchange-hybrid-encryption)
  - [GnuPG agent and host key access](#gnupg-agent-and-host-key-access)
  - [Pinentry programs](#pinentry-programs)
  - [Creating a key with GnuPG](#creating-a-key-with-gnupg)
  - [Key IDs, fingerprints, and exporting public keys](#key-ids-fingerprints-and-exporting-public-keys)
  - [Centralized key generation and hardware distribution](#centralized-key-generation-and-hardware-distribution)
  - [Web of trust and key signing parties](#web-of-trust-and-key-signing-parties)
  - [Keyservers](#keyservers)
  - [Using keys with Galdra and the token](#using-keys-with-galdra-and-the-token)
  - [OpenPGP tooling versus Brainpool in firmware](#openpgp-tooling-versus-brainpool-in-firmware)
- [Implemented cryptographic capabilities](#implemented-cryptographic-capabilities)
- [Cryptographic primitives explained](#cryptographic-primitives-explained)
  - [Brainpool P-256r1, P-384r1, P-512r1 (ECDH and ECDSA)](#brainpool-p-256r1-p-384r1-p-512r1-ecdh-and-ecdsa)
  - [X25519 (ECDH)](#x25519-ecdh)
  - [Ed25519 (signatures)](#ed25519-signatures)
  - [ChaCha20-Poly1305 AEAD](#chacha20-poly1305-aead)
  - [AES-256-GCM (and AES-128-GCM in tests)](#aes-256-gcm-and-aes-128-gcm-in-tests)
  - [Twofish-256 and Serpent-256 (AEAD via Encrypt-then-MAC)](#twofish-256-and-serpent-256-aead-via-encrypt-then-mac)
  - [RSA (OAEP, PSS, PKCS#1 v1.5 verify)](#rsa-oaep-pss-pkcs-1-v1-5-verify)
  - [HKDF, HMAC, PBKDF2](#hkdf-hmac-pbkdf2)
  - [SHA-2, SHA-3, BLAKE2, BLAKE3](#sha-2-sha-3-blake2-blake3)
  - [Shamir secret sharing](#shamir-secret-sharing)
  - [PIN policy (not a cipher)](#pin-policy-not-a-cipher)
  - [PSRAM block device (optional, not in tree)](#psram-block-device-optional-not-in-tree)
- [Workspace Cargo features](#workspace-cargo-features)
- [Host desktop UI (GTK4)](#host-desktop-ui-gtk4)
- [Cryptographic validation and supply chain integrity](#cryptographic-validation-and-supply-chain-integrity)
  - [Dependency vendoring and pinning](#dependency-vendoring-and-pinning)
  - [Where pinned and audited crates are found](#where-pinned-and-audited-crates-are-found)
  - [Test suites](#test-suites)
    - [Wycheproof (Google)](#wycheproof-google)
    - [BSI TR-03111 (German Federal Office for Information Security)](#bsi-tr-03111-german-federal-office-for-information-security)
    - [Fuzzing (cargo-fuzz / libFuzzer)](#fuzzing-cargo-fuzz-libfuzzer)
    - [dudect (timing side-channel analysis)](#dudect-timing-side-channel-analysis)
  - [Coverage summary](#coverage-summary)
  - [Known limitations](#known-limitations)
- [Post-quantum status](#post-quantum-status)
- [Zeroisation (hardware caveat)](#zeroisation-hardware-caveat)
- [PIN policy](#pin-policy)
- [Workspace layout](#workspace-layout)
- [Where key functions are implemented (quick code map)](#where-key-functions-are-implemented-quick-code-map)
  - [Firmware and vault (embedded crates)](#firmware-and-vault-embedded-crates)
  - [galdra-core-host (host library)](#galdra-core-host-host-library)
  - [galdra (CLI binary)](#galdra-cli-binary)
  - [galdrad (local REST daemon)](#galdrad-local-rest-daemon)
  - [galdra-gtk (GTK4 desktop client)](#galdra-gtk-gtk4-desktop-client)
  - [Timing analysis (dudect)](#timing-analysis-dudect)
- [Commands](#commands)
- [Build, install, and uninstall](#build-install-and-uninstall)
- [Flashing firmware](#flashing-firmware)
- [License](#license)

## About the name

**Galdr** is the actual practice of spoken or norse sung magic: incantations used to bind, protect, or reveal. In the sagas it names the act of casting the spell itself, not only the words.
Sometimes also used to activate magic rune inscriptions, as on the Kragehul I (DR 196 U) lance shaft ([Kragehul I](https://en.wikipedia.org/wiki/Kragehul_I)), the [Lindholm amulet](https://en.wikipedia.org/wiki/Lindholm_amulet) (DR 261), the [Vadstena bracteate](https://en.wikipedia.org/wiki/Vadstena_bracteate), the [Seeland-II-C](https://en.wikipedia.org/wiki/Seeland-II-C) bracteate, and other comparable Elder Futhark finds.

**Galdralag** is the metrical form used for galdr: structured, precise, rule-bound verse in which the pattern is part of the force of the spell. The suffix *lag* is akin to "law" or "pattern."

**Runes** were literally secret, encoded knowledge; the shamanic usage was only known to those who understand.

## Project overview

**Galdr** is the firmware project name for **Baochip-1x** (Dabao evaluation board) devices running the **[Xous](https://github.com/betrusted-io/xous-core)** microkernel, built for `riscv32imac-unknown-none-elf`.

## Introduction to cryptographic keys (OpenPGP and GnuPG)

If you are new to cryptographic keys and want a practical path into this project, this section explains core ideas step by step. **Galdralag** keeps **private** key operations on the **token**; the host **Galdra** tool manages **public** keys, contacts, and groups, and talks to the device over USB. Many operators also use **GnuPG** (`gpg`) on a PC for key generation, keyservers, and file workflows. The commands below illustrate common `gpg` usage; see the [GnuPG manual](https://gnupg.org/documentation/manuals/gnupg/) for the full command set. Product behaviour for Galdra is specified in [docs/GALDRA-TOOL.md](docs/GALDRA-TOOL.md).

### What are OpenPGP and GnuPG keys?

**OpenPGP** is the standard; **GnuPG** (`gpg`) is a widely used implementation. A key **certificate** usually includes a **public** half (shareable) and a **private** half (secret). Typical uses:

- **Signing** data so others can verify it came from you and was not altered.
- **Encrypting** data so only chosen recipients can read it.
- **Binding identity** to a key (name, email, callsign in the user ID).

Analogy:

- **Public key** — others use it to encrypt to you or to verify your signatures.
- **Private key** — only the holder uses it to decrypt or sign; on **Galdralag** it resides on the **hardware token**, not in a host file.
- **PIN** — unlocks use of the private key on the token (see [PIN policy](#pin-policy)); this is separate from a **passphrase** protecting a software key in `~/.gnupg`.

Keys may live in GnuPG keyrings on disk, on smart cards or security keys, or in token firmware. **Galdra** imports and tracks **public** certificates for contacts; private operations are delegated to the token where the design requires it.

### Session key exchange (hybrid encryption)

**Hybrid encryption** is how OpenPGP handles large messages:

- Public-key schemes (for example RSA or elliptic-curve encryption) are relatively slow and encrypt only small payloads.
- Symmetric ciphers (for example AES) are fast but need a shared secret.

So the implementation generates a random **session key**, encrypts the bulk of the message with that session key, and encrypts only the session key to each recipient’s **public** key. The recipient decrypts the session key with their **private** key, then decrypts the message. Each message typically uses a **new** session key, which limits damage if one session key were ever exposed.

### GnuPG agent and host key access

**gpg-agent** is a host daemon that holds unlocked private key material in memory for a limited time, prompts for passphrases or PINs through **pinentry**, and avoids repeating prompts on every operation. It applies when you use **GnuPG-managed keys on the PC** (including many smart card setups).

On **Galdralag**, token private keys are unlocked with the **device PIN** through the host protocol; **Galdra** does not implement a GUI keypad. Desktop PIN entry often goes through standard **pinentry** programs. For battery-powered or intermittently powered hosts, you can lengthen cache times in `~/.gnupg/gpg-agent.conf` (trade security for convenience):

```text
# Example: cache PIN/passphrase up to one week (seconds)
default-cache-ttl 604800
max-cache-ttl 2592000
pinentry-program /usr/bin/pinentry-gtk-2
```

Reload the agent after changes:

```text
gpg-connect-agent reloadagent /bye
```

Longer TTLs reduce how often you type a passphrase; they do **not** replace sound token PIN policy for on-device keys.

### Pinentry programs

**Pinentry** is the small program that asks for PIN or passphrase so secrets are not typed into arbitrary applications. Common variants include **pinentry-gtk-2**, **pinentry-qt**, **pinentry-curses** (terminal/SSH), and **pinentry-tty**. Configure the desired binary in `gpg-agent.conf` as shown above. Custom UIs (embedded displays, special keyboards) are outside Galdra; integrators must follow secure PIN handling rules from GnuPG and vendor documentation.

### Creating a key with GnuPG

Typical flow:

```text
gpg --full-generate-key
```

Follow the prompts: algorithm (for example RSA or modern ECC), size, expiry, and **User ID** (real name, email, optional comment). For amateur radio workflows aligned with callsign-based directories, putting the **callsign** in the name or comment helps others find and verify your certificate. Choose a **strong passphrase** if the private key will live in software; token keys rely on the **token PIN** for daily use.

List keys:

```text
gpg --list-keys
gpg --list-secret-keys
```

### Key IDs, fingerprints, and exporting public keys

Fingerprints uniquely identify a certificate. Example colon-format listing:

```text
gpg --list-keys --with-colons | grep "^fpr" | cut -d: -f10
```

For one search term (email or name):

```text
gpg --list-keys --with-colons W1ABC | grep "^fpr" | cut -d: -f10
```

The fingerprint line on `pub` is the full value; shorter **key IDs** are suffixes of that fingerprint. Export **public** material for sharing:

```text
gpg --export --armor you@example.com > my_public_key.asc
```

Never distribute **private** keys or share token PINs.

### Centralized key generation and hardware distribution

Organisations sometimes generate a **primary** key in a **high-trust** environment, keep the primary offline, and issue **subkeys** to users on hardware tokens. That centralises policy and reduces per-user key-generation mistakes. Subkeys are loaded onto devices; users still protect each device with a **PIN** (this project’s policy expects at least **five alphanumeric** characters for token PINs where enforced; see [PIN policy](#pin-policy)). Procedures for subkey creation, export, and revocation belong in operator runbooks and the GnuPG documentation.

### Web of trust and key signing parties

OpenPGP trust is **decentralised**: people verify each other’s identity and **sign** each other’s **public** certificates. Those signatures help third parties decide whether to trust a key they have not personally verified. **Key signing parties** are social events where participants verify ID and later sign keys off-line from the exchange step (fingerprints are often exchanged on paper first to reduce swap attacks). Amateur radio operators sometimes sign keys after verifying callsign and licence at club meetings or hamfests.

### Keyservers

**Keyservers** are public directories of **OpenPGP public keys** (not secrets). Uploading publishes your key and user IDs; removal is generally incomplete, so treat uploads as permanent. Prefer modern services with sensible defaults (for example [keys.openpgp.org](https://keys.openpgp.org/)) and use **`hkps://`** (TLS) in tools such as Galdra where configured. Older SKS-style pools have largely been retired; rely on project docs and current GnuPG guidance for server lists.

Typical commands:

```text
gpg --send-keys KEY_ID
gpg --search-keys someone@example.com
gpg --refresh-keys
```

Revoke compromised keys promptly and publish revocation certificates.

### Using keys with Galdra and the token

The **Galdra** CLI (`galdra`) manages contacts, groups, audit logs, and sync packages, and performs **OpenPGP** (and optional **age**) encrypt/decrypt on the host using **public** material from its database while **private** signing and decryption operations that require the token go through the USB protocol. For fetching, deleting, and revoking keys, generating or deleting token private keys, and how **Shamir** recovery relates to firmware (not a `galdra` subcommand), see [Operational guide: keys and Shamir](docs/GALDRA-TOOL.md#operational-guide-keys-and-shamir) in the specification. Illustrative patterns (see [docs/GALDRA-TOOL.md](docs/GALDRA-TOOL.md) for the full command reference):

```text
# Encrypt a file to a group or explicit contacts (OpenPGP default)
galdra encrypt --input message.txt --output message.asc --group mygroup

# Decrypt (options depend on format; OpenPGP may use --recipient)
galdra decrypt --input message.asc --output message.txt --recipient YOUR_KEY_ID

# Detached signature and verify (token signing follows project milestones)
galdra sign --input doc.txt --output doc.sig --detach
galdra verify --input doc.txt --sig doc.sig
```

Exact flags and token-backed signing readiness evolve with releases; use `galdra <subcommand> --help` and [docs/GALDRA-TOOL.md](docs/GALDRA-TOOL.md).

### OpenPGP tooling versus Brainpool in firmware

**Use OpenPGP / GnuPG / Galdra** when you need interoperability with email, keyservers, contact directories, and standard encrypt/sign workflows on the host.

**Use Brainpool (and other primitives in the vault)** inside **firmware** when implementing on-device protocols, policy-enforced curves (for example BSI-oriented profiles), and operations that must run **without** shelling out to `gpg`.

You can combine both: establish trust and distribute **public** certificates with OpenPGP tools, while the token performs private operations using firmware-defined algorithms and policies.

## Implemented cryptographic capabilities

| Algorithm | Standard | Provided by | Tests |
|-----------|----------|-------------|-------|
| BrainpoolP256r1 ECDH/ECDSA | RFC 5639, BSI TR-03111 | in-tree `vault/src/brainpool.rs`, `vault/src/ecdsa_brainpool.rs` | Unit · RFC 5639 (domain) in unit tests · Wycheproof **ECDH** (`ecdh_brainpoolP256r1_test.json`) · Wycheproof **ECDSA** (`ecdsa_brainpoolP256r1_sha256_test.json`) · dudect **host** ECDH (`timing-test`, 5k timings) |
| BrainpoolP384r1 ECDH/ECDSA | RFC 5639, BSI TR-03111 | in-tree `vault/src/brainpool384.rs` | Unit · Wycheproof · BSI cross-check JSON · RFC vectors via integration tests · dudect **host** ECDH (`timing-test`, 5k timings) |
| BrainpoolP512r1 ECDH/ECDSA | RFC 5639, BSI TR-03111 | in-tree `vault/src/brainpool512.rs` | Unit · Wycheproof · BSI cross-check JSON · RFC vectors via integration tests · dudect **host** ECDH (`timing-test`, 15k timings) |
| ChaCha20-Poly1305 AEAD | RFC 8439 | `chacha20poly1305` workspace dep | Unit · Wycheproof · RFC 8439 (unit + integration) · dudect **host** tag check (`timing-test`) |
| Shamir Secret Sharing (K-of-N) | Shamir 1979, vsss-rs | `vsss-rs` workspace dep | Unit · KAT vectors · dudect **host** recover (`timing-test`) |
| Twofish-256 AEAD | Schneier et al. 1998 | `twofish` workspace dep | Unit · KAT (`vault/tests/twofish_vectors.json`: zero-key + variable-key + variable-text + Monte Carlo) · dudect host tag check (`timing-test`, representative t-statistic -2.31 on one host run) |
| Serpent-256 AEAD | Anderson/Biham/Knudsen 1998 | `serpent` workspace dep | Unit · Spec vectors in `vault/tests/serpent_vectors.json` · dudect **host** tag check (`timing-test`) |
| RSA-2048/3072/4096 OAEP, PSS | PKCS#1 v2.2, RFC 8017 | `rsa` workspace dep | Unit · Wycheproof · dudect **host** constant-time compare on modulus-sized buffers (`timing-test`; not raw decrypt/verify wall time) |
| AES-256-GCM | FIPS 197, NIST SP 800-38D | `aes-gcm` workspace dep | galdr-core smoke · vault **Wycheproof partial** (128-bit tag; AES-128/256; IV sizes under [Wycheproof (Google)](#wycheproof-google); skips AES-192, empty IV, 257-byte IV) · dudect **host** tag check (`timing-test`) |
| HKDF (SHA-256/SHA-512) | RFC 5869 | `hkdf` workspace dep | Unit (galdr-core + vault) · Wycheproof **HKDF-SHA-256** and **HKDF-SHA-512** JSON in vault · RFC 5869 integration vectors · dudect **host** (`timing-test`) |
| HMAC (SHA-256/SHA-512) | RFC 2104 | `hmac` workspace dep | Unit (galdr-core + vault: RFC + NIST CAVP subset) · Wycheproof **HMAC-SHA-256** and **HMAC-SHA-512** JSON in vault · dudect **host** (`timing-test`) |
| PBKDF2 | RFC 8018 | `pbkdf2` workspace dep | Unit (galdr-core) · RFC 8018 integration vectors · dudect host (`timing-test`, representative t +1.81 on one host run) |
| Ed25519 sign/verify | RFC 8032 | `ed25519-dalek` workspace dep | Unit (galdr-core) · Wycheproof **Ed25519 verify** JSON in vault · RFC 8032 integration vectors · dudect **host** verify (`timing-test`) |
| X25519 ECDH | RFC 7748 | `x25519-dalek` workspace dep | Unit (galdr-core) · Wycheproof **X25519** JSON in vault · RFC 7748 integration vectors · dudect **host** ECDH (`timing-test`) |
| SHA-2 (224/256/384/512) | FIPS 180-4 | `sha2` workspace dep | Unit (galdr-core + NIST CAVP integration subset) · dudect host SHA-256 / SHA-512 (`timing-test`, representative t -1.66 / -1.96 on one host run) |
| SHA-3 family | FIPS 202 | `sha3` workspace dep | Unit (galdr-core + NIST CAVP integration subset) · dudect host SHA3-256 / SHA3-512 (`timing-test`, representative t +2.93 / +2.28 on one host run; 200k samples each) |
| BLAKE2b/BLAKE2s | RFC 7693 | `blake2` workspace dep | Unit (galdr-core + RFC integration) · dudect host BLAKE2b-256 / BLAKE2s-256 (`timing-test`, representative t +1.85 / +1.85 on one host run) |
| BLAKE3 | BLAKE3 spec | `blake3` workspace dep | Unit (galdr-core + KAT integration) · dudect host single-chunk digest (`timing-test`, representative t +2.09 on one host run) |
| PIN policy (stateful) | — | in-tree `pin-policy` | Unit · Lifecycle integration tests · dudect **host** compare (`timing-test`) |
| PSRAM block device (optional) | — | **not present in this workspace** | **MISSING** |

## Cryptographic primitives explained

The table above lists **what** is wired and **how** it is tested. This section explains **why** each primitive exists and how it fits the threat model. Curves and ciphers are **not** interchangeable: keys and parameters are type-separated in code.

### Brainpool P-256r1, P-384r1, P-512r1 (ECDH and ECDSA)

**Brainpool** curves are prime-field **short Weierstrass** curves standardized in **RFC 5639** (parameters) and used heavily in **BSI TR-03111** and European PKI. This firmware implements **ECDH** (shared secret from a static/ephemeral scalar and a peer public point) and **ECDSA** (sign/verify with a hash matched to the field size: **SHA-256** for P-256, **SHA-384** for P-384, **SHA-512** for P-512). The three curves differ in field size and performance; they address deployments that require **non-NIST** curves or national-profile interoperability.

### X25519 (ECDH)

**X25519** implements Diffie–Hellman on **Curve25519** (**RFC 7748**). It is a **Montgomery** curve construction with fixed-size keys and a simple encoding; it is the usual choice for forward-secret key agreement alongside modern protocols. Test vectors include **Wycheproof** and **RFC 7748** examples.

### Ed25519 (signatures)

**Ed25519** is **EdDSA** on a twisted Edwards curve related to Curve25519 (**RFC 8032**). It provides deterministic signatures (nonce derived from message and key), **64-byte** signatures, and **32-byte** secret keys. The firmware uses it where policy calls for fast, compact signatures with **SHA-512** internally.

### ChaCha20-Poly1305 AEAD

**ChaCha20** is a stream cipher; **Poly1305** authenticates ciphertext and AAD in one pass (**RFC 8439**). The combination is an **AEAD**: decryption verifies the tag before releasing plaintext. This is the reference modern AEAD for environments without AES hardware acceleration.

### AES-256-GCM (and AES-128-GCM in tests)

**AES** is the NIST block cipher (**FIPS 197**). **GCM** (**SP 800-38D**) combines counter-mode confidentiality with **GMAC** for integrity. The project tests **AES-128** and **AES-256** with **128-bit tags** under **Wycheproof** where the runner supports the IV length; some upstream groups (AES-192, empty IV, longest IV) are skipped.

### Twofish-256 and Serpent-256 (AEAD via Encrypt-then-MAC)

**Twofish** and **Serpent** are **128-bit block** ciphers (AES finalists). Here they are used in **CTR** mode for confidentiality and **HMAC-SHA256** over ciphertext and metadata for authentication (**Encrypt-then-MAC**), not MAC-then-encrypt. Keys are derived with **HKDF** and **domain-separated** `KeyPurpose` labels so storage keys do not collide with other uses.

### RSA (OAEP, PSS, PKCS#1 v1.5 verify)

**RSA** PKCS#1 (**RFC 8017**) covers **OAEP** encryption, **PSS** signatures, and legacy PKCS#1 v1.5 verification. Modulus sizes **2048 / 3072 / 4096** are supported in the test surface. Timing harnesses focus on **constant-time** equality on **fixed-width** buffers after decryption or verification, not on hiding RSA arithmetic itself.

### HKDF, HMAC, PBKDF2

**HKDF** (**RFC 5869**) expands a pseudorandom key with optional salt and **info** for multiple independent subkeys. **HMAC** (**RFC 2104**) is the PRF inside HKDF and standalone message authentication. **PBKDF2** (**RFC 8018**) derives keys from passwords using **HMAC** as the iteration primitive; iteration count is policy-driven.

### SHA-2, SHA-3, BLAKE2, BLAKE3

**SHA-2** (**FIPS 180-4**) is the Merkle–Damgård family (224–512 bit outputs). **SHA-3** (**FIPS 202**) is the Keccak sponge. **BLAKE2** (**RFC 7693**) targets software speed; **BLAKE3** uses a tree mode for large inputs. All appear as **hash** and **HMAC** backends where the policy or protocol names them.

### Shamir secret sharing

**Shamir** splitting stores a secret as the constant term of a polynomial over a finite field; **k** of **n** shares reconstruct; fewer than **k** reveal no information in the ideal model. Used for recovery/backup flows that require a threshold.

### PIN policy (not a cipher)

Stateful **PIN** handling: minimum length, attempt counter **before** constant-time compare, and threshold **zeroisation**. See [PIN policy](#pin-policy).

### PSRAM block device (optional, not in tree)

Optional **external PSRAM** as a block device is **not** implemented in this repository; the row marks a future integration point.

## Workspace Cargo features

Feature flags select **profiles** and **optional algorithms** for embedded builds. Defaults are **empty** on most crates: the integrator or `xtask` enables what the product needs.

| Feature | Where | Meaning |
|---------|--------|---------|
| `test-hal` | `galdr-core` | Fake **HAL** (TRNG, vault, zeroise) for **unit tests and host tools** only. **Do not** enable in production firmware. |
| `pq-signatures` | `galdr-core`, `vault`, `pin-policy`, `usb-personality` | Gates **SP 800-208**-style **XMSS / LMS** paths when implemented; see `docs/PQ_SIGNATURES.md`. |
| `profile-openpgp` | `galdr-core`, `vault` | OpenPGP-oriented profile hooks. |
| `profile-extended` | `galdr-core`, `vault` | Extended product profile; implies `profile-openpgp`. |
| `profile-pqc` | `galdr-core`, `vault` | Post-quantum **KEM** / hybrid profile hooks. |
| `profile-hardened` | `galdr-core`, `vault`, `pin-policy`, `usb-personality` | Stricter policy defaults when opted in. |
| `algo-aes-gcm`, `algo-chacha`, `algo-ed25519`, `algo-x25519`, `algo-shamir` | `vault` | Per-algorithm **compile-time** enables for size- or certification-constrained images. |
| `dudect` | `security-tests` | Builds **`dudect_galdr`** and host timing harnesses (`cargo run -p xtask -- timing-test`). |

`xtask` runs **`check-fw`** with **`pq-signatures`** in one pipeline step so the gated configuration stays buildable.

## Host desktop UI (GTK4)

The **Galdra** host-side companion (token management, contacts, groups; see [docs/GALDRA-TOOL.md](docs/GALDRA-TOOL.md)) uses a **native desktop** UI built with **GTK 4** and **Rust** bindings (**gtk-rs** / **gtk4-rs**), **not** a browser-based or HTML/JavaScript **web GUI**. The graphical client talks to the same **local daemon** (`galdrad`) or **`galdra-core-host`** library as the CLI; there is **no** requirement to serve a web page or bundle a SPA. Rationale: offline operation, platform-native accessibility, a single auditable UI stack, and no embedded HTTP server solely for rendering HTML.

## Cryptographic validation and supply chain integrity

### Dependency vendoring and pinning

`Cargo.lock` is committed so dependency versions resolve reproducibly.
The `subtle` crate is **not** taken from crates.io as-is: the workspace
uses `[patch.crates-io]` in the root `Cargo.toml` to point `subtle` at
the in-tree copy under `crates/subtle-vendored` (treat that tree like
vendored code: change only with review and lockfile updates).

Other dependencies are fetched from **crates.io** at the versions pinned
in `Cargo.lock` (normal Cargo behavior). This repository does **not**
ship a full `cargo vendor` tree under `vendor/`.

Security audited workspace dependencies:
`aes-gcm`, `chacha20poly1305`, `ed25519-dalek`, `x25519-dalek`,
`hkdf`, `pbkdf2`, `hmac`, `sha2`, `sha3`, `blake2`, `blake3`,
`vsss-rs`, `zeroize`, `subtle`, `p256`, `p384`

These rust crates are part of the RustCrypto project (except vsss-rs and the dalek family) — they all had independent security audits, are widely used in production security software, and are maintained by people with cryptographic expertise. Using them means a developer inherits that audit history rather than introducing new unreviewed cryptographic code.

### Where pinned and audited crates are found

**Unchanged (pinned) versions:** The exact dependency graph for this workspace is fixed in **[`Cargo.lock`](Cargo.lock)** at the repository root. Until that file changes in version control, every `cargo build` / `cargo test` resolves the **same** crate versions and source trees. Reviewers comparing two commits should diff `Cargo.lock` to see dependency upgrades. This project does **not** ship a `cargo vendor` directory; crates are fetched from **crates.io** at resolve time using those pins.

**Audited cryptographic crates:** The curated list in the previous paragraph names the **workspace crates** chosen for audited primitives. **Where the audits live** is upstream: each crate’s **crates.io** page links to its repository; **RustCrypto** projects publish audit-related material in their GitHub org (issue trackers, security advisories, and linked third-party reports such as published NCC Group reviews for selected AEAD crates). **curve25519-dalek** / **ed25519-dalek** and **vsss-rs** carry their own upstream documentation and review history. This README does not host PDFs; use crates.io and the maintainer repository as the canonical place to read audit scope and date.

**Not OCI images:** This repository does **not** define Docker or OCI **containers** for reproducible builds. Supply-chain assurance for Rust code is expressed through **`Cargo.lock`** and `[patch.crates-io]`, not pinned image digests.

### Test suites

#### Wycheproof (Google)
JSON-driven tests under `crates/vault/tests/data/wycheproof/` cover **ChaCha20-Poly1305**,
**Brainpool P-256r1** (ECDH and ECDSA-SHA256), **P-384r1 / P-512r1** (ECDH and ECDSA), **RSA** (OAEP, PSS,
PKCS#1 v1.5 verify), **X25519**, **Ed25519** (verify), **HKDF-SHA-256**, **HKDF-SHA-512**, **HMAC-SHA-256**, **HMAC-SHA-512**,
and **AES-GCM** with **128-bit tag** and **AES-128 / AES-256** keys for IV lengths **8, 16, 32, 48, 64, 80, 96, 120, 128, 160, 256, 512, 1024, 2048** bits (1 through 256 bytes as implemented in `wycheproof_aes_gcm.rs`). **Skipped** Wycheproof groups: **AES-192** keys, **empty IV**, and **2056-bit (257-byte) IV** (no matching fixed-size AEAD type in the runner). Primitives without a Wycheproof JSON hook here still use RFC / NIST CAVP vectors where the capability table above says so.

#### BSI TR-03111 (German Federal Office for Information Security)
German national standard test vectors for elliptic curve cryptography,
with specific coverage of Brainpool curves (P256r1, P384r1, P512r1).
This is the primary test suite for Brainpool — use it alongside Wycheproof
ECDH/ECDSA JSON where wired. Required because Brainpool is a core
part of the extended on-device profile and the NSA-independent ECC
option.

#### Fuzzing (cargo-fuzz / libFuzzer)
Malformed, random, and mutated inputs directed at all parsers and
protocol handlers — particularly USB personality switching and any
host-facing protocol parser, as these handle untrusted input directly.
Rust's ownership model prevents memory corruption but panics and logic
errors remain in scope.

#### dudect (timing side-channel analysis)
`cargo run -p xtask -- timing-test` builds and runs the `dudect_galdr` binary from `crates/security-tests` (Welch t-statistic on timing samples; pass when |t| <= **4.5**). Most harnesses use **100,000** timings; **Brainpool P256 and P384** ECDH use **5,000** each; **Brainpool P512** uses **15,000**; **PBKDF2** uses **150,000**; **SHA3-256 and SHA3-512** use **200,000** each (reduced counts on slow curves; larger N on PBKDF2/SHA3 to reduce host jitter). Harnesses cover constant-time buffer/tag comparisons, AEAD tag checks (ChaCha20-Poly1305, AES-GCM, Serpent, Twofish), HMAC verify, HKDF, Ed25519 verify, X25519 ECDH, Brainpool ECDH, Shamir recover, PBKDF2-HMAC-SHA256, SHA-256/SHA-512, SHA3-256/SHA3-512, BLAKE2b/BLAKE2s, BLAKE3 (single-chunk inputs), PIN compare, and RSA-related **constant-time equality** on modulus-sized ciphertext/signature bytes (not full OAEP decrypt or PSS verify latency). **stderr** prints `[DUDECT] Running …` before each harness; stdout prints per-harness t-statistics and a **Summary**. Wall time is often on the order of **~20 minutes** on a developer machine (one full run recorded ~1220 s). Exit code **0** when all executed harnesses pass; **1** if any |t| exceeds the threshold. The capability table marks primitives exercised by `timing-test` as **dudect host** with representative t-statistics from a recorded run (your machine will differ). Stub APIs in `security-tests` stay `DudectStatus::NotRun` when the `dudect` feature is disabled. Full stdout-oriented results and dates are recorded in **[docs/TEST_RESULTS.md](docs/TEST_RESULTS.md)**; Section 9 can be updated by pasting `dudect_galdr` output without re-running the whole pipeline.

### Coverage summary

| Threat                        | Addressed by              |
|-------------------------------|---------------------------|
| Known bad crypto inputs       | Wycheproof                |
| Brainpool-specific edge cases | BSI TR-03111              |
| Malformed / unexpected inputs | Fuzzing                   |
| Timing leaks on secrets       | `dudect_galdr` (`timing-test`) + stubs for paths not yet benchmarked |
| Supply chain substitution     | Cargo.lock + pinned crates.io versions |
| Tampering with resolved deps  | Lockfile + in-tree `subtle` patch + CI |

### Known limitations

- **Compiler-introduced side channels** — dudect catches many but not
  all. Generated assembly for sensitive paths should be reviewed,
  particularly at higher optimisation levels.
- **Hardware side-channels** — power analysis and EM emissions on
  physical Baochip-1x silicon are outside the scope of software
  testing and require lab equipment and separate evaluation.
- **Protocol logic errors** — none of the above suites catch a
  correctly implemented but wrongly designed protocol. Human
  architectural review is required before any production deployment.
Hardware goals, boot model, crypto profiles, and host-visible USB behavior are aligned with the upstream **[Baochip-1x firmware design README](https://raw.githubusercontent.com/Supermagnum/Baochip-1x-firmware/refs/heads/main/README.md)** (requirement tables, ComboHash/PKE usage, Shamir, reproducible updates, test-vector sources).

Architecture notes for this repository: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Test results

Full test vector coverage, known-answer test results, Wycheproof run
summaries, RFC vector pass/fail tables, BSI vector results, and dudect
t-statistic records are maintained in:

**[docs/TEST_RESULTS.md](docs/TEST_RESULTS.md)**

Run the full suite at any time:

```
cargo run -p xtask -- test-all
```

To run the same pipeline **without** cargo-fuzz (shorter CI or local runs), use:

```
cargo run -p xtask -- test-all --no-fuzz
```

## Testing on a virtual machine

Testers should prefer a virtual Linux machine when exercising builds, host tools, USB workflows, or anything that could affect system state. Automated tests and machine-checked suites reduce risk, but they do not prove absence of bugs; unexpected behaviour during manual testing or debugging can still damage data, confuse device state, or stress the host.

Running in a virtual machine keeps that experimentation off your primary installation: snapshots and disposable images make it straightforward to reset, compare runs, and investigate failures without risking the machine you rely on day to day. This is the recommended way to test and debug safely.

## Post-quantum status

The following post-quantum algorithms are **NOT YET IMPLEMENTED**.
They will be implemented only after an independently audited Rust crate
becomes available for each scheme. The algorithms themselves are standardised
by NIST; the gap is in the Rust implementation audit status.

| Algorithm | Standard | Awaiting |
|-----------|----------|---------|
| ML-KEM | FIPS 203 | Independent audit of a suitable `no_std` Rust crate |
| ML-DSA | FIPS 204 | Independent audit of a suitable `no_std` Rust crate |
| SLH-DSA | FIPS 205 | Independent audit of a suitable `no_std` Rust crate |
| FN-DSA (FALCON) | FIPS 206 (draft) | Standard finalisation + independent audit |
| HQC | Draft ~2027 | Standard finalisation + independent audit |

**XMSS and LMS** (SP 800-208) are implemented behind the `pq-signatures`
feature flag but carry unaudited warnings. See `docs/PQ_SIGNATURES.md` for
the full audit status and usage policy.

**BIKE and NTRU** are not implemented and will not be implemented.
BIKE was eliminated from NIST standardisation in March 2025 in favour of HQC.
NTRU encryption was eliminated in July 2022. Neither has a path to a NIST
standard.

When an independent audit of a production-quality `no_std` Rust crate for
any of the above schemes becomes available, open a tracking issue referencing
this section to begin the implementation session.

## Zeroisation (hardware caveat)

The `ZeroiseController` HAL trait and its production implementation wipe
key material from RRAM and SRAM using TRNG-sourced multi-pass overwrite,
mirroring the boot0 zeroisation path. **This path has been tested in
simulation using the `test-hal` fake only. It has not been verified on
physical Baochip-1x hardware.** Zeroisation correctness on real silicon
requires:

1. JTAG-assisted memory inspection after a triggered zeroise event to
   confirm all sensitive regions read as zeroed or overwritten.
2. Power-cycle resilience testing: interrupted zeroise must resume on
   next boot within boot0.
3. Side-channel confirmation that zeroised regions do not retain data
   remnants readable by physical attack.

Until hardware verification is complete, the zeroisation implementation
should be considered **software-correct but hardware-unverified**. Track
hardware verification status in `docs/HARDWARE_VERIFICATION.md`.

## PIN policy

- **Minimum PIN length: 5 alphanumeric characters.** This is enforced at
  the parser boundary before `pin-policy` is called. Shorter inputs are
  rejected without incrementing the attempt counter.
- **PIN attempt threshold (default: 3).** The hardware-backed counter allows
  **three** failed attempts before lockout and zeroisation, matching common
  smartcard and hardware-token practice (e.g. Nitrokey, YubiKey PIV, ISO 7816
  style limits). The ceiling is **configurable at provisioning only**, in the
  range **3–10**, and is stored in the vault policy region **next to the PIN
  verifier hash** (see `vault::VaultPinPolicyRecord`). This gives integrators
  room for operational error rates without weakening the default for typical
  deployments.
- The attempt counter is incremented and flushed to RRAM **before** the
  constant-time comparison. This ordering is an unconditional security
  invariant.
- At the attempt threshold, full zeroisation is triggered.
- The hardware one-way counter in the always-on domain provides a secondary
  tamper-evident record of all attempt events.
- Challenge/response authentication for the USB informed-host path uses
  `HMAC-SHA256(HostChallengeKey, nonce || passphrase)`. The raw passphrase
  is never transmitted over USB.

## Workspace layout

| Crate | Role |
|-------|------|
| `galdr-core` | HAL traits (`MonotonicCounter`, `HardwareTrng`, `ZeroiseController`, `VaultStorage`), shared errors, `test-hal` fakes |
| `bp512` | Brainpool P-512r1 curve support (in-tree; used by `vault` for P512 ECDH/ECDSA) |
| `vault` | RRAM vault contracts, HKDF **domain separation** labels (`KeyPurpose`), key material types (`zeroize`, no `Clone`/`Copy`) |
| `pin-policy` | PIN state machine; **counter increment before** `subtle::ConstantTimeEq` PIN check; threshold zeroisation |
| `usb-personality` | Mass-storage vs authenticated-unlock personalities; no secret leakage to uninformed hosts (scaffold) |
| `host-tools` | Host manifest hashing / update verification stubs (`std`) |
| `security-tests` | Dudect (`dudect_galdr` via `--features dudect`) and timing-analysis stubs |
| `xtask` | Embedded `cargo build` / `check` / `test-host` / `test-all` / crypto and fuzz helpers |

## Where key functions are implemented (quick code map)

Use this map to jump straight to **modules and files** when reviewing behaviour. Paths are relative to the repository root. Embedded crates live under [`crates/`](crates/); [`galdra-core-host/`](galdra-core-host/), [`galdra/`](galdra/), [`galdrad/`](galdrad/), and [`galdra-gtk/`](galdra-gtk/) are top-level workspace members.

**Flow:** firmware [`vault`](crates/vault) and related crates implement on-device cryptography; [`galdra-core-host`](galdra-core-host) holds shared host logic (database, USB token, OpenPGP); [`galdra`](galdra) is the CLI; [`galdrad`](galdrad) exposes an HTTP API over the same library; [`galdra-gtk`](galdra-gtk) is a thin GTK client that calls `galdrad`.

### Firmware and vault (embedded crates)

#### HKDF domain separation and vault subkeys

**Runtime (policy labels and intended derivation purposes):**

- [`crates/vault/src/kdf_policy.rs`](crates/vault/src/kdf_policy.rs) — `KeyPurpose` and RFC 5869-style `info` strings for each vault use (storage, USB session, PIN verifier, Shamir recovery, Serpent/Twofish/RSA wrap, etc.); `derive_subkey_sha512_stub` is the placeholder for production HKDF-SHA512 expand (returns `NotImplemented` until wired to real IKM/salt).
- [`crates/vault/src/twofish_cipher.rs`](crates/vault/src/twofish_cipher.rs) — HKDF-SHA256 expand for Twofish + HMAC keys from a `KeyPurpose`.

**Tests and vectors:**

- [`crates/vault/src/tests.rs`](crates/vault/src/tests.rs) — domain separation between purposes, HKDF info layout.
- [`crates/vault/src/wycheproof_hkdf_sha256.rs`](crates/vault/src/wycheproof_hkdf_sha256.rs), [`crates/vault/src/wycheproof_hkdf_sha512.rs`](crates/vault/src/wycheproof_hkdf_sha512.rs) — Wycheproof JSON harnesses.
- [`crates/vault/tests/rfc_vectors.rs`](crates/vault/tests/rfc_vectors.rs) — RFC 5869-style HKDF checks alongside other KDF material.
- [`crates/galdr-core/src/crypto_rfc.rs`](crates/galdr-core/src/crypto_rfc.rs) — small HKDF-SHA256 / SHA512 smoke tests.

#### ChaCha20-Poly1305 AEAD (vault)

**Runtime:**

- [`crates/vault/src/chacha_aead.rs`](crates/vault/src/chacha_aead.rs) — encrypt/decrypt path using `chacha20poly1305` with HKDF-derived keys and typed nonces.

**Tests:**

- [`crates/vault/tests/rfc_vectors.rs`](crates/vault/tests/rfc_vectors.rs) — RFC 8439 AEAD vectors (`rfc8439_chacha20_poly1305_aead`).
- [`crates/vault/src/wycheproof_chacha.rs`](crates/vault/src/wycheproof_chacha.rs) — Wycheproof JSON harness.
- [`crates/galdr-core/src/crypto_rfc.rs`](crates/galdr-core/src/crypto_rfc.rs) — RFC 8439 example cross-check.

#### Serpent and Twofish storage (Encrypt-then-MAC)

**Runtime:**

- [`crates/vault/src/serpent_cipher.rs`](crates/vault/src/serpent_cipher.rs) — Serpent-256 + HMAC EtM.
- [`crates/vault/src/twofish_cipher.rs`](crates/vault/src/twofish_cipher.rs) — Twofish-256 + HMAC EtM and HKDF key schedule.

**Tests:** [`crates/vault/src/tests.rs`](crates/vault/src/tests.rs) (HKDF distinctness vs other profiles); vector JSON under `crates/vault/tests/` where applicable.

#### Brainpool ECDH and ECDSA

**Runtime:**

- [`crates/vault/src/brainpool.rs`](crates/vault/src/brainpool.rs), [`brainpool384.rs`](crates/vault/src/brainpool384.rs), [`brainpool512.rs`](crates/vault/src/brainpool512.rs) — curve arithmetic and ECDH material.
- [`crates/vault/src/ecdsa_brainpool.rs`](crates/vault/src/ecdsa_brainpool.rs) — ECDSA with Brainpool hashes.
- [`crates/vault/src/brainpool_common.rs`](crates/vault/src/brainpool_common.rs) — shared helpers.

**Tests:** `wycheproof_brainpool*.rs` and BSI JSON under [`crates/vault/src/`](crates/vault/src/) / [`crates/vault/tests/`](crates/vault/tests/).

#### PIN policy (constant-time compare and state machine)

**Runtime:**

- [`crates/pin-policy/src/machine.rs`](crates/pin-policy/src/machine.rs) — `pin_compare` (`subtle::ConstantTimeEq`), `PinPolicyMachine`, attempt ordering (**increment before compare**).
- [`crates/pin-policy/src/pin_input.rs`](crates/pin-policy/src/pin_input.rs) — PIN and challenge parsing boundaries.

**Tests:** [`crates/pin-policy/src/tests.rs`](crates/pin-policy/src/tests.rs), [`property_tests.rs`](crates/pin-policy/src/property_tests.rs); integration tests under [`galdra-core-host/tests/`](galdra-core-host/tests/) (`pin_length_*`, etc.).

#### Shamir secret sharing

**Runtime:** [`crates/vault/src/shamir.rs`](crates/vault/src/shamir.rs).

**Tests:** vault integration tests and [`crates/security-tests/`](crates/security-tests/) dudect harness where enabled.

#### RSA key wrap and operations

**Runtime:** [`crates/vault/src/rsa_vault.rs`](crates/vault/src/rsa_vault.rs), [`rsa_keys.rs`](crates/vault/src/rsa_keys.rs); Wycheproof harness [`wycheproof_rsa.rs`](crates/vault/src/wycheproof_rsa.rs).

### galdra-core-host (host library)

Shared library crate ([`galdra-core-host/src/lib.rs`](galdra-core-host/src/lib.rs) re-exports modules). **Private** signing/decryption keys are not stored on the host; the host holds **public** certificates for contacts and talks to the token over USB where required.

| Module | File | Role |
|--------|------|------|
| `audit` | [`audit.rs`](galdra-core-host/src/audit.rs) | Append-only audit log, CSV/JSON export, hash-chain verification |
| `config` | [`config.rs`](galdra-core-host/src/config.rs) | TOML config, paths, LDAP, optional `database_key_env` (SQLCipher passphrase) |
| `contacts` | [`contacts.rs`](galdra-core-host/src/contacts.rs) | Contact CRUD, search, identity resolution |
| `db` | [`db.rs`](galdra-core-host/src/db.rs) | SQLite / SQLCipher open, schema migrations |
| `device` | [`device.rs`](galdra-core-host/src/device.rs) | USB token protocol, PIN buffer, provision/zeroise |
| `encrypt` | [`encrypt.rs`](galdra-core-host/src/encrypt.rs) | Multi-recipient OpenPGP encrypt/decrypt (Sequoia), session keys |
| `error` | [`error.rs`](galdra-core-host/src/error.rs) | `GaldraError` |
| `groups` | [`groups.rs`](galdra-core-host/src/groups.rs) | Groups and membership |
| `keyserver` | [`keyserver.rs`](galdra-core-host/src/keyserver.rs) | HKP / WKD fetch |
| `ldap` | [`ldap.rs`](galdra-core-host/src/ldap.rs) | LDAP directory key fetch |
| `sign` | [`sign.rs`](galdra-core-host/src/sign.rs) | OpenPGP sign/verify (token-backed where implemented) |
| `sync` | [`sync.rs`](galdra-core-host/src/sync.rs) | Offline contact/group export and import |

**Integration tests:** [`galdra-core-host/tests/`](galdra-core-host/tests/) (contacts, groups, audit, config, DB, device stub, PIN length, etc.).

### galdra (CLI binary)

| File | Role |
|------|------|
| [`galdra/src/main.rs`](galdra/src/main.rs) | `clap` entrypoint: `device`, `key`, `contact`, `group`, `sync`, `audit`, `encrypt`, `decrypt`, `sign`, `verify`, and subcommands |
| [`galdra/src/common.rs`](galdra/src/common.rs) | Load config, `open_database()` (SQLite/SQLCipher), `resolve_identity`, JSON output, PIN prompt |
| [`galdra/src/crypto_cmds.rs`](galdra/src/crypto_cmds.rs) | CLI wiring for encrypt/decrypt/sign/verify; OpenPGP vs **age** format |
| [`galdra/src/qr.rs`](galdra/src/qr.rs) | QR image decode for `contact import --qr` |

Run `cargo run -p galdra -- --help` for the current command tree.

### galdrad (local REST daemon)

| File | Role |
|------|------|
| [`galdrad/src/main.rs`](galdrad/src/main.rs) | `tokio` entry: load config, open DB, bind HTTP listener, serve Axum router |
| [`galdrad/src/api.rs`](galdrad/src/api.rs) | JSON routes (`/health`, `/contacts`, `/groups`, `/device/*`, `/audit`, …), `utoipa` OpenAPI, Swagger UI |
| [`galdrad/src/state.rs`](galdrad/src/state.rs) | `AppState` (shared `Db` handle for handlers) |
| [`galdrad/src/error.rs`](galdrad/src/error.rs) | HTTP error mapping to `ApiError` |

Handlers call the same [`galdra_core_host`](galdra-core-host) APIs as the CLI (often via `spawn_blocking` for synchronous DB work). See [`galdrad/src/lib.rs`](galdrad/src/lib.rs) for module layout.

### galdra-gtk (GTK4 desktop client)

| File | Role |
|------|------|
| [`galdra-gtk/src/main.rs`](galdra-gtk/src/main.rs) | GTK `Application`, main window, pages (device, contacts, groups, audit), `--base-url` / `GALDRAD_URL` for `galdrad` |
| [`galdra-gtk/src/client.rs`](galdra-gtk/src/client.rs) | Blocking `reqwest` client: `GaldradClient` (`health`, `contacts`, `groups`, `audit`, …) |

No crypto logic in the GUI: it only displays JSON from **`galdrad`**. Review behaviour in [`galdrad/src/api.rs`](galdrad/src/api.rs) and [`galdra-core-host`](galdra-core-host) for semantics.

### Timing analysis (dudect)

**Harnesses:** [`crates/security-tests/src/dudect_harnesses.rs`](crates/security-tests/src/dudect_harnesses.rs) — HKDF, ChaCha20-Poly1305 tag checks, and other primitives exercised by `cargo run -p xtask -- timing-test`.

**Fuzz targets** (libFuzzer): [`fuzz/fuzz_targets/`](fuzz/fuzz_targets/).

The sections above cover **firmware vault**, **host library**, **CLI**, **daemon**, **GUI**, and **timing** entry points. For workspace crate names at a glance, see [Workspace layout](#workspace-layout).

## Commands

```text
rustup target add riscv32imac-unknown-none-elf
cargo test --workspace --exclude xtask
cargo run -p xtask -- check-fw
cargo run -p xtask -- build-fw
cargo run -p xtask -- test-host
cargo run -p xtask -- test-crypto
cargo run -p xtask -- wycheproof
cargo run -p xtask -- test-all
```

Additional **xtask** entry points (timing, RSA bench, libFuzzer wrappers): run
`cargo run -p xtask --` with no subcommand to print the full usage line
(`timing-test`, `bench-rsa`, `fuzz`, `fuzz-chacha`, `fuzz-shamir`, etc.).

## Build, install, and uninstall

### Prerequisites

- **Rust** (stable), via [rustup](https://rustup.rs/).
- **SQLCipher-enabled SQLite** (`rusqlite` with `bundled-sqlcipher` in this workspace): on some Linux systems you need OpenSSL development headers to compile (for example `libssl-dev` on Debian/Ubuntu).
- **galdra-gtk**: GTK 4 and libadwaita development packages for your distribution (for example `libgtk-4-dev` and `libadwaita-1-dev` on Debian/Ubuntu).

### Compile host software

From the **repository root**, release binaries for the CLI, daemon, and desktop client:

```text
cargo build --release -p galdra -p galdrad -p galdra-gtk
```

Artifacts: `target/release/galdra`, `target/release/galdrad`, `target/release/galdra-gtk` (or under `CARGO_TARGET_DIR` if set).

Build **all** workspace members (embedded crates build for the host where tests require it):

```text
cargo build --workspace
```

### Compile firmware (RISC-V)

Add the embedded target, then use `xtask` (same commands as in [Commands](#commands)):

```text
rustup target add riscv32imac-unknown-none-elf
cargo run -p xtask -- check-fw
cargo run -p xtask -- build-fw
```

Release **libraries** for linking into a full Xous image:

```text
cargo build --release -p galdr-core -p vault -p pin-policy -p usb-personality --target riscv32imac-unknown-none-elf
```

Object files appear under `target/riscv32imac-unknown-none-elf/<debug|release>/`. A bootable firmware image is produced outside this snippet by linking with Xous and board support; see [Flashing firmware](#flashing-firmware) and the upstream Baochip documentation.

### Install host software

There is no `.deb` / `.rpm` / MSI in this repository.

**Using Cargo’s install layout** (installs to `~/.cargo/bin` by default; ensure it is on `PATH`):

```text
cargo install --path galdra --locked
cargo install --path galdrad --locked
cargo install --path galdra-gtk --locked
```

Run from the workspace root so `--path` resolves to each crate directory.

**Manual install:** copy the `target/release/` binaries to a directory on your `PATH` (for example `/usr/local/bin`; copying system-wide may require elevated permissions).

**First-run data:** installing binaries does not create Galdra’s config or database until you run a command. Default locations are described in the `galdra-core-host` `config` module (Linux example: `~/.config/galdra/config.toml`, `~/.local/share/galdra/galdra.db`).

### Uninstall host software

- Installed with **`cargo install`**: `cargo uninstall galdra`, `cargo uninstall galdrad`, `cargo uninstall galdra-gtk`.
- **Manually copied** binaries: remove `galdra`, `galdrad`, and `galdra-gtk` from the directory where you installed them.
- **Optional data removal** (destructive): delete your Galdra config and SQLite database if you want to remove local contacts, groups, and audit history from disk. Paths depend on the OS; they are not removed by `cargo uninstall`.

### Firmware install and uninstall

Firmware is **not** installed with Cargo. **Install** here means **flash** a verified image to the device (see [Flashing firmware](#flashing-firmware)). **Uninstall** or replace firmware by programming another image or following vendor recovery and zeroisation procedures; see the **Baochip-1x firmware design README** linked there.

## Flashing firmware

This repository builds **Rust crates** for `riscv32imac-unknown-none-elf` (see `xtask`). A complete **bootable Xous image** is assembled by linking these libraries with the microkernel and board support code; the authoritative boot, update, and integrity story (including **Verified flashing and updates**) is in the upstream **[Baochip-1x firmware design README](https://raw.githubusercontent.com/Supermagnum/Baochip-1x-firmware/refs/heads/main/README.md)**. Use that document and the **board vendor SDK** for production procedures.

**Compile firmware components for the embedded target:**

```text
rustup target add riscv32imac-unknown-none-elf
cargo run -p xtask -- build-fw
```

Release-optimized libraries (when linking a final image):

```text
cargo build --release -p galdr-core -p vault -p pin-policy -p usb-personality --target riscv32imac-unknown-none-elf
```

Artifacts appear under `target/riscv32imac-unknown-none-elf/<debug|release>/` (or your configured `CARGO_TARGET_DIR`).

**Programming the device (outline):**

1. Connect the debugger or USB cable as described in **Dabao / Baochip-1x board documentation**.
2. On **engineering samples** that still expose **JTAG**, tools such as **OpenOCD** or **probe-rs** (`probe-rs download`, `cargo-embed`, etc.) can program flash according to the chip memory map; **production silicon may have JTAG fused out**—follow vendor tooling only.
3. **Do not flash untrusted images.** Verify signatures and manifest hashes on update bundles before programming; optional read-back checks after program reduce risk of partial or glitched writes (see upstream README).
4. **boot0** is fixed in silicon; field updates target later boot stages—do not assume the whole flash image is replaceable from user tooling.

When this workspace publishes a single linked `.elf` or a standard image name for CI, this section should be updated with exact commands and base addresses.

Developer-focused crypto, fuzzing, and vector notes: [docs/GALDRALAG_DEV_REFERENCE.md](docs/GALDRALAG_DEV_REFERENCE.md).

Enable `galdr-core` feature **`test-hal`** only in tests or host tools (see crate `dev-dependencies`). Do not enable it in production firmware images.

## AI disclaimer

Portions of this repository (including documentation, tests, and tooling) may have been drafted or
refined with assistance from automated coding or language models. **Such output is not a
substitute for human review, security analysis, or independent cryptographic audit.** Maintainers
and contributors remain responsible for correctness, safety, and compliance with project
requirements. Treat AI-assisted changes like any other patch: review, test, and verify before
relying on them in production.

## License

This project is licensed under the GNU General Public License v3.0; see [LICENSE](LICENSE).
