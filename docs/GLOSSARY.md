# Glossary (plain language)

Terms used in **Galdr** / **Galdralag** documentation, **sorted A–Z**. These explanations are for **readers who are not programmers or cryptographers**. For precise technical and standards detail, follow the links in the main docs and the cited RFCs.

---

## A

**AAD (additional authenticated data)**  
Extra context (such as labels) that is checked for tampering together with an encrypted message, without necessarily being secret itself.

**AEAD (authenticated encryption with associated data)**  
Encryption that both hides content and detects tampering. If someone changes the ciphertext, decryption fails. ChaCha20-Poly1305 and AES-GCM are examples used in this project.

**ACER (Average Classification Error Rate)**  
In **ISO/IEC 30107-3** PAD evaluation: **(APCER + BPCER) / 2**, combining attack and bona-fide error rates.

**APCER (Attack Presentation Classification Error Rate)**  
In **ISO/IEC 30107-3**: the proportion of **presentation attacks** that liveness detection **incorrectly accepts** as genuine. Lower is better.

**APDU**  
A **packet** format used between a host and a smart card (command and response bytes). **OpenPGP** card operations over **CCID** use APDUs; see [OPENPGP_CARD.md](OPENPGP_CARD.md).

**age**  
A simple modern format for encrypting files (separate from OpenPGP). Whether **Galdra** supports it for a given workflow depends on the tool version; see [GALDRA-TOOL.md](GALDRA-TOOL.md).

**Audit log (security)**  
A record of security-relevant events (e.g. which **cipher profile** was chosen). This repository builds **audit strings** and hooks but **not** a full on-chip append-only log yet; see [AUDIT_LOG.md](AUDIT_LOG.md).

---

## B

**Baochip-1x**  
The family of chips this firmware is built for. It is a small computer on a chip that can run this project’s software.

**Bootloader**  
A tiny program that runs first when the device powers on. It checks that firmware is allowed to run (for example that it is **signed**) before starting the main system.

**boot0**  
Immutable **ROM** in **Baochip** that verifies the early boot chain and firmware signature before later stages run.

**boot1**  
Loadable boot stage after **boot0**; continues the signed chain (e.g. toward application images such as **UF2** payloads). Details are in upstream **Baochip** / **Xous** documentation.

**Brainpool**  
A set of standard **elliptic curves** (shapes used for modern public-key math) common in European standards. This project uses them for signing and key agreement.

**BPCER (Bona fide Presentation Classification Error Rate)**  
In **ISO/IEC 30107-3**: the proportion of **genuine** biometric presentations that liveness detection **incorrectly rejects**. Lower is better.

**Biometric pre-gate**  
An optional **“something you are”** check **before** or together with **PIN** unlock: a verified biometric match (and policy gates) must succeed before the token accepts certain operations. Crates: `biometric-api`, `biometric-vault`, and device drivers under `crates/biometric-*`. **Full** host and firmware wiring is still in progress; see [BIOMETRIC_API.md](BIOMETRIC_API.md) and [THREE_FACTOR_AUTH.md](THREE_FACTOR_AUTH.md).

**BSI TR-03111**  
A German government guideline for elliptic-curve cryptography (current version: 2.10). The project carries JSON vector files for BrainpoolP256r1 and BrainpoolP384r1 covering both ECDH and ECDSA sign/verify as an extra check that implementations behave as expected. BrainpoolP512r1 vectors were removed with the unaudited in-tree curve; see [CHANGELOG.md](../CHANGELOG.md). See `crates/vault/tests/bsi_vectors/` and `docs/TEST_RESULTS.md §2.6`.

---

## C

**CAVP (Cryptographic Algorithm Validation Program)**  
A NIST program that publishes official test vectors. This repository runs a **small subset** of such tests locally; that is **not** the same as a formal lab certification.

**CandyFV**  
A **finger vein** dataset (120 subjects) collected with the **sweet platform** at Idiap; used to benchmark accuracy of that backend. [Dataset page](https://www.idiap.ch/en/scientific-research/data/candyfv).

**CBOR**  
**Concise Binary Object Representation (RFC 8949)** — compact structured binary encoding. The **`biometric-api`** crate uses CBOR for `SignedMatchResult` payloads before Ed25519 signing.

**CCID**  
A standard way for a PC to talk to a smart card over **USB**. Your operating system treats the token like a smart card reader so **GnuPG** and similar tools can use it without special vendor drivers.

**CESS**  
An open design (*Cryptologically Enchanted Shamir’s Secret*) for combining secret sharing with authenticated encryption. This firmware follows the normative parts documented in [CESS_CONFORMANCE.md](CESS_CONFORMANCE.md).

**Cipher**  
Another word for an encryption method or the details of how data is transformed (for example which algorithm and mode).

**Cipher profile**  
A **named bundle** of choices in this project: which **symmetric** ciphers form a cascade, which **curve** is used for sessions, and **Shamir** metadata — see [CIPHER_PROFILES.md](CIPHER_PROFILES.md).

**ComboHash**  
A hardware block on **Baochip** that can speed up hashing. If firmware uses it, the **meaning** of derived keys must stay the same as in software-only builds.

**Coercion**  
An attacker forces a legitimate user (physically or under threat) to authenticate — for example to enter a **PIN** or present a **biometric**. Cryptography does not remove this risk; see [THREAT_MODEL.md](THREAT_MODEL.md) (**T13**).

**Contact (host directory)**  
In **Galdra**, someone’s **stored public key row** plus optional plain-text labels — callsign, notes, postal hints (**street**, **country**, **postal code**, **region**), amateur-radio **DMR ID** and **radio affiliation**. That extra text is **not verified** cryptographically unless you correlate it out of band.

**Constant-time (in cryptography)**  
Coding discipline so that secret values do not change how long an operation takes in ways an outsider could measure. This project also runs **timing** statistical tests on the host; those tests help catch regressions but are not a complete proof on the device.

**Cryptography**  
The field of techniques for protecting information: encryption, signatures, key agreement, and related tools.

---

## D

**Decrypt**  
Turn ciphertext back into readable data using the right key. On a **token**, decryption of sensitive material often happens **on the device** so the long-term secret never leaves it.

**Decoy volume**  
A **plausible** bulk storage view (e.g. mass-storage LUN) meant to look ordinary while real secrets stay in the **vault**. Design in [Psram.md](Psram.md); **not** fully implemented in firmware here yet.

**Domain separation**  
Using different labels or contexts when deriving keys so that keys meant for one feature cannot accidentally be reused for another (like separate locks for separate doors).

**dudect**  
A statistical **timing** check run on the developer machine. It looks for suspicious differences in how long operations take. Passing the test is a useful signal; it does not guarantee security by itself.

---

## E

**ECDH (elliptic-curve Diffie–Hellman)**  
A way for two parties to agree on a shared secret using **elliptic-curve** math, so they can set up a secure channel. This project implements several curves, including **X25519** and **Brainpool**.

**ECDHE-style (ephemeral key agreement)**  
Using a **fresh temporary** key pair per session so that later compromise of long-term keys does not automatically expose old session secrets. **TLS** uses similar ideas; this firmware focuses on token protocols, not building a web browser stack.

**Ed25519**  
A widely used standard for **digital signatures** with short keys and strong security margins.

**Encrypt**  
Scramble data so that only someone with the right key can read it.

**Encrypt-then-MAC**  
A safe ordering: encrypt first, then authenticate the result. The vault uses this style for some storage paths.

**Ephemeral ECDH**  
In this project’s **session** stack, using **fresh ephemeral** keys per session for **ECDH**, authenticated by **long-term** signing keys — see [EPHEMERAL_SESSION.md](EPHEMERAL_SESSION.md). Related to **forward secrecy**.

**EtM**  
Short for **encrypt-then-MAC**.

---

## F

**Finger vein recognition**  
A **biometric** that identifies people from **subcutaneous blood-vessel patterns** inside a finger, usually imaged with **near-infrared** light. Open-hardware matchers can integrate via **`biometric-fingervein`**; firmware CCID hooks are not complete yet.

**Firmware**  
Software stored inside the device that runs the token. **Galdr** is firmware; **Galdra** tools run on your PC.

**Fingerprint (of a key)**  
A short identifier (often shown as hexadecimal) that helps you confirm you are using the correct **public** key without comparing the whole key by eye.

**Forward secrecy**  
If someone steals your long-term keys later, they still cannot read **old** conversations that used temporary session keys that were erased. A design goal for session features; full guarantees depend on how the product is integrated. Session protocol: [EPHEMERAL_SESSION.md](EPHEMERAL_SESSION.md); threat framing: [THREAT_MODEL.md](THREAT_MODEL.md) (**T6**).

**Firmware signature**  
A cryptographic stamp proving that a firmware image was produced by someone holding a **signing key**. The chip’s **bootloader** checks this before running an update.

---

## G

**Galdr**  
The name of this **firmware** project for the **Baochip** token. The word refers to Old Norse incantation practice (see the main README *About the name*).

**Galdra**  
**Host** programs on your computer: command-line tool, optional daemon, and GUI. They talk to the token and manage things like contacts; see [GALDRA-TOOL.md](GALDRA-TOOL.md).

**Galdralag**  
The repository and umbrella name for the project (“pattern of galdr”).

**Galdralag fingerprint**  
A **host-computed** identifier for the token’s **OpenPGP SIG** long-term **public key**, not the same as an **OpenPGP v4 key fingerprint**. **Canonical form:** mandatory `G:` prefix plus **40 lowercase hexadecimal characters** (no spaces)—this is what is stored, compared on the host, and placed in **AAD** for profile-bound encrypt. **Display form:** the same 40 hex digits grouped as four characters, with a **double space** after the fifth group (cosmetic only; never used for storage). The value is **BLAKE3** of the **raw public key bytes** the card returns when reading the SIG key (compressed SEC1 for Brainpool curves, 32-byte Ed25519 verifier), **first 20 bytes** of the digest only—no profile name, timestamp, or other metadata is hashed. **Galdralag fingerprints are only defined** when the active **cipher profile** has **authenticated ephemeral ECDH turned off** (`ephemeral_ecdh: false` in the profile registry); otherwise the tool refuses to print or embed them (forward secrecy and long-term fingerprint binding do not mix).

See also: [KEY_LIFECYCLE.md — Galdralag fingerprint](KEY_LIFECYCLE.md#galdralag-fingerprint-host), [README — Web of Trust and Key Signing Parties](../README.md#web-of-trust-and-key-signing-parties).

**galdrad**  
A small **local server** on the PC that lets a GUI or scripts use **Galdra** features over HTTP. **`POST /contacts`** requires a JSON **`email`** field when creating a contact; see [GALDRA-TOOL.md](GALDRA-TOOL.md).

**galdra-core-host**  
Shared library behind the CLI and daemon: database, OpenPGP on the host, config. Private keys on the token are not stored inside this library.

**GnuPG (`gpg`)**  
Common **OpenPGP** software on Linux and other systems. It can use a smart card or CCID token for private-key operations while handling messages and keyrings on the PC.

**Glitch attack**  
A **fault injection** technique: disturb power, clock, or logic timing so a chip mis-executes (skips checks, leaks secrets). Physical-threat discussion: [THREAT_MODEL.md](THREAT_MODEL.md) (**T8**).

---

## H

**HAL (hardware abstraction layer)**  
A clean interface in code between “what the firmware wants” (random numbers, storage, wipe) and “how the specific chip does it.”

**HKDF**  
A standard recipe to turn one secret into several independent keys for different purposes, using labels so they stay separate.

**HMAC**  
A standard way to build a keyed checksum (message authentication) from a hash function. Used inside HKDF and elsewhere.

**Host**  
Your **computer** (desktop or laptop), as opposed to the **USB token** running **Galdr**.

**Hybrid encryption**  
Typical pattern: use **public-key** crypto to protect a random **session key**, then use fast **symmetric** crypto for the bulk of the data. Common in email and file encryption.

---

## K

**KAT (known-answer test)**  
A fixed test where inputs and expected outputs are published so software can self-check it matches.

**Key agreement**  
Two parties compute a shared secret without sending it in full over the wire (see **ECDH**).

**Key lifecycle**  
The **full story** of a key on the token: **generate**, **import**, **use**, **rotate**, **delete**, and **zeroise** under policy — see [KEY_LIFECYCLE.md](KEY_LIFECYCLE.md).

**KeyPurpose**  
Internal labels in the vault so different features derive different keys from the same root material safely.

---

## L

**Lock (the token)**  
End an authenticated session: PIN verification is cleared; you must unlock again before protected operations, similar to other smart cards.

**Liveness detection**  
Hardware or algorithmic checks that a **biometric** sample came from a **live** person (not a photo, mould, or other **presentation attack**). Also called **presentation attack detection (PAD)**. Policy and types are in **`biometric-api`**; PAD metrics follow **ISO/IEC 30107-3** — see [BIOMETRIC_TESTING.md](BIOMETRIC_TESTING.md).

**LMS / XMSS**  
Families of **post-quantum** **signatures** based on hashes. Optional in this project with feature flags; treat as **not yet independently audited** until stated otherwise in [PQ_SIGNATURES.md](PQ_SIGNATURES.md).

---

## M

**Monotonic counter**  
A counter that **only increases** (hardware-backed in design) so **PIN** attempts or **stateful** signatures cannot be “rewound” in software on production parts. See `MonotonicCounter` in the `galdr-core` HAL (`crates/galdr-core/src/hal.rs`).

---

## O

**OAEP / PSS**  
Standard padding schemes for **RSA** encryption (**OAEP**) and signatures (**PSS**). They avoid many historical RSA mistakes.

**OpenPGP**  
A family of standards for encrypted email, files, and key certificates. **GnuPG** is a popular implementation. The token implements an **OpenPGP card** profile so desktop tools can use it like a smart card.

**OpenPGP card**  
The **smart-card application** profile (APDUs, PINs, key slots) that makes a USB token look like an OpenPGP smart card to **GnuPG** over **CCID**. See [OPENPGP_CARD.md](OPENPGP_CARD.md).

---

## P

**Palm vein**  
**Vascular** **biometric**: the blood-vessel pattern on the inside of the palm, imaged with **near-infrared** light (`Modality::PalmVein` in **`biometric-api`**). Integrated on the **sweet** platform; firmware storage path still in progress.

**Palmprint**  
The **surface** line pattern on the inside of the palm, imaged in visible light; often fused with **palm vein** in multimodal systems (`Modality::Palmprint` in **`biometric-api`**).

**PAD (presentation attack detection)**  
Hardware or software that distinguishes **live** biometric presentations from **spoofs** (photos, masks, replayed video, etc.). See **liveness detection** and [BIOMETRIC_TESTING.md](BIOMETRIC_TESTING.md).

**PBKDF2**  
A method to stretch a **password** into a cryptographic key using many iterations, so guessing the password is slower.

**pcscd**  
The **PC/SC** daemon on Linux — bridges USB **CCID** readers to user-space apps such as **GnuPG**’s smart-card layer.

**PIN**  
A secret you type to **unlock** the token for signing or decryption. Too many wrong attempts can trigger **lockout** or **zeroisation**, depending on policy.

**PIN policy**  
Rules stored on the device: how many tries you get, how comparison is done safely, and what happens after repeated failures.

**Post-quantum (PQ)**  
Algorithms designed with future **quantum computers** in mind. Some are standardized (**ML-KEM**, **ML-DSA**); this project’s roadmap and feature gates are in [PQ_SIGNATURES.md](PQ_SIGNATURES.md).

**Power analysis**  
Side-channel attacks (**SPA**, **DPA**) that infer secrets from power consumption. Silicon behaviour for this token is **not** independently characterised — [THREAT_MODEL.md](THREAT_MODEL.md) (**T8**), [HARDWARE_VERIFICATION.md](HARDWARE_VERIFICATION.md).

**Presentation attack**  
A fake or replayed **biometric** sample (photo, mask, cast, replayed video, etc.) presented to a sensor. Defended by **liveness** / **PAD**; measured rates are **APCER** / **BPCER** — [BIOMETRIC_TESTING.md](BIOMETRIC_TESTING.md), [THREAT_MODEL.md](THREAT_MODEL.md) (**T4**).

**Private key**  
The secret half of a key pair. In this design it should **stay on the token** and not be copied to the PC.

**PKE (public-key engine)**  
Hardware in **Baochip** that can accelerate public-key operations. It is **not** “the internet” or TLS by itself—just on-chip help for math.

**PRK**  
An intermediate secret inside **HKDF** before keys are expanded for different uses.

**PSRAM**  
Optional external memory used as a **decoy** storage story in some designs. See [Psram.md](Psram.md); behaviour is documented there.

**Public key**  
The shareable half of a key pair. Others use it to encrypt to you or verify your signatures. This project treats **public** material as what may cross the USB link; **private** material should not.

---

## R

**RRAM**  
**Resistive RAM** — on **Baochip-1x**, **4,194,304 bytes** (4 MiB) of on-chip non-volatile storage used for the **vault**, PIN policy blobs, sealed keys, and related data. Layout sketches: [RRAM_LAYOUT.md](RRAM_LAYOUT.md).

**Rust**  
The programming language most of this project is written in. It helps prevent many memory-safety bugs by construction.

**RustCrypto**  
A community of audited cryptographic libraries in Rust used as dependencies here.

---

## S

**scdaemon**  
GnuPG’s **smart-card daemon** — talks **CCID** / PC/SC to reach an **OpenPGP card** on USB.

**Sequoia PGP**  
A Rust library for **OpenPGP** on the host. **Galdra** uses it for multi-recipient encryption and similar tasks; private keys remain on the token when that is how the workflow is set up.

**session token (biometric)**  
Short **HMAC-SHA256** value derived from a **nonce**, **device ID**, and **timestamp**, using a vault provisioned key—intended to be included with the **PIN** **APDU** so the token can confirm a recent biometric assertion. Implemented in **`biometric-vault`**; CCID binding is not finished.

**Shamir secret sharing**  
Split a master secret into several **shares** so that any **k** of **n** shares can reconstruct it, but fewer than **k** reveal nothing in the ideal model. Useful for backups and quorum policies. GF(256) math in the **`vault`** crate uses **`vsss-rs`**.

**Shor's algorithm**  
A quantum algorithm that breaks classical **RSA** and **elliptic-curve** discrete-log problems in polynomial time — a driver behind **post-quantum** migration. Risk framing: [THREAT_MODEL.md](THREAT_MODEL.md) (**T14**), [PQ_SIGNATURES.md](PQ_SIGNATURES.md).

**SignedMatchResult**  
**CBOR**-encoded payload (match outcome, score, **liveness**, modalities, nonce, etc.) plus an **Ed25519** signature from the biometric device. Defined in **`biometric-api`**; validated on the host before a session token is minted.

**Signature (digital)**  
Proof that someone holding the **private** key approved a message. Others verify using the **public** key.

**SQLCipher**  
Optional encryption for **Galdra**’s local contact database on disk. See [GALDRA-TOOL.md](GALDRA-TOOL.md).

**Supply chain attack**  
Tampering with **build**, **dependency**, or **distribution** so users run malicious **firmware** or tools. Mitigations include signed boot (**boot0** / Ed25519) and reproducible builds; see [THREAT_MODEL.md](THREAT_MODEL.md) (**T9**).

**sweet platform**  
Open **contactless** hand **biometric** research platform (Idiap, *Sensors* 2025). Captures **palm vein**, **palmprint**, and **finger veins** together. Host driver stub and **`test-hal`** mock: **`biometric-sweet`**. See [SWEET_PLATFORM_INTEGRATION.md](SWEET_PLATFORM_INTEGRATION.md).

---

## T

**Threat model**  
A structured description of **assets**, **adversaries**, and **mitigations** — what a system intends to protect and what it does **not** promise. This repository: [THREAT_MODEL.md](THREAT_MODEL.md).

**Three-factor authentication**  
Classic factors: **something you have** (the token), **something you know** (PIN), and optionally **something you are** (biometric). This repository implements **have + know** today; biometric crates exist but **full** pre-gate wiring is ongoing — [THREE_FACTOR_AUTH.md](THREE_FACTOR_AUTH.md).

**Token**  
The **USB hardware device** (or board running this firmware) that holds secrets and runs **Galdr**, as opposed to software on your PC.

**TRNG (true random number generator)**  
Hardware noise used to generate unpredictable keys and nonces. A token needs good randomness to be secure.

---

## U

**USB**  
The cable interface used to connect the token to a PC. Unplugging clears the **session**; you typically must enter the **PIN** again after reconnect for protected actions.

**UF2**  
A drag-and-drop file format used in **bootloader** mode to load firmware on some boards. Described in upstream **Xous** / **Baochip** documentation.

---

## V

**Vault**  
The on-device protected storage and policy layer in firmware: sealed blobs, key derivation rules, and cryptographic wrappers around sensitive data.

**Verify (a PIN)**  
Prove to the token that you know the PIN so it allows signing or decryption for that **session**.

**Vascular biometrics**  
Modalities based on **blood-vessel** patterns beneath the skin (typically **NIR**), e.g. **finger vein** and **palm vein**. Types appear as **`Modality`** variants in **`biometric-api`**.

**vsss-rs**  
A Rust **finite-field** / secret-sharing helper crate used with **Shamir** GF(256) in **`vault`**.

---

## W

**Wear levelling**  
Spreading **writes** across many cells so **flash-like** or **RRAM** media does not wear out one spot too fast. **No** wear-levelling algorithm is implemented in this repository; endurance is an **open engineering** topic — [RRAM_LAYOUT.md](RRAM_LAYOUT.md).

**Welch’s *t*-test**  
A statistical comparison used inside **dudect** timing reports. Values near zero are desired; large values warrant investigation.

**Wycheproof**  
A large public collection of test vectors from Google. This project runs selected suites to cross-check implementations (see [TEST_RESULTS.md](TEST_RESULTS.md)).

---

## X

**X25519**  
A popular modern **elliptic-curve** method for key agreement, standardized for interoperability.

**Xous**  
A capability-oriented microkernel this firmware is intended to run under. See the main README and upstream **xous-core** documentation.

---

## Z

**Zeroisation (zeroization)**  
Securely erasing secrets from memory or storage so they cannot be recovered by ordinary means. Simulation tests exist in software; **hardware** verification is tracked separately in [HARDWARE_VERIFICATION.md](HARDWARE_VERIFICATION.md).

---

## See also

- [README.md](../README.md) — project overview, token behaviour, security notes
- [RRAM_LAYOUT.md](RRAM_LAYOUT.md) — on-chip storage map (sketches)
- [KEY_LIFECYCLE.md](KEY_LIFECYCLE.md) — keys on the token
- [THREE_FACTOR_AUTH.md](THREE_FACTOR_AUTH.md) — factors and scope
- [GALDRA-TOOL.md](GALDRA-TOOL.md) — host tools and workflows
- [ARCHITECTURE.md](ARCHITECTURE.md) — how subsystems fit together
- [TEST_RESULTS.md](TEST_RESULTS.md) — what automated checks cover
- [THREAT_MODEL.md](THREAT_MODEL.md) — assets, threats, explicit limitations
