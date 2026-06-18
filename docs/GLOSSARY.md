# Glossary (plain language)

Terms used in **Galdr** / **Galdralag** documentation, **sorted A–Z**. These explanations are for **readers who are not programmers or cryptographers**. For precise technical and standards detail, follow the links in the main docs and the cited RFCs.

---

## A

**AAD (additional authenticated data)**  
Extra context (such as labels) that is checked for tampering together with an encrypted message, without necessarily being secret itself.

**AEAD (authenticated encryption with associated data)**  
Encryption that both hides content and detects tampering. If someone changes the ciphertext, decryption fails. ChaCha20-Poly1305 and AES-GCM are examples used in this project.

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

**Biometric pre-gate**  
An optional **“something you are”** check (fingerprint, vein pattern, etc.) **before** or with **PIN** unlock. **Not implemented** in this firmware tree yet; see [BIOMETRIC_API.md](BIOMETRIC_API.md) and [THREE_FACTOR_AUTH.md](THREE_FACTOR_AUTH.md).

**BSI TR-03111**  
A German government guideline for elliptic-curve cryptography. The project uses its test data as an extra check that implementations behave as expected.

---

## C

**CAVP (Cryptographic Algorithm Validation Program)**  
A NIST program that publishes official test vectors. This repository runs a **small subset** of such tests locally; that is **not** the same as a formal lab certification.

**CBOR**  
**Concise Binary Object Representation** — a compact encoding for structured data. A future **biometric** wire format might use it; nothing in this tree defines CBOR payloads for biometrics today.

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
A **biometric** that compares patterns inside a finger using infrared imaging of blood flow. Sometimes grouped under **vascular biometrics**. **Not** implemented in this firmware; third-party matchers may integrate in future.

**Firmware**  
Software stored inside the device that runs the token. **Galdr** is firmware; **Galdra** tools run on your PC.

**Fingerprint (of a key)**  
A short identifier (often shown as hexadecimal) that helps you confirm you are using the correct **public** key without comparing the whole key by eye.

**Forward secrecy**  
If someone steals your long-term keys later, they still cannot read **old** conversations that used temporary session keys that were erased. A design goal for session features; full guarantees depend on how the product is integrated.

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

**galdrad**  
A small **local server** on the PC that lets a GUI or scripts use **Galdra** features over HTTP.

**galdra-core-host**  
Shared library behind the CLI and daemon: database, OpenPGP on the host, config. Private keys on the token are not stored inside this library.

**GnuPG (`gpg`)**  
Common **OpenPGP** software on Linux and other systems. It can use a smart card or CCID token for private-key operations while handling messages and keyrings on the PC.

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
Checks that a **biometric** sample comes from a **live** person (not a photo or cast). Policy for a future **biometric pre-gate**; **not** coded here.

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

**PBKDF2**  
A method to stretch a **password** into a cryptographic key using many iterations, so guessing the password is slower.

**Palm vein**  
**Biometric** pattern from the palm’s blood vessels (infrared). A modality a future matcher might use; **not** implemented in this firmware.

**Palmprint**  
The **pattern of lines** on the palm’s skin surface (compare **palm vein**). Not implemented here.

**pcscd**  
The **PC/SC** daemon on Linux — bridges USB **CCID** readers to user-space apps such as **GnuPG**’s smart-card layer.

**PIN**  
A secret you type to **unlock** the token for signing or decryption. Too many wrong attempts can trigger **lockout** or **zeroisation**, depending on policy.

**PIN policy**  
Rules stored on the device: how many tries you get, how comparison is done safely, and what happens after repeated failures.

**Post-quantum (PQ)**  
Algorithms designed with future **quantum computers** in mind. Some are standardized (**ML-KEM**, **ML-DSA**); this project’s roadmap and feature gates are in [PQ_SIGNATURES.md](PQ_SIGNATURES.md).

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
A short-lived secret proving a **recent biometric match** at a host or gateway; **not** defined or implemented in this repository. Future docs may specify binding to `galdrad` or firmware.

**Shamir secret sharing**  
Split a master secret into several **shares** so that any **k** of **n** shares can reconstruct it, but fewer than **k** reveal nothing in the ideal model. Useful for backups and quorum policies. GF(256) math in the **`vault`** crate uses **`vsss-rs`**.

**SignedMatchResult**  
A placeholder name for a future **signed** structure reporting a biometric matcher outcome. **No** type or wire format exists in this tree; see [BIOMETRIC_API.md](BIOMETRIC_API.md).

**Signature (digital)**  
Proof that someone holding the **private** key approved a message. Others verify using the **public** key.

**SQLCipher**  
Optional encryption for **Galdra**’s local contact database on disk. See [GALDRA-TOOL.md](GALDRA-TOOL.md).

**sweet platform**  
Research **biometric** / hand-scan hardware context referenced in roadmap discussions; **not** integrated in this codebase.

---

## T

**Three-factor authentication**  
Classic factors: **something you have** (the token), **something you know** (PIN), and optionally **something you are** (biometric). This repository implements **have + know**; biometric is **not** implemented — [THREE_FACTOR_AUTH.md](THREE_FACTOR_AUTH.md).

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
**Biometric** methods based on **blood-vessel** patterns (often infrared), e.g. **finger vein** or **palm vein**. Not implemented in this firmware.

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
