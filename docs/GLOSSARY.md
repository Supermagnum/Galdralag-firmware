# Glossary

Short definitions of terms used across **Galdralag** / **Galdr** documentation and code. Normative protocol and algorithm details remain in the cited RFCs and standards; this page orients readers inside this repository.

---

## A

**AEAD (authenticated encryption with associated data)**  
Symmetric encryption that provides both confidentiality and integrity: ciphertext is authenticated, and additional data (AAD) can be authenticated without being encrypted. ChaCha20-Poly1305 and AES-GCM are AEADs used in this project.

**AAD (additional authenticated data)**  
Metadata covered by the AEAD MAC but not necessarily encrypted (for example context strings alongside ciphertext).

**age**  
A minimal modern file-encryption format (not OpenPGP). **Galdra** may support **age** alongside OpenPGP for some encrypt/decrypt flows; see [GALDRA-TOOL.md](GALDRA-TOOL.md) and `galdra` help for what is implemented.

---

## B

**Baochip-1x**  
The family of evaluation / product chips this firmware targets (see upstream board and silicon documentation). **Galdr** builds for `riscv32imac-unknown-none-elf` for these devices.

**Brainpool**  
A family of prime-field elliptic curves (for example P-256r1, P-384r1, P-512r1) standardized in **RFC 5639** and used in European and BSI-oriented profiles. This repository implements ECDH and ECDSA over Brainpool curves.

**BSI TR-03111**  
German Federal Office for Information Security technical guideline for ECC; the project includes **BSI** JSON test vectors for Brainpool cross-checks.

---

## C

**CAVP (Cryptographic Algorithm Validation Program)**  
NIST program producing known-answer test vectors; this repo includes a **subset** of CAVP-style tests (for example digests, HMAC) where noted in [TEST_RESULTS.md](TEST_RESULTS.md), not full lab validation.

**Constant-time**  
Implementation discipline so that secret-dependent branches or memory access patterns do not leak timing information. **dudect** harnesses on the host are one statistical check; they do not replace review of embedded code.

**ComboHash**  
On **Baochip-1x** silicon, a hardware accelerator for cryptographic hashing (often mentioned together with **PKE** in the upstream [Baochip firmware design README](https://github.com/Supermagnum/Baochip-1x-firmware)). When firmware routes work through ComboHash instead of software SHA-2, **HKDF `info` strings and domain separation** in `vault` must remain byte-identical to the software path.

---

## D

**Domain separation**  
Using distinct labels (for example HKDF `info` strings, `KeyPurpose` in `vault`) so keys derived from the same root material cannot be mixed across unrelated features.

**dudect**  
Statistical timing analysis (Welch *t*-test style) used here via the `dudect_galdr` binary (`cargo run -p xtask -- timing-test`). Pass when |*t*| is below a fixed threshold (4.5 in this project); results are **host-dependent**.

---

## E

**ECDH (elliptic-curve Diffie–Hellman)**  
Key agreement: two parties each have a secret scalar and exchange public points; both derive the same shared secret. Implemented here with **X25519** and **Brainpool** curves.

**ECDHE (ephemeral ECDH)**  
In TLS naming, ciphersuites that use a **fresh ephemeral** key pair per handshake for forward secrecy. This repository provides **ECDH** primitives; **TLS itself is not implemented** here. See the README section *Ephemeral ECDH (ECDHE-style) and TLS*.

**Ed25519**  
EdDSA signatures on a curve related to Curve25519 (**RFC 8032**).

**Encrypt-then-MAC**  
Encrypt data first, then MAC the ciphertext (and associated data). Used for Serpent/Twofish storage paths in the vault, as opposed to MAC-then-encrypt.

**EtM**  
See **Encrypt-then-MAC**.

---

## F

**Forward secrecy**  
Compromise of long-term keys does not retroactively expose past session keys if each session used ephemeral agreement material that was destroyed after use. Design goal for session scaffolding in the vault; full guarantees depend on integration.

---

## G

**Galdr**  
The firmware project name: cryptographic and policy code for **Baochip-1x** devices under **Xous**. The word refers to Old Norse incantation practice (see README *About the name*).

**Galdra**  
Host-side companion tooling: CLI (`galdra`), daemon (`galdrad`), optional GTK client, contacts/groups, OpenPGP workflows. Specified in [GALDRA-TOOL.md](GALDRA-TOOL.md).

**Galdralag**  
Repository and metrical name for the project (pattern / law of galdr); the GitHub organization and crate namespace use this form.

**galdrad**  
Local HTTP daemon that exposes **Galdra** functionality over a REST API for GUI and automation clients.

**galdra-core-host**  
Host-side Rust library (`galdra-core-host`): SQLite database (contacts, groups, audit), OpenPGP encrypt/decrypt via **Sequoia**, USB token protocol, config, LDAP/keyserver helpers. Shared by the **`galdra`** CLI and **`galdrad`** daemon. See [GALDRA-TOOL.md](GALDRA-TOOL.md).

**GnuPG (`gpg`)**  
Common OpenPGP implementation on PCs; often used alongside **Galdra** for keyrings and file workflows while private keys stay on the token where designed.

---

## H

**HAL (hardware abstraction layer)**  
Traits in `galdr-core` (TRNG, vault storage, zeroisation, counters) implemented by board-specific code or `test-hal` fakes in tests.

**HKDF (HMAC-based key derivation function)**  
**RFC 5869**: extract-then-expand from input keying material with optional salt and `info` for independent subkeys. Vault uses distinct `KeyPurpose` labels for domain separation.

**HMAC**  
Pseudorandom function used inside HKDF, PBKDF2, and standalone MACs (**RFC 2104** and successors).

**Hybrid encryption**  
Combine public-key encryption of a random session key with symmetric encryption of the bulk message (typical OpenPGP pattern).

---

## K

**KAT (known-answer test)**  
Fixed input/output vectors to verify an implementation matches expected outputs (for example Twofish JSON chains in `vault/tests`).

**KeyPurpose**  
Rust enum in `vault::kdf_policy` mapping each vault subkey use to a unique HKDF `info` string.

---

## L

**LMS / XMSS**  
Stateful hash-based signature schemes (**SP 800-208**). Optional **pq-signatures** feature; audit status in [PQ_SIGNATURES.md](PQ_SIGNATURES.md). Timing harnesses may list them as not wired on the host.

---

## O

**OAEP, PSS**  
RSA padding modes: **OAEP** for encryption (**RFC 8017**), **PSS** for signatures. Implemented via the `rsa` crate and Wycheproof vectors.

**OpenPGP**  
Message format and certificate standard for PGP-family tools; **Galdra** interoperates at the host for public-key workflows while sensitive operations use the token where applicable.

---

## P

**PBKDF2**  
Password-based key derivation (**RFC 8018**): slow on purpose via iteration count and HMAC.

**PIN policy**  
`pin-policy` crate: attempt counter, constant-time compare ordering, lockout and zeroisation rules for the device PIN.

**Post-quantum (PQ)**  
Algorithms believed to resist cryptanalytically relevant quantum computers; **ML-KEM**, **ML-DSA**, etc. are listed as not yet implemented pending audited crates; **XMSS/LMS** are feature-gated with audit caveats.

**PKE (public-key engine)**  
Baochip **silicon** block for asymmetric cryptography (naming may vary in vendor docs); cited alongside **ComboHash** in platform and `galdr-core` comments. Not a TLS or application protocol—**on-chip** acceleration.

**PRK (pseudorandom key)**  
HKDF intermediate output after Extract, before Expand.

**PSRAM**  
External pseudo-static RAM as an optional block device; **not** implemented in this workspace (see README and [Psram.md](Psram.md)).

---

## R

**RRAM**  
Resistive RAM used as vault storage on the target platform; layout and size assumptions appear in vault documentation.

**RustCrypto**  
Ecosystem of Rust cryptography crates; many dependencies here come from that community with published audit history.

---

## S

**Sequoia**  
**Sequoia PGP** — Rust OpenPGP implementation. **`galdra-core-host`** uses it for multi-recipient OpenPGP encryption and decryption on the host (`encrypt.rs`). Token private keys are not stored in Sequoia; host-side operations use public certificates and delegate private operations to the device when required.

**SQLCipher**  
SQLite extension that encrypts the database file at rest. **Galdra** can open the contacts/audit database with `rusqlite` + **SQLCipher** when a key is supplied (for example `database_key_env` in config pointing to an environment variable with the passphrase). See [GALDRA-TOOL.md](GALDRA-TOOL.md) and `galdra-core-host` `db`/`config` modules.

**Shamir secret sharing**  
Split a secret into *n* shares such that any *k* of them reconstruct (*k*-of-*n* threshold); fewer than *k* reveal no information in the ideal model. Implemented with `vsss-rs`.

---

## T

**Token**  
The hardware device (smartcard-style or USB gadget) that holds private keys and runs **Galdr** firmware, as opposed to the host PC running **Galdra**.

**TRNG (true random number generator)**  
Hardware entropy source exposed through `galdr-core` HAL traits for key generation and nonces where required.

---

## V

**Vault (`vault` crate)**  
RRAM-backed sealed blob layout, HKDF policy (`KeyPurpose`), and cryptographic wrappers for on-device storage and protocols.

---

## W

**Welch’s *t*-test**  
Statistical test comparing two timing distributions; **dudect** here reports a *t*-statistic against a fixed threshold. Not a proof of absence of leakage, but a regression-style check.

**Wycheproof**  
Google’s JSON test vectors for many primitives; this project runs selected Wycheproof suites in `vault` tests (see README and [TEST_RESULTS.md](TEST_RESULTS.md)).

---

## X

**X25519**  
Curve25519 Diffie–Hellman (**RFC 7748**), fixed-length keys, used for ECDH in this codebase.

**Xous**  
Capability-safe microkernel this firmware is built to run on (`github.com/betrusted-io/xous-core`). A full bootable image links Galdr libraries with Xous and board support.

---

## Z

**Zeroisation (zeroization)**  
Secure erasure of sensitive material in RAM or non-volatile storage; `ZeroiseController` and policy-driven wipes. Simulation tests exist; hardware verification is called out separately in [HARDWARE_VERIFICATION.md](HARDWARE_VERIFICATION.md).

---

## See also

- [README.md](../README.md) — overview, capabilities table, ECDH/TLS scope
- [GALDRA-TOOL.md](GALDRA-TOOL.md) — Galdra CLI, daemon, GUI, database, and operational behaviour
- [ARCHITECTURE.md](ARCHITECTURE.md) — system structure
- [GALDRALAG_DEV_REFERENCE.md](GALDRALAG_DEV_REFERENCE.md) — developer commands and workflows
- [TEST_RESULTS.md](TEST_RESULTS.md) — test and dudect summaries
