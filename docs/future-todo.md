# Galdralag — Future Expansion Areas and Rust Crates

This document surveys realistic future use cases for the Galdralag firmware and
identifies suitable, existing Rust crates for each. The same standard applied to
the current dependency tree applies here: preference for audited, `no_std`-compatible
crates from the RustCrypto ecosystem or equivalently well-reviewed projects.
Crates marked as not yet audited are noted as such; they should not be integrated
until independent audits are available.

---

## 1. Password Vault

Store per-site credentials encrypted in RRAM behind the existing PIN policy.
Retrieval via the authenticated host-tools interface — no USB keyboard personality.

| Crate | Role | Notes |
|-------|------|-------|
| `postcard` | Compact binary serialisation of credential records | `no_std`, deterministic output, used in production embedded Rust. Not a cryptographic crate — encryption is handled by existing deps. No formal security audit; assess suitability carefully. |
| `serde` | Derive `Serialize`/`Deserialize` on credential entry types | Paired with `postcard`; already widely used in the Rust ecosystem. |
| `zeroize` | Zeroise credential structs on drop | Already in the dependency tree. |

Cryptographic protection of vault entries uses `aes-gcm` or `chacha20poly1305`
plus `hkdf` with a new `KeyPurpose::PasswordEntry` domain label — all already
in tree. No new cryptographic crates required.

---

## 2. SSH Authentication

Allow the device to serve as an SSH authentication token via `gpg-agent`
forwarding to the OpenPGP/CCID interface. Also enables `sshsig` artifact signing.

| Crate | Role | Notes |
|-------|------|-------|
| `ssh-key` | SSH key format encoding/decoding (RFC 4251/4253, OpenSSH formats), `sshsig` signatures, certificate validation, `authorized_keys` and `known_hosts` support | Pure Rust, `no_std` compatible, part of the RustCrypto ecosystem. Maintained by Tony Arcieri. Not yet independently audited. |

Actual signing uses `ed25519-dalek` already in tree.
Host-side tooling (`host-tools` crate) handles `gpg-agent` socket protocol;
firmware only performs the signing operation over CCID.

---

## 3. S/MIME Email Signing and Encryption

Sign and encrypt email using certificate-based identities via the CCID interface,
compatible with major mail clients.

| Crate | Role | Notes |
|-------|------|-------|
| `cms` | Cryptographic Message Syntax (RFC 5652, RFC 5911, RFC 3274) — the wire format underlying S/MIME | Pure Rust, RustCrypto project, approximately 868K downloads/month, `no_std` compatible. Not yet independently audited. |
| `x509-cert` | X.509 certificate parsing and encoding (RFC 5280) | Pure Rust, RustCrypto project, `no_std` compatible. Not yet independently audited. |
| `der` | ASN.1 DER encoding/decoding — required by both `cms` and `x509-cert` | Pure Rust, RustCrypto project, `no_std` with heapless support, approximately 3.3M downloads/month. |

---

## 4. Code and Artifact Signing (Software Supply Chain)

Sign git commits, release tarballs, container images, and firmware update
manifests. Integrates with Sigstore/cosign infrastructure for transparency-log
backed signatures.

| Crate | Role | Notes |
|-------|------|-------|
| `ssh-key` | `sshsig` format for git commit signing via `gpg.format=ssh` | See SSH section above. |
| `cms` | CMS-wrapped detached signatures for release artifacts | See S/MIME section above. |
| `sigstore` | Host-side Sigstore/cosign/Rekor integration for transparency-log backed keyless or key-based signing | `std` only — host-tools crate use exclusively. Under active development, not yet 1.0 stable. Experimental. |

The device performs only the signing operation; the host-tools crate handles
Sigstore protocol and Rekor submission.

---

## 5. Certificate Authority Operations / Offline Root CA

Store CA root key material in RRAM, use Shamir splitting for key ceremony
multi-party custody, sign subordinate certificates offline.

| Crate | Role | Notes |
|-------|------|-------|
| `x509-cert` | Parse, construct, and encode X.509 certificates including CA certificates and certificate chains | See S/MIME section above. |
| `cms` | CRL (Certificate Revocation List) signing | See S/MIME section above. |
| `der` | ASN.1 DER serialisation of all certificate structures | See S/MIME section above. |
| `pkcs8` | Private key encoding/decoding (RFC 5208, RFC 5958) | RustCrypto project, `no_std` compatible. |
| `spki` | X.509 Subject Public Key Info encoding | RustCrypto project, `no_std` compatible. |

Shamir key ceremony: `vsss-rs` is already in the dependency tree. The device's
existing design maps directly onto CA key ceremony requirements — no new
fundamental crates needed.

---

## 6. Kerberos / PKINIT Enterprise Authentication

Authenticate to Active Directory, FreeIPA, or MIT Kerberos infrastructure using
PKINIT (RFC 4556) — the token presents a certificate-backed identity to a KDC
instead of a password.

| Crate | Role | Notes |
|-------|------|-------|
| `x509-cert` | Certificate storage and presentation | See above. |
| `cms` | PKINIT AuthPack signing (DER-encoded CMS SignedData) | See above. |

No standalone Rust PKINIT client crate exists at time of writing that is
suitable for `no_std` embedded use. The firmware only needs to perform the
signing operation; PKINIT protocol handling lives entirely in the host-side
tooling via OpenSC or PKCS#11 middleware.

Planned: Q2 hardware availability.

---

## 7. Document and Dataset Notarisation / Timestamping

Produce cryptographically verifiable signatures on documents, scientific datasets,
legal records, or research data at the point of collection.

| Crate | Role | Notes |
|-------|------|-------|
| `cms` | RFC 3161 Time-Stamp Protocol (TSP) request/response structures are built on CMS | See above. |
| `x509-cert` | Timestamping Authority (TSA) certificate handling | See above. |

The device provides the signing key; an RFC 3161 TSA on the host side provides
the timestamp token. The firmware itself does not require a clock.

---

## 8. Post-Quantum Cryptography Profile Additions

Add ML-KEM, ML-DSA, and SLH-DSA algorithm entries to the existing cipher-agnostic
profile system once independently audited crates are available.

| Crate | Status | Notes |
|-------|--------|-------|
| `ml-kem` (RustCrypto) | `no_std` compatible, tested against NIST KAT vectors | No independent audit as of 2025. RustCrypto README explicitly states this. Do not integrate before audit. |
| `ml-dsa` (RustCrypto) | `no_std` compatible, tested against NIST KAT vectors | No independent audit as of 2025. Same caveat. |
| `slh-dsa` (RustCrypto) | `no_std` compatible, tested against NIST KAT vectors | No independent audit as of 2025. Same caveat. |
| `libcrux-ml-kem` (Cryspen) | Formally verified using hax/F* framework; used in production by Mozilla | Most rigorous verification story currently available. Cryspen uncovered the KyberSlash timing bug in other implementations. Watch for formal audit availability. |

Hybrid classical+PQC profiles (e.g. X25519 + ML-KEM-768) should be the first
deployment target. The existing profile system accommodates this without
architectural changes.

Integration is intentionally deferred until at least one crate covering
ML-KEM and ML-DSA has completed an independent security audit.

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

| Crate | Independently Audited |
|-------|----------------------|
| `aes-gcm`, `chacha20poly1305`, `ed25519-dalek`, `x25519-dalek`, `hkdf`, `pbkdf2`, `hmac`, `sha2`, `sha3`, `blake2`, `blake3`, `zeroize`, `subtle`, `p256`, `p384` | Yes (existing deps) |
| `vsss-rs` | Yes (existing dep) |
| `der`, `cms`, `x509-cert`, `pkcs8`, `spki` | No independent audit yet |
| `ssh-key` | No independent audit yet |
| `ml-kem`, `ml-dsa`, `slh-dsa` | No independent audit yet |
| `postcard` | No independent audit yet |
| `sigstore` | Experimental, pre-1.0 |
