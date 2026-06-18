# CESS alignment and conformance posture

**Normative reference:** [CESS v0.2-draft](https://github.com/Supermagnum/CESS/tree/main) — specification (`spec/CESS-v0.2.md`), [algorithm registry](https://github.com/Supermagnum/CESS/blob/main/ALGORITHM-REGISTRY.md), [conformance levels](https://github.com/Supermagnum/CESS/blob/main/CONFORMANCE.md), and test vectors under `vectors/`.

This firmware and host stack **aligns** with CESS security goals and several normative constructions. It does **not** currently claim **CESS-CORE**, **CESS-FULL**, or **CESS-PQ** certification against the CESS vector suite, because the project **retains** algorithms that the CESS registry lists as **excluded** for the normative CESS fixed layer (for example **AES**, **SHA-2**, **HKDF-SHA256** in existing cipher profiles and vault code). Those choices are **intentional** for interoperability and audited-crate availability; see **Deviation register** below.

---

## What we align with (normative themes)

| CESS topic | Galdralag alignment |
|------------|---------------------|
| **GF(2^8) Shamir** (CESS §5.1) | Implemented with `vsss-rs` / vault Shamir (`docs/API_REFERENCE.md` annex); byte-wise threshold **k-of-n**, non-zero indices. |
| **No cleartext suite / profile discriminators** (CESS §8.1) | Documented in [CIPHER_PROFILE_SECURITY.md](CIPHER_PROFILE_SECURITY.md); wire layouts must not expose profile identifiers outside authenticated encryption when using CESS **Mode A** framing. |
| **Mode A outer — BrainpoolP384r1 ECDH only** (CESS §6.1.1, §6.6) | Ephemeral session protocol supports **BrainpoolP384r1**; deployments that enable CESS **Mode A** **MUST** use **only** P384 for the ECDH that feeds **`K_outer`** (see `crates/cess` constants and `SessionCurve` in `ephemeral-session`). |
| **Mode A outer plaintext** `suite_id \|\| inner_blob` (CESS §6.6) | Implemented as **data layout** helpers in `crates/cess` (`assemble_mode_a_outer_plaintext`, `parse_mode_a_outer_plaintext`). |
| **Outer KDF info** `cess-outer-envelope-v1` (CESS §6.6) | Implemented: `cess::derive_k_outer`, `hkdf_blake3` (vectors from CESS `hkdf_blake3.toml`); [`EphemeralSharedSecret::cess_k_outer_mode_a`](../crates/ephemeral-session/src/keys.rs) on the raw ECDH IKM. |
| **Outer AEAD** ChaCha20-Poly1305 (CESS §6.6) | Implemented: `cess::seal_mode_a_outer`, `cess::open_mode_a_outer` (12-byte nonce \|\| ciphertext \|\| tag, empty AAD). |
| **Wildcard inner profiles** (CESS §4, §8) | [CIPHER_PROFILES.md](CIPHER_PROFILES.md) cipher-agnostic cascades remain **inner**; outer Mode A does not fix inner algorithm choice beyond **`suite_id`**. |
| **16-bit `suite_id` registry** (CESS §8.5, §14.2) | Provisional mapping for built-in profile names in `crates/cess` (`SUITE_ID_RESERVED` = 0 rejected); formal allocation belongs in [CESS ALGORITHM-REGISTRY.md](https://github.com/Supermagnum/CESS/blob/main/ALGORITHM-REGISTRY.md) via PR. |

---

## Deviation register (explicit non-conformance to CESS-CORE fixed layer)

The CESS **CESS-CORE** level (see [CONFORMANCE.md](https://github.com/Supermagnum/CESS/blob/main/CONFORMANCE.md)) requires a **fixed layer** including **Argon2id**, **BLAKE3** integrity, **HKDF-BLAKE3**, and **ChaCha20-Poly1305** as specified, and the registry **excludes** **AES** and **SHA-2** family use in that normative stack.

**Galdralag retains:**

- **AES-256-GCM**, **ChaCha20-Poly1305**, **Twofish**, **Serpent** in **cipher profiles** (`cipher-profile` crate).
- **SHA-256** and **HKDF-SHA256** in ephemeral session key derivation (`ephemeral-session`), vault KDFs, and related code.
- **Existing audited RustCrypto** paths documented in [README.md](../README.md) cryptographic dependency policy.

Therefore this repository is **not** a drop-in **CESS-CORE** implementation for the **full** fixed-layer + vector suite until either:

1. A **deployment** adds a **CESS-native** profile that uses only CESS-approved primitives for a **separate** code path, or  
2. The CESS registry and specification admit a **documented extension profile** for this stack (out of scope here; would be a CESS repository change).

---

## Roadmap toward stronger CESS interoperability

1. **Done (this tree):** **HKDF-BLAKE3** for **`K_outer`** (`cess::hkdf_blake3`, `cess::derive_k_outer`); unit tests match CESS `vectors/hkdf_blake3.toml`. **Mode A outer** ChaCha20-Poly1305 (`cess::seal_mode_a_outer`, `open_mode_a_outer`). **`EphemeralSharedSecret::cess_k_outer_mode_a`** before HKDF-SHA256 session derivation.  
2. **Inner HKDF-BLAKE3** `info` strings for per-suite keys after outer decrypt (CESS §8.3) — not yet wired to cipher-profile inner blobs.  
3. **CI:** Vendor or submodule CESS `vectors/` and run the official **runner** beyond HKDF unit tests.  
4. **Publication:** Per CESS [CONFORMANCE.md](https://github.com/Supermagnum/CESS/blob/main/CONFORMANCE.md), publish a conformance statement with CESS version, level (when achieved), and vector commit hash.

---

## Related crates and docs

- `crates/cess` — CESS Mode A wire helpers and provisional `suite_id` values.  
- [CIPHER_PROFILE_SECURITY.md](CIPHER_PROFILE_SECURITY.md) — cleartext identifiers and traffic analysis.  
- [EPHEMERAL_SESSION.md](EPHEMERAL_SESSION.md) — Brainpool ephemeral ECDH.  
- [README.md — CESS (related open standard)](../README.md#cess-related-open-standard)
