# CESS alignment and conformance posture

**Normative reference:** [CESS v0.2-draft](https://github.com/Supermagnum/CESS/tree/main) — specification (`spec/CESS-v0.2.md`), [algorithm registry](https://github.com/Supermagnum/CESS/blob/main/ALGORITHM-REGISTRY.md) (canonical **`suite_id`** assignments are in the [**Cipher suite identifier lookup table**](https://github.com/Supermagnum/CESS/blob/main/ALGORITHM-REGISTRY.md#cipher-suite-identifier-lookup-table)), [conformance levels](https://github.com/Supermagnum/CESS/blob/main/CONFORMANCE.md), and test vectors under `vectors/`.

### Registry table semantics (summary)

The upstream **Cipher suite identifier lookup table** defines each **`suite_id`** row as one **inner** cipher tuple per `spec/CESS-v0.2.md` (Sections 4.2, 4.5, 6.1, 6.3, 6.6, 7): **classical KEM**, **HKDF-BLAKE3**, **bulk AEAD or cascade**, optional **keyed BLAKE3 integrity** between layers (Section 6.3), optional **PQ KEM**, optional **Ed25519** over `suite_id || inner_blob` when the **Signature** column lists **Ed25519**. **Mode A** outer framing is fixed **ChaCha20-Poly1305** (Section 6.6).

**Normative:** The meaning of each **`suite_id`** **MUST** be taken from the **lookup table**. If an **informative** bit-field reading **conflicts** with a table row, the **lookup table** wins (`spec/CESS-v0.2.md` Section 8.5). The registry documents an **informative** encoding layout (high/mid/low nibbles for PQ family, classical curve, bulk pattern); implementations **MUST** still treat the **published table** as authoritative.

**Unknown `suite_id`:** Implementations **MUST** reject **`suite_id`** values **not** listed in the table (unless a **deployment-specific private-use agreement** authorises them). **Outer** ChaCha20-Poly1305 tag verification **MUST** succeed before **`suite_id`** is acted on; **outer** failure, **Ed25519** failure (when applicable), and **unknown** **`suite_id`** **MUST** be **indistinguishable** to remote parties (see registry text and Sections 4.5, 8.3, 8.5). Full host/token pipelines should follow that ordering and leakage model when integrated.

**Wire sizes (upstream):** The CESS specification fixes **Mode A** outer as **12-byte nonce + ciphertext + Poly1305 tag** with **variable** ciphertext length (Section 8.3). It does **not** define a normative **single concatenated buffer** with fixed totals such as **131 / 163 / …** bytes for a full message. An uncompressed **SEC1** point for a 384-bit curve is **97** octets in common encodings (**0x04** + **x** + **y**), but that size is **not** spelled out as a normative label in-repo. Arithmetic that combines ephemeral public key length, outer AEAD, and inner fields may be useful for implementations; treat it as **informative** unless a future spec revision makes it normative.

**Remote-indistinguishability (narrow normative list):** The registry and spec nail **the same generic observable outcome** for **outer** ChaCha20-Poly1305 tag failure, **Ed25519** verification failure (before inner decrypt), and **unknown / unsupported** **`suite_id`** after outer decrypt. **Keyed BLAKE3** integrity and **inner** bulk AEAD / Poly1305 failures are specified as cryptographic steps (for example Section 6.3, Section 14.1-style **AUTH_FAILED**); they are **not** folded into that same three-way indistinguishability sentence in the current text. Unifying **all** failure paths behind one external error is **implementation or deployment policy** unless the specification is extended.

**Primitive KATs:** Canonical vectors and **runner** checks for Serpent, Twofish, cascades, ECDH samples, Ed25519, keyed BLAKE3, and per-**`suite_id`** matrix status live in the **CESS** repository under **`vectors/`**, **`runner/`**, and **`vectors/classical_suite_id_matrix.toml`**. This firmware tree exercises **`crates/cess`** helpers and selected RFC vectors locally; it does **not** replace upstream’s vector suite.

### KATs before round-trips (promotion to approved)

**Known-answer tests (KATs)** must pass **first**: they assert correctness against **external** references (RFC and NIST-style vectors, Wycheproof, CESS `vectors/`, and similar). **Round-trip** tests (encrypt then decrypt, or the reverse) run **second**: they assert **internal** consistency between the encrypt and decrypt paths. **Both** must succeed before a **provisional** **`suite_id`** in the upstream registry can reasonably be promoted to **approved**.

Failure modes are informative: a **`suite_id`** line that passes KATs but fails round-trip usually indicates a **symmetric** implementation bug (the two directions disagree on keys, `info` strings, or layer order). A line that passes round-trip but fails KATs can still be **wrong but self-consistent** and will **not interoperate** with any other conforming CESS implementation.

This repository runs both test classes where implemented (see [TEST_RESULTS.md](TEST_RESULTS.md)); exhaustive per-**`suite_id`** KAT coverage is defined and tracked in **CESS**.

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
| **Inner inter-layer integrity** (CESS §6.3-style, keyed BLAKE3 family) | For built-in **`suite_id`** profiles with **≥ 2** symmetric layers: **HMAC-BLAKE3** (32 B) over **`cess_blake3_integrity_info(suite_id)` \|\| inner AEAD ciphertext**; HKDF-BLAKE3 MAC subkey `info` = `cess_blake3_integrity_gap_info` — `cipher-profile::cascade_encrypt` / `cascade_decrypt`. Custom unmapped profiles: no inter-layer MAC. |
| **Wildcard inner profiles** (CESS §4, §8) | [CIPHER_PROFILES.md](CIPHER_PROFILES.md) cipher-agnostic cascades remain **inner**; outer Mode A does not fix inner algorithm choice beyond **`suite_id`**. |
| **16-bit `suite_id` registry** (CESS §8.5, §14.2) | Canonical numeric codes are in the CESS [**Cipher suite identifier lookup table**](https://github.com/Supermagnum/CESS/blob/main/ALGORITHM-REGISTRY.md#cipher-suite-identifier-lookup-table), including **PQ**, **Ed25519-signed**, and **triple-cascade** rows. Built-in **`cipher-profile`** names map to selected rows in `crates/cess` (`suite_id_for_profile_name`; **`0x0000`** rejected). Custom profiles need a deployment-specific or registry-backed assignment. |

**Built-in mapping:** `standard` → **`0x0001`**; `conservative` and `conservative-shamir` → **`0x0003`** (cascade ChaCha inner, Serpent outer on **BrainpoolP256r1** session curve in Galdralag; CESS table rows use **P384** for the inner KEM column — see deviation register); `high-assurance` → **`0x0012`** (same cascade on **BrainpoolP512r1**). Built-in cascade **layer order** matches the registry text (ChaCha then Serpent in the profile list = inner then outer). **Migrating** from prior private-use `suite_id` values (`0xE001`–`0xE004`) or from the old **Serpent-then-ChaCha** order requires re-encrypting; old ciphertexts are not readable with the new defaults.

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
2. **Inner HKDF-BLAKE3** `info` strings for per-suite keys (CESS §8.3) and **inter-layer HMAC-BLAKE3** (32 B) after each inner AEAD when **≥ 2** layers (HMAC input prefixes **`cess_blake3_integrity_info`**) — wired in `cipher-profile` for built-in profiles that map to a registry `suite_id` (`cascade.rs`, `cess::inner_info`, `cess::hmac_blake3`); IKM is the classical ECDH octets (`ephemeral_session::SessionKeys::cess_inner_cascade_ikm`).  
3. **CI:** Vendor or submodule CESS `vectors/` and run the official **runner** beyond HKDF unit tests. **Blocked for inner cascade profile rows** until the upstream gap below is closed (today’s runner cannot ingest `crates/cipher-profile/tests/fixtures/cascade_cess_kat.json` or an equivalent TOML and confirm those hex fields).  
4. **Publication:** Per CESS [CONFORMANCE.md](https://github.com/Supermagnum/CESS/blob/main/CONFORMANCE.md), publish a conformance statement with CESS version, level (when achieved), and vector commit hash.

### Gap: `cess-runner` and inner cascade profile KATs (registry `suite_id` + IKM)

**Checked (CESS `runner/` and `vectors/`):** The `cess-runner` binary parses `bulk_aead.toml` (and other `*.toml` files) for valid TOML only; **`verify_all_crypto_vectors`** in `runner/src/lib.rs` does **not** load or verify `bulk_aead.toml`. Crypto checks are limited to `twofish.toml`, `hkdf_blake3.toml`, `blake3_integrity.toml`, `ed25519_signing.toml`, `ecdh_p512_inner.toml`, and `classical_suite_id_matrix.toml` (see `runner/src/main.rs`).

**`vectors/bulk_aead.toml` cascade rows** (`schema = "cess-bulk-aead-v0.2"`, e.g. “Cascade: ChaCha20-Poly1305 then Serpent-CTR; Poly1305 on outer”) use **explicit** `chacha_key_hex` / `serpent_key_hex` / `poly1305_key_hex` and an outer **Poly1305** tag. That is **not** the same construction as Galdralag **`cipher-profile`** cascades for registry rows such as **`0x0003`** / **`0x0012`**: **HKDF-BLAKE3** subkeys from a **classical ECDH IKM**, **HMAC-BLAKE3** inter-layer integrity over **`cess_blake3_integrity_info` \|\| inner AEAD ciphertext**, and **Serpent-256 EtM** (CTR + **HMAC-SHA256** in this firmware’s `vault` path), with **empty AAD** on inner layers and profile AAD only on the outermost bulk step.

**`vectors/twofish.toml`** (verified by `twofish_bulk::verify_twofish_toml`) covers **`suite_id`** values **`0x0004`–`0x0007`** and **`0x0203`–`0x0207`** with **raw** layer keys and **CTR + Poly1305**–style outer tagging in the runner’s implementation. It does **not** define rows for **`0x0003`** or **`0x0012`** in the same **IKM + §8.3 HKDF labels + inter-layer MAC + Serpent EtM** shape as `cascade_cess_kat.json`.

**Conclusion:** The CESS **`cess_runner`** tool **does not** currently support running **inner cascade profile** vectors in the same format as `cascade_cess_kat.json` (fixed `ikm_hex`, `suite_id`, `aad_hex`, `plaintext_hex`, **`intermediate_before_outer_hex`**, **`expected_ciphertext_hex`**). Converting the **conservative** / **high-assurance** rows to existing `vectors/*.toml` schemas and passing them through **`cess-runner`** would **not** yield an independent confirmation of those hex values, because no matching verifier exists in the runner.

**What would need to be added in the CESS repository** (for a future runner release):

1. **Vector schema** — e.g. a new file `vectors/inner_cascade_profile.toml` (or a versioned `schema = "cess-inner-cascade-profile-v0.x"`) with rows keyed by **`suite_id`** and including at least: **`ikm_hex`** (length as used for inner HKDF-BLAKE3), **`aad_hex`**, **`plaintext_hex`**, **`intermediate_before_outer_hex`** (optional but recommended), **`outer_ciphertext_hex`** (outermost bulk AEAD output only), and normative references to **CESS §8.3** `info` strings and **§6.3** inter-layer integrity. Rows must match the **lookup table** definition for each `suite_id` (bulk order, EtM vs Poly1305, etc.).
2. **Runner crypto module** — Implement the same derivation and layering as the normative row (HKDF-BLAKE3 with UTF-8 `cess-inner-{suite:04x}-l{layer}-{key,nonce}` / `cess-blake3-integrity-…` / gap labels; inter-layer HMAC-BLAKE3 where required; inner ChaCha with **empty** AAD when the profile specifies AAD only on the outer layer; outer Serpent or Twofish per table). This will either **match Galdralag** by construction or surface a deliberate **spec vs firmware** delta that must be documented.
3. **Wire-up** — `verify_*_toml` for the new file, `verify_all_crypto_vectors(...)`, `main.rs` TOML parse list, and **`cargo test`** coverage analogous to `runner/tests/kat_vectors.rs`.
4. **Relationship to `bulk_aead.toml`** — Either deprecate overlapping cascade examples in favour of the profile-driven schema, or document that `bulk_aead` remains a **primitive composition** KAT (explicit keys, Poly1305 outer) and is **orthogonal** to registry inner-cascade profile KATs.

Until then, **independent** checks for `intermediate_before_outer_hex` / `expected_ciphertext_hex` remain **`cipher-profile`** integration tests, **`cascade-kat-gen`**, and **`scripts/verify_cascade_kats.py`** in this tree—not **`cess-runner`**. The Python script additionally verifies the **trailing 32-byte Serpent EtM HMAC-SHA256** on the outer blob (MAC key = second half of HKDF-BLAKE3-64 with `cess_inner_cascade_etm64_info` for the outer Serpent layer; HMAC input `aad || nonce || body` per `vault` `serpent_cipher.rs`). That tag check lives here because **`cess_runner`** has no equivalent vector or primitive hook for this profile-shaped cascade; upstream would need the module and schema described above to host the same assertion.

---

## Related crates and docs

- `crates/cess` — CESS Mode A wire helpers, `LISTED_SUITE_ID_RANGES` / `is_listed_suite_id` (synced to [ALGORITHM-REGISTRY.md](https://github.com/Supermagnum/CESS/blob/main/ALGORITHM-REGISTRY.md) lookup table, including classical **`0x0008`–`0x000f`** and **`0x0010`–`0x0030`**), assemble/parse rejection of unlisted `suite_id`, and built-in profile → `suite_id` mapping.  
- [CIPHER_PROFILE_SECURITY.md](CIPHER_PROFILE_SECURITY.md) — cleartext identifiers and traffic analysis.  
- [EPHEMERAL_SESSION.md](EPHEMERAL_SESSION.md) — Brainpool ephemeral ECDH.  
- [README.md — CESS (related open standard)](../README.md#cess-related-open-standard)
