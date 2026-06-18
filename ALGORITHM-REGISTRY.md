# Algorithm Registry

This document records every cryptographic primitive used in the Galdralag firmware,
the rationale for its inclusion, the provenance of the implementation, and any
known gaps in test coverage. It supplements `docs/CIPHER_PROFILES.md` and
`docs/TEST_RESULTS.md`.

---

## Symmetric ciphers

### AES-256-GCM

| Field | Value |
|-------|-------|
| Wire ID | 0x01 |
| Standard | NIST FIPS 197 + SP 800-38D |
| Designers | Joan Daemen, Vincent Rijmen (Rijndael); GCM mode by McGrew & Viega |
| Auditors | NIST AES competition (1997–2001); subsequent public cryptanalysis |
| NIST involvement | Yes — AES is a NIST standard; included for compatibility only, not as the primary cipher |
| Implementation | `aes-gcm` crate (RustCrypto); `aes` crate is the only crate in block-ciphers with a formal third-party audit |
| KAT source | NIST CAVP subset (`crates/vault/tests/nist_cavp_vectors/`) |
| Wycheproof | Yes — `crates/vault/tests/data/wycheproof/` |
| Dudect harness | `timing_aes_gcm_tag_check` |
| Fuzz target | None (covered by `fuzz_cipher_profile`) |
| Notes | Excluded from built-in cascade profiles; available for custom profiles only |

### ChaCha20-Poly1305

| Field | Value |
|-------|-------|
| Wire ID | 0x02 |
| Standard | RFC 8439 (IETF, 2018) |
| Designers | Daniel J. Bernstein |
| Auditors | Extensive public cryptanalysis; IETF standardisation process |
| NIST involvement | None |
| Implementation | `chacha20poly1305` crate (RustCrypto) |
| KAT source | RFC 8439 worked examples (`crates/vault/tests/rfc_vectors/`) |
| Wycheproof | Yes — `crates/vault/tests/data/wycheproof/` |
| Dudect harness | `timing_chacha_tag_check` |
| Fuzz target | `chacha_roundtrip` |
| Notes | Inner layer of all built-in cascade profiles |

### Twofish-256

| Field | Value |
|-------|-------|
| Wire ID | 0x03 |
| Standard | AES finalist; Schneier et al. specification (1998) |
| Designers | Bruce Schneier, John Kelsey, Doug Whiting, David Wagner, Chris Hall, Niels Ferguson |
| Auditors | NIST AES competition evaluation (independent of NIST design — NIST evaluated, did not design); public cryptanalysis |
| NIST involvement | None in design; NIST AES competition served as the evaluation vehicle |
| Implementation | `twofish` crate (RustCrypto); no formal third-party audit; compensated by dudect + fuzz |
| KAT source | Twofish reference implementation vectors (`crates/vault/tests/twofish_vectors.json`, 1203 cases including Monte Carlo) |
| Wycheproof | No Wycheproof Twofish vectors exist. Gap is documented; KAT and fuzz provide substitute coverage |
| Dudect harness | `timing_twofish_tag_check` |
| Fuzz target | `twofish_aead` |
| Notes | EtM construction: Twofish-256-CTR + HMAC-SHA256 |

### Serpent-256

| Field | Value |
|-------|-------|
| Wire ID | 0x04 |
| Standard | AES finalist; Anderson, Biham, Knudsen specification (1998) |
| Designers | Ross Anderson, Eli Biham, Lars Knudsen |
| Auditors | NIST AES competition evaluation; public cryptanalysis; regarded as most conservative AES finalist |
| NIST involvement | None in design |
| Implementation | `serpent` crate (RustCrypto); no formal third-party audit; compensated by dudect + fuzz |
| KAT source | Serpent reference vectors (`crates/vault/tests/serpent_vectors.json`) |
| Wycheproof | No Wycheproof Serpent vectors exist. Gap is documented |
| Dudect harness | `timing_serpent_tag_check` |
| Fuzz target | `serpent_aead` |
| Notes | EtM construction: Serpent-256-CTR + HMAC-SHA256 |

### Camellia-256

| Field | Value |
|-------|-------|
| Wire ID | 0x05 |
| Standard | RFC 3713 (IETF Informational, 2004); ISO/IEC 18033-3 |
| Designers | NTT and Mitsubishi Electric Corporation (Japan, 2000) |
| Auditors (1) | EU NESSIE project (KU Leuven consortium, 2000-2003): selected as recommended primitive |
| Auditors (2) | Japan CRYPTREC (Ministry of Internal Affairs / METI, 2002): listed for Japanese e-Government |
| NIST involvement | None. Designers, evaluators, and standards body (CRYPTREC) all operate independently of NIST |
| Implementation | `camellia` v0.2.0 (RustCrypto/block-ciphers); no formal third-party audit. Same audit status as `serpent` and `twofish` in this workspace. Compensated by dudect harness (`timing_camellia_tag_check`) and fuzz target (`camellia_aead`) |
| Zeroize | `features = ["zeroize"]` enabled. Routes to `cipher/zeroize`, which adds `ZeroizeOnDrop` to the internal key schedule. Not a stub — expanded subkeys are zeroised on drop |
| KAT source | RFC 3713 Appendix A (256-bit key ECB vector: key=`0123456789abcdef...00112233...eeff`, pt=`0123456789abcdef...`, ct=`9acc237dff16d76c20ef7c919e3a7509`) — `crates/vault/tests/camellia_vectors.json` |
| Wycheproof | **No Wycheproof Camellia vectors exist** (as of 2026). Wycheproof covers AES, ChaCha20, and other NIST-adjacent primitives; Camellia is absent. Gap is documented here. Compensating coverage: RFC 3713 KAT, EtM round-trip and rejection tests in `camellia_cipher.rs`, and `camellia_aead` fuzz target |
| Dudect harness | `timing_camellia_tag_check` (seed `0x43414D4C`; 100k samples; measures `subtle::ConstantTimeEq` on 32-byte HMAC-SHA256 tag pair) |
| Fuzz target | `camellia_aead` (encrypt round-trip, CTR unauthenticated, decrypt arbitrary bytes) |
| Notes | EtM construction: Camellia-256-CTR + HMAC-SHA256. Identical construction to Serpent-256 and Twofish-256. HKDF-SHA256 domain label: `galdralag/camellia/storage/v1` |

---

## Asymmetric / key-agreement

### BrainpoolP256r1, BrainpoolP384r1, BrainpoolP512r1 (ECDH + ECDSA)

| Field | Value |
|-------|-------|
| Standard | BSI TR-03111 v2.10; RFC 5639 |
| Auditors | BSI (German Federal Office for Information Security); IETF RFC process |
| NIST involvement | None. Brainpool curves were specified independently by BSI |
| Implementation | `bp256`, `bp384`, `bp512` crates (RustCrypto / elliptic-curve ecosystem) |
| KAT source | BSI TR-03111 ECDH vectors + project-owned ECDSA KAT vectors (`crates/vault/tests/bsi_vectors/`) |
| Wycheproof | Yes — Brainpool ECDH/ECDSA edge cases in `crates/vault/tests/data/wycheproof/` |
| Dudect harnesses | `timing_brainpool256_scalar_mult`, `timing_brainpool384_scalar_mult`, `timing_brainpool512_scalar_mult` |
| Fuzz targets | `brainpool384_ecdh`, `brainpool512_ecdh` |

---

## Hash functions and MACs

### BLAKE3

| Field | Value |
|-------|-------|
| Usage | HKDF-BLAKE3 key derivation (CESS profiles); HMAC-BLAKE3 inter-layer integrity |
| Standard | BLAKE3 specification (2020); no NIST involvement |
| KAT source | Official BLAKE3 upstream vectors — all 35 input lengths, hash/keyed-hash/derive-key modes (`crates/vault/tests/blake3_vectors.json`) |
| Wycheproof | Not applicable (no Wycheproof BLAKE3 corpus) |
| Dudect harness | `timing_blake3` |

### HMAC-SHA256 / HKDF-SHA256

| Field | Value |
|-------|-------|
| Usage | EtM MAC for Serpent/Twofish/Camellia layers; key derivation for non-CESS profiles |
| Standard | RFC 2104 (HMAC); RFC 5869 (HKDF) |
| KAT source | Wycheproof HMAC/HKDF vectors |
| Dudect harness | `timing_hmac_verify`, `timing_hkdf_derive` |

---

## Exclusion policy

AES and the NIST cipher suite are excluded from built-in cascade profiles as a deliberate design choice for users and organisations requiring cryptographic independence from any single country's standards process. AES-256-GCM is available for custom profiles (`CipherLayer::Aes256Gcm`, wire ID 0x01) where compatibility requirements override this preference.

RSA-OAEP and RSA-PSS are included for OpenPGP interoperability only; they are not used for session key agreement.
