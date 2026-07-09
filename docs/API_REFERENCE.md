# API reference (code map)

This document maps **where** major behaviours live in the repository and how they connect. It complements **`cargo doc`** (run per crate for full signatures and trait bounds). It is not a substitute for reading the source when behaviour details matter.

**Audience:** The [Annex: Standards implementors (IETF, GnuPG, Sequoia)](#annex-standards-implementors-ietf-gnupg-sequoia) below is written so **IETF OpenPGP working group** participants, **Internet-Draft** authors, **GnuPG** maintainers, **Sequoia PGP** (and other OpenPGP implementations) can **reproduce or compare** this project’s Shamir construction and authenticated ephemeral ECDH session protocol when designing **interoperable** standards for Shamir’s Secret Sharing and forward-secret key exchange in an OpenPGP-class ecosystem. It documents **what this codebase does**, not what any RFC requires. Official protocol rules belong in IETF consensus documents after WG review.

---

## Shamir's Secret Sharing

### Role in the stack

Shamir K-of-N is implemented in **`vault`** using **`vsss-rs`** (`Gf256` field arithmetic, byte-wise polynomials). **`cipher-profile`** carries **metadata** (`ShamirConfig`: threshold `k`, total `n`) on named profiles. **Host tools** (`galdra-core-host`) orchestrate export of signing key material, split/recover via the same `vault::shamir` functions, armoured share files, and USB calls (currently stubbed). **`vault::kdf_policy::KeyPurpose::ShamirRecovery`** reserves a distinct HKDF label for material derived after reconstruction.

Nothing in the OpenPGP card path exposes Shamir as a standard GnuPG command; see the main [README](../README.md) and [OPENPGP_CARD.md](OPENPGP_CARD.md).

### Firmware: `vault::shamir`

**Module:** `crates/vault/src/shamir.rs` (re-exported as `vault::shamir`).

| Item | Description |
|------|-------------|
| `ShamirError` | `InsufficientShares`, `InvalidShare { index }`, `DuplicateIndex`, `InvalidParameters`, `TrngFailure`, `SecretTooShort` / `SecretTooLong` (secret length 16–64 bytes). |
| `ShamirShare` | Share index (`u8`, must be non-zero) and value (`heapless::Vec<u8, 64>`). `Zeroize`/`ZeroizeOnDrop`. **No** `Clone`/`Copy`. |
| `ShamirShare::try_from_index_value(index, value)` | Build from wire or host decoding; `value` length must be 16–64 bytes. |
| `ShamirShare::value()` | Borrow share payload bytes. |
| `ShamirSecret` | Recovered secret; `as_slice()`, zeroizes on drop. |
| `shamir_split(secret, k, n, trng)` | Split `secret` into `n` shares with threshold `k`. Requires `1 <= k <= n <= 255`, `secret.len()` in **16..=64**, and `HardwareTrng` for random coefficients. Returns `heapless::Vec<ShamirShare, 255>`. |
| `shamir_recover(shares, k)` | Lagrange interpolation at zero; needs at least `k` shares with distinct indices; `k` must match split-time threshold (not inferred from payloads). |

**Tests:** `crates/vault/src/shamir.rs` (unit), `crates/vault/tests/shamir_vectors.rs`, `crates/vault/examples/shamir_vector_dump.rs`.

**Fuzz target:** `fuzz/fuzz_targets/shamir_split_recover.rs` exercises `shamir_split` / `shamir_recover` with random inputs.

### Profile metadata: `cipher_profile::ShamirConfig`

**File:** `crates/cipher-profile/src/shamir_cfg.rs`.

| Item | Description |
|------|-------------|
| `ShamirConfig { threshold, total }` | `threshold` = `k`, `total` = `n` (1–255). |
| `ShamirConfig::new(k, n)` | Fails if `k == 0`, `n == 0`, or `k > n`. |
| `ShamirConfig::none()` | `k = 1`, `n = 1` (no splitting). |
| `ShamirConfig::is_active()` | `true` when `total > 1`. |

**Profiles** attach Shamir via `CipherProfileBuilder::shamir(...)` / `CipherProfile::shamir()`. Built-in examples include **`conservative-shamir`** (see `registry.rs`).

### HKDF label: `KeyPurpose::ShamirRecovery`

**File:** `crates/vault/src/kdf_policy.rs`.

- Enum variant `KeyPurpose::ShamirRecovery` with `info()` label `b"galdr-v1/vault/shamir-recovery"`.
- Used with `derive_subkey_sha512(...)` when deriving keys from combined recovery material per policy (see rustdoc in that module).

### Host: `galdra_core_host::shamir_ops`

**File:** `galdra-core-host/src/shamir_ops.rs`.

| Item | Description |
|------|-------------|
| `ShamirShareExport` | Profile name, `threshold`, `total`, `index`, `value` (`ZeroizingShareBytes`), fingerprint, RFC3339 timestamp. |
| `ShamirShareExport::to_armoured` / `from_armoured` | PEM-like **GALDRA SHARE** ASCII format for files and QR payloads. |
| `shamir_split_key(device, profile, slot)` | Loads signing key material via `Device::export_signing_key_shamir_material`, runs `vault::shamir::shamir_split` with `FakeTrng` seed (deterministic host path), builds armoured exports. Requires profile with `shamir.is_active()`. |
| `shamir_recover_key(device, shares, slot)` | Parses `ShamirShare` from exports, `shamir_recover`, checks 32-byte result, `Device::import_shamir_recovered_signing_key`. |

### Host: `galdra_core_host::device::Device`

**File:** `galdra-core-host/src/device.rs`. **Phase 1 stub:** `connect()` and most methods return `DeviceNotConnected` until USB integration is wired.

| Method | Shamir-related role |
|--------|---------------------|
| `export_signing_key_shamir_material(slot)` | Returns `Zeroizing<[u8; 32]>` for splitting. |
| `signing_key_fingerprint_hex(slot)` | Metadata on share files. |
| `import_shamir_recovered_signing_key(slot, material)` | Writes reconstructed key material back. |

Other methods (`unlock`, `provision`, `key_list`, …) are documented in the same file.

### `galdrad` REST (JSON)

**Router:** `galdrad/src/api.rs` (`router` function).

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/shamir/split` | Body: slot, profile name; returns armoured shares. |
| `POST` | `/shamir/recover` | Body: slot + armoured share strings. |
| `GET` | `/shamir/share-info?armoured=...` | Inspect one share (metadata; large bodies may hit URL limits). |

Swagger UI (when built): `/swagger-ui` with OpenAPI JSON at `/api-docs/openapi.json` (not all routes are listed in the OpenAPI struct yet).

### `galdra` CLI

**Module:** `galdra/src/shamir_cmds.rs`, enum `ShamirCmd` in `galdra/src/main.rs`.

| Subcommand | Role |
|------------|------|
| `galdra shamir split --slot --profile --output-dir` | Write share files. |
| `galdra shamir recover --slot --share ... --confirm` | Read shares, recover, import. |
| `galdra shamir show-share --input` | Metadata only. |
| `galdra shamir export-qr` / `import-qr` | QR packaging for shares. |

Profile definitions that include Shamir use `profile add ... --shamir-threshold K --shamir-total N` (see `galdra` profile commands and [GALDRA-TOOL.md](GALDRA-TOOL.md)).

---

## Other public surfaces (summary)

### `pin-policy` (`crates/pin-policy`)

| Item | Role |
|------|------|
| `DEFAULT_MAX_PIN_ATTEMPTS` | `3`. |
| `MIN_PROVISIONED_PIN_ATTEMPTS` / `MAX_PROVISIONED_PIN_ATTEMPTS` | `3`..=`10`. |
| `PinPolicyConfig::try_with_max_attempts(n)` | Validates provisioned attempt ceiling. |
| `PinPolicyMachine` | State machine: counter before compare, threshold triggers `ZeroisationTrigger`. |
| `pin_compare` | Constant-time equality for PIN bytes. |
| `parse_unlock_pin` / `parse_challenge_passphrase` | Parser helpers for USB / challenge paths. |

### `cipher-profile` (`crates/cipher-profile`)

| Item | Role |
|------|------|
| `CipherProfile` / `CipherProfileBuilder` | Named cipher stacks, curves, Shamir metadata, canonical bytes for signing. |
| `ProfileRegistry` | Built-in and user-defined profiles (`registry.rs`). |
| `CipherLayer`, curve enums | Layered symmetric ciphers and ECDH curves for profiles. |

See [CIPHER_PROFILES.md](CIPHER_PROFILES.md).

### `vault` (besides Shamir)

| Item | Role |
|------|------|
| `KeyPurpose` | HKDF domain separation labels (`kdf_policy.rs`); includes OpenPGP slots, ephemeral session, RSA wrap, etc. |
| `derive_subkey_sha512(ikm, salt, purpose, out)` | HKDF-SHA512 expand with fixed `purpose.info()`. |
| `VaultService` / `VaultRequest` | Intended service API over the vault (`service.rs`). |
| `vault_pin_policy` | Integration of `pin-policy` with vault storage. |
| `sealed_key`, `layout` | RRAM layout and sealed blob handling. |

### `galdra-core-host` (non-Shamir)

Re-exports **`cipher_profile`**. Modules: `contacts`, `groups`, `db`, `encrypt`, `profiles`, `sync`, `audit`, … — see `galdra-core-host/src/lib.rs` and per-module rustdoc.

### `galdrad` HTTP (full list)

| Method | Path |
|--------|------|
| `GET` | `/health` |
| `GET`/`POST` | `/contacts`; `GET`/`PATCH`/`DELETE` `/contacts/:id` |
| `GET`/`POST` | `/groups`, `/groups/:name`, `/groups/:name/members`, `/groups/:name/members/:id` |
| `GET` | `/device/status`, `/audit` |
| `GET`/`POST` | `/profiles`, `/profiles/:name` (GET/DELETE) |
| `POST` | `/encrypt`, `/decrypt`, `/sign`, `/verify` |

`POST /contacts` requires **`email`**. `POST /contacts` and `PATCH /contacts/:id` accept optional **`dmr_id`**, **`radio_affiliation`**, **`street`**, **`country`**, **`postal_code`**, **`region`**, **`fluxer_id`**, **`discord_id`**, **`irc_id`**, and **`phone_number`** in JSON (alongside **`name`**, …); see structs **`CreateContactBody`** / **`UpdateContactBody`** in `galdrad/src/api.rs`.

### Firmware crates (pointers)

| Crate | Focus |
|-------|--------|
| `galdr-core` | HAL traits (`HardwareTrng`, `ZeroiseController`, …), `GaldrError`. |
| `usb-personality` | CCID, OpenPGP dispatch, vault backend. |
| `ephemeral-session` | Forward-secret ECDH session protocol (see [EPHEMERAL_SESSION.md](EPHEMERAL_SESSION.md)). |
| `security-tests` | `dudect_galdr` harnesses including `timing_shamir_recover`. |

---

## Annex: Standards implementors (IETF, GnuPG, Sequoia)

### Status and scope

This annex is a **technical snapshot** of behaviours implemented in **`vault::shamir`**, **`galdra-core-host::shamir_ops`**, and **`ephemeral-session`**. It is intended for **interoperability analysis** and **I-D writing**, not as an IETF **normative** specification. When proposing standards:

- Use the [OpenPGP WG](https://datatracker.ietf.org/wg/openpgp/about/) mailing list (`openpgp@ietf.org`) and Internet-Drafts for protocol changes.
- Engage **multiple implementations** (GnuPG, Sequoia, OpenPGP.js, etc.); see the main [README](../README.md) sections on standards process and Sequoia PGP.
- This repository **does not** define OpenPGP packet types for Shamir shares or ephemeral handshakes; mapping to RFC 4880-style messages would be **new standards work**.

### A. Shamir’s Secret Sharing (reference construction in this tree)

**Implementation:** `crates/vault/src/shamir.rs`, dependency **`vsss-rs`** (`Gf256`).

| Aspect | Definition in this codebase |
|--------|-----------------------------|
| Field | GF(256) with the same field as `vsss_rs::Gf256` (byte-wise operations; verify against the `vsss-rs` version pinned in `Cargo.lock`). |
| Sharing | For **each byte position** of the secret independently: a polynomial of degree **k − 1** with coefficients in GF(256); constant term is that byte of the secret; other coefficients from `HardwareTrng`. Share **i** (1 ≤ **i** ≤ **n**) uses evaluation point **x = i** (indices must be non-zero; duplicate indices are rejected on recover). |
| Secret length | **16 to 64 bytes** inclusive per share payload (aligned across all shares). |
| Threshold | **k** shares required; **n** total shares; **1 ≤ k ≤ n ≤ 255**. |
| Recovery | Lagrange interpolation at **x = 0** per byte; `k` must be supplied explicitly to `shamir_recover` (not inferred from share blobs alone). |

**References:** Shamir (1979); for HKDF after recovery in vault policy, [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869) with SHA-512 in `derive_subkey_sha512` and `KeyPurpose::ShamirRecovery` label `galdr-v1/vault/shamir-recovery` (octets fixed in `vault/src/kdf_policy.rs`).

**Host export format (GALDRA SHARE armour):** `galdra-core-host/src/shamir_ops.rs` — ASCII armour with headers `Profile`, `Threshold`, `Total`, `Index`, `Fingerprint`, `Created`, base64-encoded raw share bytes. Independent implementations can parse the same format for **testing**; a future standard might prefer OpenPGP packets or another container.

**Test material:** `crates/vault/tests/shamir_vectors.rs`, `fuzz/fuzz_targets/shamir_split_recover.rs`, dudect harness `timing_shamir_recover` in `security-tests`.

### B. Authenticated ephemeral ECDH session protocol (`ephemeral-session` crate)

**Documentation:** [EPHEMERAL_SESSION.md](EPHEMERAL_SESSION.md). **Sources:** `crates/ephemeral-session/src/handshake.rs` (wire), `protocol.rs` (state machine, preimages), `keys.rs` (ECDH + HKDF), `hkdf_labels.rs`, `trust.rs` (fingerprints).

#### Security goal

**Forward secrecy:** session keys derive from **ephemeral** ECDH; long-term Brainpool keys only **authenticate** the ephemeral public keys (ECDSA over SHA-256 of defined preimages).

#### Elliptic curves ([RFC 5639](https://www.rfc-editor.org/rfc/rfc5639) curves, SEC1 uncompressed points)

| `curve` wire byte | Curve | Uncompressed SEC1 length |
|-------------------|--------|---------------------------|
| `0x01` | brainpoolP256r1 | 65 |
| `0x02` | brainpoolP384r1 | 97 |

Wire byte `0x03` (brainpoolP512r1) was used in earlier protocol versions and is **not** accepted by current firmware. See [CHANGELOG.md](../CHANGELOG.md).

#### Protocol version bytes

| Message | Constant | Value |
|---------|----------|--------|
| Init | `INIT_PROTOCOL_VERSION` | `0x01` |
| Response | `RESP_PROTOCOL_VERSION` | `0x01` |

#### Long-term key fingerprint (binding identity)

**SHA-256** digest over the **uncompressed SEC1** encoding of the long-term **verifying** key (32 raw bytes). On the wire in Init/Response, this digest is encoded as **64 ASCII hexadecimal characters** (`0-9`, `a-f` in generator; parsers accept `A-F`). See `LongTermCert::fingerprint_of` in `trust.rs` and `InitMessage::encode_fingerprint_hex` in `handshake.rs`.

#### ECDSA over preimages

Long-term signing uses **Brainpool ECDSA** with **SHA-256** digest of the **raw preimage octets** (not a free-form user message): `sign_handshake_sha256_prehash` in the vault Brainpool signing helpers.

- **Initiator preimage:** `version || curve_id || initiator_ephemeral_sec1_uncompressed` (concatenation, no length prefixes except as implied by fixed SEC1 lengths).
- **Responder preimage:** `version || curve_id || responder_ephemeral_sec1 || initiator_ephemeral_sec1`.

**Signature encoding:** **DER** ECDSA signature octets (variable length; parser uses `u16` big-endian length prefix on the wire).

#### InitMessage serialisation (`InitMessage::serialise`)

Octet order:

1. `u8` version (must be `0x01` for parse to accept).
2. `u8` curve_id (must match SEC1 length below).
3. `u8` `n` — length of initiator ephemeral public key; **must** equal `SessionCurve::public_key_len()` for that curve.
4. `n` bytes — initiator ephemeral public key (SEC1 uncompressed).
5. `u8` fingerprint length — length of next field (typically `64` for hex ASCII).
6. Variable — long-term fingerprint (64 hex digits encoding 32-byte SHA-256).
7. `u16` big-endian — DER signature length.
8. Variable — DER ECDSA signature.

Maximum serialised size `MAX_HANDSHAKE_BYTES` (512).

#### ResponseMessage serialisation (`ResponseMessage::serialise`)

Same as Init through the responder’s ephemeral public key and fingerprint, then:

9. `u8` length — must equal curve SEC1 length.
10. Variable — **copy of initiator ephemeral public key** (responder binds to same session; initiator compares in constant time).
11. `u16` big-endian + DER signature for the **responder** preimage.

Full parse/serialise symmetry in `handshake.rs`.

#### ECDH shared secret

ECDH computes a shared secret from the **x**-coordinate of the point (packed to a fixed buffer per curve in `keys.rs`); implementation uses the workspace Brainpool ECDH helpers (`diffie_hellman`).

#### HKDF for session keys ([RFC 5869](https://www.rfc-editor.org/rfc/rfc5869), SHA-256)

- **IKM** = raw ECDH shared secret bytes (length curve-dependent after packing).
- **Salt** for HKDF-Extract = **lexicographic ordering** of the two ephemeral public keys: `if epk_initiator <= epk_responder { epk_initiator || epk_responder } else { epk_responder || epk_initiator }` (see `ordered_epk_salt` in `keys.rs`).
- **Extract:** PRK = HMAC-SHA256(salt, IKM) with salt as HMAC key (empty salt uses 32 zero octets per local helper).
- **Expand:** HKDF-Expand(PRK, `info`, 32) for each 32-byte key, with **distinct** UTF-8 `info` labels in `hkdf_labels::domain`:

| `info` label (exact octets) | Derived key role |
|----------------------------|------------------|
| `galdralag/session/payload-i2r/v1` | ChaCha20-Poly1305 payload, initiator to responder |
| `galdralag/session/payload-r2i/v1` | ChaCha20-Poly1305 payload, responder to initiator |
| `galdralag/session/gdss-mask/v1` | GDSS masking keystream |
| `galdralag/session/gdss-sync/v1` | GDSS sync PN |
| `galdralag/session/gdss-timing/v1` | GDSS timing schedule |
| `galdralag/session/mac/v1` | Optional HMAC |

Changing these strings breaks interoperability; any standardisation would either freeze them or register an IANA/OpenPGP profile identifier.

#### Relationship to OpenPGP

This protocol is **not** an OpenPGP message; it is a **separate** authenticated ECDH handshake used inside this firmware stack. A standards effort might adopt similar cryptography inside new OpenPGP packet types or a card APDU extension; this annex gives a **complete concrete reference** for comparison.

**Vectors and timing:** `crates/ephemeral-session/tests/session_protocol.rs`, Wycheproof-backed Brainpool tests in `vault`, dudect harnesses for handshake paths in `security-tests`.

### C. Coordination checklist for I-D authors

1. Confirm **field arithmetic** for Shamir matches intended `vsss-rs` / GF(256) definition across versions.
2. Freeze **version bytes**, **curve wire IDs**, **HKDF labels**, and **preimage layouts** if aiming for binary interoperability with this tree.
3. Decide whether **GALDRA SHARE** armour or **OpenPGP packets** carry Shamir material in a future standard.
4. File **interoperability tests** against **Sequoia** and **GnuPG** early if the WG pursues adoption.

---

## Generating HTML rustdoc

From the repository root:

```bash
cargo doc -p vault --no-deps --open
cargo doc -p pin-policy --no-deps --open
cargo doc -p cipher-profile --no-deps --open
cargo doc -p ephemeral-session --no-deps --open
cargo doc -p galdra-core-host --open
```

Use `--document-private-items` only when debugging internal flows.
