# Cipher Profiles

Galdralag is cipher-agnostic. A cipher profile specifies which symmetric
ciphers are applied, in which order, combined with the ECDHE curve for
key agreement and the Shamir configuration for long-term key recovery.

**Security considerations** (policy metadata, traffic analysis, outer-wrapper rationale, encrypted identifiers, wildcard property): [CIPHER_PROFILE_SECURITY.md](CIPHER_PROFILE_SECURITY.md).

## Built-in profiles

| Name | Curve | Layers | Shamir | Use case |
|------|-------|--------|--------|----------|
| `standard` | BP256r1 | ChaCha20-Poly1305 | none | General use |
| `conservative` | BP256r1 | ChaCha20-Poly1305 then Serpent-256 (matches CESS `suite_id` **0x0003**) | none | NSA-independent cascade |
| `conservative-shamir` | BP256r1 | Same cascade as `conservative` | 3/5 | Team deployments |
| `high-assurance` | BP512r1 | ChaCha20-Poly1305 then Serpent-256 (matches CESS `suite_id` **0x0012**) | 3/5 | Strong cascade + P512 |

## Defining a custom profile

```rust
let profile = CipherProfileBuilder::new("my-profile")?
    .description("Custom two-layer profile for field operations")
    .curve(SessionCurve::BrainpoolP384r1)
    .layer(CipherLayer::Twofish256)?
    .layer(CipherLayer::ChaCha20Poly1305)?
    .shamir(ShamirConfig::new(2, 3)?)
    .build()?;

registry.register(profile)?;
```

## Rules

- At least one cipher layer is required.
- No more than four layers.
- The same cipher cannot appear twice in one profile.
- All layers are applied in order during encryption,
  in reverse during decryption.
- Authentication is checked at every layer on decryption,
  outermost first. Failure stops decryption immediately.
- Every layer receives an independently derived key and nonce.
  No key material is shared between layers.
- Every session creation is logged with the full profile
  algorithm selection before any cryptographic operations begin.

## Keyed BLAKE3 between cascade layers (CESS)

In **CESS**, registry profiles may specify **keyed BLAKE3**-style integrity
**between** inner bulk cascade layers. That is separate from:

- each layer’s own AEAD authentication (AES-GCM tag, Poly1305, or EtM HMAC in
  this codebase), and
- the **Mode A** outer ChaCha20-Poly1305 envelope over `suite_id || inner_blob`.

Those checkpoints authenticate the intermediate AEAD output **after** each inner
stage before the next layer encrypts.

**Implementation (Galdralag):** For profiles whose name maps to a CESS
**`suite_id`** (`suite_id_for_profile_name` is `Some`) and the cascade has **two
or more** layers, `cipher-profile::cascade_encrypt` appends a **32-byte
HMAC-BLAKE3** (same construction as `cess::hmac_blake3`) over
**`cess::cess_blake3_integrity_info(suite_id)`** (UTF-8 suite label) **concatenated
with** the current inner AEAD ciphertext after each inner layer except the
outermost; `cascade_decrypt` verifies and strips those tags (constant-time
compare) in reverse order. HKDF-BLAKE3 subkeys for those MACs use UTF-8 `info`
from `cess::cess_blake3_integrity_gap_info` in
[`crates/cess/src/inner_info.rs`](../crates/cess/src/inner_info.rs). **Single-layer**
or **custom** (unmapped) profiles do **not** add inter-layer MACs.

## Combination counts (cipher stacks and BLAKE3 gap patterns)

Symmetric layers are chosen from **five** AEAD primitives (`CipherLayer`):
AES-256-GCM, ChaCha20-Poly1305, Twofish-256, Serpent-256, Camellia-256. Profiles require **at
least one** layer, **at most four** (limited by the profile validator, not the primitive count),
and **no cipher repeated** in the same profile; **order matters** (encrypt inner-first, decrypt
outer-first).

**Ordered distinct-cipher stacks** (permutation counts P(5, k) for k = 1…4):

| Cascade length (k) | Stacks P(5, k) |
|:------------------:|---------------:|
| 1 | 5 |
| 2 | 20 |
| 3 | 60 |
| 4 | 120 |
| **Total** | **205** |

If optional **CESS** keyed BLAKE3 is modelled as **independent** on/off at each
of the **k − 1** boundaries between layers, there are **2^(k−1)** patterns per
stack length **k** (one pattern when k = 1: no inter-layer gaps).

| Cascade length (k) | Stacks × BLAKE3 gap patterns | Product |
|:------------------:|-----------------------------:|--------:|
| 1 | 5 × 2^0 | **5** |
| 2 | 20 × 2^1 | **40** |
| 3 | 60 × 2^2 | **240** |
| 4 | 120 × 2^3 | **960** |
| **Total** | | **1245** |

- **205** — cipher orderings only (what `cipher-profile` enforces today).
- **1245** — same stacks multiplied by every on/off assignment for optional
  inter-layer BLAKE3 (CESS design space; not all combinations are
  registry-backed). **This tree** turns inter-layer MACs **on** for every gap
  whenever the profile maps to a **`suite_id`** and has **≥ 2** layers (not a
  per-gap runtime toggle).

Built-in profile names in this document use a **small** subset of the 205
cipher-only stacks.

## Forward secrecy

All profiles use authenticated ephemeral ECDH for key agreement
(Session 6). The long-term key is used only for authentication,
never for key agreement. Past sessions are unrecoverable from a
compromised long-term key.

## Shamir secret sharing

When a profile specifies Shamir K/N, the long-term signing key
is split into N shares at provisioning time. K shares are required
to reconstruct. Fewer than K shares reveal nothing about the key.

## Using profiles in the Galdra tool

Machine-readable output for commands that support it uses `--emit json`
(not `--output`, which is reserved for encrypt/decrypt output file paths).

### List profiles

```
galdra profile list
```

### Encrypt with a specific profile

```
galdra encrypt --group emergency_all \
               --input message.txt \
               --output message.pgp \
               --profile conservative
```

### Decrypt (profile read from ciphertext automatically)

```
galdra decrypt --input message.pgp --output message.txt --recipient alice@example.org
```

### Define a custom profile

```
galdra profile add field-ops \
  --description "Field operations profile" \
  --curve brainpool384 \
  --layer serpent256 \
  --layer chacha20poly1305 \
  --shamir-threshold 2 \
  --shamir-total 3
```

### Split a long-term key into Shamir shares

```
galdra shamir split --slot 0 --profile conservative-shamir \
                    --output-dir ./shares/
```

### Recover a long-term key from shares

```
galdra shamir recover --slot 0 \
  --share ./shares/share-1-of-5.galdra-share \
  --share ./shares/share-3-of-5.galdra-share \
  --share ./shares/share-5-of-5.galdra-share \
  --confirm
```

## Host tool security invariants (decision log)

- Private long-term key bytes never leave the token except as explicit Shamir shares or normal OpenPGP operations; the host does not log key material.
- PINs and share values are never passed on the command line or written to logs; Shamir share payloads are zeroised on drop in the host library.
- Profile metadata and audit lines may record profile names, curves, and layer labels only (no session keys, no PRK, no PIN).
- Until token-backed signing is integrated, encrypt uses a placeholder sender fingerprint in the inner profile AAD; production deployments should bind this to the real operator identity from the token.
