# Cipher Profiles

Galdralag is cipher-agnostic. A cipher profile specifies which symmetric
ciphers are applied, in which order, combined with the ECDHE curve for
key agreement and the Shamir configuration for long-term key recovery.

## Built-in profiles

| Name | Curve | Layers | Shamir | Use case |
|------|-------|--------|--------|----------|
| `standard` | BP256r1 | ChaCha20-Poly1305 | none | General use |
| `conservative` | BP256r1 | Serpent-256 to ChaCha20-Poly1305 | none | NSA-independent cascade |
| `conservative-shamir` | BP256r1 | Serpent-256 to ChaCha20-Poly1305 | 3/5 | Team deployments |
| `high-assurance` | BP512r1 | Serpent-256 to Twofish-256 to ChaCha20-Poly1305 | 3/5 | Maximum defence-in-depth |

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
