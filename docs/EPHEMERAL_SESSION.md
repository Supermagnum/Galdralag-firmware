# Authenticated Ephemeral ECDH Session Protocol

## Security property

This protocol provides cryptographic forward secrecy. A compromised
long-term signing key allows an adversary to impersonate the key owner
in future sessions but does NOT allow decryption of past sessions.

Past session keys depended on ephemeral private keys that were generated
on the token's hardware TRNG, used once for ECDH, and immediately
zeroised. They cannot be reconstructed from the long-term key or from
any other stored material.

## Protocol summary

1. Initiator generates ephemeral key pair on-token (TRNG).
2. Initiator signs the ephemeral public key with their long-term signing key.
3. Initiator sends InitMessage.
4. Responder verifies the InitMessage signature against the initiator's
   long-term public key (from trust store).
5. Responder generates ephemeral key pair on-token (TRNG).
6. Responder signs their ephemeral public key PLUS the initiator's ephemeral
   public key with their long-term signing key. This binds the response to
   this specific session.
7. Responder performs ECDH(responder_ephemeral_private, initiator_ephemeral_public)
   to shared secret. Ephemeral private key is immediately zeroised.
8. Responder derives SessionKeys via HKDF-SHA256 from the shared secret.
9. Responder sends ResponseMessage.
10. Initiator verifies the ResponseMessage signature.
11. Initiator verifies the initiator_ephemeral_public_key in the response
    matches the key from step 1 (constant-time comparison).
12. Initiator performs ECDH(initiator_ephemeral_private, responder_ephemeral_public)
    to the same shared secret. Ephemeral private key is immediately zeroised.
13. Initiator derives the same SessionKeys.

Both sides now hold identical SessionKeys. No private key material remains.

## Relationship to GR-K-GDSS

The four GDSS subkeys from the GR-K-GDSS design document map directly to
fields in SessionKeys:

| GR-K-GDSS subkey | SessionKeys field |
|-----------------|-------------------|
| Key 1 (payload encryption) | payload_key_i2r / payload_key_r2i |
| Key 2 (GDSS masking) | gdss_mask_key |
| Key 3 (sync PN sequence) | gdss_sync_key |
| Key 4 (sync timing) | gdss_timing_key |

Use `session_keys.as_gdss_keys()` to extract them in GR-K-GDSS order.

## Curves supported

All three Brainpool curves are supported. Choose based on security requirement:

| Curve | Classical security | Signature size | Key size |
|-------|-------------------|----------------|----------|
| BrainpoolP256r1 | ~128 bit | ~72 bytes DER | 65 bytes |
| BrainpoolP384r1 | ~192 bit | ~104 bytes DER | 97 bytes |
| BrainpoolP512r1 | ~256 bit | ~139 bytes DER | 129 bytes |

## Hardware caveat

Ephemeral key generation and ECDH run on the Baochip-1x token. The
ephemeral private key never exists in host memory. It is generated in
SRAM on the token and zeroised there after ECDH. On-token zeroise
behaviour on physical silicon has not yet been hardware-verified.
See docs/HARDWARE_VERIFICATION.md.

## Related: profile metadata and outer layers

For discussion of cleartext profile identifiers, traffic analysis, rationale for a **BrainpoolP384r1** outer wrapper in fixed-curve deployments, **encrypted profile identifiers**, and the **wildcard** (profile-agnostic outer) property, see [CIPHER_PROFILE_SECURITY.md](CIPHER_PROFILE_SECURITY.md).

**CESS Mode A:** After ECDH, [`EphemeralSharedSecret::cess_k_outer_mode_a`](../crates/ephemeral-session/src/keys.rs) derives **`K_outer`** (HKDF-BLAKE3 with `cess-outer-envelope-v1`). Use **BrainpoolP384r1** ephemeral ECDH for that IKM when following CESS §6.1.1. Build `suite_id || inner_blob`, then encrypt with **`cess::seal_mode_a_outer`** (see [CESS_CONFORMANCE.md](CESS_CONFORMANCE.md)).
