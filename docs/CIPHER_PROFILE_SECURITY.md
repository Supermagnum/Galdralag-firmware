# Security considerations: profile identifiers, traffic analysis, and outer wrappers

This note documents design rationale for **cipher profiles**, **session establishment**, and **metadata exposure** in the Galdralag stack. It complements [CIPHER_PROFILES.md](CIPHER_PROFILES.md) and [EPHEMERAL_SESSION.md](EPHEMERAL_SESSION.md). It is **not** a substitute for threat modelling or independent audit.

---

## Cleartext profile identifiers and information leakage

A **profile identifier** (human-readable profile name, registry ID, or other stable label for a cipher cascade and policy) is **policy metadata**: it tells a recipient *which* algorithm stack and parameters apply.

If that identifier is transmitted **in cleartext** on the wire or stored in **unauthenticated** metadata visible before decryption (for example in plaintext headers, unencrypted side channels, or logs), a passive observer learns facts that are not necessary to deliver confidentiality of the user payload:

- **Policy fingerprinting:** Which named policy or suite a party is using (for example “high-assurance” vs “standard”), which can correlate to role, organisational segment, or sensitivity class.
- **Deployment clustering:** Repeated identifiers tie multiple sessions or messages to the **same** policy choice, improving correlation even when content and long-term keys remain unknown.
- **Target selection:** Attackers may prioritise endpoints or messages that advertise stronger or more sensitive profiles.

**Risk:** confidentiality of *bits* may still hold, but **confidentiality of intent and policy** does not. Treat profile identifiers as sensitive unless the deployment explicitly accepts that leakage.

---

## Traffic analysis and the attack surface

Even when payloads are encrypted, **observable features** of traffic enlarge the surface for **traffic analysis** and **metadata attacks**:

- **Cleartext identifiers** (see above) directly expose policy labels.
- **Length and timing patterns** may differ across profiles if inner cascades, padding, or framing are not uniform.
- **Session shapes** (for example handshake sizes if the curve or framing varies per deployment) can fingerprint implementations or policy tiers.

A **passive adversary** who records traffic may build graphs of who talks to whom, when, and under which **visible** policy tags, without breaking AEAD. Designs that **minimise cleartext policy metadata** and **stabilise outer transcript shapes** reduce this surface.

---

## Rationale for a mandatory BrainpoolP384r1 outer wrapper

In deployments that fix a **single** authenticated ECDH-based **outer** layer for session establishment (ahead of any inner cipher cascade), standardising that layer on **BrainpoolP384r1** provides:

- **Security margin:** Roughly **192-bit** classical strength for ECDH and ECDSA over that curve (see [EPHEMERAL_SESSION.md](EPHEMERAL_SESSION.md) curve table).
- **Institutional alignment:** Brainpool curves are specified in **RFC 5639** and are common in **BSI-oriented** and EU procurement contexts; an outer wrapper at this level supports review and compliance narratives that require avoiding NIST-only baselines where policy demands it.
- **Separation of concerns:** The **outer** layer performs **authenticated key agreement and channel binding**; **inner** layers remain **cipher-agnostic** (AES-GCM, ChaCha20-Poly1305, Twofish, Serpent, Shamir configuration, and so on). Auditors can review one stable outer construction while profiles evolve inside the protected envelope.

**Note:** The implementation may support multiple Brainpool curves for ephemeral ECDH where the protocol allows negotiation; **“mandatory P384”** here means the **product or interoperability profile** chooses P384 as the **sole** outer curve, not that every build hard-codes only P384 in all code paths.

---

## Rationale for encrypted profile identifiers

Requiring that **profile identifiers** (and other policy labels) appear only **inside confidentiality- and integrity-protected data** after keys are established:

- **Closes passive metadata leakage:** Observers who have not completed the agreed handshake cannot read which profile or registry entry applies.
- **Binds policy to authentication:** Identifiers should be covered by the same **AEAD** or authenticated framing as the rest of the policy-sensitive material, so tampering is detected.
- **Aligns with layered design:** Outer session keys protect an **inner** structure that carries profile choice; the outer layer does not need to interpret profile semantics.

Deployments should avoid putting profile names in **cleartext signalling**, **unauthenticated extensions**, or **pre-key** plaintext unless there is an explicit, reviewed reason (for example public test vectors).

---

## Wildcard property preserved by this construction

A useful **interoperability property** is that the **outer** session and transport layer remains **profile-agnostic**: it establishes keys and carries an **opaque** inner payload without parsing inner profile-specific fields.

That preserves a **wildcard** character for inner profiles:

- **Any** conforming inner profile (any allowed symmetric cascade, Shamir settings, and profile-bound labels) can be nested behind the **same** outer wrapper without changing the outer protocol’s identity or requiring per-profile outer code paths.
- **Updates** to inner profiles (new layers, new registry entries) do not require changes to the outer handshake **format**, only to what recipients do **after** decryption.

So the construction separates **“how we agree keys and authenticate the channel”** (outer, fixed curve policy) from **“which symmetric policy and vault semantics apply”** (inner, cipher-agnostic profiles), which is the intended modularity of [CIPHER_PROFILES.md](CIPHER_PROFILES.md).

---

## Related documents

- [CIPHER_PROFILES.md](CIPHER_PROFILES.md) — profile definition, layers, Shamir, host tool usage  
- [EPHEMERAL_SESSION.md](EPHEMERAL_SESSION.md) — ephemeral ECDH session protocol and curves  
- [API_REFERENCE.md](API_REFERENCE.md) — wire layouts and annex for handshake and Shamir  
- [CESS](https://github.com/Supermagnum/CESS) — related standard for threshold sharing and cipher-agnostic envelopes (separate repository)
