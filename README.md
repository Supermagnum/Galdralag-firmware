# Galdr firmware (Galdralag)

> **Status:** Implementation in progress. No production-ready release exists.
> Cryptographic primitives are drawn exclusively from audited workspace
> dependencies. Post-quantum algorithms are feature-gated and marked
> **PENDING INDEPENDENT AUDIT** — do not use in production until that
> status changes. See [Post-quantum status](#post-quantum-status) below.

## About the name

**Galdr** is the actual practice of spoken or norse sung magic: incantations used to bind, protect, or reveal. In the sagas it names the act of casting the spell itself, not only the words.
Sometimes also used to activate magic rune inscriptions, as on the Kragehul I (DR 196 U) lance shaft ([Kragehul I](https://en.wikipedia.org/wiki/Kragehul_I)), the [Lindholm amulet](https://en.wikipedia.org/wiki/Lindholm_amulet) (DR 261), the [Vadstena bracteate](https://en.wikipedia.org/wiki/Vadstena_bracteate), the [Seeland-II-C](https://en.wikipedia.org/wiki/Seeland-II-C) bracteate, and other comparable Elder Futhark finds.

**Galdralag** is the metrical form used for galdr: structured, precise, rule-bound verse in which the pattern is part of the force of the spell. The suffix *lag* is akin to "law" or "pattern."

**Runes** were literally secret, encoded knowledge; the shamanic usage was only known to those who understand.

---

**Galdr** is the firmware project name for **Baochip-1x** (Dabao evaluation board) devices running the **[Xous](https://github.com/betrusted-io/xous-core)** microkernel, built for `riscv32imac-unknown-none-elf`.


## Cryptographic validation and supply chain integrity

### Dependency vendoring and pinning

`Cargo.lock` is committed so dependency versions resolve reproducibly.
The `subtle` crate is **not** taken from crates.io as-is: the workspace
uses `[patch.crates-io]` in the root `Cargo.toml` to point `subtle` at
the in-tree copy under `crates/subtle-vendored` (treat that tree like
vendored code: change only with review and lockfile updates).

Other dependencies are fetched from **crates.io** at the versions pinned
in `Cargo.lock` (normal Cargo behavior). This repository does **not**
ship a full `cargo vendor` tree under `vendor/`.

Security audited workspace dependencies:
`aes-gcm`, `chacha20poly1305`, `ed25519-dalek`, `x25519-dalek`,
`hkdf`, `pbkdf2`, `hmac`, `sha2`, `sha3`, `blake2`, `blake3`,
`vsss-rs`, `zeroize`, `subtle`, `p256`, `p384`

These rust crates are part of the RustCrypto project (except vsss-rs and the dalek family) — they all had independent security audits, are widely used in production security software, and are maintained by people with cryptographic expertise. Using them means a developer inherits that audit history rather than introducing new unreviewed cryptographic code.

### Test suites

#### Wycheproof (Google)
Edge-case and known-bad test vectors covering all algorithms in use:
AES-GCM, ChaCha20-Poly1305, ECDH, ECDSA, Ed25519, HKDF, X25519.
Catches malformed inputs, weak nonces, invalid curve points, signature
malleability, and off-by-one errors that pass normal unit tests.

#### BSI TR-03111 (German Federal Office for Information Security)
German national standard test vectors for elliptic curve cryptography,
with specific coverage of Brainpool curves (P256r1, P384r1, P512r1).
This is the primary test suite for Brainpool — Wycheproof coverage
for these curves is thinner. Required because Brainpool is a core
part of the extended on-device profile and the NSA-independent ECC
option.

#### Fuzzing (cargo-fuzz / libFuzzer)
Malformed, random, and mutated inputs directed at all parsers and
protocol handlers — particularly USB personality switching and any
host-facing protocol parser, as these handle untrusted input directly.
Rust's ownership model prevents memory corruption but panics and logic
errors remain in scope.

#### dudect (timing side-channel analysis)
Measures whether execution time varies based on secret input values.
Validates that `subtle`-based constant-time comparisons have not been
optimised back into branches by the compiler. Applied to all PIN
comparisons, key material handling, and any code path where secret
data influences control flow.

### Coverage summary

| Threat                        | Addressed by              |
|-------------------------------|---------------------------|
| Known bad crypto inputs       | Wycheproof                |
| Brainpool-specific edge cases | BSI TR-03111              |
| Malformed / unexpected inputs | Fuzzing                   |
| Timing leaks on secrets       | dudect                    |
| Supply chain substitution     | Cargo.lock + pinned crates.io versions |
| Tampering with resolved deps  | Lockfile + in-tree `subtle` patch + CI |

### Known limitations

- **Compiler-introduced side channels** — dudect catches many but not
  all. Generated assembly for sensitive paths should be reviewed,
  particularly at higher optimisation levels.
- **Hardware side-channels** — power analysis and EM emissions on
  physical Baochip-1x silicon are outside the scope of software
  testing and require lab equipment and separate evaluation.
- **Protocol logic errors** — none of the above suites catch a
  correctly implemented but wrongly designed protocol. Human
  architectural review is required before any production deployment.
Hardware goals, boot model, crypto profiles, and host-visible USB behavior are aligned with the upstream **[Baochip-1x firmware design README](https://raw.githubusercontent.com/Supermagnum/Baochip-1x-firmware/refs/heads/main/README.md)** (requirement tables, ComboHash/PKE usage, Shamir, reproducible updates, test-vector sources).

Architecture notes for this repository: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Implemented cryptographic capabilities

| Algorithm | Standard | Provided by | Tests |
|-----------|----------|-------------|-------|
| BrainpoolP256r1 ECDH/ECDSA | RFC 5639, BSI TR-03111 | in-tree `vault/src/brainpool.rs`, `vault/src/ecdsa_brainpool.rs` | Unit · RFC 5639 (domain) in unit tests · Wycheproof **MISSING** (no vector set in repo) · dudect **MISSING** |
| BrainpoolP384r1 ECDH/ECDSA | RFC 5639, BSI TR-03111 | in-tree `vault/src/brainpool384.rs` | Unit · Wycheproof · BSI cross-check JSON · RFC vectors via integration tests · dudect **MISSING** (stub only) |
| BrainpoolP512r1 ECDH/ECDSA | RFC 5639, BSI TR-03111 | in-tree `vault/src/brainpool512.rs` | Unit · Wycheproof · BSI cross-check JSON · RFC vectors via integration tests · dudect **MISSING** (stub only) |
| ChaCha20-Poly1305 AEAD | RFC 8439 | `chacha20poly1305` workspace dep | Unit · Wycheproof · RFC 8439 (unit + integration) · dudect **MISSING** |
| Shamir Secret Sharing (K-of-N) | Shamir 1979, vsss-rs | `vsss-rs` workspace dep | Unit · KAT vectors · dudect **MISSING** |
| Twofish-256 AEAD | Schneier et al. 1998 | **not present in this workspace** | **MISSING** |
| Serpent-256 AEAD | Anderson/Biham/Knudsen 1998 | `serpent` workspace dep | Unit · Spec vectors in `vault/tests/serpent_vectors.json` · dudect **MISSING** |
| RSA-2048/3072/4096 OAEP, PSS | PKCS#1 v2.2, RFC 8017 | `rsa` workspace dep | Unit · Wycheproof · dudect **MISSING** |
| AES-256-GCM | FIPS 197, NIST SP 800-38D | `aes-gcm` workspace dep (galdr-core dev-tests) | **MISSING** in vault crate automated vectors |
| HKDF (SHA-256/SHA-512) | RFC 5869 | `hkdf` workspace dep | Unit (galdr-core + vault) · Wycheproof in vault where applicable · RFC 5869 integration vectors · dudect **MISSING** |
| HMAC (SHA-256/SHA-512) | RFC 2104 | `hmac` workspace dep | Unit (galdr-core) · Wycheproof in vault where applicable · RFC 2104 integration vectors · dudect **MISSING** |
| PBKDF2 | RFC 8018 | `pbkdf2` workspace dep | Unit (galdr-core) · RFC 8018 integration vectors · dudect **MISSING** |
| Ed25519 sign/verify | RFC 8032 | `ed25519-dalek` workspace dep | Unit (galdr-core) · Wycheproof **MISSING** in vault · RFC 8032 integration vectors · dudect **MISSING** |
| X25519 ECDH | RFC 7748 | `x25519-dalek` workspace dep | Unit (galdr-core) · Wycheproof **MISSING** in vault · RFC 7748 integration vectors · dudect **MISSING** |
| SHA-2 (224/256/384/512) | FIPS 180-4 | `sha2` workspace dep | Unit (galdr-core + NIST CAVP integration subset) · dudect **MISSING** |
| SHA-3 family | FIPS 202 | `sha3` workspace dep | Unit (galdr-core + NIST CAVP integration subset) · dudect **MISSING** |
| BLAKE2b/BLAKE2s | RFC 7693 | `blake2` workspace dep | Unit (galdr-core + RFC integration) · dudect **MISSING** |
| BLAKE3 | BLAKE3 spec | `blake3` workspace dep | Unit (galdr-core + KAT integration) · dudect **MISSING** |
| PIN policy (stateful) | — | in-tree `pin-policy` | Unit · Lifecycle integration tests · dudect **MISSING** |
| PSRAM block device (optional) | — | **not present in this workspace** | **MISSING** |

## Test results

Full test vector coverage, known-answer test results, Wycheproof run
summaries, RFC vector pass/fail tables, BSI vector results, and dudect
t-statistic records are maintained in:

**[docs/TEST_RESULTS.md](docs/TEST_RESULTS.md)**

Run the full suite at any time:

```
cargo run -p xtask -- test-all
```

To run the same pipeline **without** cargo-fuzz (shorter CI or local runs), use:

```
cargo run -p xtask -- test-all --no-fuzz
```

## Post-quantum status

The following post-quantum algorithms are **NOT YET IMPLEMENTED**.
They will be implemented only after an independently audited Rust crate
becomes available for each scheme. The algorithms themselves are standardised
by NIST; the gap is in the Rust implementation audit status.

| Algorithm | Standard | Awaiting |
|-----------|----------|---------|
| ML-KEM | FIPS 203 | Independent audit of a suitable `no_std` Rust crate |
| ML-DSA | FIPS 204 | Independent audit of a suitable `no_std` Rust crate |
| SLH-DSA | FIPS 205 | Independent audit of a suitable `no_std` Rust crate |
| FN-DSA (FALCON) | FIPS 206 (draft) | Standard finalisation + independent audit |
| HQC | Draft ~2027 | Standard finalisation + independent audit |

**XMSS and LMS** (SP 800-208) are implemented behind the `pq-signatures`
feature flag but carry unaudited warnings. See `docs/PQ_SIGNATURES.md` for
the full audit status and usage policy.

**BIKE and NTRU** are not implemented and will not be implemented.
BIKE was eliminated from NIST standardisation in March 2025 in favour of HQC.
NTRU encryption was eliminated in July 2022. Neither has a path to a NIST
standard.

When an independent audit of a production-quality `no_std` Rust crate for
any of the above schemes becomes available, open a tracking issue referencing
this section to begin the implementation session.

## Zeroisation — hardware caveat

The `ZeroiseController` HAL trait and its production implementation wipe
key material from RRAM and SRAM using TRNG-sourced multi-pass overwrite,
mirroring the boot0 zeroisation path. **This path has been tested in
simulation using the `test-hal` fake only. It has not been verified on
physical Baochip-1x hardware.** Zeroisation correctness on real silicon
requires:

1. JTAG-assisted memory inspection after a triggered zeroise event to
   confirm all sensitive regions read as zeroed or overwritten.
2. Power-cycle resilience testing: interrupted zeroise must resume on
   next boot within boot0.
3. Side-channel confirmation that zeroised regions do not retain data
   remnants readable by physical attack.

Until hardware verification is complete, the zeroisation implementation
should be considered **software-correct but hardware-unverified**. Track
hardware verification status in `docs/HARDWARE_VERIFICATION.md`.

## PIN policy

- **Minimum PIN length: 5 alphanumeric characters.** This is enforced at
  the parser boundary before `pin-policy` is called. Shorter inputs are
  rejected without incrementing the attempt counter.
- **PIN attempt threshold (default: 3).** The hardware-backed counter allows
  **three** failed attempts before lockout and zeroisation, matching common
  smartcard and hardware-token practice (e.g. Nitrokey, YubiKey PIV, ISO 7816
  style limits). The ceiling is **configurable at provisioning only**, in the
  range **3–10**, and is stored in the vault policy region **next to the PIN
  verifier hash** (see `vault::VaultPinPolicyRecord`). This gives integrators
  room for operational error rates without weakening the default for typical
  deployments.
- The attempt counter is incremented and flushed to RRAM **before** the
  constant-time comparison. This ordering is an unconditional security
  invariant.
- At the attempt threshold, full zeroisation is triggered.
- The hardware one-way counter in the always-on domain provides a secondary
  tamper-evident record of all attempt events.
- Challenge/response authentication for the USB informed-host path uses
  `HMAC-SHA256(HostChallengeKey, nonce || passphrase)`. The raw passphrase
  is never transmitted over USB.

## Workspace layout

| Crate | Role |
|-------|------|
| `galdr-core` | HAL traits (`MonotonicCounter`, `HardwareTrng`, `ZeroiseController`, `VaultStorage`), shared errors, `test-hal` fakes |
| `bp512` | Brainpool P-512r1 curve support (in-tree; used by `vault` for P512 ECDH/ECDSA) |
| `vault` | RRAM vault contracts, HKDF **domain separation** labels (`KeyPurpose`), key material types (`zeroize`, no `Clone`/`Copy`) |
| `pin-policy` | PIN state machine; **counter increment before** `subtle::ConstantTimeEq` PIN check; threshold zeroisation |
| `usb-personality` | Mass-storage vs authenticated-unlock personalities; no secret leakage to uninformed hosts (scaffold) |
| `host-tools` | Host manifest hashing / update verification stubs (`std`) |
| `security-tests` | Dudect / timing-analysis stubs and future host security hooks |
| `xtask` | Embedded `cargo build` / `check` / `test-host` / `test-all` / crypto and fuzz helpers |

## Commands

```text
rustup target add riscv32imac-unknown-none-elf
cargo test --workspace --exclude xtask
cargo run -p xtask -- check-fw
cargo run -p xtask -- build-fw
cargo run -p xtask -- test-host
cargo run -p xtask -- test-crypto
cargo run -p xtask -- wycheproof
cargo run -p xtask -- test-all
```

Additional **xtask** entry points (timing, RSA bench, libFuzzer wrappers): run
`cargo run -p xtask --` with no subcommand to print the full usage line
(`timing-test`, `bench-rsa`, `fuzz`, `fuzz-chacha`, `fuzz-shamir`, etc.).

## Flashing firmware

This repository builds **Rust crates** for `riscv32imac-unknown-none-elf` (see `xtask`). A complete **bootable Xous image** is assembled by linking these libraries with the microkernel and board support code; the authoritative boot, update, and integrity story (including **Verified flashing and updates**) is in the upstream **[Baochip-1x firmware design README](https://raw.githubusercontent.com/Supermagnum/Baochip-1x-firmware/refs/heads/main/README.md)**. Use that document and the **board vendor SDK** for production procedures.

**Compile firmware components for the embedded target:**

```text
rustup target add riscv32imac-unknown-none-elf
cargo run -p xtask -- build-fw
```

Release-optimized libraries (when linking a final image):

```text
cargo build --release -p galdr-core -p vault -p pin-policy -p usb-personality --target riscv32imac-unknown-none-elf
```

Artifacts appear under `target/riscv32imac-unknown-none-elf/<debug|release>/` (or your configured `CARGO_TARGET_DIR`).

**Programming the device (outline):**

1. Connect the debugger or USB cable as described in **Dabao / Baochip-1x board documentation**.
2. On **engineering samples** that still expose **JTAG**, tools such as **OpenOCD** or **probe-rs** (`probe-rs download`, `cargo-embed`, etc.) can program flash according to the chip memory map; **production silicon may have JTAG fused out**—follow vendor tooling only.
3. **Do not flash untrusted images.** Verify signatures and manifest hashes on update bundles before programming; optional read-back checks after program reduce risk of partial or glitched writes (see upstream README).
4. **boot0** is fixed in silicon; field updates target later boot stages—do not assume the whole flash image is replaceable from user tooling.

When this workspace publishes a single linked `.elf` or a standard image name for CI, this section should be updated with exact commands and base addresses.

Developer-focused crypto, fuzzing, and vector notes: [docs/GALDRALAG_DEV_REFERENCE.md](docs/GALDRALAG_DEV_REFERENCE.md).

Enable `galdr-core` feature **`test-hal`** only in tests or host tools (see crate `dev-dependencies`). Do not enable it in production firmware images.

## AI disclaimer

Portions of this repository (including documentation, tests, and tooling) may have been drafted or
refined with assistance from automated coding or language models. **Such output is not a
substitute for human review, security analysis, or independent cryptographic audit.** Maintainers
and contributors remain responsible for correctness, safety, and compliance with project
requirements. Treat AI-assisted changes like any other patch: review, test, and verify before
relying on them in production.

## License

This project is licensed under the GNU General Public License v3.0; see [LICENSE](LICENSE).
