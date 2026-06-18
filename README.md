# Galdr firmware (Galdralag)

## About the name

**Galdr** is the actual practice of spoken or sung magic: incantations used to bind, protect, or reveal. In the sagas it names the act of casting the spell itself, not only the words.
Sometimes also used to activate magic rune inscriptions, as on the Kragehul I (DR 196 U) lance shaft ([Kragehul I](https://en.wikipedia.org/wiki/Kragehul_I)), the [Lindholm amulet](https://en.wikipedia.org/wiki/Lindholm_amulet) (DR 261), the [Vadstena bracteate](https://en.wikipedia.org/wiki/Vadstena_bracteate), the [Seeland-II-C](https://en.wikipedia.org/wiki/Seeland-II-C) bracteate, and other comparable Elder Futhark finds.

**Galdralag** is the metrical form used for galdr: structured, precise, rule-bound verse in which the pattern is part of the force of the spell. The suffix *lag* is akin to "law" or "pattern."

**Runes** were literally secret, encoded knowledge; the shamanic usage was only known to those who understand.

---

**Galdr** is the firmware project name for **Baochip-1x** (Dabao evaluation board) devices running the **[Xous](https://github.com/betrusted-io/xous-core)** microkernel, built for `riscv32imac-unknown-none-elf`.


## Cryptographic validation and supply chain integrity

### Dependency vendoring and pinning

All cryptographic dependencies are vendored locally via `cargo vendor`
and committed to the repository. The `vendor/` directory is treated as
read-only; any modification will break the build. `Cargo.lock` is
committed and pinned — no network fetches occur during builds.

Audited workspace dependencies:
`aes-gcm`, `chacha20poly1305`, `ed25519-dalek`, `x25519-dalek`,
`hkdf`, `pbkdf2`, `hmac`, `sha2`, `sha3`, `blake2`, `blake3`,
`vsss-rs`, `zeroize`, `subtle`, `p256`, `p384`

These crates are members of the RustCrypto project or the dalek
family and carry independent security audits. No cryptographic
primitive is implemented from scratch anywhere in this codebase.

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
| Supply chain substitution     | Cargo vendor + Cargo.lock |
| Post-vendor tampering         | Read-only vendor dir + CI |

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

## Workspace layout

| Crate | Role |
|-------|------|
| `galdr-core` | HAL traits (`MonotonicCounter`, `HardwareTrng`, `ZeroiseController`, `VaultStorage`), shared errors, `test-hal` fakes |
| `vault` | RRAM vault contracts, HKDF **domain separation** labels (`KeyPurpose`), key material types (`zeroize`, no `Clone`/`Copy`) |
| `pin-policy` | PIN state machine; **counter increment before** `subtle::ConstantTimeEq` PIN check; threshold zeroisation |
| `usb-personality` | Mass-storage vs authenticated-unlock personalities; no secret leakage to uninformed hosts (scaffold) |
| `host-tools` | Host manifest hashing / update verification stubs (`std`) |
| `xtask` | Embedded `cargo build` / `check` / `test-host` orchestration |

Cryptographic **primitives** are not implemented in-tree: use the audited workspace dependencies (`aes-gcm`, `chacha20poly1305`, `ed25519-dalek`, `x25519-dalek`, `hkdf`, `pbkdf2`, `hmac`, `sha2`, `sha3`, `blake2`, `blake3`, `vsss-rs`, `zeroize`, `subtle`, `p256`, `p384`).

These rust crates are part of the RustCrypto project (except vsss-rs and the dalek family) — they all had independent security audits, are widely used in production security software, and are maintained by people with cryptographic expertise. Using them means a developer inherits that audit history rather than introducing new unreviewed cryptographic code.

## Commands

```text
rustup target add riscv32imac-unknown-none-elf
cargo test --workspace --exclude xtask
cargo run -p xtask -- check-fw
cargo run -p xtask -- build-fw
cargo run -p xtask -- test-host
```

Enable `galdr-core` feature **`test-hal`** only in tests or host tools (see crate `dev-dependencies`). Do not enable it in production firmware images.

## License

This project is licensed under the GNU General Public License v3.0; see [LICENSE](LICENSE).
