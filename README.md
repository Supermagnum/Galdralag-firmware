# Galdr firmware (Galdralag)

## About the name

**Galdr** is the actual practice of spoken or sung magic: incantations used to bind, protect, or reveal. In the sagas it names the act of casting the spell itself, not only the words.
Sometimes also used to activate magic rune inscriptions, as on the Kragehul I (DR 196 U) lance shaft ([Kragehul I](https://en.wikipedia.org/wiki/Kragehul_I)), the [Lindholm amulet](https://en.wikipedia.org/wiki/Lindholm_amulet) (DR 261), the [Vadstena bracteate](https://en.wikipedia.org/wiki/Vadstena_bracteate), the [Seeland-II-C](https://en.wikipedia.org/wiki/Seeland-II-C) bracteate, and other comparable Elder Futhark finds.

**Galdralag** is the metrical form used for galdr: structured, precise, rule-bound verse in which the pattern is part of the force of the spell. The suffix *lag* is akin to "law" or "pattern."

**Runes** were literally secret, encoded knowledge; the usage was only known to those who understand.

---

**Galdr** is the firmware project name for **Baochip-1x** (Dabao evaluation board) devices running the **[Xous](https://github.com/betrusted-io/xous-core)** microkernel, built for `riscv32imac-unknown-none-elf`.

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
