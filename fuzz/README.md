# cargo-fuzz (libFuzzer)

This directory holds **cargo-fuzz** targets for the workspace. Run from the repo root:

```bash
cargo install cargo-fuzz   # once
rustup toolchain install nightly

# Via xtask (default 60 s per target)
cargo run -p xtask -- fuzz chacha_roundtrip 120

# Or from this directory
cd fuzz
rustup run nightly cargo fuzz run chacha_roundtrip -- -max_total_time=60
```

See `Cargo.toml` `[[bin]]` entries for the exact target names. `xtask` aliases are in `xtask/src/main.rs` (`fuzz_bin_name`).

**Dependabot:** GitHub Dependabot must not scan this nested workspace (`.github/dependabot.yml`). It path-depends on crates that use `foo.workspace = true`, so a `/fuzz` update would rewrite root workspace pins. After bumping shared crypto crates at the repo root, regenerate this lockfile in the same PR (`cd fuzz && cargo update …`).

---

## Corpus material (project-specific)

Good seed inputs get libFuzzer to interesting parser and crypto edge cases much faster than random bytes. Prefer **mutations of known-valid** structures over purely random data.

### Handshake message parsers (`fuzz_ephemeral_handshake`)

Planned / related: `fuzz_host_protocol` (USB vendor command parser) is described in `docs/Psram.md` and `docs/dev-ref.md` when that target is wired.

For **`fuzz_ephemeral_handshake`**:

- Valid serialised `InitMessage` and `ResponseMessage` bytes from the test suite (the fuzzer mutates known-valid inputs rather than starting from noise).
- Truncated versions of valid messages (drop the last 1, 2, 4, or 8 bytes).
- Messages with each field individually zeroed.
- Messages with maximum-length fields.

### AEAD / cipher round-trips

| Fuzz binary (this repo) | Notes |
|-------------------------|--------|
| `chacha_roundtrip` | ChaCha20-Poly1305 path |
| `twofish_aead` | Twofish EtM |
| `serpent_aead` | Serpent EtM |

Corpus ideas (shared pattern):

- Valid ciphertexts from the test suite (correct tag, wrong tag, truncated tag).
- Empty plaintext and single-byte plaintext ciphertexts.
- Maximum-size ciphertexts (within harness limits).
- Ciphertexts with tag bytes set to all zeros and all ones.

### Cascade / profile (`fuzz_cipher_profile`)

Covers `CipherProfile` parsing and `cascade_decrypt` (see target source).

- Valid ciphertexts as above, plus profile-aware inputs.
- All **built-in** profiles serialised to bytes via `CipherProfile::to_bytes()`.
- Each serialised profile with **one byte flipped** at every offset (or a sampled subset for large blobs).
- Profiles with the **layer count** byte set to 0, 1, 4, and 255 (invalid but structured).

### DER / key import (`rsa_der_import`)

- Existing test certificates and PKCS material from in-tree vault tests (for example under `crates/vault/tests/`).
- PKCS#8 and SPKI structures with each length field off by one.
- ASN.1 with truncated inner structures.
- The **rsa** crate’s own test vectors (good seed material for import parsers).

**ASN.1 / DER:** [Wycheproof](https://github.com/google/wycheproof) JSON in `crates/vault/tests/data/wycheproof/` (RSA-OAEP, RSA-PSS, PKCS#1 verify, and related groups) already contains many **carefully crafted malformed** inputs. Those vectors are excellent **additional corpus seeds** for DER and ASN.1 parsing paths—beyond what the regular test suite generates—because they encode realistic key and signature blobs with edge-case structure.

### OpenPGP APDU dispatch (`openpgp_dispatch`)

Exercises `CommandApdu::parse`, `handle_apdu` on a `OpenPgpVaultBackend` with default DOs (Brainpool ECDSA/ECDH), `algorithm_attributes` TLV parsing, `parse_ecdh_peer_public_key`, and dalek Ed25519/X25519 key material constructors.

- **xtask aliases:** `openpgp`, `openpgp-dispatch`, `openpgp_dispatch` (see `fuzz_bin_name`).

Suggested corpus seeds:

- Valid short APDUs: SELECT OpenPGP AID (`00 A4 04 00 …`), VERIFY, GET DATA `00 CA 00 4F`, GET CHALLENGE `00 84 00 00 20` (32-byte Le), MSE `00 22 41 B8 03 83 01 03` (set DEC ref to Curve25519).
- Truncated and extended-length APDU variants.
- Raw bytes from `openpgp_command_flow` integration tests.

### Biometric SignedMatchResult (`biometric_dispatch`)

Exercises CBOR parsing and `galdrad_validate_match_result` on arbitrary bytes: must not panic, must reject invalid CBOR and bogus signatures, and must reject `liveness = false`.

- **xtask aliases:** `biometric`, `biometric-dispatch`, `biometric_dispatch` (see `fuzz_bin_name`).

Suggested corpus seeds:

- Valid `SignedMatchResult` bytes from `biometric-api` unit tests.
- Truncated valid payloads at each length prefix boundary.
- Valid CBOR map with fields permuted or extra unknown keys (should still fail verify or policy).

### Shamir (`shamir_split_recover`)

- Valid shares from a **k=2, n=3** split of a known secret.
- Shares with corrupted index bytes.
- Shares with corrupted value bytes.
- Duplicate-index pairs.

### PSRAM block device (`fuzz_psram_block_rw`)

This target is documented in `docs/Psram.md` / `docs/dev-ref.md` for when it is added to `fuzz/Cargo.toml`.

Suggested corpus:

- Sequential LBA sequences (0, 1, 2, …).
- Maximum LBA and maximum length.
- LBA + length combinations that would overflow the fake device geometry.
- Zero-length read/write.

### Profile parser (`fuzz_cipher_profile`)

(See **Cascade / profile** above.)

- All built-in profiles from `CipherProfile::to_bytes()`.
- Per-byte bit flips across the serialised form.
- Layer count byte set to 0, 1, 4, 255.

---

## Checked-in seed corpus

**`fuzz/seed_corpus/<target_name>/`** holds version-controlled starter inputs (one file per seed). Regenerate after changing the generator:

```bash
python3 fuzz/scripts/gen_seed_corpus.py
```

**`fuzz/corpus/`** is gitignored: libFuzzer writes discovered inputs and crash artifacts there during local runs.

**Default corpus path:** If you do **not** pass a corpus directory, `cargo fuzz run <target>` uses **`corpus/<target>/`** under this `fuzz/` directory only. It does **not** automatically read `seed_corpus/<target>/`. Checked-in seeds are skipped unless you pass them explicitly or copy them into `corpus/`.

For a quick run using **only** the checked-in seeds:

```bash
cd fuzz
rustup run nightly cargo fuzz run chacha_roundtrip seed_corpus/chacha_roundtrip/
```

To **merge** a writable corpus with checked-in seeds, pass two corpus paths (both must exist). From `fuzz/`:

```bash
mkdir -p corpus/chacha_roundtrip
rustup run nightly cargo fuzz run chacha_roundtrip corpus/chacha_roundtrip seed_corpus/chacha_roundtrip -- -max_total_time=180
```

Or copy seeds once: `cp seed_corpus/chacha_roundtrip/* corpus/chacha_roundtrip/` then run with a single corpus path.

**Coverage not increasing:** On a small harness like `chacha_roundtrip`, edge coverage often **plateaus** once the corpus is saturated. Flat `cov:` for a long run is normal; watch for crashes and stability instead of expecting endless coverage growth.

libFuzzer may **append new corpus files** to whatever directory you pass as the corpus. For long sessions, prefer copying seeds into `corpus/<target>/` so you do not pollute `seed_corpus/`. `cargo run -p xtask -- fuzz …` does not pass a seed path; use the `cargo fuzz run` form above when you want these seeds loaded.

---

## Corpus health (LibFuzzer output)

**Healthy:** Coverage rises quickly at first, then **plateaus**; **`ft` (features)** can keep growing while **`cov` (edges)** is flat (finer-grained signal on the same paths). Corpus size often settles in a **reasonable** range (tens to a few hundred items for a tight harness). **`exec/s`** stays in the same ballpark across pulses; no `ALARM: working on the last unit for …` (that usually means a pathological slow input).

**Unhealthy:** `cov` never moves from the first pulse (often **invalid or identical seeds**). `cov` jumps once and never changes with **no** `ft` growth (seeds too similar). Corpus explodes to **thousands** of files quickly (merge with `cmin`, review harness). **`exec/s` very low** from the start on a small target (expensive work per iteration or accidental I/O).

**After fuzzing for a while** (from `fuzz/`):

```bash
rustup run nightly cargo fuzz cmin chacha_roundtrip corpus/chacha_roundtrip
rustup run nightly cargo fuzz coverage chacha_roundtrip corpus/chacha_roundtrip
```

`cmin` deduplicates the corpus in place. `coverage` writes HTML under `coverage/<target>/` and needs **LLVM coverage tools** bundled with Rust: `rustup component add llvm-tools-preview --toolchain nightly` (see [rustc instrument-coverage](https://doc.rust-lang.org/rustc/instrument-coverage.html#installing-llvm-coverage-tools)). If `llvm-profdata` is missing, the coverage step fails after building.

**Why `coverage` finishes in seconds:** It replays **each corpus file once** (plus LLVM merge), not millions of fuzz iterations. A few dozen inputs is tiny work compared to a long `cargo fuzz run` session; finishing quickly is normal.

Refresh corpora after fixing crashes (minimize with `cargo fuzz tmin` as needed).
