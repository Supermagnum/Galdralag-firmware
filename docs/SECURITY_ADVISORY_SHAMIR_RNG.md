# Security advisory: Shamir split used fixed-seed RNG (host)

**Status:** Fixed in commit `d8628017dfd07afd352e7384b53f9e06b80ce41a`. Treat all shares produced before that commit as compromised.

## Summary

Host-side Shamir secret splitting (`galdra shamir split`, `galdrad` `POST /shamir/split`, `galdra-gtk` split UI) seeded polynomial coefficients with a **hardcoded constant** (`FakeTrng::from_seed(0x5F4D_414D_4952)`). Because GF(256) addition is XOR and every coefficient above the constant term came from that predictable generator, **one share plus the public source code was enough to recover the full secret**. The configured K-of-N threshold provided no cryptographic protection on this path.

## Affected versions

| Introduced | Fixed |
|------------|-------|
| Commit `ec9faa90e1be5c5bc656245e786c87ccf564a971` (2026-06-18) | Commit `d8628017dfd07afd352e7384b53f9e06b80ce41a` |

Any release or build that includes the vulnerable `galdra-core-host/src/shamir_ops.rs` behaviour before the fix is affected. Firmware-only builds that never call host split are not a separate exposure vector for **new** splits, but keys already split on a vulnerable host remain compromised.

## Impact

- **Confidentiality:** Any Shamir shares exported through the host split path before the fix must be treated as **fully exposing** the underlying 32-byte signing key material.
- **Threshold property:** Theft of **one** share (not K) was sufficient for recovery, given public source.
- **Threat model:** [THREAT_MODEL.md](THREAT_MODEL.md) **T11** was **false** for all host-produced shares until the fix.

## Required action

If you used `galdra shamir split`, `galdrad` `/shamir/split`, or the GTK split UI before a fixed build:

1. **Assume the pre-split secret and all exported shares are exposed.**
2. **Generate or provision a new key** on the token (do not reuse the old secret).
3. **Re-split with a fixed version** and distribute new shares; destroy old share files and QR payloads.
4. **Rotate** any operational dependency on the old key (signatures, encryption recipients, audit references).

Recovery-only workflows (`shamir recover`) that consumed already-compromised shares do not undo the exposure.

## Fix

- Production split uses **`rand::rngs::OsRng`** (OS entropy), not `FakeTrng`.
- `shamir_split` requires [`ShamirSplitRng`](../crates/galdr-core/src/hal.rs): fixed-seed test doubles are gated behind `test-hal` only.
- `test-hal` removed from normal `galdra-core-host` dependencies; `xtask check-host` verifies release host binaries do not resolve `test-hal`.
- Regression tests: non-determinism, cross-secret XOR attack failure, and a vault unit test documenting the fixed-seed attack class.

## References

- [CHANGELOG.md](../CHANGELOG.md) — security entry (fix commit `d8628017dfd07afd352e7384b53f9e06b80ce41a`)
- [API_REFERENCE.md](API_REFERENCE.md) — host Shamir orchestration
- [THREAT_MODEL.md](THREAT_MODEL.md) — T11
