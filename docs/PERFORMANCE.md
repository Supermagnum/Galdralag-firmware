# Performance baselines

Host measurements for cryptographic primitives (software paths). Values are medians of 100 runs unless noted. Regenerate RSA numbers with:

`cargo test -p vault rsa_perf_baseline -- --ignored --nocapture`

## RSA 2048-bit (software, `rsa` crate)

Recorded on reference host (Linux x86_64, debug profile, 2025-03):

| Operation | Median time |
|-----------|-------------|
| OAEP decrypt | 81.0 ms |
| PSS sign (SHA-256) | 81.1 ms |
| PSS verify (SHA-256) | 5.6 ms |

These baselines are for comparison with the Baochip-1x PKE hardware path in a future integration session.
