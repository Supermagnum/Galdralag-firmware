# Post-quantum signatures (XMSS / LMS)

The workspace reserves a `pq-signatures` Cargo feature flag for future
stateful hash-based signatures (XMSS per RFC 8391, LMS/HSS per RFC 8554).

**Status:** No XMSS or LMS implementation is wired in this repository yet.
The feature flag is a no-op placeholder for forward compatibility.

**Policy:** When an implementation is added, it must ship with an independent
audit of the chosen Rust crates, documented test vectors, and clear warnings in
release notes until the audit is complete.

Do not enable `pq-signatures` in production firmware until this document is
updated with audit identifiers and test coverage summaries.
