# bp512 (in-tree)

Brainpool P-512r1 (`brainpoolP512r1`) using the same `elliptic-curve` / `primeorder` stack as `bp384`.

Field and scalar arithmetic use the `primefield` **crypto-bigint Montgomery** backend (no fiat-crypto synthesis for this prime).

Domain parameters are from RFC 5639 Section 3.7 (512-bit curves).
