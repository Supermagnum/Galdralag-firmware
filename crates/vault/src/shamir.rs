//! Shamir secret sharing over GF(256) using `vsss_rs::Gf256` field arithmetic.

use core::ops::{Add, Mul};

use ff::Field;
use galdr_core::hal::ShamirSplitRng;
use heapless::Vec;
use vsss_rs::Gf256;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Errors from Shamir split and recovery.
#[derive(Debug, Eq, PartialEq)]
pub enum ShamirError {
    /// Fewer than `k` shares were provided (or unique indices < k).
    InsufficientShares,
    /// A share value length does not match the others or is malformed.
    InvalidShare { index: u8 },
    /// Two shares use the same index.
    DuplicateIndex { index: u8 },
    /// Parameters violate documented bounds or consistency rules.
    InvalidParameters,
    /// TRNG could not supply random coefficients.
    TrngFailure,
    /// Secret is shorter than 16 bytes (minimum profile size).
    SecretTooShort,
    /// Secret is longer than 64 bytes (maximum profile size).
    SecretTooLong,
}

/// A Shamir share. Holds the share index and share value.
/// Zeroizes on drop. No Clone, no Copy.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ShamirShare {
    pub index: u8,
    value: Vec<u8, 64>,
}

/// Recovered secret bytes; zeroizes on drop. No Clone, no Copy.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ShamirSecret {
    buf: Vec<u8, 64>,
}

impl ShamirShare {
    /// Build a share from an index and raw value bytes (for example JSON vectors or wire decoding).
    pub fn try_from_index_value(index: u8, value: &[u8]) -> Result<Self, ShamirError> {
        if index == 0 {
            return Err(ShamirError::InvalidShare { index });
        }
        let l = value.len();
        if !(16..=64).contains(&l) {
            return Err(ShamirError::InvalidShare { index });
        }
        let mut buf = Vec::<u8, 64>::new();
        for b in value {
            buf.push(*b).map_err(|_| ShamirError::InvalidParameters)?;
        }
        Ok(Self { index, value: buf })
    }

    /// Share payload (same length as the original secret).
    pub fn value(&self) -> &[u8] {
        self.value.as_slice()
    }

    fn value_len(&self) -> usize {
        self.value.len()
    }
}

impl ShamirSecret {
    /// Borrow recovered secret bytes.
    pub fn as_slice(&self) -> &[u8] {
        self.buf.as_slice()
    }

    #[cfg(test)]
    pub(crate) fn as_mut_slice_for_test(&mut self) -> &mut [u8] {
        self.buf.as_mut_slice()
    }
}

/// Split `secret` into `n` shares with threshold `k`.
///
/// Requirements:
///   1 <= k <= n <= 255
///   secret.len() >= 16 (minimum 128-bit secret)
///   secret.len() <= 64 (maximum 512-bit secret for this profile)
///
/// Returns Err if parameters violate these constraints or if the TRNG fails.
/// The caller is responsible for distributing shares securely.
///
/// Requires [`ShamirSplitRng`]: production paths must not use fixed-seed or predictable RNGs.
pub fn shamir_split<T: ShamirSplitRng>(
    secret: &[u8],
    k: u8,
    n: u8,
    trng: &mut T,
) -> Result<Vec<ShamirShare, 255>, ShamirError> {
    validate_split_params(secret, k, n)?;
    let len = secret.len();
    let mut shares: Vec<ShamirShare, 255> = Vec::new();
    for idx in 1..=n {
        let mut value = Vec::<u8, 64>::new();
        for _ in 0..len {
            value.push(0).map_err(|_| ShamirError::InvalidParameters)?;
        }
        shares
            .push(ShamirShare { index: idx, value })
            .map_err(|_| ShamirError::InvalidParameters)?;
    }
    let kk = usize::from(k);
    for (byte_pos, &sb) in secret.iter().enumerate().take(len) {
        let mut coeffs: Vec<Gf256, 64> = Vec::new();
        let s = Gf256(sb);
        coeffs.push(s).map_err(|_| ShamirError::InvalidParameters)?;
        for _ in 1..kk {
            let mut b = [0u8];
            trng.try_fill_bytes(&mut b)
                .map_err(|_| ShamirError::TrngFailure)?;
            coeffs
                .push(Gf256(b[0]))
                .map_err(|_| ShamirError::InvalidParameters)?;
        }
        for share_idx in 1usize..=usize::from(n) {
            let x = gf_x_for_index(share_idx as u8)?;
            let y = eval_poly(&coeffs, x);
            let entry = shares
                .get_mut(share_idx - 1)
                .ok_or(ShamirError::InvalidParameters)?;
            entry.value[byte_pos] = y.0;
        }
    }
    Ok(shares)
}

/// Recover the secret from at least `k` shares.
///
/// `shares` may be provided in any order. Duplicate indices are rejected.
/// If fewer than `k` shares are provided, returns Err(InsufficientShares).
/// If any share is malformed, returns Err(InvalidShare { index }).
///
/// The returned secret zeroizes on drop.
///
/// The threshold `k` must match the value used when the shares were created; it cannot be inferred
/// from the share payloads alone.
pub fn shamir_recover(shares: &[ShamirShare], k: u8) -> Result<ShamirSecret, ShamirError> {
    if k == 0 {
        return Err(ShamirError::InvalidParameters);
    }
    if shares.len() < usize::from(k) {
        return Err(ShamirError::InsufficientShares);
    }
    let mut seen = [false; 256];
    for s in shares {
        if s.index == 0 {
            return Err(ShamirError::InvalidShare { index: s.index });
        }
        if seen[usize::from(s.index)] {
            return Err(ShamirError::DuplicateIndex { index: s.index });
        }
        seen[usize::from(s.index)] = true;
    }
    let len = if let Some(first) = shares.first() {
        let l = first.value_len();
        if !(16..=64).contains(&l) {
            return Err(ShamirError::InvalidShare { index: first.index });
        }
        l
    } else {
        return Err(ShamirError::InsufficientShares);
    };
    for s in shares {
        if s.value_len() != len {
            return Err(ShamirError::InvalidShare { index: s.index });
        }
    }
    let mut sorted: Vec<&ShamirShare, 255> = Vec::new();
    for s in shares {
        sorted.push(s).map_err(|_| ShamirError::InvalidParameters)?;
    }
    sort_shares_by_index(&mut sorted);
    let take = usize::from(k);
    let mut chosen: Vec<&ShamirShare, 255> = Vec::new();
    for sh in sorted.iter().take(take) {
        chosen
            .push(*sh)
            .map_err(|_| ShamirError::InvalidParameters)?;
    }
    if chosen.len() < take {
        return Err(ShamirError::InsufficientShares);
    }
    let mut out = Vec::<u8, 64>::new();
    for _ in 0..len {
        out.push(0).map_err(|_| ShamirError::InvalidParameters)?;
    }
    for byte_pos in 0..len {
        let mut xs: Vec<Gf256, 64> = Vec::new();
        let mut ys: Vec<Gf256, 64> = Vec::new();
        for sh in &chosen {
            let x = gf_x_for_index(sh.index)?;
            let y = Gf256(sh.value[byte_pos]);
            xs.push(x).map_err(|_| ShamirError::InvalidParameters)?;
            ys.push(y).map_err(|_| ShamirError::InvalidParameters)?;
        }
        let s = lagrange_at_zero(&xs, &ys).ok_or(ShamirError::InvalidShare { index: 0 })?;
        out[byte_pos] = s.0;
    }
    Ok(ShamirSecret { buf: out })
}

fn validate_split_params(secret: &[u8], k: u8, n: u8) -> Result<(), ShamirError> {
    if secret.len() < 16 {
        return Err(ShamirError::SecretTooShort);
    }
    if secret.len() > 64 {
        return Err(ShamirError::SecretTooLong);
    }
    if k == 0 || n == 0 {
        return Err(ShamirError::InvalidParameters);
    }
    if k > n {
        return Err(ShamirError::InvalidParameters);
    }
    if usize::from(n) > 255 {
        return Err(ShamirError::InvalidParameters);
    }
    Ok(())
}

fn gf_x_for_index(index: u8) -> Result<Gf256, ShamirError> {
    if index == 0 {
        return Err(ShamirError::InvalidShare { index: 0 });
    }
    Ok(Gf256(index))
}

fn eval_poly(coeffs: &Vec<Gf256, 64>, x: Gf256) -> Gf256 {
    let mut acc = Gf256(0);
    let mut xp = Gf256(1);
    for c in coeffs {
        let term = c.mul(&xp);
        acc = acc.add(&term);
        xp = xp.mul(&x);
    }
    acc
}

fn lagrange_at_zero(xs: &Vec<Gf256, 64>, ys: &Vec<Gf256, 64>) -> Option<Gf256> {
    if xs.len() != ys.len() || xs.is_empty() {
        return None;
    }
    let k = xs.len();
    let mut acc = Gf256(0);
    for i in 0..k {
        let xi = xs[i];
        let mut num = Gf256(1);
        let mut den = Gf256(1);
        for j in 0..k {
            if i == j {
                continue;
            }
            let xj = xs[j];
            num = num.mul(&xj);
            den = den.mul(&xi.add(&xj));
        }
        let inv = den.invert();
        let inv = inv.into_option()?;
        let coeff = num.mul(&inv);
        let term = ys[i].mul(&coeff);
        acc = acc.add(&term);
    }
    Some(acc)
}

fn sort_shares_by_index(shares: &mut Vec<&ShamirShare, 255>) {
    let n = shares.len();
    for i in 0..n {
        for j in 0..n.saturating_sub(1).saturating_sub(i) {
            let a = shares[j].index;
            let b = shares[j + 1].index;
            if a > b {
                shares.swap(j, j + 1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! Shamir unit tests.
    //!
    //! **Attack succeeds (test-only, documents the bug class):**
    //! `fixed_seed_xor_attack_succeeds_with_fake_trng_documents_vulnerability_class` uses
    //! `FakeTrng` with a shared fixed seed and asserts the XOR single-share trick **recovers**
    //! the secret. Requires `galdr-core/test-hal` in dev-dependencies only; not reachable from
    //! host CLI/API/GUI binaries (`xtask check-host` enforces this).
    //!
    //! **Attack fails (production path):** see `galdra-core-host::shamir_ops` tests
    //! (`production_split_cross_secret_xor_attack_fails`, OsRng).

    use super::*;
    use galdr_core::fake_hal::FakeTrng;

    #[test]
    fn basic_split_recover_k2_n3() -> Result<(), ShamirError> {
        let secret = [0x11u8; 32];
        let mut trng = FakeTrng::from_seed(0x51);
        let shares = shamir_split(&secret, 2, 3, &mut trng)?;
        let r1 = shamir_recover(&[clone_share(&shares[0])?, clone_share(&shares[1])?], 2)?;
        let r2 = shamir_recover(&[clone_share(&shares[0])?, clone_share(&shares[2])?], 2)?;
        let r3 = shamir_recover(&[clone_share(&shares[1])?, clone_share(&shares[2])?], 2)?;
        assert_eq!(r1.as_slice(), secret.as_slice());
        assert_eq!(r2.as_slice(), secret.as_slice());
        assert_eq!(r3.as_slice(), secret.as_slice());
        Ok(())
    }

    #[test]
    fn threshold_insufficient() -> Result<(), ShamirError> {
        let secret = [0x22u8; 32];
        let mut trng = FakeTrng::from_seed(0x52);
        let shares = shamir_split(&secret, 3, 5, &mut trng)?;
        let two = [clone_share(&shares[0])?, clone_share(&shares[1])?];
        let r = shamir_recover(&two, 3);
        assert!(matches!(r, Err(ShamirError::InsufficientShares)));
        Ok(())
    }

    #[test]
    fn threshold_exact_k3() -> Result<(), ShamirError> {
        let secret = [0x33u8; 32];
        let mut trng = FakeTrng::from_seed(0x53);
        let shares = shamir_split(&secret, 3, 5, &mut trng)?;
        let three = [
            clone_share(&shares[0])?,
            clone_share(&shares[2])?,
            clone_share(&shares[4])?,
        ];
        let r = shamir_recover(&three, 3)?;
        assert_eq!(r.as_slice(), secret.as_slice());
        Ok(())
    }

    #[test]
    fn all_five_shares_k2() -> Result<(), ShamirError> {
        let secret = [0x44u8; 24];
        let mut trng = FakeTrng::from_seed(0x54);
        let shares = shamir_split(&secret, 2, 5, &mut trng)?;
        let all: Vec<ShamirShare, 255> = clone_all(&shares)?;
        let r = shamir_recover(all.as_slice(), 2)?;
        assert_eq!(r.as_slice(), secret.as_slice());
        Ok(())
    }

    #[test]
    fn duplicate_index_rejected() -> Result<(), ShamirError> {
        let secret = [0x55u8; 16];
        let mut trng = FakeTrng::from_seed(0x55);
        let shares = shamir_split(&secret, 2, 3, &mut trng)?;
        let dup = [
            clone_share(&shares[0])?,
            ShamirShare {
                index: 1,
                value: clone_vec(&shares[1].value)?,
            },
        ];
        let r = shamir_recover(&dup, 2);
        assert!(matches!(r, Err(ShamirError::DuplicateIndex { index: 1 })));
        Ok(())
    }

    #[test]
    fn invalid_params() {
        let mut trng = FakeTrng::from_seed(1);
        let s = [0u8; 16];
        assert!(matches!(
            shamir_split(&s, 0, 3, &mut trng),
            Err(ShamirError::InvalidParameters)
        ));
        assert!(matches!(
            shamir_split(&s, 4, 3, &mut trng),
            Err(ShamirError::InvalidParameters)
        ));
        assert!(matches!(
            shamir_split(&[0u8; 8], 2, 3, &mut trng),
            Err(ShamirError::SecretTooShort)
        ));
        let long = [0u8; 65];
        assert!(matches!(
            shamir_split(&long, 2, 3, &mut trng),
            Err(ShamirError::SecretTooLong)
        ));
    }

    #[test]
    fn fixed_seed_xor_attack_succeeds_with_fake_trng_documents_vulnerability_class(
    ) -> Result<(), ShamirError> {
        let secret = [0xA5u8; 32];
        let dummy = [0x00u8; 32];
        let seed = 0x5F4D_414D_4952u64;
        let mut t1 = FakeTrng::from_seed(seed);
        let mut t2 = FakeTrng::from_seed(seed);
        let shares_s = shamir_split(&secret, 2, 3, &mut t1)?;
        let shares_d = shamir_split(&dummy, 2, 3, &mut t2)?;
        let mut recovered = [0u8; 32];
        for i in 0..32 {
            recovered[i] = shares_s[0].value()[i] ^ shares_d[0].value()[i] ^ dummy[i];
        }
        assert_eq!(
            recovered, secret,
            "FakeTrng fixed seed: XOR trick recovers secret (bug class; must not ship in production)"
        );
        Ok(())
    }

    #[test]
    fn share_independence_distinct_values() -> Result<(), ShamirError> {
        let secret = [0xABu8; 32];
        let mut t1 = FakeTrng::from_seed(0x61);
        let mut t2 = FakeTrng::from_seed(0x62);
        let a = shamir_split(&secret, 2, 3, &mut t1)?;
        let b = shamir_split(&secret, 2, 3, &mut t2)?;
        assert_ne!(a[0].value(), b[0].value());
        Ok(())
    }

    #[test]
    fn secret_zeroize_on_drop() -> Result<(), ShamirError> {
        let secret = [0xCDu8; 16];
        let mut trng = FakeTrng::from_seed(0x63);
        let shares = shamir_split(&secret, 2, 3, &mut trng)?;
        let pair = [clone_share(&shares[0])?, clone_share(&shares[1])?];
        let mut rec = shamir_recover(&pair, 2)?;
        rec.as_mut_slice_for_test().fill(0xEF);
        use zeroize::Zeroize;
        rec.zeroize();
        assert!(rec.as_slice().iter().all(|b| *b == 0));
        Ok(())
    }

    #[test]
    fn round_trip_min_max_len() -> Result<(), ShamirError> {
        let mut trng = FakeTrng::from_seed(0x70);
        let min = [0x01u8; 16];
        let max = [0x02u8; 64];
        let smin = shamir_split(&min, 2, 3, &mut trng)?;
        let mut trng = FakeTrng::from_seed(0x71);
        let smax = shamir_split(&max, 2, 3, &mut trng)?;
        assert_eq!(
            shamir_recover(&[clone_share(&smin[0])?, clone_share(&smin[1])?], 2)?.as_slice(),
            &min[..]
        );
        assert_eq!(
            shamir_recover(&[clone_share(&smax[0])?, clone_share(&smax[1])?], 2)?.as_slice(),
            &max[..]
        );
        Ok(())
    }

    #[test]
    fn degenerate_k1() -> Result<(), ShamirError> {
        let secret = [0x77u8; 20];
        let mut trng = FakeTrng::from_seed(0x80);
        let shares = shamir_split(&secret, 1, 4, &mut trng)?;
        let r = shamir_recover(&[clone_share(&shares[2])?], 1)?;
        assert_eq!(r.as_slice(), secret.as_slice());
        Ok(())
    }

    #[test]
    fn k_equals_n() -> Result<(), ShamirError> {
        let secret = [0x88u8; 28];
        let mut trng = FakeTrng::from_seed(0x81);
        let shares = shamir_split(&secret, 4, 4, &mut trng)?;
        let all = clone_all(&shares)?;
        let r = shamir_recover(all.as_slice(), 4)?;
        assert_eq!(r.as_slice(), secret.as_slice());
        Ok(())
    }

    fn clone_vec(v: &Vec<u8, 64>) -> Result<Vec<u8, 64>, ShamirError> {
        let mut out = Vec::new();
        for b in v {
            out.push(*b).map_err(|_| ShamirError::InvalidParameters)?;
        }
        Ok(out)
    }

    fn clone_share(s: &ShamirShare) -> Result<ShamirShare, ShamirError> {
        Ok(ShamirShare {
            index: s.index,
            value: clone_vec(&s.value)?,
        })
    }

    fn clone_all(shares: &[ShamirShare]) -> Result<Vec<ShamirShare, 255>, ShamirError> {
        let mut out = Vec::new();
        for s in shares {
            out.push(clone_share(s)?)
                .map_err(|_| ShamirError::InvalidParameters)?;
        }
        Ok(out)
    }
}
