//! Trust store for long-term peer keys.

use crate::curve_select::SessionCurve;
use crate::error::EphemeralSessionError;
use heapless::Vec;
use sha2::{Digest, Sha256};
use subtle::{Choice, ConstantTimeEq};

/// Maximum uncompressed SEC1 public key (Brainpool P-512r1).
pub const MAX_SEC1: usize = 129;

/// A long-term public key certificate used to verify handshake signatures.
/// Contains the Brainpool verifying key and its fingerprint (raw SHA-256 of SEC1 bytes).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LongTermCert {
    /// Raw SHA-256 digest of the verifying key SEC1 uncompressed bytes (32 bytes).
    pub fingerprint: Vec<u8, 32>,
    pub curve: SessionCurve,
    /// Uncompressed SEC1 public key bytes.
    pub verifying_key: Vec<u8, MAX_SEC1>,
}

impl LongTermCert {
    /// Compute the fingerprint of a public key (SHA-256 of the SEC1 bytes).
    pub fn fingerprint_of(public_key_sec1: &[u8]) -> Vec<u8, 32> {
        let h = Sha256::digest(public_key_sec1);
        let mut out = Vec::new();
        for b in h {
            out.push(b).expect("32 bytes");
        }
        out
    }

    /// Constant-time equality of raw fingerprints (32 bytes).
    pub fn fingerprint_ct_eq(&self, other: &[u8]) -> Choice {
        if other.len() != self.fingerprint.len() {
            return Choice::from(0u8);
        }
        self.fingerprint.as_slice().ct_eq(other)
    }
}

/// A read-only view of trusted long-term public keys.
/// Used during handshake to verify peer signatures.
pub trait TrustStore {
    /// Look up a long-term certificate by its SHA-256 fingerprint (32 raw bytes).
    /// Returns `None` if the fingerprint is not in the trust store.
    fn lookup(&self, fingerprint: &[u8]) -> Option<LongTermCert>;
}

/// A simple in-memory trust store backed by a fixed-size array.
/// Suitable for embedded use with a small number of trusted peers.
pub struct InMemoryTrustStore<const N: usize> {
    entries: Vec<LongTermCert, N>,
}

impl<const N: usize> InMemoryTrustStore<N> {
    /// Create an empty trust store.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Insert a certificate. Fails if the store is full.
    pub fn add(&mut self, cert: LongTermCert) -> Result<(), EphemeralSessionError> {
        self.entries
            .push(cert)
            .map_err(|_| EphemeralSessionError::TrustStoreFull)
    }

    /// Remove an entry by fingerprint. Returns `true` if an entry was removed.
    pub fn remove(&mut self, fingerprint: &[u8]) -> bool {
        let mut i = 0usize;
        let mut removed = false;
        while i < self.entries.len() {
            let fp = self.entries[i].fingerprint.as_slice();
            if fp.len() == fingerprint.len() && bool::from(fp.ct_eq(fingerprint)) {
                let _ = self.entries.swap_remove(i);
                removed = true;
                break;
            }
            i += 1;
        }
        removed
    }
}

impl<const N: usize> Default for InMemoryTrustStore<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> TrustStore for InMemoryTrustStore<N> {
    fn lookup(&self, fingerprint: &[u8]) -> Option<LongTermCert> {
        if fingerprint.len() != 32 {
            return None;
        }
        let mut found: Option<LongTermCert> = None;
        for e in &self.entries {
            let m = e.fingerprint.as_slice().ct_eq(fingerprint);
            if bool::from(m) {
                if found.is_some() {
                    return None;
                }
                found = Some(e.clone());
            }
        }
        found
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve_select::SessionCurve;
    use galdr_core::fake_hal::FakeTrng;
    use galdr_vault::ecdsa_brainpool::BrainpoolSigningKey;

    fn sample_cert() -> LongTermCert {
        let mut trng = FakeTrng::from_seed(0x71);
        let sk = BrainpoolSigningKey::generate(&mut trng).expect("sk");
        let vk = sk.verifying_key();
        let sec1 = vk.to_sec1_uncompressed();
        let mut verifying_key = Vec::new();
        verifying_key.extend_from_slice(&sec1).expect("sec1");
        let fp = LongTermCert::fingerprint_of(&sec1);
        LongTermCert {
            fingerprint: fp,
            curve: SessionCurve::BrainpoolP256r1,
            verifying_key,
        }
    }

    #[test]
    fn test_lookup_found() {
        let c = sample_cert();
        let fp = c.fingerprint.clone();
        let mut s = InMemoryTrustStore::<4>::new();
        s.add(c).expect("add");
        let got = s.lookup(fp.as_slice());
        assert!(got.is_some());
    }

    #[test]
    fn test_lookup_not_found() {
        let s = InMemoryTrustStore::<4>::new();
        assert!(s.lookup(&[0u8; 32]).is_none());
    }

    #[test]
    fn test_store_full() {
        let mut s = InMemoryTrustStore::<1>::new();
        s.add(sample_cert()).expect("add");
        let mut trng = FakeTrng::from_seed(0x72);
        let sk = BrainpoolSigningKey::generate(&mut trng).expect("sk");
        let vk = sk.verifying_key();
        let sec1 = vk.to_sec1_uncompressed();
        let mut verifying_key = Vec::new();
        verifying_key.extend_from_slice(&sec1).expect("sec1");
        let c2 = LongTermCert {
            fingerprint: LongTermCert::fingerprint_of(&sec1),
            curve: SessionCurve::BrainpoolP256r1,
            verifying_key,
        };
        assert_eq!(s.add(c2), Err(EphemeralSessionError::TrustStoreFull));
    }

    #[test]
    fn test_remove() {
        let c = sample_cert();
        let fp = c.fingerprint.clone();
        let mut s = InMemoryTrustStore::<4>::new();
        s.add(c).expect("add");
        assert!(s.remove(fp.as_slice()));
        assert!(s.lookup(fp.as_slice()).is_none());
    }
}
