//! OpenPGP card data objects (DOs), algorithm attributes, and TLV helpers.

#![deny(unsafe_code)]

use heapless::Vec;
use sha1::{Digest as Sha1Digest, Sha1};
use sha2::{Digest, Sha256};

/// Supported curves and OIDs as used in OpenPGP card algorithm attributes (§4.4.3.9).
pub mod curve_oids {
    /// BrainpoolP256r1.
    pub const BRAINPOOL_P256R1: &[u8] = &[0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07];
    /// BrainpoolP384r1.
    pub const BRAINPOOL_P384R1: &[u8] = &[0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B];
    /// BrainpoolP512r1.
    pub const BRAINPOOL_P512R1: &[u8] = &[0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D];
    /// NIST P-256 (prime256v1).
    pub const NIST_P256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
    /// NIST P-384.
    pub const NIST_P384: &[u8] = &[0x2B, 0x81, 0x04, 0x00, 0x22];
    /// Ed25519 (EdDSA / signing).
    pub const ED25519: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01];
    /// Curve25519 (ECDH / decryption).
    pub const CURVE25519: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01];
}

/// Parsed algorithm attributes for a key slot (OpenPGP card §4.4.3.9).
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum AlgorithmAttributes {
    /// RSA key.
    Rsa {
        /// Modulus size in bits.
        modulus_bits: u16,
        /// Public exponent size in bits.
        exponent_bits: u16,
        /// Import format byte.
        import_format: u8,
    },
    /// ECDH (X25519 or ECDH over NIST/Brainpool).
    Ecdh {
        /// DER OID bytes for the curve.
        curve_oid: Vec<u8, 16>,
    },
    /// ECDSA signature.
    Ecdsa { curve_oid: Vec<u8, 16> },
    /// EdDSA (Ed25519).
    EdDsa { curve_oid: Vec<u8, 16> },
}

impl AlgorithmAttributes {
    /// Encode to OpenPGP card algorithm attributes bytes for storage in DO C1/C2/C3.
    #[allow(clippy::result_unit_err)]
    pub fn to_bytes(&self) -> Result<Vec<u8, 32>, ()> {
        let mut v = Vec::new();
        match self {
            AlgorithmAttributes::Rsa {
                modulus_bits,
                exponent_bits,
                import_format,
            } => {
                v.push(0x01).map_err(|_| ())?;
                v.push((*modulus_bits / 256) as u8).map_err(|_| ())?;
                v.push(*modulus_bits as u8).map_err(|_| ())?;
                v.push((*exponent_bits / 256) as u8).map_err(|_| ())?;
                v.push(*exponent_bits as u8).map_err(|_| ())?;
                v.push(*import_format).map_err(|_| ())?;
            }
            AlgorithmAttributes::Ecdh { curve_oid } => {
                v.push(0x12).map_err(|_| ())?;
                for b in curve_oid.as_slice() {
                    v.push(*b).map_err(|_| ())?;
                }
            }
            AlgorithmAttributes::Ecdsa { curve_oid } => {
                v.push(0x13).map_err(|_| ())?;
                for b in curve_oid.as_slice() {
                    v.push(*b).map_err(|_| ())?;
                }
            }
            AlgorithmAttributes::EdDsa { curve_oid } => {
                v.push(0x16).map_err(|_| ())?;
                for b in curve_oid.as_slice() {
                    v.push(*b).map_err(|_| ())?;
                }
            }
        }
        Ok(v)
    }

    /// Parse algorithm attributes from DO contents.
    #[allow(clippy::result_unit_err)]
    pub fn parse(data: &[u8]) -> Result<Self, ()> {
        if data.is_empty() {
            return Err(());
        }
        match data[0] {
            0x01 if data.len() >= 6 => Ok(AlgorithmAttributes::Rsa {
                modulus_bits: u16::from_be_bytes([data[1], data[2]]),
                exponent_bits: u16::from_be_bytes([data[3], data[4]]),
                import_format: data[5],
            }),
            0x12 => {
                let mut oid = Vec::new();
                for b in &data[1..] {
                    oid.push(*b).map_err(|_| ())?;
                }
                Ok(AlgorithmAttributes::Ecdh { curve_oid: oid })
            }
            0x13 => {
                let mut oid = Vec::new();
                for b in &data[1..] {
                    oid.push(*b).map_err(|_| ())?;
                }
                Ok(AlgorithmAttributes::Ecdsa { curve_oid: oid })
            }
            0x16 => {
                let mut oid = Vec::new();
                for b in &data[1..] {
                    oid.push(*b).map_err(|_| ())?;
                }
                Ok(AlgorithmAttributes::EdDsa { curve_oid: oid })
            }
            _ => Err(()),
        }
    }
}

/// Default extended capabilities (tag 0xC0) — only claim features that are implemented.
pub fn extended_capabilities_default() -> [u8; 10] {
    [
        0xB0, // byte0: bit7 GET CHALLENGE; other bits as before (key import, PW status, ...)
        0x00, 0x00, 0x40, // bytes 2-3: max GET CHALLENGE length (64)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]
}

/// Compute OpenPGP v4 fingerprint (SHA-1) over canonical public key packet body (RFC 4880 §12.2).
///
/// SHA-1 is required for GnuPG interoperability with card fingerprints; cryptographic security relies
/// on stronger hashes for operational signatures.
pub fn compute_v4_fingerprint(
    creation_timestamp: u32,
    algorithm_id: u8,
    key_material: &[u8],
) -> [u8; 20] {
    let mut h = Sha1::new();
    Sha1Digest::update(&mut h, [0x04u8]);
    Sha1Digest::update(&mut h, creation_timestamp.to_be_bytes());
    Sha1Digest::update(&mut h, [algorithm_id]);
    Sha1Digest::update(&mut h, key_material);
    let d = Sha1Digest::finalize(h);
    let mut out = [0u8; 20];
    out.copy_from_slice(&d);
    out
}

/// Hash PIN bytes for comparison to stored vault verifier (SHA-256 digest).
pub fn pin_bytes_to_verifier_digest(pin: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    Digest::update(&mut h, pin);
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn algorithm_attributes_brainpool256_roundtrip() {
        let mut oid = Vec::new();
        for b in curve_oids::BRAINPOOL_P256R1 {
            oid.push(*b).unwrap();
        }
        let a = AlgorithmAttributes::Ecdsa { curve_oid: oid };
        let b = a.to_bytes().unwrap();
        let p = AlgorithmAttributes::parse(b.as_slice()).unwrap();
        assert_eq!(a, p);
    }

    #[test]
    fn algorithm_attributes_ed25519_roundtrip() {
        let mut oid = Vec::new();
        for b in curve_oids::ED25519 {
            oid.push(*b).unwrap();
        }
        let a = AlgorithmAttributes::EdDsa { curve_oid: oid };
        let b = a.to_bytes().unwrap();
        let p = AlgorithmAttributes::parse(b.as_slice()).unwrap();
        assert_eq!(a, p);
    }

    #[test]
    fn algorithm_attributes_rsa2048_roundtrip() {
        let a = AlgorithmAttributes::Rsa {
            modulus_bits: 2048,
            exponent_bits: 32,
            import_format: 0,
        };
        let b = a.to_bytes().unwrap();
        let p = AlgorithmAttributes::parse(b.as_slice()).unwrap();
        assert_eq!(a, p);
    }

    #[test]
    fn fingerprint_compute_known_vector() {
        // Synthetic body: v4-like prefix + fixed material; stable golden SHA-1.
        let fp = compute_v4_fingerprint(0x5E0C_2000, 0x13, &[0x01u8, 0x02, 0x03]);
        assert_eq!(
            fp,
            [
                0x6F, 0xDE, 0x2B, 0x89, 0xDC, 0x64, 0x48, 0x3E, 0x1D, 0x13, 0x02, 0xA3, 0x34, 0x64,
                0xB2, 0x36, 0xAA, 0x6E, 0x17, 0x9F
            ]
        );
    }
}
