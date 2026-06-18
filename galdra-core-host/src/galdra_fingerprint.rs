//! Galdralag fingerprint: `G:` + 40 hex chars (BLAKE3-160 of raw SIG public key bytes).

use std::fmt;
use std::str::FromStr;

const PREFIX: &str = "G:";
const HASH_PREFIX_LEN: usize = 20;

/// Parse error for [`GaldraFingerprint`].
#[derive(Debug, Clone, Eq, PartialEq, thiserror::Error)]
pub enum GaldraFingerprintParseError {
    /// Missing or wrong `G:` prefix.
    #[error("Galdralag fingerprint must use canonical G: prefix followed by 40 lowercase hex digits")]
    InvalidFormat,
    #[error("Galdralag fingerprint contains non-hexadecimal characters")]
    InvalidHex,
}

/// Canonical storage: `G:` + 40 lowercase hex digits (160-bit BLAKE3 digest).
#[derive(Debug, Clone, Eq)]
pub struct GaldraFingerprint(String);

impl PartialEq for GaldraFingerprint {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl GaldraFingerprint {
    /// BLAKE3 over `public_key_bytes`, first 20 bytes of digest, formatted as canonical `G:` + hex.
    pub fn from_public_key_bytes(public_key_bytes: &[u8]) -> Self {
        let h = blake3::hash(public_key_bytes);
        let slice20 = &h.as_bytes()[..HASH_PREFIX_LEN];
        let lower = hex::encode(slice20);
        GaldraFingerprint(format!("G:{lower}"))
    }

    /// Borrow canonical form (`G:` + 40 hex, no spaces).
    pub fn canonical(&self) -> &str {
        self.0.as_str()
    }

    /// Human-readable groups of 4 hex digits; double space after the fifth group (cosmetic only).
    pub fn display(&self) -> String {
        let hex_part = &self.0[PREFIX.len()..];
        debug_assert_eq!(hex_part.len(), 40);
        let mut s = String::with_capacity(PREFIX.len() + 40 + 12);
        s.push_str(PREFIX);
        for (i, chunk) in hex_part.as_bytes().chunks(4).enumerate() {
            if i > 0 {
                if i == 5 {
                    s.push_str("  ");
                } else {
                    s.push(' ');
                }
            }
            s.push_str(std::str::from_utf8(chunk).expect("hex ascii"));
        }
        s
    }

    fn normalize_input(s: &str) -> Result<String, GaldraFingerprintParseError> {
        let stripped: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        if stripped.len() < PREFIX.len() {
            return Err(GaldraFingerprintParseError::InvalidFormat);
        }
        if !stripped[..PREFIX.len()].eq_ignore_ascii_case(PREFIX) {
            return Err(GaldraFingerprintParseError::InvalidFormat);
        }
        let hex_part = &stripped[PREFIX.len()..];
        if hex_part.len() != 40 {
            return Err(GaldraFingerprintParseError::InvalidFormat);
        }
        if !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(GaldraFingerprintParseError::InvalidHex);
        }
        Ok(format!(
            "G:{}",
            hex_part.to_ascii_lowercase()
        ))
    }
}

impl FromStr for GaldraFingerprint {
    type Err = GaldraFingerprintParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::normalize_input(s).map(GaldraFingerprint)
    }
}

impl fmt::Display for GaldraFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_bytes_round_trip_canonical() {
        let pk = [0x02u8; 33];
        let fp = GaldraFingerprint::from_public_key_bytes(&pk);
        assert!(fp.canonical().starts_with("G:"));
        assert_eq!(fp.canonical().len(), 42);
        let parsed: GaldraFingerprint = fp.canonical().parse().expect("parse canonical");
        assert_eq!(parsed, fp);
    }

    #[test]
    fn display_grouping() {
        let pk = [7u8; 33];
        let fp = GaldraFingerprint::from_public_key_bytes(&pk);
        let d = fp.display();
        assert!(d.starts_with("G:"));
        assert!(d.contains("  "));
    }

    #[test]
    fn parse_display_form() {
        let pk = [9u8; 33];
        let fp = GaldraFingerprint::from_public_key_bytes(&pk);
        let round: GaldraFingerprint = fp.display().parse().expect("display parse");
        assert_eq!(round, fp);
    }

    #[test]
    fn inequality_different_key() {
        let a = GaldraFingerprint::from_public_key_bytes(&[1u8; 33]);
        let b = GaldraFingerprint::from_public_key_bytes(&[2u8; 33]);
        assert_ne!(a, b);
    }

    #[test]
    fn reject_wrong_prefix() {
        assert!(
            GaldraFingerprint::from_str("H:0000000000000000000000000000000000000000").is_err()
        );
    }

    #[test]
    fn reject_wrong_length() {
        assert!(GaldraFingerprint::from_str("G:abcd").is_err());
    }

    #[test]
    fn reject_non_hex() {
        assert!(GaldraFingerprint::from_str("G:gggggggggggggggggggggggggggggggggggggggg").is_err());
    }
}
