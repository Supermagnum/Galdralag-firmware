//! Negotiated Brainpool curve for a session.

use core::fmt;
use galdr_core::legacy_removed::{MSG_SESSION_CURVE_P512, SESSION_CURVE_WIRE_BRAINPOOL_P512};

/// The elliptic curve used for this session's ephemeral key pair.
/// Both initiator and responder must agree before any key material is generated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionCurve {
    /// BrainpoolP256r1. ~128-bit security. Smallest keys and signatures.
    BrainpoolP256r1,
    /// BrainpoolP384r1. ~192-bit security.
    BrainpoolP384r1,
}

impl SessionCurve {
    /// The wire byte identifying this curve in handshake messages.
    pub fn wire_id(self) -> u8 {
        match self {
            SessionCurve::BrainpoolP256r1 => 0x01,
            SessionCurve::BrainpoolP384r1 => 0x02,
        }
    }

    /// Parse from wire byte. Returns `None` for unknown values (not removed P-512).
    pub fn from_wire(byte: u8) -> Option<Self> {
        Self::try_from_wire(byte).ok()
    }

    /// Parse wire byte, distinguishing retired BrainpoolP512r1 (`0x03`) from other rejections.
    pub fn try_from_wire(byte: u8) -> Result<Self, SessionCurveWireError> {
        match byte {
            0x01 => Ok(SessionCurve::BrainpoolP256r1),
            0x02 => Ok(SessionCurve::BrainpoolP384r1),
            SESSION_CURVE_WIRE_BRAINPOOL_P512 => Err(SessionCurveWireError::RemovedBrainpoolP512),
            _ => Err(SessionCurveWireError::Unknown),
        }
    }

    /// Length in bytes of an uncompressed public key on this curve.
    pub fn public_key_len(self) -> usize {
        match self {
            SessionCurve::BrainpoolP256r1 => 65,
            SessionCurve::BrainpoolP384r1 => 97,
        }
    }
}

/// Failure to parse a session curve wire byte.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SessionCurveWireError {
    /// Unrecognised curve wire byte.
    Unknown,
    /// Retired BrainpoolP512r1 (`0x03`).
    RemovedBrainpoolP512,
}

impl fmt::Display for SessionCurveWireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionCurveWireError::Unknown => write!(f, "unknown session curve wire byte"),
            SessionCurveWireError::RemovedBrainpoolP512 => write!(f, "{MSG_SESSION_CURVE_P512}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_id_roundtrip() {
        for c in [
            SessionCurve::BrainpoolP256r1,
            SessionCurve::BrainpoolP384r1,
        ] {
            assert_eq!(SessionCurve::from_wire(c.wire_id()), Some(c));
        }
    }

    #[test]
    fn removed_p512_wire_id() {
        assert_eq!(
            SessionCurve::try_from_wire(SESSION_CURVE_WIRE_BRAINPOOL_P512),
            Err(SessionCurveWireError::RemovedBrainpoolP512)
        );
        assert_eq!(SessionCurve::from_wire(SESSION_CURVE_WIRE_BRAINPOOL_P512), None);
    }

    #[test]
    fn unknown_wire_id() {
        assert_eq!(SessionCurve::from_wire(0x00), None);
        assert_eq!(
            SessionCurve::try_from_wire(0x00),
            Err(SessionCurveWireError::Unknown)
        );
        assert_eq!(SessionCurve::from_wire(0xFF), None);
    }
}
