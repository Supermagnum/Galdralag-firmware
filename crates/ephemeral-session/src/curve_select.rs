//! Negotiated Brainpool curve for a session.

/// The elliptic curve used for this session's ephemeral key pair.
/// Both initiator and responder must agree before any key material is generated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionCurve {
    /// BrainpoolP256r1. ~128-bit security. Smallest keys and signatures.
    BrainpoolP256r1,
    /// BrainpoolP384r1. ~192-bit security.
    BrainpoolP384r1,
    /// BrainpoolP512r1. ~256-bit security. Largest keys and signatures.
    BrainpoolP512r1,
}

impl SessionCurve {
    /// The wire byte identifying this curve in handshake messages.
    pub fn wire_id(self) -> u8 {
        match self {
            SessionCurve::BrainpoolP256r1 => 0x01,
            SessionCurve::BrainpoolP384r1 => 0x02,
            SessionCurve::BrainpoolP512r1 => 0x03,
        }
    }

    /// Parse from wire byte. Returns `None` for unknown values.
    pub fn from_wire(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(SessionCurve::BrainpoolP256r1),
            0x02 => Some(SessionCurve::BrainpoolP384r1),
            0x03 => Some(SessionCurve::BrainpoolP512r1),
            _ => None,
        }
    }

    /// Length in bytes of an uncompressed public key on this curve.
    pub fn public_key_len(self) -> usize {
        match self {
            SessionCurve::BrainpoolP256r1 => 65,
            SessionCurve::BrainpoolP384r1 => 97,
            SessionCurve::BrainpoolP512r1 => 129,
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
            SessionCurve::BrainpoolP512r1,
        ] {
            assert_eq!(SessionCurve::from_wire(c.wire_id()), Some(c));
        }
    }

    #[test]
    fn unknown_wire_id() {
        assert_eq!(SessionCurve::from_wire(0x00), None);
        assert_eq!(SessionCurve::from_wire(0xFF), None);
    }
}
