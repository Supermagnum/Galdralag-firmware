//! OpenPGP card algorithm attributes (DO C1/C2/C3) parsing for host-side checks.
//!
//! Mirrors the firmware [`AlgorithmAttributes`] logic in `usb-personality` without depending on
//! the embedded crate.

use galdr_core::legacy_removed::{self, MSG_KEY_ALGO_P512};

/// OpenPGP card key slot (SIG / DEC / AUT).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum OpenPgpKeySlot {
    /// Signing slot (DO `0xC1`).
    Sig,
    /// Decryption slot (DO `0xC2`).
    Dec,
    /// Authentication slot (DO `0xC3`).
    Aut,
}

impl OpenPgpKeySlot {
    /// Data object tag for this slot's algorithm attributes.
    pub const fn do_tag(self) -> u16 {
        match self {
            Self::Sig => 0xC1,
            Self::Dec => 0xC2,
            Self::Aut => 0xC3,
        }
    }

    /// Short label used in user-facing messages (`SIG`, `DEC`, `AUT`).
    pub const fn label(self) -> &'static str {
        match self {
            Self::Sig => "SIG",
            Self::Dec => "DEC",
            Self::Aut => "AUT",
        }
    }

    /// All slots in display order.
    pub const ALL: [Self; 3] = [Self::Sig, Self::Dec, Self::Aut];
}

/// Parsed algorithm attributes from a C1/C2/C3 data object.
#[derive(Debug, Clone, PartialEq, Eq)]
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
        curve_oid: Vec<u8>,
    },
    /// ECDSA signature.
    Ecdsa {
        /// DER OID bytes for the curve.
        curve_oid: Vec<u8>,
    },
    /// EdDSA (Ed25519).
    EdDsa {
        /// DER OID bytes for the curve.
        curve_oid: Vec<u8>,
    },
}

impl AlgorithmAttributes {
    /// True when algorithm attributes name a curve retired from Galdralag (BrainpoolP512r1).
    pub fn uses_removed_curve(&self) -> bool {
        match self {
            Self::Rsa { .. } => false,
            Self::Ecdh { curve_oid } | Self::Ecdsa { curve_oid } | Self::EdDsa { curve_oid } => {
                legacy_removed::is_brainpool_p512_oid(curve_oid)
            }
        }
    }

    /// Parse algorithm attributes from DO contents.
    pub fn parse(data: &[u8]) -> Result<Self, ()> {
        if data.is_empty() {
            return Err(());
        }
        match data[0] {
            0x01 if data.len() >= 6 => Ok(Self::Rsa {
                modulus_bits: u16::from_be_bytes([data[1], data[2]]),
                exponent_bits: u16::from_be_bytes([data[3], data[4]]),
                import_format: data[5],
            }),
            0x12 => Ok(Self::Ecdh {
                curve_oid: data[1..].to_vec(),
            }),
            0x13 => Ok(Self::Ecdsa {
                curve_oid: data[1..].to_vec(),
            }),
            0x16 => Ok(Self::EdDsa {
                curve_oid: data[1..].to_vec(),
            }),
            _ => Err(()),
        }
    }
}

/// One slot whose stored algorithm attributes still name BrainpoolP512r1.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct StaleP512Slot {
    /// Affected slot.
    pub slot: OpenPgpKeySlot,
    /// User-facing warning (slot label + [`MSG_KEY_ALGO_P512`]).
    pub message: String,
}

/// Format a stale-slot warning for display or [`crate::GaldraError::RemovedLegacyCrypto`].
pub fn stale_p512_message(slot: OpenPgpKeySlot) -> String {
    format!("OpenPGP {} slot: {MSG_KEY_ALGO_P512}", slot.label())
}

/// Inspect one DO payload; returns a warning when it encodes BrainpoolP512r1.
pub fn stale_p512_slot_from_do_bytes(slot: OpenPgpKeySlot, data: &[u8]) -> Option<StaleP512Slot> {
    if data.is_empty() {
        return None;
    }
    let attrs = AlgorithmAttributes::parse(data).ok()?;
    if !attrs.uses_removed_curve() {
        return None;
    }
    Some(StaleP512Slot {
        slot,
        message: stale_p512_message(slot),
    })
}

/// Inspect C1/C2/C3 payloads and return warnings for every slot that still names P-512.
pub fn stale_p512_slots_from_do_bytes(
    sig: &[u8],
    dec: &[u8],
    aut: &[u8],
) -> Vec<StaleP512Slot> {
    let pairs = [
        (OpenPgpKeySlot::Sig, sig),
        (OpenPgpKeySlot::Dec, dec),
        (OpenPgpKeySlot::Aut, aut),
    ];
    pairs
        .into_iter()
        .filter_map(|(slot, data)| stale_p512_slot_from_do_bytes(slot, data))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use galdr_core::legacy_removed::BRAINPOOL_P512R1_OID;

    fn p512_ecdsa_bytes() -> Vec<u8> {
        let mut v = vec![0x13];
        v.extend_from_slice(BRAINPOOL_P512R1_OID);
        v
    }

    fn p512_ecdh_bytes() -> Vec<u8> {
        let mut v = vec![0x12];
        v.extend_from_slice(BRAINPOOL_P512R1_OID);
        v
    }

    #[test]
    fn stale_sig_slot_detects_p512_ecdsa_oid() {
        let stale = stale_p512_slot_from_do_bytes(OpenPgpKeySlot::Sig, &p512_ecdsa_bytes())
            .expect("P-512 ECDSA attrs");
        assert_eq!(stale.slot, OpenPgpKeySlot::Sig);
        assert!(stale.message.contains("SIG"));
        assert!(stale.message.contains("BrainpoolP512r1"));
        assert!(stale.message.contains(MSG_KEY_ALGO_P512));
    }

    #[test]
    fn stale_dec_slot_detects_p512_ecdh_oid() {
        let stale = stale_p512_slot_from_do_bytes(OpenPgpKeySlot::Dec, &p512_ecdh_bytes())
            .expect("P-512 ECDH attrs");
        assert_eq!(stale.slot, OpenPgpKeySlot::Dec);
        assert!(stale.message.contains("DEC"));
    }

    #[test]
    fn stale_slots_from_all_three_dos() {
        let mut p256 = vec![0x13];
        p256.extend_from_slice(&[
            0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07,
        ]);
        let warnings = stale_p512_slots_from_do_bytes(
            &p512_ecdsa_bytes(),
            &p512_ecdh_bytes(),
            &p512_ecdsa_bytes(),
        );
        assert_eq!(warnings.len(), 3);
        assert_eq!(warnings[0].slot, OpenPgpKeySlot::Sig);
        assert_eq!(warnings[1].slot, OpenPgpKeySlot::Dec);
        assert_eq!(warnings[2].slot, OpenPgpKeySlot::Aut);
        assert!(stale_p512_slots_from_do_bytes(&p256, &p256, &p256).is_empty());
    }

    #[test]
    fn empty_do_is_not_stale() {
        assert!(stale_p512_slot_from_do_bytes(OpenPgpKeySlot::Sig, &[]).is_none());
    }
}
