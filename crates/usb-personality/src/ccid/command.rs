//! Parse PC/SC CCID **PC_to_RDR** bulk messages (USB CCID 1.1).

#![deny(unsafe_code)]

use heapless::Vec;

const HDR_LEN: usize = 10;

/// PC_to_RDR message types used for T=1 APDU exchange.
#[derive(Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum PcToRdr {
    /// PC_to_RDR_IccPowerOn (0x62).
    IccPowerOn { slot: u8, seq: u8, power_select: u8 },
    /// PC_to_RDR_IccPowerOff (0x63).
    IccPowerOff { slot: u8, seq: u8 },
    /// PC_to_RDR_GetSlotStatus (0x65).
    GetSlotStatus { slot: u8, seq: u8 },
    /// PC_to_RDR_XfrBlock (0x6F): APDU payload in `apdu`.
    XfrBlock {
        slot: u8,
        seq: u8,
        apdu: Vec<u8, 512>,
    },
    /// PC_to_RDR_Abort (0x72).
    Abort { slot: u8, seq: u8 },
}

/// Malformed or unsupported CCID host message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CcidError {
    TooShort,
    LengthMismatch,
    UnknownMessageType,
    PayloadTooLarge,
}

/// Parse `data` as a PC_to_RDR message. Header is 10 bytes; `dwLength` is little-endian APDU length.
pub fn parse_pc_to_rdr(data: &[u8]) -> Result<PcToRdr, CcidError> {
    if data.len() < HDR_LEN {
        return Err(CcidError::TooShort);
    }
    let msg_type = data[0];
    let dw_length = u32::from_le_bytes(data[1..5].try_into().map_err(|_| CcidError::TooShort)?);
    let slot = data[5];
    let seq = data[6];
    let b7 = data[7];

    let expected = HDR_LEN.saturating_add(dw_length as usize);
    if data.len() != expected {
        return Err(CcidError::LengthMismatch);
    }

    match msg_type {
        0x62 => {
            if dw_length != 0 {
                return Err(CcidError::LengthMismatch);
            }
            Ok(PcToRdr::IccPowerOn {
                slot,
                seq,
                power_select: b7,
            })
        }
        0x63 => {
            if dw_length != 0 {
                return Err(CcidError::LengthMismatch);
            }
            Ok(PcToRdr::IccPowerOff { slot, seq })
        }
        0x65 => {
            if dw_length != 0 {
                return Err(CcidError::LengthMismatch);
            }
            Ok(PcToRdr::GetSlotStatus { slot, seq })
        }
        0x6F => {
            let payload = &data[HDR_LEN..];
            if payload.len() > 512 {
                return Err(CcidError::PayloadTooLarge);
            }
            let mut apdu = Vec::new();
            for b in payload {
                apdu.push(*b).map_err(|_| CcidError::PayloadTooLarge)?;
            }
            Ok(PcToRdr::XfrBlock { slot, seq, apdu })
        }
        0x72 => {
            if dw_length != 0 {
                return Err(CcidError::LengthMismatch);
            }
            Ok(PcToRdr::Abort { slot, seq })
        }
        _ => Err(CcidError::UnknownMessageType),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hdr(t: u8, dw_len: u32, slot: u8, seq: u8, b7: u8, b8: u8, b9: u8) -> [u8; 10] {
        let mut h = [0u8; 10];
        h[0] = t;
        h[1..5].copy_from_slice(&dw_len.to_le_bytes());
        h[5] = slot;
        h[6] = seq;
        h[7] = b7;
        h[8] = b8;
        h[9] = b9;
        h
    }

    #[test]
    fn parse_icc_power_on() {
        let mut m = [0u8; 10];
        m.copy_from_slice(&hdr(0x62, 0, 0, 1, 0, 0, 0));
        match parse_pc_to_rdr(&m).unwrap() {
            PcToRdr::IccPowerOn {
                slot,
                seq,
                power_select,
            } => {
                assert_eq!(slot, 0);
                assert_eq!(seq, 1);
                assert_eq!(power_select, 0);
            }
            _ => panic!("expected IccPowerOn"),
        }
    }

    #[test]
    fn parse_xfr_block() {
        let apdu = [
            0x00u8, 0xA4, 0x04, 0x00, 0x06, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01,
        ];
        let mut m = heapless::Vec::<u8, 600>::new();
        let h = hdr(0x6F, apdu.len() as u32, 0, 2, 0, 0, 0);
        for b in h {
            m.push(b).unwrap();
        }
        for b in apdu {
            m.push(b).unwrap();
        }
        match parse_pc_to_rdr(m.as_slice()).unwrap() {
            PcToRdr::XfrBlock { slot, seq, apdu: a } => {
                assert_eq!(slot, 0);
                assert_eq!(seq, 2);
                assert_eq!(a.as_slice(), apdu.as_slice());
            }
            _ => panic!("expected XfrBlock"),
        }
    }

    #[test]
    fn parse_unknown_type() {
        let m = hdr(0xFF, 0, 0, 0, 0, 0, 0);
        assert_eq!(parse_pc_to_rdr(&m), Err(CcidError::UnknownMessageType));
    }

    #[test]
    fn parse_truncated() {
        let m = [0x62u8, 0, 0, 0, 0];
        assert_eq!(parse_pc_to_rdr(&m), Err(CcidError::TooShort));
    }
}
