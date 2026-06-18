//! ISO 7816-4 APDU parsing and response encoding for the OpenPGP application.

#![deny(unsafe_code)]

use heapless::Vec;

use super::error::StatusWord;

/// Parsed ISO 7816-4 command APDU.
#[derive(Debug, Eq, PartialEq)]
pub struct CommandApdu {
    /// Class byte.
    pub cla: u8,
    /// Instruction byte.
    pub ins: u8,
    /// Parameter 1.
    pub p1: u8,
    /// Parameter 2.
    pub p2: u8,
    /// Command data field.
    pub data: Vec<u8, 512>,
    /// Expected response length (`Le`), if present.
    pub le: Option<u16>,
}

/// Malformed command APDU.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApduError {
    Empty,
    TooShort,
    InconsistentLengths,
}

impl CommandApdu {
    /// Parse raw bytes (short and extended length encodings).
    pub fn parse(raw: &[u8]) -> Result<Self, ApduError> {
        if raw.is_empty() {
            return Err(ApduError::Empty);
        }
        if raw.len() < 4 {
            return Err(ApduError::TooShort);
        }
        let cla = raw[0];
        let ins = raw[1];
        let p1 = raw[2];
        let p2 = raw[3];

        if raw.len() == 4 {
            return Ok(Self {
                cla,
                ins,
                p1,
                p2,
                data: Vec::new(),
                le: None,
            });
        }

        // Case 2 short: 4 + Le
        if raw.len() == 5 {
            return Ok(Self {
                cla,
                ins,
                p1,
                p2,
                data: Vec::new(),
                le: Some(le_short(raw[4])),
            });
        }

        let l0 = raw[4];
        // Extended APDU: Lc = 0 => next two bytes are 16-bit Lc (5..7), data follows.
        if l0 == 0 && raw.len() > 7 {
            let lc = u16::from_be_bytes([raw[5], raw[6]]) as usize;
            let data_end = 7usize.saturating_add(lc);
            if raw.len() < data_end {
                return Err(ApduError::InconsistentLengths);
            }
            let mut data = Vec::new();
            for b in &raw[7..data_end] {
                data.push(*b).map_err(|_| ApduError::InconsistentLengths)?;
            }
            let le = if raw.len() > data_end {
                if raw.len() == data_end + 1 {
                    Some(le_short(raw[data_end]))
                } else if raw.len() == data_end + 2 {
                    Some(u16::from_be_bytes([raw[data_end], raw[data_end + 1]]))
                } else if raw.len() == data_end + 3 && raw[data_end] == 0 {
                    Some(u16::from_be_bytes([raw[data_end + 1], raw[data_end + 2]]))
                } else {
                    return Err(ApduError::InconsistentLengths);
                }
            } else {
                None
            };
            return Ok(Self {
                cla,
                ins,
                p1,
                p2,
                data,
                le,
            });
        }

        // Short Lc
        let lc = l0 as usize;
        let data_start = 5usize;
        let data_end = data_start.saturating_add(lc);
        if raw.len() < data_end {
            return Err(ApduError::InconsistentLengths);
        }
        let mut data = Vec::new();
        for b in &raw[data_start..data_end] {
            data.push(*b).map_err(|_| ApduError::InconsistentLengths)?;
        }

        let le = if raw.len() > data_end {
            if raw.len() == data_end + 1 {
                Some(le_short(raw[data_end]))
            } else if raw.len() == data_end + 2 {
                if raw[data_end] == 0 {
                    Some(u16::from_be_bytes([0, raw[data_end + 1]]))
                } else {
                    Some(u16::from_be_bytes([raw[data_end], raw[data_end + 1]]))
                }
            } else if raw.len() == data_end + 3 && raw[data_end] == 0 {
                Some(u16::from_be_bytes([raw[data_end + 1], raw[data_end + 2]]))
            } else {
                return Err(ApduError::InconsistentLengths);
            }
        } else {
            None
        };

        Ok(Self {
            cla,
            ins,
            p1,
            p2,
            data,
            le,
        })
    }
}

fn le_short(b: u8) -> u16 {
    if b == 0 {
        256
    } else {
        u16::from(b)
    }
}

/// Response APDU with status word.
#[derive(Debug, Eq, PartialEq)]
pub struct ResponseApdu {
    /// Response data (before status).
    pub data: Vec<u8, 512>,
    pub sw1: u8,
    pub sw2: u8,
}

impl ResponseApdu {
    /// Success with payload.
    pub fn ok(data: Vec<u8, 512>) -> Self {
        Self {
            data,
            sw1: StatusWord::Success.sw1(),
            sw2: StatusWord::Success.sw2(),
        }
    }

    /// Success with empty body.
    pub fn ok_empty() -> Self {
        Self {
            data: Vec::new(),
            sw1: StatusWord::Success.sw1(),
            sw2: StatusWord::Success.sw2(),
        }
    }

    /// Failure with status word.
    pub fn error(sw: StatusWord) -> Self {
        Self {
            data: Vec::new(),
            sw1: sw.sw1(),
            sw2: sw.sw2(),
        }
    }

    /// Encode to bytes (data || SW1 || SW2), total at most 514 bytes.
    pub fn to_bytes(&self) -> Vec<u8, 514> {
        let mut out = Vec::new();
        for b in &self.data {
            let _ = out.push(*b);
        }
        let _ = out.push(self.sw1);
        let _ = out.push(self.sw2);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_short_apdu_no_data_no_le() {
        let raw = [0x00u8, 0xA4, 0x04, 0x00];
        let c = CommandApdu::parse(&raw).unwrap();
        assert_eq!(c.cla, 0x00);
        assert_eq!(c.ins, 0xA4);
        assert_eq!(c.data.len(), 0);
        assert_eq!(c.le, None);
    }

    #[test]
    fn parse_case2_apdu() {
        let raw = [0x00u8, 0xCA, 0x00, 0x4F, 0x00];
        let c = CommandApdu::parse(&raw).unwrap();
        assert_eq!(c.le, Some(256));
    }

    #[test]
    fn parse_case4_apdu() {
        let d = [0x01u8, 0x02, 0x03];
        let mut raw = [0x00u8; 9];
        raw[0..4].copy_from_slice(&[0x00, 0xDA, 0x00, 0x5E]);
        raw[4] = 3;
        raw[5..8].copy_from_slice(&d);
        raw[8] = 0x00;
        let c = CommandApdu::parse(&raw).unwrap();
        assert_eq!(c.data.as_slice(), d);
        assert_eq!(c.le, Some(256));
    }

    #[test]
    fn parse_extended_apdu() {
        // Lc=0 + 16-bit Lc=3, data 3 bytes, Le extended 2 bytes
        let raw = [
            0x00u8, 0xDA, 0x00, 0x5E, 0x00, 0x00, 0x03, 0xAA, 0xBB, 0xCC, 0x00, 0x01, 0x00,
        ];
        let c = CommandApdu::parse(&raw).unwrap();
        assert_eq!(c.data.as_slice(), &[0xAA, 0xBB, 0xCC]);
        assert_eq!(c.le, Some(256));
    }

    #[test]
    fn parse_truncated_apdu() {
        // Lc claims 5 data bytes but only one byte of payload follows the header.
        let raw = [0x00u8, 0xA4, 0x04, 0x00, 0x05, 0x01];
        assert_eq!(CommandApdu::parse(&raw), Err(ApduError::InconsistentLengths));
    }

    #[test]
    fn status_word_bytes() {
        let r = ResponseApdu::error(StatusWord::InstructionNotSupported);
        assert_eq!(r.sw1, 0x6D);
        assert_eq!(r.sw2, 0x00);
        let b = r.to_bytes();
        assert_eq!(b.len(), 2);
    }
}
