//! Mode A outer plaintext: `suite_id` (16-bit BE) || `inner_blob`.

use alloc::vec::Vec;
use core::fmt;

/// Validated non-reserved 16-bit cipher suite identifier (CESS §8.5, §14.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SuiteId(pub u16);

impl SuiteId {
    /// Build from raw value; **`0` is reserved** and rejected.
    pub fn new(raw: u16) -> Result<Self, CessWireError> {
        if raw == super::SUITE_ID_RESERVED {
            return Err(CessWireError::ReservedSuiteId);
        }
        Ok(SuiteId(raw))
    }

    pub fn raw(self) -> u16 {
        self.0
    }
}

/// Errors from Mode A plaintext packing or parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CessWireError {
    /// `suite_id == 0` is reserved (CESS §14.2).
    ReservedSuiteId,
    /// Parsed buffer too short to contain a 16-bit suite id.
    TooShort,
}

impl fmt::Display for CessWireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CessWireError::ReservedSuiteId => write!(f, "suite_id 0x0000 is reserved"),
            CessWireError::TooShort => write!(f, "buffer shorter than 2 octets"),
        }
    }
}

/// Assemble CESS Mode A outer AEAD **plaintext**: `suite_id_be || inner_blob` (CESS §6.6).
pub fn assemble_mode_a_outer_plaintext(
    suite_id: u16,
    inner_blob: &[u8],
) -> Result<Vec<u8>, CessWireError> {
    let _ = SuiteId::new(suite_id)?;
    let mut out = Vec::with_capacity(2 + inner_blob.len());
    out.push((suite_id >> 8) as u8);
    out.push(suite_id as u8);
    out.extend_from_slice(inner_blob);
    Ok(out)
}

/// Parse outer AEAD plaintext after decryption; returns `(suite_id, inner_blob)`.
pub fn parse_mode_a_outer_plaintext(buf: &[u8]) -> Result<(u16, &[u8]), CessWireError> {
    if buf.len() < 2 {
        return Err(CessWireError::TooShort);
    }
    let suite_id = u16::from_be_bytes([buf[0], buf[1]]);
    let _ = SuiteId::new(suite_id)?;
    Ok((suite_id, &buf[2..]))
}
