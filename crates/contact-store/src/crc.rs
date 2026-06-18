//! CRC32C (Castagnoli) for on-chip record integrity.

use crc32fast::Hasher;

/// Compute CRC32C over `data` (hardware may accelerate; software fallback via `crc32fast`).
pub fn crc32c(data: &[u8]) -> u32 {
    let mut h = Hasher::new();
    h.update(data);
    h.finalize()
}

/// Verify stored CRC against all bytes except the CRC field (last four bytes of a record).
pub fn record_crc_ok(bytes: &[u8]) -> bool {
    if bytes.len() < 4 {
        return false;
    }
    let body = &bytes[..bytes.len() - 4];
    let stored = u32::from_le_bytes(
        bytes[bytes.len() - 4..]
            .try_into()
            .unwrap_or([0, 0, 0, 0]),
    );
    crc32c(body) == stored
}
