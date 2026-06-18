//! HKDF-SHA256 domain separation labels for session keys.

/// HKDF info strings for all keys derived from the ephemeral shared secret.
/// These are fixed constants. Do not change them after deployment — changing
/// them breaks compatibility with sessions established by other nodes.
pub mod domain {
    /// Derived key for ChaCha20-Poly1305 payload encryption (sending direction).
    /// "initiator to responder" encryption key.
    pub const PAYLOAD_KEY_I2R: &[u8] = b"galdralag/session/payload-i2r/v1";

    /// Derived key for ChaCha20-Poly1305 payload encryption (receiving direction).
    /// "responder to initiator" encryption key.
    pub const PAYLOAD_KEY_R2I: &[u8] = b"galdralag/session/payload-r2i/v1";

    /// Derived key for GDSS masking keystream (ChaCha20, unauthenticated).
    /// Used as input to the Box-Muller transform in GR-K-GDSS.
    pub const GDSS_MASK_KEY: &[u8] = b"galdralag/session/gdss-mask/v1";

    /// Derived key for GDSS sync burst PN sequence.
    pub const GDSS_SYNC_KEY: &[u8] = b"galdralag/session/gdss-sync/v1";

    /// Derived key for GDSS sync burst timing offset schedule.
    pub const GDSS_TIMING_KEY: &[u8] = b"galdralag/session/gdss-timing/v1";

    /// Derived key for HMAC-based message authentication (if not using AEAD).
    pub const MAC_KEY: &[u8] = b"galdralag/session/mac/v1";
}

#[cfg(test)]
mod tests {
    use super::domain::*;

    #[test]
    fn domain_labels_all_distinct() {
        let labels = [
            PAYLOAD_KEY_I2R,
            PAYLOAD_KEY_R2I,
            GDSS_MASK_KEY,
            GDSS_SYNC_KEY,
            GDSS_TIMING_KEY,
            MAC_KEY,
        ];
        for i in 0..labels.len() {
            for j in i + 1..labels.len() {
                assert_ne!(labels[i], labels[j]);
            }
        }
    }

    #[test]
    fn domain_labels_non_empty() {
        for l in [
            PAYLOAD_KEY_I2R,
            PAYLOAD_KEY_R2I,
            GDSS_MASK_KEY,
            GDSS_SYNC_KEY,
            GDSS_TIMING_KEY,
            MAC_KEY,
        ] {
            assert!(!l.is_empty());
        }
    }
}
