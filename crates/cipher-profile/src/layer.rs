//! Symmetric cipher layer identifiers.

/// One symmetric cipher layer in a profile's cascade.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherLayer {
    /// AES-256-GCM (NIST SP 800-38D). AEAD at this layer.
    Aes256Gcm,

    /// ChaCha20-Poly1305 (RFC 8439). AEAD at this layer.
    ChaCha20Poly1305,

    /// Twofish-256 EtM (vault construction). AEAD at this layer.
    Twofish256,

    /// Serpent-256 EtM (vault construction). AEAD at this layer.
    Serpent256,
}

impl CipherLayer {
    /// HKDF info string fragment for this cipher (combined with profile and layer index).
    pub fn domain_fragment(self) -> &'static [u8] {
        match self {
            CipherLayer::Aes256Gcm => b"aes256gcm",
            CipherLayer::ChaCha20Poly1305 => b"chacha20poly1305",
            CipherLayer::Twofish256 => b"twofish256",
            CipherLayer::Serpent256 => b"serpent256",
        }
    }

    /// Wire byte for serialised profiles.
    pub fn wire_id(self) -> u8 {
        match self {
            CipherLayer::Aes256Gcm => 0x01,
            CipherLayer::ChaCha20Poly1305 => 0x02,
            CipherLayer::Twofish256 => 0x03,
            CipherLayer::Serpent256 => 0x04,
        }
    }

    /// Parse from wire byte.
    pub fn from_wire(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(CipherLayer::Aes256Gcm),
            0x02 => Some(CipherLayer::ChaCha20Poly1305),
            0x03 => Some(CipherLayer::Twofish256),
            0x04 => Some(CipherLayer::Serpent256),
            _ => None,
        }
    }
}
