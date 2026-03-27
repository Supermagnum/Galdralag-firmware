//! Audit records for profile use at session creation.

use crate::layer::CipherLayer;
use ephemeral_session::SessionCurve;
use heapless::{String, Vec};

/// Audit record for logging which algorithms a session uses.
#[derive(Debug)]
pub struct ProfileAuditRecord {
    /// Profile name.
    pub profile_name: String<64>,
    /// Curve label (short ASCII).
    pub curve: &'static str,
    /// Cipher layer names in order (inner to outer).
    pub layers: Vec<&'static str, 4>,
    /// Shamir threshold.
    pub shamir_k: u8,
    /// Shamir total shares.
    pub shamir_n: u8,
    /// Unix seconds (caller-supplied).
    pub timestamp: u64,
}

/// Map curve to a short audit label.
pub fn curve_audit_str(c: SessionCurve) -> &'static str {
    match c {
        SessionCurve::BrainpoolP256r1 => "bp256",
        SessionCurve::BrainpoolP384r1 => "bp384",
        SessionCurve::BrainpoolP512r1 => "bp512",
    }
}

/// Static name for a cipher layer in audit output.
pub fn layer_audit_name(c: CipherLayer) -> &'static str {
    match c {
        CipherLayer::Aes256Gcm => "aes256gcm",
        CipherLayer::ChaCha20Poly1305 => "chacha20poly1305",
        CipherLayer::Twofish256 => "twofish256",
        CipherLayer::Serpent256 => "serpent256",
    }
}

impl ProfileAuditRecord {
    /// Compact ASCII detail string for vault audit logs.
    pub fn to_audit_string(&self) -> String<256> {
        let mut s = String::new();
        let _ = s.push_str("{\"profile\":\"");
        let _ = s.push_str(self.profile_name.as_str());
        let _ = s.push_str("\",\"curve\":\"");
        let _ = s.push_str(self.curve);
        let _ = s.push_str("\",\"layers\":[");
        for (i, layer) in self.layers.iter().enumerate() {
            if i > 0 {
                let _ = s.push_str(",");
            }
            let _ = s.push_str("\"");
            let _ = s.push_str(layer);
            let _ = s.push_str("\"");
        }
        let _ = s.push_str("],\"shamir\":\"");
        let _ = s.push_str(u8_decimal(self.shamir_k).as_str());
        let _ = s.push_str("/");
        let _ = s.push_str(u8_decimal(self.shamir_n).as_str());
        let _ = s.push_str("\"}");
        s
    }
}

fn u8_decimal(n: u8) -> heapless::String<4> {
    let mut s = heapless::String::new();
    if n >= 100 {
        let _ = s.push((b'0' + n / 100) as char);
        let _ = s.push((b'0' + (n / 10) % 10) as char);
        let _ = s.push((b'0' + n % 10) as char);
    } else if n >= 10 {
        let _ = s.push((b'0' + n / 10) as char);
        let _ = s.push((b'0' + n % 10) as char);
    } else {
        let _ = s.push((b'0' + n) as char);
    }
    s
}
