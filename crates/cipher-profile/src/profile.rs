//! Named cipher profile and builder.

use crate::audit::{curve_audit_str, layer_audit_name, ProfileAuditRecord};
use crate::error::CipherProfileError;
use crate::layer::CipherLayer;
use crate::shamir_cfg::ShamirConfig;
use ephemeral_session::SessionCurve;
use heapless::{String, Vec};

const MAX_NAME: usize = 64;
const MAX_DESC: usize = 128;

/// A validated cipher profile (immutable after construction).
/// Clone is allowed: profiles hold algorithm metadata only, not secret keys.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CipherProfile {
    name: String<MAX_NAME>,
    description: String<MAX_DESC>,
    curve: SessionCurve,
    layers: Vec<CipherLayer, 4>,
    shamir: ShamirConfig,
    /// When true (default for legacy serialised blobs), authenticated ephemeral ECDH is part of the
    /// product posture; host tooling must not emit a Galdralag `G:` fingerprint derived from the SIG key.
    ephemeral_ecdh: bool,
}

impl CipherProfile {
    /// Profile identifier.
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    /// Human-readable description.
    pub fn description(&self) -> &str {
        self.description.as_str()
    }

    /// ECDHE curve for the session handshake.
    pub fn curve(&self) -> SessionCurve {
        self.curve
    }

    /// Ordered cipher layers (inner first, outer last).
    pub fn layers(&self) -> &[CipherLayer] {
        self.layers.as_slice()
    }

    /// Shamir configuration for long-term key handling metadata.
    pub fn shamir(&self) -> ShamirConfig {
        self.shamir
    }

    /// When true, authenticated ephemeral ECDH is active for this profile's security model; Galdralag
    /// `G:` fingerprints must not be produced.
    pub fn ephemeral_ecdh(&self) -> bool {
        self.ephemeral_ecdh
    }

    /// Serialise to compact bytes.
    ///
    /// **Wire format:** legacy payloads end after `shamir.threshold` and `shamir.total`; parsers
    /// default `ephemeral_ecdh` to **true** for those blobs (migration). New encodings append one
    /// byte: `0` = `ephemeral_ecdh` false, `1` = true.
    pub fn to_bytes(&self) -> Vec<u8, 256> {
        let mut out = Vec::new();
        let name_b = self.name.as_str().as_bytes();
        let desc_b = self.description.as_str().as_bytes();
        let _ = out.push(name_b.len() as u8);
        for b in name_b {
            let _ = out.push(*b);
        }
        let _ = out.push(desc_b.len() as u8);
        for b in desc_b {
            let _ = out.push(*b);
        }
        let _ = out.push(self.curve.wire_id());
        let _ = out.push(self.layers.len() as u8);
        for layer in self.layers.iter() {
            let _ = out.push(layer.wire_id());
        }
        let _ = out.push(self.shamir.threshold);
        let _ = out.push(self.shamir.total);
        let _ = out.push(if self.ephemeral_ecdh { 1 } else { 0 });
        out
    }

    /// Parse from `to_bytes` output.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CipherProfileError> {
        let mut i = 0usize;
        let nl = *bytes.get(i).ok_or(CipherProfileError::MalformedEncoding)? as usize;
        i += 1;
        if nl > MAX_NAME {
            return Err(CipherProfileError::MalformedEncoding);
        }
        let name_slice = bytes
            .get(i..i + nl)
            .ok_or(CipherProfileError::MalformedEncoding)?;
        i += nl;
        let dl = *bytes.get(i).ok_or(CipherProfileError::MalformedEncoding)? as usize;
        i += 1;
        if dl > MAX_DESC {
            return Err(CipherProfileError::MalformedEncoding);
        }
        let desc_slice = bytes
            .get(i..i + dl)
            .ok_or(CipherProfileError::MalformedEncoding)?;
        i += dl;
        let cw = *bytes.get(i).ok_or(CipherProfileError::MalformedEncoding)?;
        i += 1;
        let curve = SessionCurve::from_wire(cw).ok_or(CipherProfileError::MalformedEncoding)?;
        let lc = *bytes.get(i).ok_or(CipherProfileError::MalformedEncoding)? as usize;
        i += 1;
        if lc == 0 || lc > 4 {
            return Err(CipherProfileError::MalformedEncoding);
        }
        let mut layers = Vec::new();
        for _ in 0..lc {
            let wid = *bytes.get(i).ok_or(CipherProfileError::MalformedEncoding)?;
            i += 1;
            let layer = CipherLayer::from_wire(wid).ok_or(CipherProfileError::MalformedEncoding)?;
            layers
                .push(layer)
                .map_err(|_| CipherProfileError::MalformedEncoding)?;
        }
        let sk = *bytes.get(i).ok_or(CipherProfileError::MalformedEncoding)?;
        i += 1;
        let sn = *bytes.get(i).ok_or(CipherProfileError::MalformedEncoding)?;
        i += 1;
        let ephemeral_ecdh = match bytes.get(i).copied() {
            None => true, // Migration: existing `user_profiles` rows without trailing byte.
            Some(flags) => {
                i += 1;
                match flags {
                    0 => false,
                    1 => true,
                    _ => return Err(CipherProfileError::MalformedEncoding),
                }
            }
        };
        if i != bytes.len() {
            return Err(CipherProfileError::MalformedEncoding);
        }
        let shamir =
            ShamirConfig::new(sk, sn).map_err(|_| CipherProfileError::InvalidShamirConfig)?;
        let name =
            core::str::from_utf8(name_slice).map_err(|_| CipherProfileError::MalformedEncoding)?;
        let desc =
            core::str::from_utf8(desc_slice).map_err(|_| CipherProfileError::MalformedEncoding)?;
        validate_profile_name(name)?;
        let mut ns = String::new();
        ns.push_str(name)
            .map_err(|_| CipherProfileError::MalformedEncoding)?;
        let mut ds = String::new();
        ds.push_str(desc)
            .map_err(|_| CipherProfileError::MalformedEncoding)?;
        check_layers(&layers)?;
        Ok(CipherProfile {
            name: ns,
            description: ds,
            curve,
            layers,
            shamir,
            ephemeral_ecdh,
        })
    }

    /// Build an audit record. `unix_timestamp` is supplied by the caller (RTC or host).
    pub fn audit_record(&self, unix_timestamp: u64) -> ProfileAuditRecord {
        let mut layers = Vec::new();
        for layer in self.layers.iter() {
            let _ = layers.push(layer_audit_name(*layer));
        }
        ProfileAuditRecord {
            profile_name: {
                let mut s = String::new();
                let _ = s.push_str(self.name.as_str());
                s
            },
            curve: curve_audit_str(self.curve),
            layers,
            shamir_k: self.shamir.threshold,
            shamir_n: self.shamir.total,
            timestamp: unix_timestamp,
        }
    }
}

/// Builder for [`CipherProfile`].
pub struct CipherProfileBuilder {
    name: String<MAX_NAME>,
    description: String<MAX_DESC>,
    curve: Option<SessionCurve>,
    layers: Vec<CipherLayer, 4>,
    shamir: ShamirConfig,
    ephemeral_ecdh: bool,
}

impl CipherProfileBuilder {
    /// Start a builder; validates `name`.
    pub fn new(name: &str) -> Result<Self, CipherProfileError> {
        validate_profile_name(name)?;
        let mut ns = String::new();
        ns.push_str(name)
            .map_err(|_| CipherProfileError::InvalidProfileName)?;
        Ok(Self {
            name: ns,
            description: String::new(),
            curve: None,
            layers: Vec::new(),
            shamir: ShamirConfig::none(),
            ephemeral_ecdh: true,
        })
    }

    /// Set description (max 128 UTF-8 bytes; ASCII expected).
    pub fn description(mut self, desc: &str) -> Self {
        self.description.clear();
        if desc.len() <= MAX_DESC {
            let _ = self.description.push_str(desc);
        }
        self
    }

    /// Set ECDHE curve (required before `build`).
    pub fn curve(mut self, curve: SessionCurve) -> Self {
        self.curve = Some(curve);
        self
    }

    /// Append a cipher layer (order = encrypt order).
    pub fn layer(mut self, cipher: CipherLayer) -> Result<Self, CipherProfileError> {
        if self.layers.len() >= 4 {
            return Err(CipherProfileError::TooManyLayers);
        }
        for existing in self.layers.iter() {
            if *existing == cipher {
                return Err(CipherProfileError::DuplicateCipher);
            }
        }
        self.layers
            .push(cipher)
            .map_err(|_| CipherProfileError::TooManyLayers)?;
        Ok(self)
    }

    /// Set Shamir metadata.
    pub fn shamir(mut self, config: ShamirConfig) -> Self {
        self.shamir = config;
        self
    }

    /// Whether this profile uses authenticated ephemeral ECDH (default **true**).
    pub fn ephemeral_ecdh(mut self, on: bool) -> Self {
        self.ephemeral_ecdh = on;
        self
    }

    /// Validate and build.
    pub fn build(self) -> Result<CipherProfile, CipherProfileError> {
        if self.layers.is_empty() {
            return Err(CipherProfileError::NoLayers);
        }
        let curve = self.curve.ok_or(CipherProfileError::CurveMismatch)?;
        check_layers(&self.layers)?;
        let _ = ShamirConfig::new(self.shamir.threshold, self.shamir.total)?;
        Ok(CipherProfile {
            name: self.name,
            description: self.description,
            curve,
            layers: self.layers,
            shamir: self.shamir,
            ephemeral_ecdh: self.ephemeral_ecdh,
        })
    }
}

fn validate_profile_name(name: &str) -> Result<(), CipherProfileError> {
    if name.is_empty() {
        return Err(CipherProfileError::InvalidProfileName);
    }
    if name.len() > MAX_NAME {
        return Err(CipherProfileError::InvalidProfileName);
    }
    for c in name.chars() {
        if c.is_ascii_alphanumeric() || c == '-' {
            continue;
        }
        return Err(CipherProfileError::InvalidProfileName);
    }
    Ok(())
}

fn check_layers(layers: &Vec<CipherLayer, 4>) -> Result<(), CipherProfileError> {
    if layers.is_empty() {
        return Err(CipherProfileError::NoLayers);
    }
    if layers.len() > 4 {
        return Err(CipherProfileError::TooManyLayers);
    }
    for i in 0..layers.len() {
        for j in i + 1..layers.len() {
            if layers[i] == layers[j] {
                return Err(CipherProfileError::DuplicateCipher);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ephemeral_session::SessionCurve;

    fn tr<T, E: core::fmt::Debug>(r: Result<T, E>) -> T {
        match r {
            Ok(v) => v,
            Err(e) => panic!("{:?}", e),
        }
    }

    #[test]
    fn profile_builder_valid_single_layer() {
        let b = tr(CipherProfileBuilder::new("ab-c"));
        let b = tr(b
            .curve(SessionCurve::BrainpoolP256r1)
            .layer(CipherLayer::ChaCha20Poly1305));
        let p = tr(b.build());
        assert_eq!(p.layers().len(), 1);
    }

    #[test]
    fn profile_builder_valid_cascade() {
        let b = tr(CipherProfileBuilder::new("x"));
        let b = tr(b
            .curve(SessionCurve::BrainpoolP256r1)
            .layer(CipherLayer::Serpent256));
        let b = tr(b.layer(CipherLayer::ChaCha20Poly1305));
        let p = tr(b.build());
        assert_eq!(
            p.layers(),
            &[CipherLayer::Serpent256, CipherLayer::ChaCha20Poly1305]
        );
    }

    #[test]
    fn profile_builder_no_layers() {
        let e = tr(CipherProfileBuilder::new("x"))
            .curve(SessionCurve::BrainpoolP256r1)
            .build();
        assert_eq!(e, Err(CipherProfileError::NoLayers));
    }

    #[test]
    fn profile_builder_too_many_layers() {
        let mut b = tr(CipherProfileBuilder::new("x")).curve(SessionCurve::BrainpoolP256r1);
        b = tr(b.layer(CipherLayer::ChaCha20Poly1305));
        b = tr(b.layer(CipherLayer::Serpent256));
        b = tr(b.layer(CipherLayer::Twofish256));
        b = tr(b.layer(CipherLayer::Aes256Gcm));
        let e = b.layer(CipherLayer::ChaCha20Poly1305);
        assert!(matches!(e, Err(CipherProfileError::TooManyLayers)));
    }

    #[test]
    fn profile_builder_duplicate_cipher() {
        let b = tr(CipherProfileBuilder::new("x")).curve(SessionCurve::BrainpoolP256r1);
        let b = tr(b.layer(CipherLayer::ChaCha20Poly1305));
        let e = b.layer(CipherLayer::ChaCha20Poly1305);
        assert!(matches!(e, Err(CipherProfileError::DuplicateCipher)));
    }

    #[test]
    fn profile_builder_no_curve() {
        let b = tr(CipherProfileBuilder::new("x"));
        let b = tr(b.layer(CipherLayer::ChaCha20Poly1305));
        let e = b.build();
        assert_eq!(e, Err(CipherProfileError::CurveMismatch));
    }

    #[test]
    fn profile_serialise_parse_roundtrip() {
        let sham = tr(ShamirConfig::new(2, 3));
        let b = tr(CipherProfileBuilder::new("my-p"));
        let b = b.description("d").curve(SessionCurve::BrainpoolP384r1);
        let b = tr(b.layer(CipherLayer::Twofish256));
        let b = b.shamir(sham);
        let p = tr(b.build());
        let b = p.to_bytes();
        let q = tr(CipherProfile::from_bytes(b.as_slice()));
        assert_eq!(p.name(), q.name());
        assert_eq!(p.description(), q.description());
        assert_eq!(p.curve(), q.curve());
        assert_eq!(p.layers(), q.layers());
        assert_eq!(p.shamir(), q.shamir());
        assert_eq!(p.ephemeral_ecdh(), q.ephemeral_ecdh());
    }

    #[test]
    fn profile_parse_legacy_defaults_ephemeral_ecdh_true() {
        let b = tr(CipherProfileBuilder::new("legacy"));
        let b = b
            .description("")
            .curve(SessionCurve::BrainpoolP256r1)
            .ephemeral_ecdh(false);
        let b = tr(b.layer(CipherLayer::ChaCha20Poly1305));
        let p = tr(b.build());
        let mut legacy = Vec::<u8, 256>::new();
        let full = p.to_bytes();
        // Strip trailing ephemeral byte to simulate pre-migration blobs.
        for (idx, b) in full.iter().enumerate() {
            if idx + 1 == full.len() {
                break;
            }
            let _ = legacy.push(*b);
        }
        let q = tr(CipherProfile::from_bytes(legacy.as_slice()));
        assert!(q.ephemeral_ecdh(), "legacy blobs must default ephemeral_ecdh to true");
        assert_ne!(p.ephemeral_ecdh(), q.ephemeral_ecdh());
    }

    #[test]
    fn profile_ephemeral_ecdh_false_roundtrip() {
        let b = tr(CipherProfileBuilder::new("nofp"));
        let b = b
            .curve(SessionCurve::BrainpoolP256r1)
            .ephemeral_ecdh(false);
        let b = tr(b.layer(CipherLayer::ChaCha20Poly1305));
        let p = tr(b.build());
        assert!(!p.ephemeral_ecdh());
        let raw = p.to_bytes();
        let q = tr(CipherProfile::from_bytes(raw.as_slice()));
        assert!(!q.ephemeral_ecdh());
    }

    #[test]
    fn profile_parse_truncated() {
        let r = CipherProfile::from_bytes(&[1, b'a']);
        assert_eq!(r, Err(CipherProfileError::MalformedEncoding));
    }

    #[test]
    fn profile_parse_unknown_cipher_wire_id() {
        let mut v = Vec::<u8, 256>::new();
        let _ = v.push(1);
        let _ = v.push(b'x');
        let _ = v.push(0);
        let _ = v.push(SessionCurve::BrainpoolP256r1.wire_id());
        let _ = v.push(1);
        let _ = v.push(0xff);
        let _ = v.push(1);
        let _ = v.push(1);
        let r = CipherProfile::from_bytes(v.as_slice());
        assert_eq!(r, Err(CipherProfileError::MalformedEncoding));
    }
}
