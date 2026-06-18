//! Wire format for `InitMessage` and `ResponseMessage`.

use crate::curve_select::SessionCurve;
use crate::error::EphemeralSessionError;
use heapless::Vec;

/// Protocol version byte for [`InitMessage`].
pub const INIT_PROTOCOL_VERSION: u8 = 0x01;
/// Protocol version byte for [`ResponseMessage`].
pub const RESP_PROTOCOL_VERSION: u8 = 0x01;

/// Maximum DER-encoded ECDSA signature (Brainpool P-512r1).
pub const MAX_SIG_BYTES: usize = 200;
/// Maximum serialised handshake message size.
pub const MAX_HANDSHAKE_BYTES: usize = 512;

/// Initiator handshake message.
#[derive(Clone)]
pub struct InitMessage {
    pub version: u8,
    pub curve: SessionCurve,
    pub ephemeral_public_key: Vec<u8, 129>,
    pub long_term_fingerprint: Vec<u8, 64>,
    pub signature: Vec<u8, MAX_SIG_BYTES>,
}

/// Responder handshake message.
#[derive(Clone)]
pub struct ResponseMessage {
    pub version: u8,
    pub curve: SessionCurve,
    pub ephemeral_public_key: Vec<u8, 129>,
    pub long_term_fingerprint: Vec<u8, 64>,
    pub initiator_ephemeral_public_key: Vec<u8, 129>,
    pub signature: Vec<u8, MAX_SIG_BYTES>,
}

fn hex_encode_32(raw: &[u8; 32]) -> Vec<u8, 64> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = Vec::new();
    for b in raw {
        out.push(HEX[(b >> 4) as usize]).expect("len");
        out.push(HEX[(b & 0x0f) as usize]).expect("len");
    }
    out
}

fn hex_decode_64(hex: &[u8]) -> Result<[u8; 32], EphemeralSessionError> {
    if hex.len() != 64 {
        return Err(EphemeralSessionError::MalformedHandshake);
    }
    fn val(c: u8) -> Result<u8, EphemeralSessionError> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(EphemeralSessionError::MalformedHandshake),
        }
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let hi = val(hex[i * 2])?;
        let lo = val(hex[i * 2 + 1])?;
        out[i] = hi << 4 | lo;
    }
    Ok(out)
}

impl InitMessage {
    /// Serialise to a flat byte array.
    pub fn serialise(&self) -> Result<Vec<u8, MAX_HANDSHAKE_BYTES>, EphemeralSessionError> {
        let mut out = Vec::new();
        out.push(self.version)
            .map_err(|_| EphemeralSessionError::MalformedHandshake)?;
        out.push(self.curve.wire_id())
            .map_err(|_| EphemeralSessionError::MalformedHandshake)?;
        let epk = self.ephemeral_public_key.as_slice();
        let n = epk.len();
        if n > u8::MAX as usize {
            return Err(EphemeralSessionError::MalformedHandshake);
        }
        out.push(n as u8)
            .map_err(|_| EphemeralSessionError::MalformedHandshake)?;
        out.extend_from_slice(epk)
            .map_err(|_| EphemeralSessionError::MalformedHandshake)?;
        let fp = self.long_term_fingerprint.as_slice();
        if fp.len() > u8::MAX as usize {
            return Err(EphemeralSessionError::MalformedHandshake);
        }
        out.push(fp.len() as u8)
            .map_err(|_| EphemeralSessionError::MalformedHandshake)?;
        out.extend_from_slice(fp)
            .map_err(|_| EphemeralSessionError::MalformedHandshake)?;
        let sig = self.signature.as_slice();
        if sig.len() > u16::MAX as usize {
            return Err(EphemeralSessionError::MalformedHandshake);
        }
        let slen = sig.len() as u16;
        out.push((slen >> 8) as u8)
            .map_err(|_| EphemeralSessionError::MalformedHandshake)?;
        out.push((slen & 0xff) as u8)
            .map_err(|_| EphemeralSessionError::MalformedHandshake)?;
        out.extend_from_slice(sig)
            .map_err(|_| EphemeralSessionError::MalformedHandshake)?;
        Ok(out)
    }

    /// Parse from wire bytes.
    pub fn parse(bytes: &[u8]) -> Result<Self, EphemeralSessionError> {
        if bytes.len() < 6 {
            return Err(EphemeralSessionError::MalformedHandshake);
        }
        let version = bytes[0];
        if version != INIT_PROTOCOL_VERSION {
            return Err(EphemeralSessionError::MalformedHandshake);
        }
        let curve =
            SessionCurve::from_wire(bytes[1]).ok_or(EphemeralSessionError::MalformedHandshake)?;
        let n = bytes[2] as usize;
        let expected = curve.public_key_len();
        if n != expected {
            return Err(EphemeralSessionError::MalformedHandshake);
        }
        if bytes.len() < 3 + n + 1 {
            return Err(EphemeralSessionError::MalformedHandshake);
        }
        let mut ephemeral_public_key = Vec::new();
        ephemeral_public_key
            .extend_from_slice(&bytes[3..3 + n])
            .map_err(|_| EphemeralSessionError::MalformedHandshake)?;
        let mut o = 3 + n;
        let flen = bytes[o] as usize;
        o += 1;
        if bytes.len() < o + flen + 2 {
            return Err(EphemeralSessionError::MalformedHandshake);
        }
        let mut long_term_fingerprint = Vec::new();
        long_term_fingerprint
            .extend_from_slice(&bytes[o..o + flen])
            .map_err(|_| EphemeralSessionError::MalformedHandshake)?;
        o += flen;
        let slen = u16::from_be_bytes([bytes[o], bytes[o + 1]]) as usize;
        o += 2;
        if bytes.len() < o + slen {
            return Err(EphemeralSessionError::MalformedHandshake);
        }
        let mut signature = Vec::new();
        signature
            .extend_from_slice(&bytes[o..o + slen])
            .map_err(|_| EphemeralSessionError::MalformedHandshake)?;
        Ok(InitMessage {
            version,
            curve,
            ephemeral_public_key,
            long_term_fingerprint,
            signature,
        })
    }

    /// Encode raw 32-byte fingerprint as 64-byte hex ASCII for the wire format.
    pub fn encode_fingerprint_hex(raw_fp: &[u8; 32]) -> Vec<u8, 64> {
        hex_encode_32(raw_fp)
    }

    /// Decode wire fingerprint (64 hex ASCII) to raw 32 bytes.
    pub fn decode_fingerprint_hex(hex: &[u8]) -> Result<[u8; 32], EphemeralSessionError> {
        hex_decode_64(hex)
    }
}

impl ResponseMessage {
    /// Serialise to a flat byte array.
    pub fn serialise(&self) -> Result<Vec<u8, MAX_HANDSHAKE_BYTES>, EphemeralSessionError> {
        let mut out = Vec::new();
        out.push(self.version)
            .map_err(|_| EphemeralSessionError::MalformedHandshake)?;
        out.push(self.curve.wire_id())
            .map_err(|_| EphemeralSessionError::MalformedHandshake)?;
        let epk = self.ephemeral_public_key.as_slice();
        let n = epk.len();
        if n > u8::MAX as usize {
            return Err(EphemeralSessionError::MalformedHandshake);
        }
        out.push(n as u8)
            .map_err(|_| EphemeralSessionError::MalformedHandshake)?;
        out.extend_from_slice(epk)
            .map_err(|_| EphemeralSessionError::MalformedHandshake)?;
        let fp = self.long_term_fingerprint.as_slice();
        if fp.len() > u8::MAX as usize {
            return Err(EphemeralSessionError::MalformedHandshake);
        }
        out.push(fp.len() as u8)
            .map_err(|_| EphemeralSessionError::MalformedHandshake)?;
        out.extend_from_slice(fp)
            .map_err(|_| EphemeralSessionError::MalformedHandshake)?;
        let iepk = self.initiator_ephemeral_public_key.as_slice();
        let in_ = iepk.len();
        if in_ > u8::MAX as usize {
            return Err(EphemeralSessionError::MalformedHandshake);
        }
        out.push(in_ as u8)
            .map_err(|_| EphemeralSessionError::MalformedHandshake)?;
        out.extend_from_slice(iepk)
            .map_err(|_| EphemeralSessionError::MalformedHandshake)?;
        let sig = self.signature.as_slice();
        if sig.len() > u16::MAX as usize {
            return Err(EphemeralSessionError::MalformedHandshake);
        }
        let slen = sig.len() as u16;
        out.push((slen >> 8) as u8)
            .map_err(|_| EphemeralSessionError::MalformedHandshake)?;
        out.push((slen & 0xff) as u8)
            .map_err(|_| EphemeralSessionError::MalformedHandshake)?;
        out.extend_from_slice(sig)
            .map_err(|_| EphemeralSessionError::MalformedHandshake)?;
        Ok(out)
    }

    /// Parse from wire bytes.
    pub fn parse(bytes: &[u8]) -> Result<Self, EphemeralSessionError> {
        if bytes.len() < 6 {
            return Err(EphemeralSessionError::MalformedHandshake);
        }
        let version = bytes[0];
        if version != RESP_PROTOCOL_VERSION {
            return Err(EphemeralSessionError::MalformedHandshake);
        }
        let curve =
            SessionCurve::from_wire(bytes[1]).ok_or(EphemeralSessionError::MalformedHandshake)?;
        let n = bytes[2] as usize;
        let expected = curve.public_key_len();
        if n != expected {
            return Err(EphemeralSessionError::MalformedHandshake);
        }
        if bytes.len() < 3 + n + 1 {
            return Err(EphemeralSessionError::MalformedHandshake);
        }
        let mut ephemeral_public_key = Vec::new();
        ephemeral_public_key
            .extend_from_slice(&bytes[3..3 + n])
            .map_err(|_| EphemeralSessionError::MalformedHandshake)?;
        let mut o = 3 + n;
        let flen = bytes[o] as usize;
        o += 1;
        if bytes.len() < o + flen + 1 {
            return Err(EphemeralSessionError::MalformedHandshake);
        }
        let mut long_term_fingerprint = Vec::new();
        long_term_fingerprint
            .extend_from_slice(&bytes[o..o + flen])
            .map_err(|_| EphemeralSessionError::MalformedHandshake)?;
        o += flen;
        let in_ = bytes[o] as usize;
        o += 1;
        if in_ != expected {
            return Err(EphemeralSessionError::MalformedHandshake);
        }
        if bytes.len() < o + in_ + 2 {
            return Err(EphemeralSessionError::MalformedHandshake);
        }
        let mut initiator_ephemeral_public_key = Vec::new();
        initiator_ephemeral_public_key
            .extend_from_slice(&bytes[o..o + in_])
            .map_err(|_| EphemeralSessionError::MalformedHandshake)?;
        o += in_;
        let slen = u16::from_be_bytes([bytes[o], bytes[o + 1]]) as usize;
        o += 2;
        if bytes.len() < o + slen {
            return Err(EphemeralSessionError::MalformedHandshake);
        }
        let mut signature = Vec::new();
        signature
            .extend_from_slice(&bytes[o..o + slen])
            .map_err(|_| EphemeralSessionError::MalformedHandshake)?;
        Ok(ResponseMessage {
            version,
            curve,
            ephemeral_public_key,
            long_term_fingerprint,
            initiator_ephemeral_public_key,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve_select::SessionCurve;

    fn sample_init() -> InitMessage {
        let mut ephemeral_public_key = Vec::new();
        ephemeral_public_key.resize_default(65).expect("65");
        let mut long_term_fingerprint = Vec::new();
        long_term_fingerprint.resize_default(64).expect("64");
        let mut signature = Vec::new();
        signature.resize_default(10).expect("sig");
        InitMessage {
            version: INIT_PROTOCOL_VERSION,
            curve: SessionCurve::BrainpoolP256r1,
            ephemeral_public_key,
            long_term_fingerprint,
            signature,
        }
    }

    fn sample_resp() -> ResponseMessage {
        let mut ephemeral_public_key = Vec::new();
        ephemeral_public_key.resize_default(65).expect("65");
        let mut long_term_fingerprint = Vec::new();
        long_term_fingerprint.resize_default(64).expect("64");
        let mut initiator_ephemeral_public_key = Vec::new();
        initiator_ephemeral_public_key
            .resize_default(65)
            .expect("65");
        let mut signature = Vec::new();
        signature.resize_default(10).expect("sig");
        ResponseMessage {
            version: RESP_PROTOCOL_VERSION,
            curve: SessionCurve::BrainpoolP256r1,
            ephemeral_public_key,
            long_term_fingerprint,
            initiator_ephemeral_public_key,
            signature,
        }
    }

    #[test]
    fn init_message_serialise_parse_roundtrip() {
        let m = sample_init();
        let b = m.serialise().expect("ser");
        let p = InitMessage::parse(b.as_slice()).expect("parse");
        assert_eq!(p.version, m.version);
        assert_eq!(p.curve, m.curve);
        assert_eq!(p.ephemeral_public_key, m.ephemeral_public_key);
        assert_eq!(p.long_term_fingerprint, m.long_term_fingerprint);
        assert_eq!(p.signature, m.signature);
    }

    #[test]
    fn response_message_serialise_parse_roundtrip() {
        let m = sample_resp();
        let b = m.serialise().expect("ser");
        let p = ResponseMessage::parse(b.as_slice()).expect("parse");
        assert_eq!(p.version, m.version);
        assert_eq!(p.curve, m.curve);
        assert_eq!(p.ephemeral_public_key, m.ephemeral_public_key);
        assert_eq!(p.long_term_fingerprint, m.long_term_fingerprint);
        assert_eq!(
            p.initiator_ephemeral_public_key,
            m.initiator_ephemeral_public_key
        );
        assert_eq!(p.signature, m.signature);
    }

    #[test]
    fn parse_truncated_init_message() {
        let r = InitMessage::parse(&[1, 1, 65]);
        assert!(matches!(r, Err(EphemeralSessionError::MalformedHandshake)));
    }

    #[test]
    fn parse_unknown_curve() {
        let mut v = vec![INIT_PROTOCOL_VERSION, 0xFF, 65u8];
        v.extend_from_slice(&[0u8; 65]);
        let r = InitMessage::parse(&v);
        assert!(matches!(r, Err(EphemeralSessionError::MalformedHandshake)));
    }

    #[test]
    fn parse_version_mismatch() {
        let mut v = vec![0x02u8, 1, 65];
        v.extend_from_slice(&[0u8; 65]);
        let r = InitMessage::parse(&v);
        assert!(matches!(r, Err(EphemeralSessionError::MalformedHandshake)));
    }
}
