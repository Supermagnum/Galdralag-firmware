//! PERFORM SECURITY OPERATION — decipher (PSO:DECIPHER).
//!
//! ECDH command data (OpenPGP card §7.2.11): constructed DO `0xA6` containing `0x7F49` with
//! primitive `0x86` holding the peer ephemeral public key (uncompressed SEC1).

#![deny(unsafe_code)]

/// OpenPGP card ECDH wrapper tag (constructed).
const TAG_ECDH_WRAPPER: u16 = 0xA6;
/// Generalized ECC public key (constructed).
const TAG_ECC_PK: u16 = 0x7F49;
/// Ephemeral session key (primitive).
const TAG_EPHEMERAL_KEY: u16 = 0x86;

fn parse_ber_length(buf: &[u8]) -> Result<(usize, &[u8]), ()> {
    if buf.is_empty() {
        return Err(());
    }
    let b0 = buf[0] as usize;
    if b0 & 0x80 == 0 {
        return Ok((b0, &buf[1..]));
    }
    let n = b0 & 0x7F;
    if n == 0 || n > 4 || buf.len() < 1 + n {
        return Err(());
    }
    let mut len = 0usize;
    for i in 0..n {
        len = (len << 8) | buf[1 + i] as usize;
    }
    Ok((len, &buf[1 + n..]))
}

fn parse_ber_tag(buf: &[u8]) -> Result<(u16, &[u8]), ()> {
    if buf.is_empty() {
        return Err(());
    }
    let b0 = buf[0];
    if (b0 & 0x1F) != 0x1F {
        return Ok((u16::from(b0), &buf[1..]));
    }
    if buf.len() < 2 {
        return Err(());
    }
    let b1 = buf[1];
    if (b1 & 0x80) != 0 {
        return Err(());
    }
    Ok((u16::from(b0) << 8 | u16::from(b1), &buf[2..]))
}

fn read_tlv(buf: &[u8]) -> Result<(u16, &[u8], &[u8]), ()> {
    let (tag, rest) = parse_ber_tag(buf)?;
    let (len, rest) = parse_ber_length(rest)?;
    if rest.len() < len {
        return Err(());
    }
    let (value, rest) = rest.split_at(len);
    Ok((tag, value, rest))
}

/// Extract peer uncompressed SEC1 public key bytes from PSO:DECIPHER ECDH command data.
pub fn parse_ecdh_peer_public_key(data: &[u8]) -> Option<&[u8]> {
    let (tag, inner, _) = read_tlv(data).ok()?;
    if tag != TAG_ECDH_WRAPPER {
        return None;
    }
    let (tag2, inner2, _) = read_tlv(inner).ok()?;
    if tag2 != TAG_ECC_PK {
        return None;
    }
    let (tag3, peer, _) = read_tlv(inner2).ok()?;
    if tag3 != TAG_EPHEMERAL_KEY {
        return None;
    }
    if peer.is_empty() {
        return None;
    }
    Some(peer)
}
