//! CESS §8.3 inner HKDF-BLAKE3 `info` UTF-8 strings (suite id as 4 lowercase hex digits, big-endian).
//!
//! Normative pattern from CESS v0.2 §8.3: `cess-inner-` || hex(`suite_id`) || per-layer suffix so
//! cascade subkeys are distinct. Layer index is decimal (`l0`–`l99`).

use alloc::vec::Vec;

const HEX: &[u8; 16] = b"0123456789abcdef";

fn push_hex_u16_be(out: &mut Vec<u8>, v: u16) {
    for shift in (0..4).rev() {
        let nib = ((v >> (shift * 4)) & 0xf) as usize;
        out.push(HEX[nib]);
    }
}

fn push_layer_index(out: &mut Vec<u8>, layer_index: u8) {
    out.extend_from_slice(b"-l");
    if layer_index < 10 {
        out.push(b'0' + layer_index);
    } else if layer_index < 100 {
        out.push(b'0' + (layer_index / 10));
        out.push(b'0' + (layer_index % 10));
    } else {
        out.push(b'0' + (layer_index / 100));
        out.push(b'0' + ((layer_index / 10) % 10));
        out.push(b'0' + (layer_index % 10));
    }
}

/// `cess-inner-{suite_id:04x}-l{layer}-key` (HKDF-BLAKE3 info for bulk AEAD key material).
pub fn cess_inner_cascade_layer_key_info(suite_id: u16, layer_index: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(32);
    out.extend_from_slice(b"cess-inner-");
    push_hex_u16_be(&mut out, suite_id);
    push_layer_index(&mut out, layer_index);
    out.extend_from_slice(b"-key");
    out
}

/// `cess-inner-{suite_id:04x}-l{layer}-nonce` (HKDF-BLAKE3 info for deterministic nonce material).
pub fn cess_inner_cascade_layer_nonce_info(suite_id: u16, layer_index: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(34);
    out.extend_from_slice(b"cess-inner-");
    push_hex_u16_be(&mut out, suite_id);
    push_layer_index(&mut out, layer_index);
    out.extend_from_slice(b"-nonce");
    out
}

/// Single HKDF-BLAKE3 expand to 64 octets for Serpent / Twofish EtM (cipher || MAC keys).
pub fn cess_inner_cascade_etm64_info(suite_id: u16, layer_index: u8, cipher: CessInnerEtM64Cipher) -> Vec<u8> {
    let mut out = Vec::with_capacity(40);
    out.extend_from_slice(b"cess-inner-");
    push_hex_u16_be(&mut out, suite_id);
    push_layer_index(&mut out, layer_index);
    match cipher {
        CessInnerEtM64Cipher::Serpent256 => out.extend_from_slice(b"-serpent256"),
        CessInnerEtM64Cipher::Twofish256 => out.extend_from_slice(b"-twofish256"),
    }
    out
}

/// Which 64-byte EtM profile the info tail names (distinct labels per cipher).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CessInnerEtM64Cipher {
    Serpent256,
    Twofish256,
}

/// §8.3 keyed BLAKE3 integrity info (`cess-blake3-integrity-{04x}`) when a profile registers that step.
pub fn cess_blake3_integrity_info(suite_id: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(28);
    out.extend_from_slice(b"cess-blake3-integrity-");
    push_hex_u16_be(&mut out, suite_id);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cess_inner_key_info_matches_section_8_3_shape() {
        let v = cess_inner_cascade_layer_key_info(0x0003, 0);
        assert_eq!(v, b"cess-inner-0003-l0-key");
        let v = cess_inner_cascade_layer_nonce_info(0x0003, 1);
        assert_eq!(v, b"cess-inner-0003-l1-nonce");
    }

    #[test]
    fn cess_blake3_integrity_example_0x0004() {
        assert_eq!(
            cess_blake3_integrity_info(0x0004).as_slice(),
            b"cess-blake3-integrity-0004"
        );
    }
}
