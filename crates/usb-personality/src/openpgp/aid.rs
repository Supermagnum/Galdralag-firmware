//! OpenPGP card application identifier (AID) and related constants.

#![deny(unsafe_code)]

/// OpenPGP application AID prefix (5 bytes).
pub const OPENPGP_AID_PREFIX: &[u8] = &[0xD2, 0x76, 0x00, 0x01, 0x24];

/// OpenPGP card spec version embedded in full AID (3.4).
pub const OPENPGP_CARD_VERSION_MAJOR: u8 = 0x03;
pub const OPENPGP_CARD_VERSION_MINOR: u8 = 0x04;

/// Build 16-byte OpenPGP AID: prefix + version + manufacturer (2) + serial (4) + RFU (2).
pub fn build_aid(manufacturer_id: u16, serial: [u8; 4]) -> [u8; 16] {
    let mut aid = [0u8; 16];
    aid[0..5].copy_from_slice(OPENPGP_AID_PREFIX);
    aid[5] = OPENPGP_CARD_VERSION_MAJOR;
    aid[6] = OPENPGP_CARD_VERSION_MINOR;
    aid[7..9].copy_from_slice(&manufacturer_id.to_be_bytes());
    aid[9..13].copy_from_slice(&serial);
    // aid[13..16] RFU zero
    aid
}

/// Returns true if `aid` selects the OpenPGP application (partial match on prefix + version bytes).
pub fn aid_matches_openpgp(aid: &[u8]) -> bool {
    if aid.len() < 7 {
        return false;
    }
    aid.starts_with(OPENPGP_AID_PREFIX)
        && aid[5] == OPENPGP_CARD_VERSION_MAJOR
        && aid[6] == OPENPGP_CARD_VERSION_MINOR
}
