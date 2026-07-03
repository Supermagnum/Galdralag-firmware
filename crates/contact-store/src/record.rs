//! Fixed 256-byte RRAM contact records and field metadata.

use crate::crc::{crc32c, record_crc_ok};
use crate::error::ContactStoreError;
use crate::layout::{CONTACT_RECORD_BYTES, CONTACT_RECORD_MAGIC, MAX_STRING_FIELD_BYTES};
use bitflags::bitflags;
use galdr_core::legacy_removed::KEY_ALGO_WIRE_BRAINPOOL_P512;
use zeroize::Zeroize;

bitflags! {
    /// Persisted contact flags (PIN verified state is SRAM-only in the index).
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct ContactFlags: u8 {
        /// Slot holds a live contact.
        const ACTIVE = 0b0000_0001;
        /// Contact key or identity was revoked.
        const REVOKED = 0b0000_0010;
        /// Host indicated stale key material.
        const STALE = 0b0000_0100;
        /// Own-identity slot (one of four).
        const SELF_KEY = 0b0000_1000;
    }
}

/// Public-key algorithm tag stored in RRAM.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyAlgo {
    Ed25519 = 1,
    X25519 = 2,
    BrainpoolP256r1 = 3,
    BrainpoolP384r1 = 4,
    NistP256 = 6,
    NistP384 = 7,
    Rsa2048 = 8,
    Rsa3072 = 9,
    Rsa4096 = 10,
}

impl KeyAlgo {
    /// Parse wire byte.
    pub fn from_wire(byte: u8) -> Result<Self, ContactStoreError> {
        match byte {
            1 => Ok(Self::Ed25519),
            2 => Ok(Self::X25519),
            3 => Ok(Self::BrainpoolP256r1),
            4 => Ok(Self::BrainpoolP384r1),
            KEY_ALGO_WIRE_BRAINPOOL_P512 => Err(ContactStoreError::RemovedBrainpoolP512),
            6 => Ok(Self::NistP256),
            7 => Ok(Self::NistP384),
            8 => Ok(Self::Rsa2048),
            9 => Ok(Self::Rsa3072),
            10 => Ok(Self::Rsa4096),
            _ => Err(ContactStoreError::InvalidAlgo),
        }
    }

    /// Wire byte for persistence.
    pub fn to_wire(self) -> u8 {
        self as u8
    }
}

/// Provenance of a single logical field (two bits in `source_map`).
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FieldSource {
    SelfAttested = 0,
    HostVerified = 1,
    RegistrySync = 2,
    OobVerified = 3,
}

impl FieldSource {
    fn from_bits(bits: u64) -> Self {
        match bits & 0b11 {
            1 => Self::HostVerified,
            2 => Self::RegistrySync,
            3 => Self::OobVerified,
            _ => Self::SelfAttested,
        }
    }

    fn to_bits(self) -> u64 {
        self as u64
    }
}

/// Named field indices for `source_map` (up to 32 fields, two bits each).
pub mod field {
    /// OpenPGP fingerprint bytes.
    pub const FINGERPRINT: u8 = 0;
    /// Display name string.
    pub const DISPLAY_NAME: u8 = 1;
    /// E-mail string.
    pub const EMAIL: u8 = 2;
    /// Callsign bytes.
    pub const CALLSIGN: u8 = 3;
    /// DMR subscriber id.
    pub const DMR_ID: u8 = 4;
    /// Organisation string.
    pub const ORGANISATION: u8 = 5;
    /// Department string.
    pub const DEPARTMENT: u8 = 6;
    /// Role string.
    pub const ROLE: u8 = 7;
    /// Free-form note.
    pub const NOTE: u8 = 8;
    /// Badge number string.
    pub const BADGE_NUMBER: u8 = 9;
    /// Street address string.
    pub const STREET: u8 = 10;
    /// Country string.
    pub const COUNTRY: u8 = 11;
    /// Postal code string.
    pub const POSTAL_CODE: u8 = 12;
    /// Region / state string.
    pub const REGION: u8 = 13;
    /// Radio affiliation string.
    pub const RADIO_AFFILIATION: u8 = 14;
    /// Fluxer id string.
    pub const FLUXER_ID: u8 = 15;
    /// Discord id string.
    pub const DISCORD_ID: u8 = 16;
    /// IRC id string.
    pub const IRC_ID: u8 = 17;
    /// Public key blob.
    pub const PUBLIC_KEY: u8 = 18;
}

/// Read provenance bits for a logical field.
pub fn field_source_get(map: u64, field_id: u8) -> FieldSource {
    let shift = u64::from(field_id) * 2;
    FieldSource::from_bits((map >> shift) & 0b11)
}

/// Update provenance for one field.
pub fn field_source_set(map: u64, field_id: u8, source: FieldSource) -> u64 {
    let shift = u64::from(field_id) * 2;
    let mask = !(0b11u64 << shift);
    (map & mask) | (source.to_bits() << shift)
}

/// Offset/length reference into the string heap (packed 6 bytes on the wire).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Zeroize)]
pub struct StringRef {
    /// Byte offset from the string-heap base.
    pub offset: u32,
    /// Byte length (UTF-8).
    pub len: u16,
}

impl StringRef {
    /// True when both offset and length are zero (absent string).
    pub fn is_empty(self) -> bool {
        self.offset == 0 && self.len == 0
    }

    fn write_to(self, out: &mut [u8]) {
        out[..4].copy_from_slice(&self.offset.to_le_bytes());
        out[4..6].copy_from_slice(&self.len.to_le_bytes());
    }

    fn read_from(inp: &[u8; 6]) -> Self {
        let offset = u32::from_le_bytes([inp[0], inp[1], inp[2], inp[3]]);
        let len = u16::from_le_bytes([inp[4], inp[5]]);
        Self { offset, len }
    }
}

/// In-memory contact record (RRAM wire layout via [`ContactRecord::as_bytes`]).
#[derive(Clone, Copy, Zeroize)]
pub struct ContactRecord {
    /// Active-record magic (`CONTACT_RECORD_MAGIC`); zeroed on delete.
    pub magic: u32,
    /// [`ContactFlags`] bitset.
    pub flags: u8,
    /// [`KeyAlgo`] wire id.
    pub key_algo: u8,
    /// Non-zero when the public key requires PIN unlock.
    pub pin_protected: u8,
    pub reserved0: u8,
    /// OpenPGP v4 fingerprint (32 bytes).
    pub fingerprint: [u8; 32],
    /// NUL-padded amateur-radio callsign (12 bytes).
    pub callsign: [u8; 12],
    /// DMR subscriber id (`0` = absent).
    pub dmr_id: u32,
    /// Offset into the key-material region.
    pub key_offset: u32,
    /// Length of the key blob.
    pub key_len: u16,
    pub reserved1: u16,
    /// AES-GCM nonce for PIN-wrapped keys.
    pub pin_nonce: [u8; 12],
    /// AES-GCM tag for PIN-wrapped keys.
    pub pin_tag: [u8; 16],
    /// Last key-fetch timestamp (seconds since epoch, host-defined).
    pub last_fetched: u32,
    /// Two-bit provenance per [`field`] id.
    pub source_map: u64,
    /// PIN verifier digest compared via `pin-policy` (32 bytes).
    pub pin_verifier: [u8; 32],
    pub email: StringRef,
    pub display_name: StringRef,
    pub badge_number: StringRef,
    pub organisation: StringRef,
    pub department: StringRef,
    pub role: StringRef,
    pub note: StringRef,
    pub radio_affiliation: StringRef,
    pub street: StringRef,
    pub country: StringRef,
    pub postal_code: StringRef,
    pub region: StringRef,
    pub fluxer_id: StringRef,
    pub discord_id: StringRef,
    pub irc_id: StringRef,
    pub reserved2: [u8; 26],
    /// CRC32C over bytes `0..230` (last four bytes of the record).
    pub crc32c: u32,
}

/// Wire size of [`ContactRecord`] (packed layout).
pub const CONTACT_RECORD_WIRE_BYTES: usize = 4
    + 4
    + 32
    + 12
    + 4
    + 4
    + 2
    + 2
    + 12
    + 16
    + 4
    + 8
    + 32
    + 15 * 6
    + 4
    + 26;

const _: () = assert!(CONTACT_RECORD_WIRE_BYTES == CONTACT_RECORD_BYTES);

fn read_u32(bytes: &[u8; CONTACT_RECORD_BYTES], o: &mut usize) -> u32 {
    let v = u32::from_le_bytes([
        bytes[*o],
        bytes[*o + 1],
        bytes[*o + 2],
        bytes[*o + 3],
    ]);
    *o += 4;
    v
}

fn read_u16(bytes: &[u8; CONTACT_RECORD_BYTES], o: &mut usize) -> u16 {
    let v = u16::from_le_bytes([bytes[*o], bytes[*o + 1]]);
    *o += 2;
    v
}

fn read_u64(bytes: &[u8; CONTACT_RECORD_BYTES], o: &mut usize) -> u64 {
    let v = u64::from_le_bytes([
        bytes[*o],
        bytes[*o + 1],
        bytes[*o + 2],
        bytes[*o + 3],
        bytes[*o + 4],
        bytes[*o + 5],
        bytes[*o + 6],
        bytes[*o + 7],
    ]);
    *o += 8;
    v
}

fn read_string_ref(bytes: &[u8; CONTACT_RECORD_BYTES], o: &mut usize) -> StringRef {
    let mut six = [0u8; 6];
    six.copy_from_slice(&bytes[*o..*o + 6]);
    *o += 6;
    StringRef::read_from(&six)
}

#[allow(clippy::derivable_impls)]
impl Default for ContactRecord {
    fn default() -> Self {
        Self {
            magic: 0,
            flags: 0,
            key_algo: 0,
            pin_protected: 0,
            reserved0: 0,
            fingerprint: [0u8; 32],
            callsign: [0u8; 12],
            dmr_id: 0,
            key_offset: 0,
            key_len: 0,
            reserved1: 0,
            pin_nonce: [0u8; 12],
            pin_tag: [0u8; 16],
            last_fetched: 0,
            source_map: 0,
            pin_verifier: [0u8; 32],
            email: StringRef::default(),
            display_name: StringRef::default(),
            badge_number: StringRef::default(),
            organisation: StringRef::default(),
            department: StringRef::default(),
            role: StringRef::default(),
            note: StringRef::default(),
            radio_affiliation: StringRef::default(),
            street: StringRef::default(),
            country: StringRef::default(),
            postal_code: StringRef::default(),
            region: StringRef::default(),
            fluxer_id: StringRef::default(),
            discord_id: StringRef::default(),
            irc_id: StringRef::default(),
            reserved2: [0u8; 26],
            crc32c: 0,
        }
    }
}

impl ContactRecord {
    /// True when magic and ACTIVE flag indicate an occupied slot.
    pub fn is_active(&self) -> bool {
        self.magic == CONTACT_RECORD_MAGIC
            && ContactFlags::from_bits_truncate(self.flags).contains(ContactFlags::ACTIVE)
    }

    /// Serialize to bytes.
    pub fn as_bytes(&self) -> [u8; CONTACT_RECORD_BYTES] {
        let mut out = [0u8; CONTACT_RECORD_BYTES];
        let mut o = 0usize;
        out[o..o + 4].copy_from_slice(&self.magic.to_le_bytes());
        o += 4;
        out[o] = self.flags;
        o += 1;
        out[o] = self.key_algo;
        o += 1;
        out[o] = self.pin_protected;
        o += 1;
        out[o] = self.reserved0;
        o += 1;
        out[o..o + 32].copy_from_slice(&self.fingerprint);
        o += 32;
        out[o..o + 12].copy_from_slice(&self.callsign);
        o += 12;
        out[o..o + 4].copy_from_slice(&self.dmr_id.to_le_bytes());
        o += 4;
        out[o..o + 4].copy_from_slice(&self.key_offset.to_le_bytes());
        o += 4;
        out[o..o + 2].copy_from_slice(&self.key_len.to_le_bytes());
        o += 2;
        out[o..o + 2].copy_from_slice(&self.reserved1.to_le_bytes());
        o += 2;
        out[o..o + 12].copy_from_slice(&self.pin_nonce);
        o += 12;
        out[o..o + 16].copy_from_slice(&self.pin_tag);
        o += 16;
        out[o..o + 4].copy_from_slice(&self.last_fetched.to_le_bytes());
        o += 4;
        out[o..o + 8].copy_from_slice(&self.source_map.to_le_bytes());
        o += 8;
        out[o..o + 32].copy_from_slice(&self.pin_verifier);
        o += 32;
        for r in [
            self.email,
            self.display_name,
            self.badge_number,
            self.organisation,
            self.department,
            self.role,
            self.note,
            self.radio_affiliation,
            self.street,
            self.country,
            self.postal_code,
            self.region,
            self.fluxer_id,
            self.discord_id,
            self.irc_id,
        ] {
            r.write_to(&mut out[o..o + 6]);
            o += 6;
        }
        out[o..o + 26].copy_from_slice(&self.reserved2);
        o += 26;
        out[o..o + 4].copy_from_slice(&self.crc32c.to_le_bytes());
        out
    }

    /// Load from RRAM bytes and verify CRC32C.
    pub fn from_bytes_verified(bytes: &[u8; CONTACT_RECORD_BYTES]) -> Result<Self, ContactStoreError> {
        if !record_crc_ok(bytes.as_slice()) {
            return Err(ContactStoreError::CorruptRecord);
        }
        let rec = Self::from_bytes_unchecked(bytes);
        if rec.magic == CONTACT_RECORD_MAGIC && rec.is_active() {
            let _ = KeyAlgo::from_wire(rec.key_algo)?;
        }
        Ok(rec)
    }

    /// Load without CRC check (boot rebuild paths verify separately).
    pub fn from_bytes_unchecked(bytes: &[u8; CONTACT_RECORD_BYTES]) -> Self {
        let mut o = 0usize;
        let magic = read_u32(bytes, &mut o);
        let flags = bytes[o];
        o += 1;
        let key_algo = bytes[o];
        o += 1;
        let pin_protected = bytes[o];
        o += 1;
        let reserved0 = bytes[o];
        o += 1;
        let mut fingerprint = [0u8; 32];
        fingerprint.copy_from_slice(&bytes[o..o + 32]);
        o += 32;
        let mut callsign = [0u8; 12];
        callsign.copy_from_slice(&bytes[o..o + 12]);
        o += 12;
        let dmr_id = read_u32(bytes, &mut o);
        let key_offset = read_u32(bytes, &mut o);
        let key_len = read_u16(bytes, &mut o);
        let reserved1 = read_u16(bytes, &mut o);
        let mut pin_nonce = [0u8; 12];
        pin_nonce.copy_from_slice(&bytes[o..o + 12]);
        o += 12;
        let mut pin_tag = [0u8; 16];
        pin_tag.copy_from_slice(&bytes[o..o + 16]);
        o += 16;
        let last_fetched = read_u32(bytes, &mut o);
        let source_map = read_u64(bytes, &mut o);
        let mut pin_verifier = [0u8; 32];
        pin_verifier.copy_from_slice(&bytes[o..o + 32]);
        o += 32;
        let email = read_string_ref(bytes, &mut o);
        let display_name = read_string_ref(bytes, &mut o);
        let badge_number = read_string_ref(bytes, &mut o);
        let organisation = read_string_ref(bytes, &mut o);
        let department = read_string_ref(bytes, &mut o);
        let role = read_string_ref(bytes, &mut o);
        let note = read_string_ref(bytes, &mut o);
        let radio_affiliation = read_string_ref(bytes, &mut o);
        let street = read_string_ref(bytes, &mut o);
        let country = read_string_ref(bytes, &mut o);
        let postal_code = read_string_ref(bytes, &mut o);
        let region = read_string_ref(bytes, &mut o);
        let fluxer_id = read_string_ref(bytes, &mut o);
        let discord_id = read_string_ref(bytes, &mut o);
        let irc_id = read_string_ref(bytes, &mut o);
        let mut reserved2 = [0u8; 26];
        reserved2.copy_from_slice(&bytes[o..o + 26]);
        o += 26;
        let crc32c = read_u32(bytes, &mut o);
        Self {
            magic,
            flags,
            key_algo,
            pin_protected,
            reserved0,
            fingerprint,
            callsign,
            dmr_id,
            key_offset,
            key_len,
            reserved1,
            pin_nonce,
            pin_tag,
            last_fetched,
            source_map,
            pin_verifier,
            email,
            display_name,
            badge_number,
            organisation,
            department,
            role,
            note,
            radio_affiliation,
            street,
            country,
            postal_code,
            region,
            fluxer_id,
            discord_id,
            irc_id,
            crc32c,
            reserved2,
        }
    }

    /// Recompute and store CRC32C over bytes before the CRC field.
    pub fn recompute_crc(&mut self) {
        let mut tmp = self.as_bytes();
        let body = &mut tmp[..CONTACT_RECORD_BYTES - 4];
        self.crc32c = crc32c(body);
    }

    /// Flags as a typed bitset.
    pub fn contact_flags(&self) -> ContactFlags {
        ContactFlags::from_bits_truncate(self.flags)
    }

    /// Set flags from a typed bitset.
    pub fn set_contact_flags(&mut self, f: ContactFlags) {
        self.flags = f.bits();
    }

    /// Validate string ref length bound.
    pub fn validate_string_ref(r: StringRef) -> Result<(), ContactStoreError> {
        if r.len > MAX_STRING_FIELD_BYTES {
            return Err(ContactStoreError::StringTooLong);
        }
        Ok(())
    }
}

/// Zeroizing public-key blob returned to callers (no `Clone` / `Copy`).
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct PublicKeyBlob {
    buf: [u8; crate::layout::MAX_PUBLIC_KEY_BYTES],
    len: usize,
}

impl PublicKeyBlob {
    /// Construct from key bytes (length must fit).
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ContactStoreError> {
        if bytes.len() > crate::layout::MAX_PUBLIC_KEY_BYTES {
            return Err(ContactStoreError::KeyTooLarge);
        }
        let mut s = Self {
            buf: [0u8; crate::layout::MAX_PUBLIC_KEY_BYTES],
            len: bytes.len(),
        };
        s.buf[..bytes.len()].copy_from_slice(bytes);
        Ok(s)
    }

    /// Key octets.
    pub fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

/// PIN bytes for unlock (zeroizes on drop; no `Clone` / `Copy`).
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct PinBuffer {
    bytes: [u8; 32],
    len: u8,
}

impl PinBuffer {
    /// Build from UTF-8 PIN (max 32 bytes).
    pub fn from_utf8(pin: &[u8]) -> Result<Self, ContactStoreError> {
        if pin.is_empty() || pin.len() > 32 {
            return Err(ContactStoreError::PinFailed);
        }
        let mut s = Self {
            bytes: [0u8; 32],
            len: pin.len() as u8,
        };
        s.bytes[..pin.len()].copy_from_slice(pin);
        Ok(s)
    }

    /// PIN octets.
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use static_assertions::assert_not_impl_any;

    assert_not_impl_any!(PublicKeyBlob: Clone, Copy);
    assert_not_impl_any!(PinBuffer: Clone, Copy);

    #[test]
    fn contact_record_wire_size_is_256_bytes() {
        assert_eq!(CONTACT_RECORD_WIRE_BYTES, 256);
    }

    #[test]
    fn key_algo_p512_rejected() {
        assert_eq!(
            KeyAlgo::from_wire(KEY_ALGO_WIRE_BRAINPOOL_P512),
            Err(ContactStoreError::RemovedBrainpoolP512)
        );
    }

    #[test]
    fn active_record_p512_key_algo_rejected_on_load() {
        let mut r = ContactRecord::default();
        r.magic = CONTACT_RECORD_MAGIC;
        r.set_contact_flags(ContactFlags::ACTIVE);
        r.key_algo = KEY_ALGO_WIRE_BRAINPOOL_P512;
        r.recompute_crc();
        let b = r.as_bytes();
        assert!(matches!(
            ContactRecord::from_bytes_verified(&b),
            Err(ContactStoreError::RemovedBrainpoolP512)
        ));
    }

    #[test]
    fn crc_roundtrip() {
        let mut r = ContactRecord::default();
        r.magic = CONTACT_RECORD_MAGIC;
        r.set_contact_flags(ContactFlags::ACTIVE);
        r.key_algo = KeyAlgo::Ed25519.to_wire();
        r.recompute_crc();
        let b = r.as_bytes();
        assert!(record_crc_ok(b.as_slice()));
        assert!(ContactRecord::from_bytes_verified(&b).is_ok());
    }

    #[test]
    fn field_source_map_helpers() {
        let mut m = 0u64;
        m = field_source_set(m, field::EMAIL, FieldSource::RegistrySync);
        assert_eq!(field_source_get(m, field::EMAIL), FieldSource::RegistrySync);
        assert_eq!(field_source_get(m, field::NOTE), FieldSource::SelfAttested);
    }
}
