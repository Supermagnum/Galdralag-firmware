//! Wire identifiers and user-facing text for algorithms retired after bp512 removal.
//!
//! See repository [CHANGELOG.md](https://github.com/Supermagnum/Galdralag-firmware/blob/main/CHANGELOG.md).

/// Contact-store [`KeyAlgo`] wire value for BrainpoolP512r1 (removed).
pub const KEY_ALGO_WIRE_BRAINPOOL_P512: u8 = 0x05;

/// Ephemeral session handshake curve byte for BrainpoolP512r1 (removed).
pub const SESSION_CURVE_WIRE_BRAINPOOL_P512: u8 = 0x03;

/// CESS registry suite id for the retired `high-assurance` built-in profile.
pub const CESS_SUITE_ID_HIGH_ASSURANCE: u16 = 0x0012;

/// Built-in cipher profile name retired with P-512 support.
pub const PROFILE_NAME_HIGH_ASSURANCE: &str = "high-assurance";

/// BrainpoolP512r1 OID (RFC 5639) in OpenPGP card algorithm attributes.
pub const BRAINPOOL_P512R1_OID: &[u8] = &[
    0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D,
];

/// User-facing text when a stored key or contact record names BrainpoolP512r1.
pub const MSG_KEY_ALGO_P512: &str = "This key uses BrainpoolP512r1, which was removed in this \
firmware/host version (unaudited implementation, see CHANGELOG). Generate a new key on a \
supported curve.";

/// User-facing text when ciphertext used the retired `high-assurance` profile / suite `0x0012`.
pub const MSG_CIPHERTEXT_HIGH_ASSURANCE: &str = "This ciphertext was encrypted with the \
high-assurance profile, which has been removed and cannot be decrypted by this version. Decrypt \
with a prior version before upgrading, or the data is permanently inaccessible.";

/// User-facing text when an ephemeral session handshake offers curve wire byte `0x03`.
pub const MSG_SESSION_CURVE_P512: &str = "This session was negotiated with BrainpoolP512r1 \
ephemeral ECDH, which is no longer supported. The peer must use a supported curve.";

/// Returns true when `suite_id` is listed in CESS but retired in Galdralag firmware.
#[inline]
pub fn is_retired_suite_id(id: u16) -> bool {
    id == CESS_SUITE_ID_HIGH_ASSURANCE
}

/// Returns true when an OpenPGP algorithm-attribute OID names BrainpoolP512r1.
#[inline]
pub fn is_brainpool_p512_oid(oid: &[u8]) -> bool {
    oid == BRAINPOOL_P512R1_OID
}
