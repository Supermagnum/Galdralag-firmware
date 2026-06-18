//! Typed errors for [`crate::GaldraError`].

/// Primary error type for all public `galdra-core-host` APIs.
#[derive(Debug, thiserror::Error)]
pub enum GaldraError {
    /// SQLite or database layer failure.
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    /// No contact matches the given identifier.
    #[error("contact not found: {0}")]
    ContactNotFound(String),

    /// No group matches the given name.
    #[error("group not found: {0}")]
    GroupNotFound(String),

    /// Membership window has expired for this identity in the group.
    #[error("group membership expired for {identity} in {group}")]
    MembershipExpired { identity: String, group: String },

    /// No recipient can receive ciphertext because every key or membership is expired.
    #[error("all group members have expired keys — cannot encrypt")]
    AllMembersExpired,

    /// Keyserver, WKD, or LDAP fetch failed.
    #[error("key fetch failed: {0}")]
    KeyFetch(String),

    /// No USB token is present.
    #[error("device not connected")]
    DeviceNotConnected,

    /// Token must be unlocked before this operation.
    #[error("device locked — unlock with `galdra device unlock`")]
    DeviceLocked,

    /// PIN does not meet minimum length.
    #[error("PIN too short — minimum 5 alphanumeric characters")]
    PinTooShort,

    /// PIN contains disallowed characters.
    #[error("PIN must contain only alphanumeric characters (a-z, A-Z, 0-9)")]
    PinNotAlphanumeric,

    /// Low-level USB transport failure.
    #[error("USB error: {0}")]
    Usb(String),

    /// Configuration file or value is invalid.
    #[error("config error: {0}")]
    Config(String),

    /// Generic I/O failure (files, stdin, prompts).
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON or other serialisation failure.
    #[error("serialisation error: {0}")]
    Serialise(String),

    /// Audit log hash chain does not verify.
    #[error("audit log integrity check failed: {0}")]
    AuditChainBroken(String),

    /// User cancelled a destructive or sensitive action.
    #[error("operation aborted by user")]
    UserAborted,

    /// Token key slot already occupied.
    #[error("slot {0} is already occupied")]
    SlotOccupied(u32),

    /// Token key slot is empty.
    #[error("slot {0} is empty")]
    SlotEmpty(u32),

    /// OpenPGP or sequoia operation failed.
    #[error("OpenPGP error: {0}")]
    OpenPgp(String),

    /// No usable encryption subkey for a recipient.
    #[error("no encryption subkey: {0}")]
    NoEncryptionSubkey(String),

    /// LDAP operation failed.
    #[error("LDAP error: {0}")]
    Ldap(String),

    /// QR decode or image load failed.
    #[error("QR import error: {0}")]
    QrImport(String),

    /// age format not applicable for this recipient set.
    #[error("age format error: {0}")]
    AgeFormat(String),

    /// Cipher profile construction, cascade, or registry error.
    #[error("cipher profile: {0}")]
    CipherProfile(String),

    /// Named profile is not in the local registry.
    #[error("profile not found: {0}")]
    ProfileNotFound(String),

    /// User profile name already exists.
    #[error("profile already exists: {0}")]
    ProfileDuplicate(String),

    /// Shamir share export, recovery, or vault Shamir error.
    #[error("Shamir: {0}")]
    Shamir(String),

    /// Ephemeral key offer has passed its `expires_at` timestamp.
    #[error("ephemeral offer expired: {0}")]
    EpkExpired(String),

    /// Ephemeral key offer has already been consumed (single-use).
    #[error("ephemeral offer already consumed: {0}")]
    EpkConsumed(String),

    /// No ephemeral key offer found for the given session ID.
    #[error("ephemeral offer not found: {0}")]
    EpkNotFound(String),

    /// Smart card / PC/SC failure.
    #[error("smart card: {0}")]
    SmartCard(String),
}
