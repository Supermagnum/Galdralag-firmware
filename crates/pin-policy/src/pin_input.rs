//! Parser boundary for PIN and challenge-response passphrases (minimum length, alphanumeric profile).

/// Errors returned before any PIN policy state transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PinParseError {
    /// Fewer than five characters in the Unicode sense.
    TooShort,
    /// Contains a character outside `[A-Za-z0-9]`.
    InvalidCharacter,
}

/// Parse a PIN or passphrase for the informed-host path. **Call this before** constructing a
/// [`crate::PinPolicyMachine`] attempt so short or invalid inputs do not touch the attempt counter.
pub fn parse_unlock_pin(input: &str) -> Result<&str, PinParseError> {
    let len = input.chars().count();
    if len < 5 {
        return Err(PinParseError::TooShort);
    }
    if !input.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(PinParseError::InvalidCharacter);
    }
    Ok(input)
}

/// Same rules as [`parse_unlock_pin`] for `HMAC-SHA256(HostChallengeKey, nonce || passphrase)`. The
/// raw passphrase is never transmitted over USB; only this parsed form is hashed.
pub fn parse_challenge_passphrase(input: &str) -> Result<&str, PinParseError> {
    parse_unlock_pin(input)
}
