//! Host-side security test harness stubs.
//!
//! Real constant-time analysis belongs in a controlled environment (fixed CPU frequency,
//! isolated cores). These symbols exist so CI and `cargo xtask timing-test` have a stable entry
//! point while [dudect](https://github.com/oreparaz/dudect)-style measurements are integrated.

#![forbid(unsafe_code)]

/// Placeholder for ChaCha20-Poly1305 decrypt timing classification.
pub fn dudect_stub_chacha_decrypt() -> DudectStatus {
    DudectStatus::NotRun
}

/// Placeholder for Shamir recovery timing classification.
pub fn dudect_stub_shamir_recover() -> DudectStatus {
    DudectStatus::NotRun
}

/// Placeholder for Brainpool scalar multiply / ECDH path classification.
pub fn dudect_stub_brainpool_ecdh() -> DudectStatus {
    DudectStatus::NotRun
}

/// Placeholder for Brainpool P-384r1 scalar multiplication timing classification.
pub fn timing_brainpool384_scalar_mult() -> DudectStatus {
    DudectStatus::NotRun
}

/// Placeholder for Brainpool P-512r1 scalar multiplication timing classification.
pub fn timing_brainpool512_scalar_mult() -> DudectStatus {
    DudectStatus::NotRun
}

/// Placeholder for Serpent EtM tag verification timing classification (target |t| <= 4.5 at 100k samples).
pub fn timing_serpent_tag_check() -> DudectStatus {
    DudectStatus::NotRun
}

/// Placeholder for RSA-OAEP decrypt timing classification (valid vs invalid ciphertext).
pub fn timing_rsa_oaep_decrypt() -> DudectStatus {
    DudectStatus::NotRun
}

/// Placeholder for RSA-PSS verify timing classification (valid vs invalid signatures).
pub fn timing_rsa_pss_verify() -> DudectStatus {
    DudectStatus::NotRun
}

/// Outcome of a timing study (stub values only until wired to dudect).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DudectStatus {
    /// Harness not executed on this host.
    NotRun,
    /// Placeholder for a completed run that still needs review.
    PendingIntegration,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stubs_are_callable() {
        assert_eq!(dudect_stub_chacha_decrypt(), DudectStatus::NotRun);
        assert_eq!(dudect_stub_shamir_recover(), DudectStatus::NotRun);
        assert_eq!(dudect_stub_brainpool_ecdh(), DudectStatus::NotRun);
        assert_eq!(timing_brainpool384_scalar_mult(), DudectStatus::NotRun);
        assert_eq!(timing_brainpool512_scalar_mult(), DudectStatus::NotRun);
        assert_eq!(timing_serpent_tag_check(), DudectStatus::NotRun);
        assert_eq!(timing_rsa_oaep_decrypt(), DudectStatus::NotRun);
        assert_eq!(timing_rsa_pss_verify(), DudectStatus::NotRun);
    }
}
