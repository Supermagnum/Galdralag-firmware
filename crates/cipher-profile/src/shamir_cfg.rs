//! Shamir K-of-N metadata attached to a profile (long-term key handling).

use crate::error::CipherProfileError;

/// Shamir K-of-N configuration attached to a cipher profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShamirConfig {
    /// Minimum shares required to reconstruct. Range: 1–255.
    pub threshold: u8,
    /// Total shares to generate. Range: threshold–255.
    pub total: u8,
}

impl ShamirConfig {
    /// Create and validate a Shamir configuration.
    pub fn new(threshold: u8, total: u8) -> Result<Self, CipherProfileError> {
        if threshold == 0 {
            return Err(CipherProfileError::InvalidShamirConfig);
        }
        if total == 0 {
            return Err(CipherProfileError::InvalidShamirConfig);
        }
        if threshold > total {
            return Err(CipherProfileError::InvalidShamirConfig);
        }
        Ok(Self { threshold, total })
    }

    /// No Shamir splitting (single holder).
    pub fn none() -> Self {
        Self {
            threshold: 1,
            total: 1,
        }
    }

    /// `true` when more than one share exists.
    pub fn is_active(self) -> bool {
        self.total > 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shamir_valid() {
        assert_eq!(
            ShamirConfig::new(2, 5),
            Ok(ShamirConfig {
                threshold: 2,
                total: 5,
            })
        );
    }

    #[test]
    fn shamir_k_zero() {
        assert_eq!(
            ShamirConfig::new(0, 5),
            Err(CipherProfileError::InvalidShamirConfig)
        );
    }

    #[test]
    fn shamir_k_gt_n() {
        assert_eq!(
            ShamirConfig::new(4, 3),
            Err(CipherProfileError::InvalidShamirConfig)
        );
    }

    #[test]
    fn shamir_n_zero() {
        assert_eq!(
            ShamirConfig::new(1, 0),
            Err(CipherProfileError::InvalidShamirConfig)
        );
    }

    #[test]
    fn shamir_none() {
        let n = ShamirConfig::none();
        assert_eq!(n.threshold, 1);
        assert_eq!(n.total, 1);
        assert!(!n.is_active());
    }
}
