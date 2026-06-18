//! OpenPGP card status words (ISO 7816-4 and OpenPGP card application).

#![deny(unsafe_code)]

/// OpenPGP card status words (ISO 7816-4 + OpenPGP extensions).
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum StatusWord {
    /// 0x9000 — success.
    Success,
    /// 0x6100 — response bytes still available (GET RESPONSE); SW2 holds count (or 0xFF).
    MoreDataAvailable(u8),
    /// 0x6285 — selected file in termination state (card locked).
    TerminationState,
    /// 0x6300 — verification failed (wrong PIN).
    VerificationFailed,
    /// 0x63Cx — verification failed, x retries remaining (low nibble).
    VerificationFailedRetries(u8),
    /// 0x6400 — execution error (no precise diagnosis).
    ExecutionError,
    /// 0x6581 — memory failure.
    MemoryFailure,
    /// 0x6700 — wrong length.
    WrongLength,
    /// 0x6881 — logical channel not supported.
    LogicalChannelNotSupported,
    /// 0x6882 — secure messaging not supported.
    SecureMessagingNotSupported,
    /// 0x6900 — command not allowed.
    CommandNotAllowed,
    /// 0x6982 — security status not satisfied (PIN not verified).
    SecurityStatusNotSatisfied,
    /// 0x6983 — authentication method blocked (PIN blocked).
    AuthMethodBlocked,
    /// 0x6985 — conditions of use not satisfied.
    ConditionsNotSatisfied,
    /// 0x6A80 — incorrect parameters in command data.
    IncorrectParameters,
    /// 0x6A82 — file (application) not found.
    FileNotFound,
    /// 0x6A88 — reference data not found (key slot empty).
    ReferenceDataNotFound,
    /// 0x6B00 — wrong parameters P1-P2.
    WrongParametersP1P2,
    /// 0x6D00 — instruction code not supported.
    InstructionNotSupported,
    /// 0x6E00 — class not supported.
    ClassNotSupported,
    /// 0x6F00 — no precise diagnosis.
    NoPreciseDiagnosis,
}

impl StatusWord {
    /// ISO 7816-4 SW1.
    pub fn sw1(self) -> u8 {
        match self {
            StatusWord::Success => 0x90,
            StatusWord::MoreDataAvailable(_) => 0x61,
            StatusWord::TerminationState => 0x62,
            StatusWord::VerificationFailed => 0x63,
            StatusWord::VerificationFailedRetries(_) => 0x63,
            StatusWord::ExecutionError => 0x64,
            StatusWord::MemoryFailure => 0x65,
            StatusWord::WrongLength => 0x67,
            StatusWord::LogicalChannelNotSupported => 0x68,
            StatusWord::SecureMessagingNotSupported => 0x68,
            StatusWord::CommandNotAllowed => 0x69,
            StatusWord::SecurityStatusNotSatisfied => 0x69,
            StatusWord::AuthMethodBlocked => 0x69,
            StatusWord::ConditionsNotSatisfied => 0x69,
            StatusWord::IncorrectParameters => 0x6A,
            StatusWord::FileNotFound => 0x6A,
            StatusWord::ReferenceDataNotFound => 0x6A,
            StatusWord::WrongParametersP1P2 => 0x6B,
            StatusWord::InstructionNotSupported => 0x6D,
            StatusWord::ClassNotSupported => 0x6E,
            StatusWord::NoPreciseDiagnosis => 0x6F,
        }
    }

    /// ISO 7816-4 SW2.
    pub fn sw2(self) -> u8 {
        match self {
            StatusWord::Success => 0x00,
            StatusWord::MoreDataAvailable(n) => n,
            StatusWord::TerminationState => 0x85,
            StatusWord::VerificationFailed => 0x00,
            StatusWord::VerificationFailedRetries(x) => 0xC0 | (x & 0x0F),
            StatusWord::ExecutionError => 0x00,
            StatusWord::MemoryFailure => 0x81,
            StatusWord::WrongLength => 0x00,
            StatusWord::LogicalChannelNotSupported => 0x81,
            StatusWord::SecureMessagingNotSupported => 0x82,
            StatusWord::CommandNotAllowed => 0x00,
            StatusWord::SecurityStatusNotSatisfied => 0x82,
            StatusWord::AuthMethodBlocked => 0x83,
            StatusWord::ConditionsNotSatisfied => 0x85,
            StatusWord::IncorrectParameters => 0x80,
            StatusWord::FileNotFound => 0x82,
            StatusWord::ReferenceDataNotFound => 0x88,
            StatusWord::WrongParametersP1P2 => 0x00,
            StatusWord::InstructionNotSupported => 0x00,
            StatusWord::ClassNotSupported => 0x00,
            StatusWord::NoPreciseDiagnosis => 0x00,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_word_bytes_cover_common_cases() {
        let cases = [
            (StatusWord::Success, 0x90, 0x00),
            (StatusWord::SecurityStatusNotSatisfied, 0x69, 0x82),
            (StatusWord::MoreDataAvailable(0x42), 0x61, 0x42),
            (StatusWord::VerificationFailedRetries(3), 0x63, 0xC3), // SW2 encodes remaining tries
        ];
        for (sw, e1, e2) in cases {
            assert_eq!(sw.sw1(), e1, "sw1 {:?}", sw);
            assert_eq!(sw.sw2(), e2, "sw2 {:?}", sw);
        }
    }
}
