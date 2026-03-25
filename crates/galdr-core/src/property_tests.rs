//! Property-based checks for HAL-style mocks (not a substitute for silicon validation).

use crate::hal::MonotonicCounter;
use crate::HalError;
use proptest::prelude::*;

struct LocalCounter(u32);

impl MonotonicCounter for LocalCounter {
    fn read(&self) -> Result<u32, HalError> {
        Ok(self.0)
    }

    fn increment(&mut self) -> Result<u32, HalError> {
        self.0 = self.0.saturating_add(1);
        Ok(self.0)
    }
}

proptest! {
    #[test]
    fn counter_never_decrements(k in 0usize..256usize) {
        let mut c = LocalCounter(0);
        let mut last = 0u32;
        for _ in 0..k {
            let n = c.increment().unwrap();
            prop_assert!(n >= last);
            last = n;
        }
    }
}
