//! HAL contract smoke tests (local mocks; do not require `test-hal`).

use crate::hal::MonotonicCounter;
use crate::HalError;

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

#[test]
fn monotonic_counter_increments() {
    let mut c = LocalCounter(0);
    assert_eq!(c.increment().unwrap(), 1);
    assert_eq!(c.read().unwrap(), 1);
}
