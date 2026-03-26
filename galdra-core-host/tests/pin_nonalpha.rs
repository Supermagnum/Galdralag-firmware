use galdra_core_host::device::PinBuffer;
use galdra_core_host::GaldraError;

#[test]
fn pin_non_alphanumeric_rejected() {
    let r = PinBuffer::new("abc!e".to_string());
    assert!(matches!(r, Err(GaldraError::PinNotAlphanumeric)));
}
