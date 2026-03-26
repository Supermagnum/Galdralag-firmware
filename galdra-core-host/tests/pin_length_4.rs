use galdra_core_host::device::PinBuffer;
use galdra_core_host::GaldraError;

#[test]
fn pin_four_chars_rejected() {
    let r = PinBuffer::new("abcd".to_string());
    assert!(matches!(r, Err(GaldraError::PinTooShort)));
}
