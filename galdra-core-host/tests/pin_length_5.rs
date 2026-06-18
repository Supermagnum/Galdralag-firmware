use galdra_core_host::device::PinBuffer;

#[test]
fn pin_five_chars_ok() {
    PinBuffer::new("abcde".to_string()).expect("ok");
}
