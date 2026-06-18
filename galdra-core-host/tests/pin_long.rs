use galdra_core_host::device::PinBuffer;

#[test]
fn pin_long_alphanumeric_ok() {
    let s = "a".repeat(100);
    PinBuffer::new(s).expect("ok");
}
