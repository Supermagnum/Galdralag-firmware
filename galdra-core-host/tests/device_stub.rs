use galdra_core_host::device::Device;
use galdra_core_host::GaldraError;

#[test]
fn connect_stub_not_connected() {
    let r = Device::connect();
    assert!(matches!(r, Err(GaldraError::DeviceNotConnected)));
}
