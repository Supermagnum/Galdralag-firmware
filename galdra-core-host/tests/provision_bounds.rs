use galdra_core_host::device::ProvisionPolicy;

#[test]
fn provision_policy_bounds() {
    assert!(ProvisionPolicy {
        pin_attempts: 2,
        min_pin_length: 8,
    }
    .validate()
    .is_err());

    assert!(ProvisionPolicy {
        pin_attempts: 3,
        min_pin_length: 8,
    }
    .validate()
    .is_ok());

    assert!(ProvisionPolicy {
        pin_attempts: 10,
        min_pin_length: 8,
    }
    .validate()
    .is_ok());

    assert!(ProvisionPolicy {
        pin_attempts: 11,
        min_pin_length: 8,
    }
    .validate()
    .is_err());

    assert!(ProvisionPolicy {
        pin_attempts: 5,
        min_pin_length: 4,
    }
    .validate()
    .is_err());

    assert!(ProvisionPolicy {
        pin_attempts: 5,
        min_pin_length: 5,
    }
    .validate()
    .is_ok());
}
