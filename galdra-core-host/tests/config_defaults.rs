use galdra_core_host::config::load_config;
use std::path::Path;

#[test]
fn missing_config_file_uses_defaults() {
    let p = Path::new("/nonexistent/galdra/config-impossible-xyz.toml");
    let c = load_config(p).expect("defaults");
    assert!(!c.keyservers.servers.is_empty());
    assert_eq!(c.key_expiry_warn_days, 30);
}
