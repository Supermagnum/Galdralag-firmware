use galdra_core_host::config::load_config;
use galdra_core_host::GaldraError;
use std::io::Write;

#[test]
fn malformed_toml_errors() {
    let mut f = tempfile::NamedTempFile::new().expect("tmp");
    writeln!(f, "this is not [[valid").expect("w");
    let err = load_config(f.path()).expect_err("err");
    assert!(matches!(err, GaldraError::Config(_)));
}
