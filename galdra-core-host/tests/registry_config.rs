use galdra_core_host::config::load_config;
use galdra_core_host::registry::{endpoints_from_config, resolve_registry};
use std::io::Write;

#[test]
fn geographic_nodes_parse_and_order() {
    let mut f = tempfile::NamedTempFile::new().expect("tmp");
    writeln!(
        f,
        r#"
[keyserver]
enabled = true
failover = true
timeout_seconds = 20
url = "https://legacy.invalid"

[[keyserver.nodes]]
region = "Northern Europe"
node_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
url = "https://oslo.invalid"

[[keyserver.nodes]]
region = "Western Europe"
url = "https://de.invalid"
"#
    )
    .expect("w");
    let cfg = load_config(f.path()).expect("parse");
    let ks = cfg.keyserver.as_ref().expect("keyserver section");
    let eps = endpoints_from_config(ks).expect("endpoints");
    assert_eq!(eps.len(), 2);
    assert_eq!(eps[0].region.as_deref(), Some("Northern Europe"));
    assert_eq!(eps[0].url, "https://oslo.invalid");
    assert_eq!(eps[1].url, "https://de.invalid");

    let resolved = resolve_registry(None, Some(ks), None).expect("resolve");
    assert!(resolved.failover);
    assert_eq!(resolved.timeout_seconds, 20);
    assert_eq!(resolved.endpoints.len(), 2);
}

#[test]
fn failover_disabled_in_config() {
    let mut f = tempfile::NamedTempFile::new().expect("tmp");
    writeln!(
        f,
        r#"
[keyserver]
url = "https://only.invalid"
failover = false

[[keyserver.nodes]]
region = "A"
url = "https://a.invalid"

[[keyserver.nodes]]
region = "B"
url = "https://b.invalid"
"#
    )
    .expect("w");
    let ks = load_config(f.path()).expect("parse").keyserver.unwrap();
    let resolved = resolve_registry(None, Some(&ks), None).expect("resolve");
    assert!(!resolved.failover);
}

#[test]
fn registry_disabled_errors() {
    let mut f = tempfile::NamedTempFile::new().expect("tmp");
    writeln!(
        f,
        r#"
[keyserver]
enabled = false
url = "https://off.invalid"
"#
    )
    .expect("w");
    let ks = load_config(f.path()).expect("parse").keyserver.unwrap();
    assert!(resolve_registry(None, Some(&ks), None).is_err());
}
