use galdra_core_host::audit::{self, AuditAction, AuditEntry, AuditFilter};
use galdra_core_host::db::Db;
use chrono::Utc;

#[test]
fn csv_and_json_export_parse() {
    let mut db = Db::open_in_memory().expect("db");
    audit::audit_append(
        &mut db,
        AuditEntry {
            timestamp: Utc::now(),
            operator: None,
            action: AuditAction::Sign,
            subject: Some("x".to_string()),
            detail: Some("y".to_string()),
            device_serial: None,
        },
    )
    .expect("a");

    let mut csv = Vec::new();
    audit::audit_export_csv(
        &db,
        AuditFilter::default(),
        &mut csv,
    )
    .expect("csv");
    let s = String::from_utf8(csv).expect("utf8");
    assert!(s.contains("sign"));

    let mut json = Vec::new();
    audit::audit_export_json(
        &db,
        AuditFilter::default(),
        &mut json,
    )
    .expect("json");
    let v: serde_json::Value = serde_json::from_slice(&json).expect("parse");
    assert!(v.is_array());
}
