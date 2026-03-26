use galdra_core_host::audit::{self, AuditAction, AuditEntry, AuditVerifyResult};
use galdra_core_host::db::Db;
use chrono::Utc;

#[test]
fn delete_middle_row_breaks_chain() {
    let mut db = Db::open_in_memory().expect("db");
    for i in 0..5 {
        audit::audit_append(
            &mut db,
            AuditEntry {
                timestamp: Utc::now(),
                operator: None,
                action: AuditAction::Encrypt,
                subject: Some(format!("s{i}")),
                detail: None,
                device_serial: None,
            },
        )
        .expect("append");
    }
    db.connection_mut()
        .execute("DELETE FROM audit_log WHERE id = 3", [])
        .expect("sql");
    let v = audit::audit_verify_chain(&db).expect("verify");
    assert!(matches!(v, AuditVerifyResult::ChainBroken { .. }));
}
