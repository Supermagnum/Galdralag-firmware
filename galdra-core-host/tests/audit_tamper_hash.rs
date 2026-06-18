use chrono::Utc;
use galdra_core_host::audit::{self, AuditAction, AuditEntry, AuditVerifyResult};
use galdra_core_host::db::Db;

#[test]
fn update_prev_hash_breaks_chain() {
    let mut db = Db::open_in_memory().expect("db");
    for i in 0..4 {
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
        .execute(
            "UPDATE audit_log SET prev_hash = 'ff' || substr(prev_hash, 3) WHERE id = 2",
            [],
        )
        .expect("sql");
    let v = audit::audit_verify_chain(&db).expect("verify");
    assert!(matches!(v, AuditVerifyResult::ChainBroken { .. }));
}
