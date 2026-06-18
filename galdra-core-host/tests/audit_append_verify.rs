use chrono::Utc;
use galdra_core_host::audit::{self, AuditAction, AuditEntry, AuditVerifyResult};
use galdra_core_host::db::Db;

#[test]
fn append_many_verify_ok() {
    let mut db = Db::open_in_memory().expect("db");
    for i in 0..10 {
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
    let v = audit::audit_verify_chain(&db).expect("verify");
    assert_eq!(v, AuditVerifyResult::Ok);
}
