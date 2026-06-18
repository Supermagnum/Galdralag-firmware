//! Integration tests for ephemeral key offer lifecycle (public API surface).

use chrono::Utc;
use galdra_core_host::audit::{audit_query, AuditAction, AuditFilter};
use galdra_core_host::db::Db;
use galdra_core_host::ephemeral_offers::{
    check_expiry, check_not_consumed, get_offer, list_offers, mark_consumed, revoke_offer,
    store_offer, OfferRow,
};
use galdra_core_host::GaldraError;

fn mem_db() -> Db {
    Db::open_in_memory().expect("in-memory db")
}

fn row(session_id: &str, delta_secs: i64) -> OfferRow {
    let now = Utc::now().timestamp();
    OfferRow {
        session_id: session_id.to_string(),
        epk_hex: "04".repeat(33),
        curve: "brainpoolP256r1".to_string(),
        long_term_fingerprint: "deadbeefdeadbeef".to_string(),
        signature_hex: "cafebabe".to_string(),
        expires_at: now + delta_secs,
        created_at: now,
        consumed: false,
        revoked: false,
        imported_at: Utc::now().to_rfc3339(),
        my_private_key_bytes: None,
    }
}

// ---------------------------------------------------------------------------
// Migration
// ---------------------------------------------------------------------------

#[test]
fn migration_004_creates_table_and_index() {
    let db = mem_db();
    let table_count: i64 = db
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='ephemeral_offers'",
            [],
            |r| r.get(0),
        )
        .expect("query table");
    assert_eq!(table_count, 1, "ephemeral_offers table must exist");

    let index_count: i64 = db
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_ephemeral_offers_expires'",
            [],
            |r| r.get(0),
        )
        .expect("query index");
    assert_eq!(index_count, 1, "expiry index must exist");
}

// ---------------------------------------------------------------------------
// Store / get
// ---------------------------------------------------------------------------

#[test]
fn store_and_retrieve_all_fields() {
    let mut db = mem_db();
    let now = Utc::now().timestamp();
    let r = OfferRow {
        session_id: "aaaa0000bbbb1111".to_string(),
        epk_hex: "04".repeat(33),
        curve: "brainpoolP256r1".to_string(),
        long_term_fingerprint: "ff00ff00ff00".to_string(),
        signature_hex: "1234abcd".to_string(),
        expires_at: now + 7200,
        created_at: now,
        consumed: false,
        revoked: false,
        imported_at: Utc::now().to_rfc3339(),
        my_private_key_bytes: Some(vec![0xaa; 32]),
    };
    store_offer(&mut db, &r).expect("store");
    let got = get_offer(&db, "aaaa0000bbbb1111").expect("get");

    assert_eq!(got.session_id, r.session_id);
    assert_eq!(got.epk_hex, r.epk_hex);
    assert_eq!(got.curve, r.curve);
    assert_eq!(got.long_term_fingerprint, r.long_term_fingerprint);
    assert_eq!(got.expires_at, r.expires_at);
    assert_eq!(got.created_at, r.created_at);
    assert!(!got.consumed);
    assert!(!got.revoked);
    assert_eq!(
        got.my_private_key_bytes.as_deref(),
        Some([0xaa_u8; 32].as_ref())
    );
}

// ---------------------------------------------------------------------------
// Expiry checks
// ---------------------------------------------------------------------------

#[test]
fn check_expiry_past_returns_error() {
    let r = row("exp_past", -1);
    let err = check_expiry(&r).expect_err("should be expired");
    assert!(matches!(err, GaldraError::EpkExpired(_)));
}

#[test]
fn check_expiry_future_is_ok() {
    let r = row("exp_future", 3600);
    check_expiry(&r).expect("must be valid");
}

// ---------------------------------------------------------------------------
// Consumed checks
// ---------------------------------------------------------------------------

#[test]
fn check_not_consumed_on_fresh_offer() {
    let r = row("fresh", 3600);
    check_not_consumed(&r).expect("should not be consumed");
}

#[test]
fn check_not_consumed_on_consumed_offer() {
    let mut r = row("consumed", 3600);
    r.consumed = true;
    let err = check_not_consumed(&r).expect_err("should be consumed");
    assert!(matches!(err, GaldraError::EpkConsumed(_)));
}

// ---------------------------------------------------------------------------
// Mark consumed
// ---------------------------------------------------------------------------

#[test]
fn mark_consumed_sets_flag_and_second_call_errors() {
    let mut db = mem_db();
    store_offer(&mut db, &row("mc_test", 3600)).expect("store");
    mark_consumed(&mut db, "mc_test").expect("first mark");
    let got = get_offer(&db, "mc_test").expect("get");
    assert!(got.consumed);

    let err = mark_consumed(&mut db, "mc_test").expect_err("second mark");
    assert!(matches!(err, GaldraError::EpkConsumed(_)));
}

// ---------------------------------------------------------------------------
// Revoke
// ---------------------------------------------------------------------------

#[test]
fn revoke_sets_revoked_and_nulls_private_key() {
    let mut db = mem_db();
    let mut r = row("revoke_me", 3600);
    r.my_private_key_bytes = Some(vec![0x7f; 32]);
    store_offer(&mut db, &r).expect("store");

    revoke_offer(&mut db, "revoke_me").expect("revoke");

    let got = get_offer(&db, "revoke_me").expect("get");
    assert!(got.revoked);
    assert!(got.my_private_key_bytes.is_none());
}

#[test]
fn revoke_nonexistent_offer_returns_not_found() {
    let mut db = mem_db();
    let err = revoke_offer(&mut db, "does_not_exist").expect_err("must fail");
    assert!(matches!(err, GaldraError::EpkNotFound(_)));
}

// ---------------------------------------------------------------------------
// List
// ---------------------------------------------------------------------------

#[test]
fn list_offers_returns_all_rows_newest_first() {
    let mut db = mem_db();
    let now = Utc::now().timestamp();

    let mut r1 = row("session_older_001", 3600);
    r1.created_at = now - 200;
    let mut r2 = row("session_newer_002", 7200);
    r2.created_at = now - 100;

    store_offer(&mut db, &r1).expect("s1");
    store_offer(&mut db, &r2).expect("s2");

    let rows = list_offers(&db).expect("list");
    assert_eq!(rows.len(), 2);
    // Newest first by created_at.
    assert_eq!(rows[0].session_id, "session_newer_002");
    assert_eq!(rows[1].session_id, "session_older_001");
}

// ---------------------------------------------------------------------------
// Audit integration
// ---------------------------------------------------------------------------

#[test]
fn epk_import_and_reject_actions_appear_in_audit_log() {
    use galdra_core_host::audit::{audit_append, AuditEntry};

    let mut db = mem_db();
    store_offer(&mut db, &row("audit_sid_import", 3600)).expect("store");

    audit_append(
        &mut db,
        AuditEntry {
            timestamp: Utc::now(),
            operator: Some("test-op".to_string()),
            action: AuditAction::EpkImport,
            subject: Some("audit_sid_import".to_string()),
            detail: Some(r#"{"session_id":"audit_sid_import"}"#.to_string()),
            device_serial: None,
        },
    )
    .expect("audit import");

    audit_append(
        &mut db,
        AuditEntry {
            timestamp: Utc::now(),
            operator: None,
            action: AuditAction::EpkReject,
            subject: Some("audit_sid_reject".to_string()),
            detail: Some(r#"{"session_id":"audit_sid_reject","reason":"expired"}"#.to_string()),
            device_serial: None,
        },
    )
    .expect("audit reject");

    let import_rows = audit_query(
        &db,
        AuditFilter {
            since: None,
            action: Some(AuditAction::EpkImport),
            limit: None,
        },
    )
    .expect("query import");
    assert_eq!(import_rows.len(), 1);
    assert_eq!(import_rows[0].action, AuditAction::EpkImport);
    assert_eq!(import_rows[0].subject.as_deref(), Some("audit_sid_import"));
    assert!(import_rows[0]
        .detail
        .as_deref()
        .unwrap_or("")
        .contains("audit_sid_import"));

    let reject_rows = audit_query(
        &db,
        AuditFilter {
            since: None,
            action: Some(AuditAction::EpkReject),
            limit: None,
        },
    )
    .expect("query reject");
    assert_eq!(reject_rows.len(), 1);
    assert!(reject_rows[0]
        .detail
        .as_deref()
        .unwrap_or("")
        .contains("expired"));
}

// ---------------------------------------------------------------------------
// Not found
// ---------------------------------------------------------------------------

#[test]
fn get_offer_returns_not_found_for_unknown_session() {
    let db = mem_db();
    let err = get_offer(&db, "unknown_session").expect_err("must fail");
    assert!(matches!(err, GaldraError::EpkNotFound(_)));
}

#[test]
fn mark_consumed_returns_not_found_for_unknown_session() {
    let mut db = mem_db();
    let err = mark_consumed(&mut db, "unknown_session").expect_err("must fail");
    assert!(matches!(err, GaldraError::EpkNotFound(_)));
}
