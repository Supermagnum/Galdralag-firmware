use galdra_core_host::db::Db;

#[test]
fn migrations_create_expected_tables() {
    let db = Db::open_in_memory().expect("db");
    let mut stmt = db
        .connection()
        .prepare(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name",
        )
        .expect("prepare");
    let names: Vec<String> = stmt
        .query_map([], |row| row.get(0))
        .expect("q")
        .filter_map(|r| r.ok())
        .collect();
    assert!(names.iter().any(|n| n == "identities"));
    assert!(names.iter().any(|n| n == "groups"));
    assert!(names.iter().any(|n| n == "group_metadata"));
    assert!(names.iter().any(|n| n == "audit_log"));
    assert!(names.iter().any(|n| n == "config"));
    assert!(names.iter().any(|n| n == "schema_migrations"));

    let mut stmt = db
        .connection()
        .prepare("PRAGMA table_info(identities)")
        .expect("pragma");
    let cols: Vec<String> = stmt
        .query_map([], |row| row.get::<_, String>(1))
        .expect("q")
        .filter_map(|r| r.ok())
        .collect();
    assert!(cols.contains(&"pgp_pubkey".to_string()));
    assert!(cols.contains(&"source".to_string()));

    let mut stmt = db
        .connection()
        .prepare("PRAGMA table_info(audit_log)")
        .expect("pragma");
    let cols: Vec<String> = stmt
        .query_map([], |row| row.get::<_, String>(1))
        .expect("q")
        .filter_map(|r| r.ok())
        .collect();
    assert!(cols.contains(&"prev_hash".to_string()));
}

#[test]
fn schema_migrations_records_versions() {
    let db = Db::open_in_memory().expect("db");
    let v: i64 = db
        .connection()
        .query_row("SELECT MAX(version) FROM schema_migrations", [], |r| r.get(0))
        .expect("v");
    assert!(v >= 2);
}
