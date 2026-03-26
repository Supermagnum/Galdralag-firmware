use galdra_core_host::config::{database_key_from_env, Config};
use galdra_core_host::db::Db;
use galdra_core_host::GaldraError;

#[test]
fn sqlcipher_open_roundtrip() {
    let dir = tempfile::tempdir().expect("tmp");
    let path = dir.path().join("enc.db");
    let passphrase = "correct horse battery staple";

    {
        let db = Db::open(&path, Some(passphrase)).expect("open new");
        let n: i64 = db
            .connection()
            .query_row("SELECT COUNT(*) FROM schema_migrations", [], |r| r.get(0))
            .expect("count");
        assert!(n >= 1);
    }
    {
        let db = Db::open(&path, Some(passphrase)).expect("reopen");
        let n: i64 = db
            .connection()
            .query_row("SELECT COUNT(*) FROM schema_migrations", [], |r| r.get(0))
            .expect("count");
        assert!(n >= 1);
    }
    match Db::open(&path, Some("wrong passphrase")) {
        Ok(_) => panic!("expected failure with wrong key"),
        Err(e) => assert!(matches!(e, GaldraError::Database(_))),
    }
}

#[test]
fn database_key_from_env_missing_var_errors() {
    let mut c = Config::default();
    c.database_key_env = Some("GALDRA_TEST_DB_KEY_ABSENT_9f3a2c1e".to_string());
    std::env::remove_var("GALDRA_TEST_DB_KEY_ABSENT_9f3a2c1e");
    let e = database_key_from_env(&c).expect_err("missing env");
    match e {
        GaldraError::Config(msg) => assert!(msg.contains("not set"), "{msg}"),
        o => panic!("expected Config error, got {o:?}"),
    }
}
