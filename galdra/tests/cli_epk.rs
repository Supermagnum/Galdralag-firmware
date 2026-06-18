//! CLI integration tests for the `galdra epk` subcommand.

use assert_cmd::Command;
use galdra_core_host::db::Db;
use predicates::prelude::*;
use tempfile::TempDir;

fn fresh_db(path: &std::path::Path) {
    Db::open(path, None).expect("db");
}

// ---------------------------------------------------------------------------
// `epk status` — does not require GPG; works on an empty DB.
// ---------------------------------------------------------------------------

#[test]
fn epk_status_empty_db_exits_zero() {
    let dir = TempDir::new().expect("tmp");
    let db_path = dir.path().join("g.db");
    fresh_db(&db_path);

    Command::cargo_bin("galdra")
        .expect("galdra")
        .env("HOME", dir.path())
        .args([
            "--db",
            db_path.to_str().expect("utf8"),
            "epk",
            "status",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("No ephemeral offers"));
}

#[test]
fn epk_status_json_empty_db() {
    let dir = TempDir::new().expect("tmp");
    let db_path = dir.path().join("g.db");
    fresh_db(&db_path);

    let out = Command::cargo_bin("galdra")
        .expect("galdra")
        .env("HOME", dir.path())
        .args([
            "--db",
            db_path.to_str().expect("utf8"),
            "--emit",
            "json",
            "epk",
            "status",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let v: serde_json::Value =
        serde_json::from_slice(&out).expect("valid JSON");
    assert_eq!(v["offers"].as_array().expect("array").len(), 0);
}

// ---------------------------------------------------------------------------
// `epk expire` — requires --confirm; does not require GPG.
// ---------------------------------------------------------------------------

#[test]
fn epk_expire_without_confirm_exits_nonzero() {
    let dir = TempDir::new().expect("tmp");
    let db_path = dir.path().join("g.db");
    fresh_db(&db_path);

    Command::cargo_bin("galdra")
        .expect("galdra")
        .env("HOME", dir.path())
        .args([
            "--db",
            db_path.to_str().expect("utf8"),
            "epk",
            "expire",
            "no_such_session",
        ])
        .assert()
        .failure();
}

#[test]
fn epk_expire_nonexistent_session_with_confirm_exits_nonzero() {
    let dir = TempDir::new().expect("tmp");
    let db_path = dir.path().join("g.db");
    fresh_db(&db_path);

    Command::cargo_bin("galdra")
        .expect("galdra")
        .env("HOME", dir.path())
        .args([
            "--db",
            db_path.to_str().expect("utf8"),
            "epk",
            "expire",
            "no_such_session",
            "--confirm",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
}

// ---------------------------------------------------------------------------
// `epk generate` — requires gpg in PATH; marked ignore.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires gpg in PATH with a test keyring and signing key"]
fn epk_generate_produces_gpg_file() {
    let dir = TempDir::new().expect("tmp");
    let db_path = dir.path().join("g.db");
    fresh_db(&db_path);
    let out_path = dir.path().join("test.epk.gpg");

    Command::cargo_bin("galdra")
        .expect("galdra")
        .env("HOME", dir.path())
        .args([
            "--db",
            db_path.to_str().expect("utf8"),
            "epk",
            "generate",
            "--gpg-key-id",
            "TEST_KEY_ID",
            "--recipient",
            "TEST_KEY_ID",
            "--expires",
            "3600",
            "--output",
            out_path.to_str().expect("utf8"),
        ])
        .assert()
        .success();

    assert!(out_path.exists());
    assert!(std::fs::metadata(&out_path).expect("meta").len() > 0);
}

// ---------------------------------------------------------------------------
// `epk import` — requires gpg in PATH; marked ignore.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires gpg in PATH and a valid .epk.gpg fixture file"]
fn epk_import_valid_offer_stores_in_db() {
    let dir = TempDir::new().expect("tmp");
    let db_path = dir.path().join("g.db");
    fresh_db(&db_path);

    // This test requires a pre-generated fixture file and a known fingerprint.
    // Run `galdra epk generate` first to produce one, then update the paths below.
    Command::cargo_bin("galdra")
        .expect("galdra")
        .env("HOME", dir.path())
        .args([
            "--db",
            db_path.to_str().expect("utf8"),
            "epk",
            "import",
            "test_fixtures/test.epk.gpg",
            "--verify-fingerprint",
            "AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD",
        ])
        .assert()
        .success();

    Command::cargo_bin("galdra")
        .expect("galdra")
        .env("HOME", dir.path())
        .args([
            "--db",
            db_path.to_str().expect("utf8"),
            "--emit",
            "json",
            "epk",
            "status",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("session_id"));
}
