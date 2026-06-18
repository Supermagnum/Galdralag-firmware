//! CLI integration tests for HTTP registry commands.

use assert_cmd::Command;
use galdra_core_host::db::Db;
use predicates::prelude::*;
use sequoia_openpgp::armor;
use sequoia_openpgp::cert::CertBuilder;
use sequoia_openpgp::serialize::Serialize as PgpSerialize;
use tempfile::TempDir;

fn fresh_db(path: &std::path::Path) {
    let _db = Db::open(path, None).expect("db");
}

fn armored_pubkey_tmp(dir: &std::path::Path) -> std::path::PathBuf {
    let (cert, _) = CertBuilder::new()
        .add_userid("Fixture <test@example.com>")
        .add_signing_subkey()
        .generate()
        .expect("generate");
    let mut buf = Vec::new();
    let mut w =
        armor::Writer::new(&mut buf, armor::Kind::PublicKey).expect("armor writer");
    cert.serialize(&mut w).expect("serialize cert");
    w.finalize().expect("finalize armor");
    let text = String::from_utf8(buf).expect("utf8");
    let path = dir.join("fixture.asc");
    std::fs::write(&path, text).expect("write");
    path
}

#[test]
fn keyserver_push_dry_run_fixture_outputs_json() {
    let dir = TempDir::new().expect("tmp");
    let db_path = dir.path().join("g.db");
    fresh_db(&db_path);
    let pubkey = armored_pubkey_tmp(dir.path());

    Command::cargo_bin("galdra")
        .expect("galdra")
        .env("HOME", dir.path())
        .args([
            "--db",
            db_path.to_str().expect("utf8"),
            "--quiet",
            "keyserver",
            "push",
            "--dry-run",
            "--email",
            "test@example.com",
            "--keyserver-url",
            "https://keys.example.invalid",
            "--fixture-armored-key",
            pubkey.to_str().expect("utf8"),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"email\""))
        .stdout(predicate::str::contains("test@example.com"))
        .stdout(predicate::str::contains("\"armored_public_key\""))
        .stdout(predicate::str::contains("BEGIN PGP PUBLIC KEY BLOCK"));
}
