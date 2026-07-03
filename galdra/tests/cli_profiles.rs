//! CLI integration tests for cipher profiles (assert_cmd).

use assert_cmd::Command;
use galdra_core_host::contacts::{self, KeySource, NewContact};
use galdra_core_host::db::Db;
use galdra_core_host::groups;
use predicates::prelude::*;
use sequoia_openpgp::cert::CertBuilder;
use sequoia_openpgp::serialize::Serialize;
use tempfile::TempDir;

fn fresh_db(path: &std::path::Path) {
    let _db = Db::open(path, None).expect("db");
}

#[test]
fn test_profile_list_shows_builtins() {
    let dir = TempDir::new().expect("tmp");
    let db_path = dir.path().join("g.db");
    fresh_db(&db_path);
    Command::cargo_bin("galdra")
        .expect("galdra")
        .env("HOME", dir.path())
        .args(["--db", db_path.to_str().expect("utf8"), "profile", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("standard"))
        .stdout(predicate::str::contains("conservative"))
        .stdout(predicate::str::contains("conservative-shamir"));
}

#[test]
fn test_profile_show_conservative() {
    let dir = TempDir::new().expect("tmp");
    let db_path = dir.path().join("g.db");
    fresh_db(&db_path);
    Command::cargo_bin("galdra")
        .expect("galdra")
        .env("HOME", dir.path())
        .args([
            "--db",
            db_path.to_str().expect("utf8"),
            "profile",
            "show",
            "conservative",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("serpent256").or(predicate::str::contains("Serpent")))
        .stdout(predicate::str::contains("chacha20poly1305").or(predicate::str::contains("ChaCha")))
        .stdout(predicate::str::contains("bp256").or(predicate::str::contains("Brainpool")));
}

#[test]
fn test_profile_add_custom() {
    let dir = TempDir::new().expect("tmp");
    let db_path = dir.path().join("g.db");
    fresh_db(&db_path);
    Command::cargo_bin("galdra")
        .expect("galdra")
        .env("HOME", dir.path())
        .args([
            "--db",
            db_path.to_str().expect("utf8"),
            "profile",
            "add",
            "my-profile",
            "--curve",
            "brainpool256",
            "--layer",
            "chacha20poly1305",
            "--description",
            "Test",
        ])
        .write_stdin("y\n")
        .assert()
        .success();

    Command::cargo_bin("galdra")
        .expect("galdra")
        .env("HOME", dir.path())
        .args([
            "--db",
            db_path.to_str().expect("utf8"),
            "profile",
            "show",
            "my-profile",
        ])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("chacha20poly1305")
                .or(predicate::str::contains("ChaCha20-Poly1305")),
        );
}

#[test]
fn test_profile_add_duplicate_cipher() {
    let dir = TempDir::new().expect("tmp");
    let db_path = dir.path().join("g.db");
    fresh_db(&db_path);
    Command::cargo_bin("galdra")
        .expect("galdra")
        .env("HOME", dir.path())
        .args([
            "--db",
            db_path.to_str().expect("utf8"),
            "profile",
            "add",
            "bad",
            "--curve",
            "brainpool256",
            "--layer",
            "serpent256",
            "--layer",
            "serpent256",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("DuplicateCipher"));
}

#[test]
fn test_profile_remove_builtin() {
    let dir = TempDir::new().expect("tmp");
    let db_path = dir.path().join("g.db");
    fresh_db(&db_path);
    Command::cargo_bin("galdra")
        .expect("galdra")
        .env("HOME", dir.path())
        .args([
            "--db",
            db_path.to_str().expect("utf8"),
            "profile",
            "remove",
            "standard",
            "--confirm",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("built-in"));
}

#[test]
fn test_profile_remove_user() {
    let dir = TempDir::new().expect("tmp");
    let db_path = dir.path().join("g.db");
    fresh_db(&db_path);
    Command::cargo_bin("galdra")
        .expect("galdra")
        .env("HOME", dir.path())
        .args([
            "--db",
            db_path.to_str().expect("utf8"),
            "profile",
            "add",
            "tmp-user-profile",
            "--curve",
            "brainpool256",
            "--layer",
            "chacha20poly1305",
        ])
        .write_stdin("y\n")
        .assert()
        .success();

    Command::cargo_bin("galdra")
        .expect("galdra")
        .env("HOME", dir.path())
        .args([
            "--db",
            db_path.to_str().expect("utf8"),
            "profile",
            "remove",
            "tmp-user-profile",
            "--confirm",
        ])
        .assert()
        .success();

    Command::cargo_bin("galdra")
        .expect("galdra")
        .env("HOME", dir.path())
        .args([
            "--db",
            db_path.to_str().expect("utf8"),
            "profile",
            "show",
            "tmp-user-profile",
        ])
        .assert()
        .failure();
}

fn db_with_alice_group(db_path: &std::path::Path) {
    let mut db = Db::open(db_path, None).expect("db");
    let (alice, _) = CertBuilder::new()
        .add_userid("alice@example.org")
        .add_transport_encryption_subkey()
        .generate()
        .expect("cert");
    let mut armored = Vec::new();
    alice
        .as_tsk()
        .serialize(&mut armored)
        .expect("serialize secret key transferrable");
    let nc = NewContact {
        display_name: "Alice".to_string(),
        email: "alice@example.org".to_string(),
        callsign: Some("ALICE".to_string()),
        badge_number: None,
        organisation: None,
        department: None,
        role: None,
        note: None,
        dmr_id: None,
        radio_affiliation: None,
        street: None,
        country: None,
        postal_code: None,
        region: None,
        fluxer_id: None,
        discord_id: None,
        irc_id: None,
    };
    let id = contacts::contact_add(&mut db, nc).expect("add");
    contacts::contact_upsert_key(
        &mut db,
        &id.id,
        &armored,
        &alice.fingerprint().to_string(),
        KeySource::File,
        None,
    )
    .expect("key");
    groups::group_create(&mut db, "g1", None, false).expect("group");
    groups::group_add_member(&mut db, "g1", &id.id, None, None).expect("member");
}

#[test]
fn test_encrypt_with_profile() {
    let dir = TempDir::new().expect("tmp");
    let db_path = dir.path().join("g.db");
    db_with_alice_group(&db_path);
    let plain = dir.path().join("in.txt");
    let out = dir.path().join("out.pgp");
    std::fs::write(&plain, b"hello world").expect("write");
    Command::cargo_bin("galdra")
        .expect("galdra")
        .env("HOME", dir.path())
        .args([
            "--db",
            db_path.to_str().expect("utf8"),
            "encrypt",
            "--group",
            "g1",
            "--input",
            plain.to_str().expect("utf8"),
            "--output",
            out.to_str().expect("utf8"),
            "--profile",
            "conservative",
        ])
        .assert()
        .success();
    let meta = std::fs::metadata(&out).expect("meta");
    assert!(meta.len() > 0);
}

#[test]
fn test_decrypt_reads_profile_from_ciphertext() {
    let dir = TempDir::new().expect("tmp");
    let db_path = dir.path().join("g.db");
    db_with_alice_group(&db_path);
    let plain = dir.path().join("in.txt");
    let ct = dir.path().join("msg.pgp");
    let dec = dir.path().join("out.txt");
    std::fs::write(&plain, b"roundtrip payload").expect("write");
    Command::cargo_bin("galdra")
        .expect("galdra")
        .env("HOME", dir.path())
        .args([
            "--db",
            db_path.to_str().expect("utf8"),
            "encrypt",
            "--group",
            "g1",
            "--input",
            plain.to_str().expect("utf8"),
            "--output",
            ct.to_str().expect("utf8"),
            "--profile",
            "conservative",
        ])
        .assert()
        .success();

    Command::cargo_bin("galdra")
        .expect("galdra")
        .env("HOME", dir.path())
        .args([
            "--db",
            db_path.to_str().expect("utf8"),
            "decrypt",
            "--recipient",
            "alice@example.org",
            "--input",
            ct.to_str().expect("utf8"),
            "--output",
            dec.to_str().expect("utf8"),
        ])
        .assert()
        .success();
    let got = std::fs::read_to_string(&dec).expect("read");
    assert_eq!(got, "roundtrip payload");
}

#[test]
#[ignore = "requires connected token or shamir test harness"]
fn test_shamir_split_produces_files() {
    let dir = TempDir::new().expect("tmp");
    let db_path = dir.path().join("g.db");
    fresh_db(&db_path);
    let outd = dir.path().join("shares");
    Command::cargo_bin("galdra")
        .expect("galdra")
        .env("HOME", dir.path())
        .args([
            "--db",
            db_path.to_str().expect("utf8"),
            "shamir",
            "split",
            "--slot",
            "0",
            "--profile",
            "conservative-shamir",
            "--output-dir",
            outd.to_str().expect("utf8"),
        ])
        .assert()
        .success();
}

#[test]
#[ignore = "requires share fixtures from hardware split"]
fn test_shamir_show_share_no_value() {
    // Placeholder: run after manual split produces files.
}

#[test]
#[ignore = "requires token; without hardware recover fails before share count check"]
fn test_shamir_recover_insufficient_shares() {
    let dir = TempDir::new().expect("tmp");
    let db_path = dir.path().join("g.db");
    fresh_db(&db_path);
    let s1 = dir.path().join("s1.share");
    let arm = r"-----BEGIN GALDRA SHARE-----
Version: 1
Profile: conservative-shamir
Threshold: 3
Total: 5
Index: 1
Fingerprint: aa:bb
Created: 2020-01-01T00:00:00Z

AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
-----END GALDRA SHARE-----
";
    std::fs::write(&s1, arm).expect("write");
    Command::cargo_bin("galdra")
        .expect("galdra")
        .env("HOME", dir.path())
        .args([
            "--db",
            db_path.to_str().expect("utf8"),
            "shamir",
            "recover",
            "--slot",
            "0",
            "--share",
            s1.to_str().expect("utf8"),
            "--confirm",
        ])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("insufficient shares")
                .or(predicate::str::contains("device not connected")),
        );
}
