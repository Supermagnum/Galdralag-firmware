use galdra_core_host::contacts::{self, KeySource, NewContact};
use galdra_core_host::db::Db;

#[test]
fn resolve_by_fingerprint_ignores_separators() {
    let mut db = Db::open_in_memory().expect("db");
    let c = contacts::contact_add(
        &mut db,
        NewContact {
            display_name: "Bob".to_string(),
            email: "bob@example.org".to_string(),
            callsign: None,
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
            phone_number: None,
        },
    )
    .expect("add");
    let stored_spaced = "0123 4567 89AB CDEF 0123 4567 89AB CDEF 0123 4567";
    contacts::contact_upsert_key(
        &mut db,
        &c.id,
        &[0xde, 0xad],
        stored_spaced,
        KeySource::Manual,
        None,
    )
    .expect("upsert key");

    let by_fp = contacts::resolve_contact_identifier(
        &db,
        "0123456789abcdef0123456789abcdef01234567",
    )
    .expect("resolve fingerprint lower/mixed");
    assert_eq!(by_fp.id, c.id);
}

#[test]
fn resolve_by_dmr_id_decimal_token() {
    let mut db = Db::open_in_memory().expect("db");
    let c = contacts::contact_add(
        &mut db,
        NewContact {
            display_name: "DM".to_string(),
            email: "dm@example.org".to_string(),
            callsign: None,
            badge_number: None,
            organisation: None,
            department: None,
            role: None,
            note: None,
            dmr_id: Some(2_881_554),
            radio_affiliation: None,
            street: None,
            country: None,
            postal_code: None,
            region: None,
            fluxer_id: None,
            discord_id: None,
            irc_id: None,
            phone_number: None,
        },
    )
    .expect("add");

    let by_dmr = contacts::resolve_contact_identifier(&db, " 2881554 ").expect("resolve dmr");
    assert_eq!(by_dmr.id, c.id);
}
