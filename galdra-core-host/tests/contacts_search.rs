use galdra_core_host::contacts::{self, ContactFilter, NewContact};
use galdra_core_host::db::Db;

#[test]
fn search_matches_multiple_fields() {
    let mut db = Db::open_in_memory().expect("db");
    contacts::contact_add(
        &mut db,
        NewContact {
            display_name: "Dr Net".to_string(),
            callsign: Some("K2NET".to_string()),
            email: Some("net@example.org".to_string()),
            badge_number: Some("B99".to_string()),
            organisation: None,
            department: None,
            role: Some("net_control".to_string()),
            note: Some("runs the net".to_string()),
            dmr_id: Some(1234567),
            radio_affiliation: Some("ARL".to_string()),
            street: Some("Karl Johans gate 1".to_string()),
            country: Some("NO".to_string()),
            postal_code: Some("0154".to_string()),
            region: Some("Oslo".to_string()),
        },
    )
    .expect("add");

    assert_eq!(contacts::contact_search(&db, "Net").expect("s").len(), 1);
    assert_eq!(contacts::contact_search(&db, "K2NET").expect("s").len(), 1);
    assert_eq!(contacts::contact_search(&db, "net@").expect("s").len(), 1);
    assert_eq!(contacts::contact_search(&db, "B99").expect("s").len(), 1);
    assert_eq!(
        contacts::contact_search(&db, "net_control")
            .expect("s")
            .len(),
        1
    );
    assert_eq!(
        contacts::contact_search(&db, "runs the").expect("s").len(),
        1
    );
    assert_eq!(contacts::contact_search(&db, "ARL").expect("s").len(), 1);
    assert_eq!(
        contacts::contact_search(&db, "1234567").expect("s").len(),
        1
    );
    assert_eq!(contacts::contact_search(&db, "Oslo").expect("s").len(), 1);
    assert_eq!(contacts::contact_search(&db, "0154").expect("s").len(), 1);

    let list = contacts::contact_list(
        &db,
        ContactFilter {
            expired: false,
            organisation: None,
            role: Some("net_control".to_string()),
        },
    )
    .expect("list");
    assert_eq!(list.len(), 1);
}
