use galdra_core_host::contacts::{self, NewContact};
use galdra_core_host::db::Db;
use galdra_core_host::groups;

#[test]
fn group_create_add_remove_delete() {
    let mut db = Db::open_in_memory().expect("db");
    let a = contacts::contact_add(
        &mut db,
        NewContact {
            display_name: "A".to_string(),
            callsign: None,
            email: None,
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
        },
    )
    .expect("a");

    groups::group_create(&mut db, "g1", Some("d"), false).expect("gc");
    groups::group_add_member(&mut db, "g1", &a.id, None, None).expect("gam");
    let g = groups::group_get(&db, "g1").expect("gg");
    assert_eq!(g.members.len(), 1);
    groups::group_remove_member(&mut db, "g1", &a.id).expect("grm");
    let g = groups::group_get(&db, "g1").expect("gg");
    assert!(g.members.is_empty());
    groups::group_delete(&mut db, "g1").expect("gd");
    assert!(groups::group_get(&db, "g1").is_err());
}
