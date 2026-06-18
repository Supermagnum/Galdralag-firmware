use galdra_core_host::contacts::{self, NewContact};
use galdra_core_host::db::Db;
use galdra_core_host::groups;

#[test]
fn add_from_group_copies_members() {
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
    let b = contacts::contact_add(
        &mut db,
        NewContact {
            display_name: "B".to_string(),
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
    .expect("b");
    groups::group_create(&mut db, "src", None, false).expect("gc");
    groups::group_add_member(&mut db, "src", &a.id, None, None).expect("a");
    groups::group_add_member(&mut db, "src", &b.id, None, None).expect("b");
    groups::group_create(&mut db, "dst", None, false).expect("gcd");
    let n = groups::group_add_from_group(&mut db, "dst", "src", None).expect("copy");
    assert_eq!(n, 2);
    let g = groups::group_get(&db, "dst").expect("gg");
    assert_eq!(g.members.len(), 2);
}
