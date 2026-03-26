use galdra_core_host::contacts::{
    self, ContactUpdate, NewContact,
};
use galdra_core_host::db::Db;

#[test]
fn contact_crud_roundtrip() {
    let mut db = Db::open_in_memory().expect("db");
    let c = contacts::contact_add(
        &mut db,
        NewContact {
            display_name: "Alice".to_string(),
            callsign: Some("W1ABC".to_string()),
            email: Some("a@example.org".to_string()),
            badge_number: None,
            organisation: None,
            department: None,
            role: None,
            note: None,
        },
    )
    .expect("add");
    let by_id = contacts::contact_get_by_id(&db, &c.id).expect("get id");
    assert_eq!(by_id.display_name, "Alice");
    let by_cs = contacts::contact_get_by_callsign(&db, "W1ABC").expect("cs");
    assert_eq!(by_cs.id, c.id);
    let by_em = contacts::contact_get_by_email(&db, "a@example.org").expect("em");
    assert_eq!(by_em.id, c.id);

    let u = contacts::contact_update(
        &mut db,
        &c.id,
        ContactUpdate {
            display_name: Some("Alice B".to_string()),
            ..Default::default()
        },
    )
    .expect("upd");
    assert_eq!(u.display_name, "Alice B");

    contacts::contact_delete(&mut db, &c.id).expect("del");
    assert!(contacts::contact_get_by_id(&db, &c.id).is_err());
}
