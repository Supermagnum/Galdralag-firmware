use chrono::{Duration, Utc};
use galdra_core_host::contacts::{self, NewContact};
use galdra_core_host::db::Db;
use galdra_core_host::groups;
use galdra_core_host::GaldraError;

#[test]
fn active_members_excludes_expired() {
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
        },
    )
    .expect("a");
    groups::group_create(&mut db, "g", None, false).expect("gc");
    let past = Utc::now() - Duration::hours(1);
    groups::group_add_member(&mut db, "g", &a.id, None, Some(past)).expect("gam");
    let active = groups::group_active_members(&db, "g");
    assert!(matches!(active, Err(GaldraError::AllMembersExpired)));
}
