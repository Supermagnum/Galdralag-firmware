//! GObject row model for `gtk::ColumnView` profile list.

use gtk::glib;
use gtk::glib::subclass::prelude::*;
use std::cell::RefCell;

use crate::client::ProfileSummary;

mod imp {
    use super::*;

    #[derive(Default)]
    pub struct ProfileRowObj {
        pub name: RefCell<String>,
        pub curve: RefCell<String>,
        pub layers: RefCell<String>,
        pub shamir: RefCell<String>,
        pub source: RefCell<String>,
        pub builtin: RefCell<bool>,
    }

    #[glib::object_subclass]
    impl ObjectSubclass for ProfileRowObj {
        const NAME: &'static str = "GaldraProfileRow";
        type Type = super::ProfileRow;
        type ParentType = glib::Object;
    }

    impl ObjectImpl for ProfileRowObj {}
}

glib::wrapper! {
    pub struct ProfileRow(ObjectSubclass<imp::ProfileRowObj>);
}

impl ProfileRow {
    pub fn from_summary(p: &ProfileSummary) -> Self {
        let o: Self = glib::Object::new();
        let imp = imp::ProfileRowObj::from_obj(&o);
        imp.name.replace(p.name.clone());
        imp.curve.replace(p.curve.clone());
        imp.layers.replace(p.layer_summary());
        imp.shamir.replace(p.shamir_label());
        imp.source.replace(p.source_label().to_string());
        imp.builtin.replace(p.is_builtin);
        o
    }

    pub fn name(&self) -> String {
        imp::ProfileRowObj::from_obj(self).name.borrow().clone()
    }

    pub fn curve(&self) -> String {
        imp::ProfileRowObj::from_obj(self).curve.borrow().clone()
    }

    pub fn layers(&self) -> String {
        imp::ProfileRowObj::from_obj(self).layers.borrow().clone()
    }

    pub fn shamir(&self) -> String {
        imp::ProfileRowObj::from_obj(self).shamir.borrow().clone()
    }

    pub fn source(&self) -> String {
        imp::ProfileRowObj::from_obj(self).source.borrow().clone()
    }

    pub fn is_builtin(&self) -> bool {
        *imp::ProfileRowObj::from_obj(self).builtin.borrow()
    }
}
