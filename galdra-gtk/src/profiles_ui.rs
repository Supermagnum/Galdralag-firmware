//! Profiles tab: `ColumnView`, toolbar, create/edit/delete, profile editor window.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;

use gtk::gio::spawn_blocking;
use gtk::gio;
use gtk::glib;
use gtk::prelude::*;

use crate::client::{CreateProfileBody, GaldradClient};
use crate::profile_row::ProfileRow;

const CURVES: &[&str] = &["bp256", "bp384", "bp512"];
const LAYER_OPTS: &[&str] = &[
    "aes256gcm",
    "chacha20poly1305",
    "twofish256",
    "serpent256",
];

pub fn build(
    client: Arc<GaldradClient>,
    err_label: gtk::Label,
    parent: gtk::ApplicationWindow,
    on_crypto_resync: impl Fn() + Clone + 'static,
) -> (gtk::Box, impl Fn() + Clone + 'static) {
    let bx = gtk::Box::new(gtk::Orientation::Vertical, 8);
    bx.set_margin_top(12);
    bx.set_margin_bottom(12);
    bx.set_margin_start(12);
    bx.set_margin_end(12);

    let h = gtk::Label::new(Some("Cipher profiles (GET/POST/DELETE /profiles)"));
    h.set_halign(gtk::Align::Start);
    h.add_css_class("heading");
    bx.append(&h);

    let toolbar = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    let btn_new = gtk::Button::builder().label("New profile").build();
    let btn_edit = gtk::Button::builder().label("Edit").build();
    let btn_del = gtk::Button::builder().label("Remove").build();
    toolbar.append(&btn_new);
    toolbar.append(&btn_edit);
    toolbar.append(&btn_del);
    bx.append(&toolbar);

    let store = gio::ListStore::new::<ProfileRow>();
    let sel = gtk::SingleSelection::new(Some(store.clone()));
    let cv = gtk::ColumnView::new(Some(sel.clone()));
    cv.set_vexpand(true);
    cv.set_hexpand(true);

    fn col_lock() -> gtk::ColumnViewColumn {
        let factory = gtk::SignalListItemFactory::new();
        factory.connect_setup(move |_, list_item| {
            let img = gtk::Image::builder().icon_size(gtk::IconSize::Normal).build();
            list_item.set_child(Some(&img));
        });
        factory.connect_bind(move |_, list_item| {
            let img = list_item.child().and_downcast::<gtk::Image>().unwrap();
            let obj = list_item.item().and_downcast::<ProfileRow>().unwrap();
            if obj.is_builtin() {
                img.set_icon_name(Some("object-locked-symbolic"));
                img.set_tooltip_text(Some("Built-in profile"));
            } else {
                img.set_icon_name(None);
                img.set_tooltip_text(Some("User profile"));
            }
        });
        gtk::ColumnViewColumn::new(Some(""), Some(factory))
    }

    fn col_text(title: &str, f: impl Fn(&ProfileRow) -> String + 'static) -> gtk::ColumnViewColumn {
        let factory = gtk::SignalListItemFactory::new();
        factory.connect_setup(move |_, list_item| {
            let label = gtk::Label::builder().xalign(0.0).build();
            list_item.set_child(Some(&label));
        });
        factory.connect_bind(move |_, list_item| {
            let label = list_item.child().and_downcast::<gtk::Label>().unwrap();
            let obj = list_item.item().and_downcast::<ProfileRow>().unwrap();
            label.set_text(&f(&obj));
        });
        gtk::ColumnViewColumn::new(Some(title), Some(factory))
    }

    cv.append_column(&col_lock());
    cv.append_column(&col_text("Name", |r| r.name()));
    cv.append_column(&col_text("Curve", |r| r.curve()));
    cv.append_column(&col_text("Layers", |r| r.layers()));
    cv.append_column(&col_text("Shamir", |r| r.shamir()));
    cv.append_column(&col_text("Source", |r| r.source()));

    let scroll = gtk::ScrolledWindow::builder()
        .vexpand(true)
        .hexpand(true)
        .child(&cv)
        .build();
    bx.append(&scroll);

    let refresh = {
        let client = client.clone();
        let err_label = err_label.clone();
        let store = store.clone();
        let refresh = move || {
            let err_w = err_label.downgrade();
            let store_w = store.downgrade();
            let c = client.clone();
            glib::spawn_future_local(async move {
                let res = spawn_blocking(move || c.profiles()).await.unwrap();
                let Some(store) = store_w.upgrade() else {
                    return;
                };
                while store.n_items() > 0 {
                    store.remove(0);
                }
                match res {
                    Ok(rows) => {
                        if let Some(el) = err_w.upgrade() {
                            el.set_visible(false);
                        }
                        for p in rows {
                            store.append(&ProfileRow::from_summary(&p));
                        }
                    }
                    Err(e) => {
                        if let Some(el) = err_w.upgrade() {
                            el.set_text(&e);
                            el.set_visible(true);
                        }
                    }
                }
            });
        };
        refresh
    };

    refresh();

    let open_editor = {
        let client = client.clone();
        let err_label = err_label.clone();
        let parent = parent.clone();
        let on_crypto = on_crypto_resync.clone();
        let refresh = refresh.clone();
        move |mode: EditorMode| {
            open_profile_editor(&parent, &client, &err_label, mode, {
                let refresh = refresh.clone();
                let on_crypto = on_crypto.clone();
                move |ok| {
                    if ok {
                        refresh();
                        on_crypto();
                    }
                }
            });
        }
    };

    btn_new.connect_clicked({
        let open_editor = open_editor.clone();
        move |_| open_editor(EditorMode::New)
    });

    btn_edit.connect_clicked({
        let sel = sel.clone();
        let open_editor = open_editor.clone();
        move |_| {
            let Some(pos) = sel.selected_item() else {
                return;
            };
            let Some(row) = pos.downcast_ref::<ProfileRow>() else {
                return;
            };
            let name = row.name();
            open_editor(EditorMode::Edit(name));
        }
    });

    btn_del.connect_clicked({
        let sel = sel.clone();
        let client = client.clone();
        let err_label = err_label.clone();
        let parent = parent.clone();
        let refresh = refresh.clone();
        let on_crypto = on_crypto_resync.clone();
        move |_| {
            let Some(pos) = sel.selected_item() else {
                return;
            };
            let Some(row) = pos.downcast_ref::<ProfileRow>() else {
                return;
            };
            if row.is_builtin() {
                err_label.set_text("Built-in profiles cannot be removed.");
                err_label.set_visible(true);
                return;
            }
            let name = row.name();
            let d = gtk::MessageDialog::new(
                Some(&parent),
                gtk::DialogFlags::MODAL | gtk::DialogFlags::DESTROY_WITH_PARENT,
                gtk::MessageType::Question,
                gtk::ButtonsType::OkCancel,
                format!("Remove profile \"{name}\"?"),
            );
            let client = client.clone();
            let err_label = err_label.clone();
            let refresh_c = refresh.clone();
            let on_crypto_c = on_crypto.clone();
            d.connect_response(move |d, resp| {
                d.destroy();
                if resp != gtk::ResponseType::Ok {
                    return;
                }
                let name = name.clone();
                let c = client.clone();
                let err_w = err_label.downgrade();
                let refresh_c = refresh_c.clone();
                let on_crypto_c = on_crypto_c.clone();
                glib::spawn_future_local(async move {
                    let res = spawn_blocking(move || c.delete_profile(&name)).await.unwrap();
                    if let Some(el) = err_w.upgrade() {
                        match res {
                            Ok(()) => {
                                el.set_visible(false);
                                refresh_c();
                                on_crypto_c();
                            }
                            Err(e) => {
                                el.set_text(&e);
                                el.set_visible(true);
                            }
                        }
                    }
                });
            });
            d.present();
        }
    });

    (bx, refresh)
}

pub enum EditorMode {
    New,
    Edit(String),
}

fn open_profile_editor(
    parent: &gtk::ApplicationWindow,
    client: &GaldradClient,
    err_label: &gtk::Label,
    mode: EditorMode,
    on_done: impl Fn(bool) + 'static,
) {
    let dialog = gtk::Window::builder()
        .transient_for(parent)
        .modal(true)
        .title("Profile")
        .default_width(520)
        .default_height(480)
        .build();

    let root = gtk::Box::new(gtk::Orientation::Vertical, 8);
    root.set_margin_top(12);
    root.set_margin_bottom(12);
    root.set_margin_start(12);
    root.set_margin_end(12);
    dialog.set_child(Some(&root));

    let name_entry = gtk::Entry::new();
    let curve_list = gtk::StringList::new(&[]);
    for c in CURVES {
        curve_list.append(c);
    }
    let curve_dd = gtk::DropDown::new(Some(curve_list), None::<gtk::Expression>);

    let layers_box = gtk::Box::new(gtk::Orientation::Vertical, 4);
    let layers_frame = gtk::Frame::new(Some("Layers (up to 4)"));
    layers_frame.set_child(Some(&layers_box));

    let shamir_check = gtk::CheckButton::with_label("Shamir (k-of-n)");
    let shamir_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    shamir_row.append(&gtk::Label::new(Some("k:")));
    let spin_k = gtk::SpinButton::with_range(1.0, 255.0, 1.0);
    shamir_row.append(&spin_k);
    shamir_row.append(&gtk::Label::new(Some("n:")));
    let spin_n = gtk::SpinButton::with_range(1.0, 255.0, 1.0);
    shamir_row.append(&spin_n);

    let dup_lbl = gtk::Label::new(None);
    dup_lbl.add_css_class("error");
    dup_lbl.set_wrap(true);

    let layer_dds: Rc<RefCell<Vec<gtk::DropDown>>> = Rc::new(RefCell::new(Vec::new()));

    let push_layer = |layers_box: &gtk::Box, layer_dds: &Rc<RefCell<Vec<gtk::DropDown>>>, sel: Option<usize>| {
        if layer_dds.borrow().len() >= 4 {
            return;
        }
        let list = gtk::StringList::new(&[]);
        for o in LAYER_OPTS {
            list.append(o);
        }
        let dd = gtk::DropDown::new(Some(list), None::<gtk::Expression>);
        if let Some(i) = sel {
            if i < LAYER_OPTS.len() {
                dd.set_selected(i as u32);
            }
        } else {
            dd.set_selected(0);
        }
        let row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        row.append(&dd);
        layers_box.append(&row);
        layer_dds.borrow_mut().push(dd);
    };

    match &mode {
        EditorMode::New => {
            name_entry.set_text("my-profile");
            curve_dd.set_selected(0);
            push_layer(&layers_box, &layer_dds, None);
        }
        EditorMode::Edit(name) => {
            name_entry.set_text(name);
            name_entry.set_sensitive(false);
            match client.get_profile(name) {
                Ok(p) => {
                    if let Some(i) = CURVES.iter().position(|c| *c == p.curve.as_str()) {
                        curve_dd.set_selected(i as u32);
                    }
                    for layer in &p.layers {
                        let idx = LAYER_OPTS.iter().position(|o| *o == layer.as_str());
                        push_layer(&layers_box, &layer_dds, idx);
                    }
                    if layer_dds.borrow().is_empty() {
                        push_layer(&layers_box, &layer_dds, None);
                    }
                    let active = p.shamir_k > 1 || p.shamir_n > 1;
                    shamir_check.set_active(active);
                    spin_k.set_value(f64::from(p.shamir_k));
                    spin_n.set_value(f64::from(p.shamir_n));
                }
                Err(e) => {
                    err_label.set_text(&e);
                    err_label.set_visible(true);
                    on_done(false);
                    return;
                }
            }
        }
    }

    let btn_add_layer = gtk::Button::builder().label("Add layer").build();
    let layers_box_w = layers_box.clone();
    let layer_dds_add = layer_dds.clone();
    btn_add_layer.connect_clicked(move |_| {
        if layer_dds_add.borrow().len() >= 4 {
            return;
        }
        push_layer(&layers_box_w, &layer_dds_add, None);
    });

    root.append(&gtk::Label::new(Some("Name")));
    root.append(&name_entry);
    root.append(&gtk::Label::new(Some("Curve")));
    root.append(&curve_dd);
    root.append(&layers_frame);
    root.append(&btn_add_layer);
    root.append(&shamir_check);
    root.append(&shamir_row);
    root.append(&dup_lbl);

    let btn_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    let btn_save = gtk::Button::builder().label("Save").build();
    let btn_cancel = gtk::Button::builder().label("Cancel").build();
    btn_row.append(&btn_save);
    btn_row.append(&btn_cancel);
    root.append(&btn_row);

    let on_done = Rc::new(on_done);
    let dialog_c = dialog.clone();
    let finished = Rc::new(std::cell::Cell::new(false));

    btn_cancel.connect_clicked({
        let dialog = dialog.clone();
        let on_done = on_done.clone();
        let finished = finished.clone();
        move |_| {
            finished.set(true);
            dialog.close();
            on_done(false);
        }
    });

    dialog.connect_close_request({
        let on_done = on_done.clone();
        let finished = finished.clone();
        move |_w| {
            if !finished.get() {
                finished.set(true);
                on_done(false);
            }
            gtk::glib::Propagation::Proceed
        }
    });

    btn_save.connect_clicked({
        let dialog = dialog_c.clone();
        let on_done = on_done.clone();
        let finished = finished.clone();
        let client = client.clone();
        let name_entry = name_entry.clone();
        let curve_dd = curve_dd.clone();
        let shamir_check = shamir_check.clone();
        let spin_k = spin_k.clone();
        let spin_n = spin_n.clone();
        let layer_dds = layer_dds.clone();
        let dup_lbl = dup_lbl.clone();
        move |_| {
            let name = name_entry.text().to_string();
            if name.trim().is_empty() {
                dup_lbl.set_text("Name is required.");
                return;
            }
            let curve_i = curve_dd.selected();
            let curve = CURVES
                .get(curve_i as usize)
                .unwrap_or(&"bp256")
                .to_string();
            let rows = layer_dds.borrow();
            let mut layers: Vec<String> = Vec::new();
            for dd in rows.iter() {
                let i = dd.selected() as usize;
                let s = LAYER_OPTS.get(i).unwrap_or(&"aes256gcm").to_string();
                layers.push(s);
            }
            drop(rows);
            if layers.is_empty() {
                dup_lbl.set_text("At least one layer is required.");
                return;
            }
            let mut seen = std::collections::HashSet::new();
            for l in &layers {
                if !seen.insert(l.as_str()) {
                    dup_lbl.set_text(
                        "Duplicate cipher layer in stack (remove or change the duplicate).",
                    );
                    return;
                }
            }
            dup_lbl.set_text("");
            let (kt, nt) = if shamir_check.is_active() {
                (spin_k.value() as u8, spin_n.value() as u8)
            } else {
                (1u8, 1u8)
            };
            if kt > nt {
                dup_lbl.set_text("Shamir threshold k must be <= n.");
                return;
            }
            let body = CreateProfileBody {
                name: name.clone(),
                description: Some(String::new()),
                curve,
                layers,
                shamir_threshold: Some(kt),
                shamir_total: Some(nt),
            };
            let res = match &mode {
                EditorMode::New => client.create_profile(&body),
                EditorMode::Edit(old) => {
                    if old != &body.name {
                        dup_lbl.set_text("Renaming is not supported in this dialog.");
                        return;
                    }
                    if let Err(e) = client.delete_profile(old) {
                        dup_lbl.set_text(&e);
                        return;
                    }
                    client.create_profile(&body)
                }
            };
            match res {
                Ok(()) => {
                    finished.set(true);
                    dialog.close();
                    on_done(true);
                }
                Err(e) => dup_lbl.set_text(&e),
            }
        }
    });

    dialog.present();
}
