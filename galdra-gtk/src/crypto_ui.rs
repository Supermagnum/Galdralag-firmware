//! Encrypt / decrypt tab with profile dropdown and persisted default profile.

use std::sync::Arc;

use gtk::gio::spawn_blocking;
use gtk::glib;
use gtk::prelude::*;

use crate::client::GaldradClient;
use crate::gtk_config::GtkConfig;

pub fn build(
    client: Arc<GaldradClient>,
    parent: &gtk::ApplicationWindow,
) -> (gtk::Box, impl Fn() + Clone + 'static) {
    let bx = gtk::Box::new(gtk::Orientation::Vertical, 8);
    bx.set_margin_top(12);
    bx.set_margin_bottom(12);
    bx.set_margin_start(12);
    bx.set_margin_end(12);

    let h1 = gtk::Label::new(Some("Encrypt (POST /encrypt)"));
    h1.set_halign(gtk::Align::Start);
    h1.add_css_class("heading");
    bx.append(&h1);

    let profile_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    profile_row.append(&gtk::Label::new(Some("Profile:")));
    let profile_list = gtk::StringList::new(&[]);
    let profile_dd = gtk::DropDown::new(Some(profile_list.clone()), None::<gtk::Expression>);
    profile_row.append(&profile_dd);
    bx.append(&profile_row);

    let group_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    group_row.append(&gtk::Label::new(Some("Group:")));
    let group_entry = gtk::Entry::new();
    group_row.append(&group_entry);
    bx.append(&group_row);

    let path_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    path_row.append(&gtk::Label::new(Some("Input file:")));
    let path_entry = gtk::Entry::new();
    let btn_browse_in = gtk::Button::builder().label("Browse").build();
    path_row.append(&path_entry);
    path_row.append(&btn_browse_in);
    bx.append(&path_row);

    let out = text_view();
    let btn_enc = gtk::Button::builder().label("Encrypt").build();
    bx.append(&btn_enc);
    bx.append(&scrolled(&out));

    let h2 = gtk::Label::new(Some("Decrypt (POST /decrypt)"));
    h2.set_halign(gtk::Align::Start);
    h2.set_margin_top(16);
    h2.add_css_class("heading");
    bx.append(&h2);

    let hint = gtk::Label::new(Some(
        "Recipient is a contact id, callsign, or email. Optional profile hint must match the envelope.",
    ));
    hint.set_wrap(true);
    hint.set_halign(gtk::Align::Start);
    bx.append(&hint);

    let rec_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    rec_row.append(&gtk::Label::new(Some("Recipient:")));
    let recipient_entry = gtk::Entry::new();
    rec_row.append(&recipient_entry);
    bx.append(&rec_row);

    let prof_hint_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    prof_hint_row.append(&gtk::Label::new(Some("Profile hint:")));
    let hint_list = gtk::StringList::new(&[]);
    let hint_dd = gtk::DropDown::new(Some(hint_list.clone()), None::<gtk::Expression>);
    prof_hint_row.append(&hint_dd);
    bx.append(&prof_hint_row);

    let dec_path_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    dec_path_row.append(&gtk::Label::new(Some("Ciphertext file:")));
    let dec_path_entry = gtk::Entry::new();
    let btn_browse_ct = gtk::Button::builder().label("Browse").build();
    dec_path_row.append(&dec_path_entry);
    dec_path_row.append(&btn_browse_ct);
    bx.append(&dec_path_row);

    let dec_out = text_view();
    let btn_dec = gtk::Button::builder().label("Decrypt").build();
    bx.append(&btn_dec);
    bx.append(&scrolled(&dec_out));

    let names: std::rc::Rc<std::cell::RefCell<Vec<String>>> =
        std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let hint_opts: std::rc::Rc<std::cell::RefCell<Vec<Option<String>>>> =
        std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));

    let reload = {
        let client = client.clone();
        let profile_dd = profile_dd.clone();
        let profile_list = profile_list.clone();
        let hint_dd = hint_dd.clone();
        let hint_list = hint_list.clone();
        let names = names.clone();
        let hint_opts = hint_opts.clone();
        move || {
            let client = client.clone();
            let profile_dd = profile_dd.clone();
            let profile_list = profile_list.clone();
            let hint_dd = hint_dd.clone();
            let hint_list = hint_list.clone();
            let names = names.clone();
            let hint_opts = hint_opts.clone();
            glib::spawn_future_local(async move {
                let res = spawn_blocking(move || client.profiles()).await.unwrap();
                let Ok(rows) = res else {
                    return;
                };
                while profile_list.n_items() > 0 {
                    profile_list.remove(0);
                }
                while hint_list.n_items() > 0 {
                    hint_list.remove(0);
                }
                let mut nn = Vec::new();
                for p in &rows {
                    let label = p.dropdown_label();
                    profile_list.append(&label);
                    nn.push(p.name.clone());
                }
                *names.borrow_mut() = nn;
                let cfg = GtkConfig::load();
                if let Some(i) = rows
                    .iter()
                    .position(|r| r.name == cfg.default_encrypt_profile)
                {
                    profile_dd.set_selected(i as u32);
                } else if !rows.is_empty() {
                    profile_dd.set_selected(0);
                }
                hint_list.append("(none)");
                let mut ho = vec![None];
                for p in rows {
                    hint_list.append(&p.dropdown_label());
                    ho.push(Some(p.name));
                }
                *hint_opts.borrow_mut() = ho;
                hint_dd.set_selected(0);
            });
        }
    };

    reload();

    btn_browse_in.connect_clicked({
        let path_entry = path_entry.clone();
        let parent = parent.clone();
        move |_| {
            let d = gtk::FileChooserDialog::new(
                Some("Plaintext file"),
                Some(&parent),
                gtk::FileChooserAction::Open,
                &[
                    ("Cancel", gtk::ResponseType::Cancel),
                    ("Open", gtk::ResponseType::Accept),
                ],
            );
            let path_entry = path_entry.clone();
            d.connect_response(move |d, resp| {
                if resp == gtk::ResponseType::Accept {
                    if let Some(f) = d.file() {
                        if let Some(p) = f.path() {
                            path_entry.set_text(p.to_string_lossy().as_ref());
                        }
                    }
                }
                d.destroy();
            });
            d.present();
        }
    });

    btn_browse_ct.connect_clicked({
        let dec_path_entry = dec_path_entry.clone();
        let parent = parent.clone();
        move |_| {
            let d = gtk::FileChooserDialog::new(
                Some("Ciphertext file"),
                Some(&parent),
                gtk::FileChooserAction::Open,
                &[
                    ("Cancel", gtk::ResponseType::Cancel),
                    ("Open", gtk::ResponseType::Accept),
                ],
            );
            let dec_path_entry = dec_path_entry.clone();
            d.connect_response(move |d, resp| {
                if resp == gtk::ResponseType::Accept {
                    if let Some(f) = d.file() {
                        if let Some(p) = f.path() {
                            dec_path_entry.set_text(p.to_string_lossy().as_ref());
                        }
                    }
                }
                d.destroy();
            });
            d.present();
        }
    });

    btn_enc.connect_clicked({
        let client = client.clone();
        let group_e = group_entry.clone();
        let path_e = path_entry.clone();
        let profile_dd = profile_dd.clone();
        let names = names.clone();
        let out_w = out.clone();
        move |_| {
            let i = profile_dd.selected() as usize;
            let prof = names
                .borrow()
                .get(i)
                .cloned()
                .unwrap_or_else(|| "standard".to_string());
            let mut cfg = GtkConfig::load();
            cfg.default_encrypt_profile = prof.clone();
            let _ = cfg.save();
            let c2 = client.clone();
            let grp = group_e.text().to_string();
            let path = std::path::PathBuf::from(path_e.text().as_str());
            let ov = out_w.clone();
            glib::spawn_future_local(async move {
                let res = spawn_blocking(move || {
                    let plain = std::fs::read(&path).map_err(|e| e.to_string())?;
                    c2.post_encrypt_b64(&grp, &prof, &plain)
                })
                .await
                .unwrap();
                match res {
                    Ok(s) => set_text_view(&ov, &s),
                    Err(e) => set_text_view(&ov, &format!("Error: {e}")),
                }
            });
        }
    });

    btn_dec.connect_clicked({
        let client = client.clone();
        let recipient_entry = recipient_entry.clone();
        let dec_path_entry = dec_path_entry.clone();
        let hint_dd = hint_dd.clone();
        let hint_opts = hint_opts.clone();
        let dec_out_w = dec_out.clone();
        move |_| {
            let rec = recipient_entry.text().to_string();
            let i = hint_dd.selected() as usize;
            let hint_owned = hint_opts.borrow().get(i).cloned().flatten();
            let path = std::path::PathBuf::from(dec_path_entry.text().as_str());
            let c2 = client.clone();
            let ov = dec_out_w.clone();
            glib::spawn_future_local(async move {
                let res = spawn_blocking(move || {
                    let ct = std::fs::read(&path).map_err(|e| e.to_string())?;
                    let ph = hint_owned.as_deref();
                    c2.post_decrypt_b64(&rec, ph, &ct)
                })
                .await
                .unwrap();
                match res {
                    Ok(s) => set_text_view(&ov, &s),
                    Err(e) => set_text_view(&ov, &format!("Error: {e}")),
                }
            });
        }
    });

    (bx, reload)
}

fn text_view() -> gtk::TextView {
    let tv = gtk::TextView::new();
    tv.set_editable(false);
    tv.set_monospace(true);
    tv.set_wrap_mode(gtk::WrapMode::Word);
    tv.set_top_margin(8);
    tv.set_bottom_margin(8);
    tv.set_left_margin(8);
    tv.set_right_margin(8);
    tv
}

fn set_text_view(tv: &gtk::TextView, text: &str) {
    tv.buffer().set_text(text);
}

fn scrolled(w: &impl IsA<gtk::Widget>) -> gtk::ScrolledWindow {
    gtk::ScrolledWindow::builder()
        .vexpand(true)
        .hexpand(true)
        .child(w)
        .build()
}
