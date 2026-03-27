//! Shamir split / recover / share viewer (POST /shamir/*, GET share-info).

use std::sync::Arc;

use gtk::gio::spawn_blocking;
use gtk::glib;
use gtk::prelude::*;

use crate::client::GaldradClient;

fn split_pem_blocks(s: &str) -> Vec<String> {
    let marker = "-----BEGIN";
    let mut out = Vec::new();
    for piece in s.split(marker) {
        if piece.trim().is_empty() {
            continue;
        }
        out.push(format!("{marker}{piece}"));
    }
    out
}

pub fn build(client: Arc<GaldradClient>) -> gtk::Box {
    let bx = gtk::Box::new(gtk::Orientation::Vertical, 8);
    bx.set_margin_top(12);
    bx.set_margin_bottom(12);
    bx.set_margin_start(12);
    bx.set_margin_end(12);

    let nb = gtk::Notebook::new();
    nb.set_vexpand(true);
    bx.append(&nb);

    // Split
    let split_page = gtk::Box::new(gtk::Orientation::Vertical, 8);
    split_page.append(&gtk::Label::new(Some(
        "Split a profile key on the connected token (POST /shamir/split).",
    )));
    let slot_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    slot_row.append(&gtk::Label::new(Some("Slot:")));
    let split_slot = gtk::SpinButton::with_range(0.0, 255.0, 1.0);
    slot_row.append(&split_slot);
    split_page.append(&slot_row);
    let prof_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    prof_row.append(&gtk::Label::new(Some("Profile:")));
    let split_profile = gtk::Entry::new();
    split_profile.set_text("conservative-shamir");
    prof_row.append(&split_profile);
    split_page.append(&prof_row);
    let btn_split = gtk::Button::builder().label("Split").build();
    split_page.append(&btn_split);
    let split_out = text_view();
    split_page.append(&scrolled(&split_out));
    nb.append_page(&split_page, Some(&gtk::Label::new(Some("Split"))));

    // Recover
    let rec_page = gtk::Box::new(gtk::Orientation::Vertical, 8);
    rec_page.append(&gtk::Label::new(Some(
        "Paste one or more armoured shares (POST /shamir/recover).",
    )));
    let rslot_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    rslot_row.append(&gtk::Label::new(Some("Slot:")));
    let rec_slot = gtk::SpinButton::with_range(0.0, 255.0, 1.0);
    rslot_row.append(&rec_slot);
    rec_page.append(&rslot_row);
    let rec_tv = gtk::TextView::new();
    rec_tv.set_wrap_mode(gtk::WrapMode::Word);
    rec_tv.set_monospace(true);
    rec_tv.set_vexpand(true);
    rec_page.append(&scrolled(&rec_tv));
    let btn_rec = gtk::Button::builder().label("Recover").build();
    rec_page.append(&btn_rec);
    let rec_status = gtk::Label::new(None);
    rec_status.set_wrap(true);
    rec_page.append(&rec_status);
    nb.append_page(&rec_page, Some(&gtk::Label::new(Some("Recover"))));

    // Viewer
    let view_page = gtk::Box::new(gtk::Orientation::Vertical, 8);
    view_page.append(&gtk::Label::new(Some(
        "Inspect a single armoured share (GET /shamir/share-info). Large shares may exceed URL limits.",
    )));
    let view_tv = gtk::TextView::new();
    view_tv.set_wrap_mode(gtk::WrapMode::Word);
    view_tv.set_monospace(true);
    view_tv.set_vexpand(true);
    view_page.append(&scrolled(&view_tv));
    let btn_info = gtk::Button::builder().label("Inspect share").build();
    view_page.append(&btn_info);
    let view_out = text_view();
    view_page.append(&scrolled(&view_out));
    nb.append_page(&view_page, Some(&gtk::Label::new(Some("Viewer"))));

    btn_split.connect_clicked({
        let client = client.clone();
        let split_slot = split_slot.clone();
        let split_profile = split_profile.clone();
        let split_out = split_out.clone();
        move |_| {
            let slot = split_slot.value() as u32;
            let profile = split_profile.text().to_string();
            let c = client.clone();
            let tv = split_out.clone();
            glib::spawn_future_local(async move {
                let res = spawn_blocking(move || c.shamir_split(slot, &profile)).await.unwrap();
                match res {
                    Ok(arms) => {
                        let s = arms.join("\n\n");
                        set_text_view(&tv, &s);
                    }
                    Err(e) => set_text_view(&tv, &format!("Error: {e}")),
                }
            });
        }
    });

    btn_rec.connect_clicked({
        let client = client.clone();
        let rec_slot = rec_slot.clone();
        let rec_tv = rec_tv.clone();
        let rec_status = rec_status.clone();
        move |_| {
            let slot = rec_slot.value() as u32;
            let text = rec_tv.buffer().text(
                &rec_tv.buffer().start_iter(),
                &rec_tv.buffer().end_iter(),
                true,
            );
            let shares = split_pem_blocks(&text);
            if shares.is_empty() {
                rec_status.set_text("No armoured blocks found (expect lines starting with -----BEGIN).");
                return;
            }
            let c = client.clone();
            let rec_status = rec_status.clone();
            glib::spawn_future_local(async move {
                let res = spawn_blocking(move || c.shamir_recover(slot, &shares)).await.unwrap();
                match res {
                    Ok(()) => rec_status.set_text("Recover completed (see galdrad logs / device)."),
                    Err(e) => rec_status.set_text(&format!("Error: {e}")),
                }
            });
        }
    });

    btn_info.connect_clicked({
        let client = client.clone();
        let view_tv = view_tv.clone();
        let view_out = view_out.clone();
        move |_| {
            let text = view_tv.buffer().text(
                &view_tv.buffer().start_iter(),
                &view_tv.buffer().end_iter(),
                true,
            );
            let t = text.trim().to_string();
            if t.is_empty() {
                set_text_view(&view_out, "Paste an armoured share first.");
                return;
            }
            let c = client.clone();
            let view_out = view_out.clone();
            glib::spawn_future_local(async move {
                let res = spawn_blocking(move || c.shamir_share_info(&t)).await.unwrap();
                match res {
                    Ok(info) => {
                        let s = format!(
                            "profile: {}\nthreshold: {} / {}\nindex: {}\nfingerprint: {}\ncreated: {}",
                            info.profile,
                            info.threshold,
                            info.total,
                            info.index,
                            info.fingerprint,
                            info.created
                        );
                        set_text_view(&view_out, &s);
                    }
                    Err(e) => set_text_view(&view_out, &format!("Error: {e}")),
                }
            });
        }
    });

    bx
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
