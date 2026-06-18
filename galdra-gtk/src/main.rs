//! GTK4 desktop client for Galdra via the local `galdrad` HTTP API.

mod client;
mod crypto_ui;
mod gtk_config;
mod profile_row;
mod profiles_ui;
mod shamir_ui;

use clap::Parser;
use gtk::gio::spawn_blocking;
use gtk::glib;
use gtk::prelude::*;

use client::{GaldradClient, GroupRow, IdentityRow};
use std::rc::Rc;
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "galdra-gtk", about = "Galdra desktop UI (galdrad REST client)")]
struct Cli {
    /// Base URL of galdrad (e.g. http://127.0.0.1:8742).
    #[arg(long, env = "GALDRAD_URL", default_value = "http://127.0.0.1:8742")]
    base_url: String,
}

fn main() -> glib::ExitCode {
    let cli = Cli::parse();
    let app = gtk::Application::new(
        Some("org.galdra.desktop"),
        gtk::gio::ApplicationFlags::empty(),
    );

    app.connect_activate(move |app| match build_window(app, &cli.base_url) {
        Ok(w) => w.present(),
        Err(e) => {
            eprintln!("galdra-gtk: {e}");
            let d = gtk::MessageDialog::new(
                None::<&gtk::Window>,
                gtk::DialogFlags::MODAL,
                gtk::MessageType::Error,
                gtk::ButtonsType::Close,
                "Could not start",
            );
            d.set_secondary_text(Some(&e));
            d.connect_response(|d, _| d.destroy());
            d.present();
        }
    });

    app.run()
}

fn build_window(app: &gtk::Application, base_url: &str) -> Result<gtk::ApplicationWindow, String> {
    let client = Arc::new(GaldradClient::new(base_url).map_err(|e| format!("HTTP client: {e}"))?);

    let window = gtk::ApplicationWindow::builder()
        .application(app)
        .title("Galdra")
        .default_width(960)
        .default_height(640)
        .build();

    let url_bar = gtk::Label::new(Some(client.base_url()));
    url_bar.add_css_class("dim-label");
    url_bar.set_halign(gtk::Align::Start);
    url_bar.set_margin_start(12);
    url_bar.set_margin_end(12);

    let err_label = gtk::Label::new(None);
    err_label.add_css_class("error");
    err_label.set_wrap(true);
    err_label.set_visible(false);

    let header = gtk::HeaderBar::new();
    let title = gtk::Label::new(Some("Galdra"));
    title.add_css_class("title");
    header.set_title_widget(Some(&title));

    let stack = gtk::Stack::new();
    let switcher = gtk::StackSwitcher::new();
    switcher.set_stack(Some(&stack));

    let refresh = gtk::Button::builder()
        .label("Refresh")
        .tooltip_text("Reload data for the current page")
        .build();
    header.pack_end(&refresh);

    let overview_health = text_view();
    let overview_device = text_view();
    let overview_page = overview_tab(&overview_health, &overview_device);
    stack.add_titled(&overview_page, Some("overview"), "Overview");

    let contacts_list = gtk::ListBox::new();
    contacts_list.add_css_class("boxed-list");
    let contacts_page = scrolled(&contacts_list);
    stack.add_titled(&contacts_page, Some("contacts"), "Contacts");

    let groups_list = gtk::ListBox::new();
    groups_list.add_css_class("boxed-list");
    let groups_page = scrolled(&groups_list);
    stack.add_titled(&groups_page, Some("groups"), "Groups");

    let audit_text = text_view();
    let audit_page = scrolled(&audit_text);
    stack.add_titled(&audit_page, Some("audit"), "Audit");

    let (crypto_page, crypto_reload) = crypto_ui::build(client.clone(), &window);
    let (profiles_page, profiles_refresh) = profiles_ui::build(
        client.clone(),
        err_label.clone(),
        window.clone(),
        crypto_reload.clone(),
    );
    stack.add_titled(&profiles_page, Some("profiles"), "Profiles");

    stack.add_titled(&crypto_page, Some("crypto"), "Crypto");

    let shamir_page = shamir_ui::build(client.clone());
    stack.add_titled(&shamir_page, Some("shamir"), "Shamir");

    let root = gtk::Box::new(gtk::Orientation::Vertical, 0);
    root.append(&err_label);
    root.append(&header);
    root.append(&url_bar);
    root.append(&switcher);
    root.append(&stack);

    window.set_child(Some(&root));

    let do_refresh: Rc<dyn Fn()> = Rc::new({
        let client = client.clone();
        let stack = stack.clone();
        let err_label = err_label.clone();
        let overview_health = overview_health.clone();
        let overview_device = overview_device.clone();
        let contacts_list = contacts_list.clone();
        let groups_list = groups_list.clone();
        let audit_text = audit_text.clone();
        let profiles_refresh = profiles_refresh.clone();
        let crypto_reload = crypto_reload.clone();
        move || {
            let name = stack
                .visible_child_name()
                .map(|s| s.to_string())
                .unwrap_or_default();
            match name.as_str() {
                "overview" => {
                    refresh_overview(&client, &err_label, &overview_health, &overview_device)
                }
                "contacts" => refresh_contacts(&client, &err_label, &contacts_list),
                "groups" => refresh_groups(&client, &err_label, &groups_list),
                "audit" => refresh_audit(&client, &err_label, &audit_text),
                "profiles" => profiles_refresh(),
                "crypto" => crypto_reload(),
                _ => {}
            }
        }
    });

    refresh.connect_clicked({
        let do_refresh = do_refresh.clone();
        move |_| do_refresh()
    });

    stack.connect_visible_child_name_notify({
        let do_refresh = do_refresh.clone();
        move |_stack| {
            do_refresh();
        }
    });

    do_refresh();

    Ok(window)
}

fn refresh_overview(
    client: &Arc<GaldradClient>,
    err_label: &gtk::Label,
    health_tv: &gtk::TextView,
    device_tv: &gtk::TextView,
) {
    let err_w = err_label.downgrade();
    let h_w = health_tv.downgrade();
    let d_w = device_tv.downgrade();
    let c = client.clone();
    glib::spawn_future_local(async move {
        let c2 = c.clone();
        let (rh, rd) = spawn_blocking(move || {
            let health = c.health_pretty();
            let device = c2.device_status_pretty();
            (health, device)
        })
        .await
        .unwrap();
        if let Some(hv) = h_w.upgrade() {
            match rh {
                Ok(s) => set_text_view(&hv, &s),
                Err(e) => {
                    if let Some(el) = err_w.upgrade() {
                        show_error(&el, &e);
                    }
                }
            }
        }
        if let Some(dv) = d_w.upgrade() {
            match rd {
                Ok(s) => set_text_view(&dv, &s),
                Err(e) => {
                    if let Some(el) = err_w.upgrade() {
                        show_error(&el, &e);
                    }
                }
            }
        }
    });
}

fn refresh_contacts(client: &Arc<GaldradClient>, err_label: &gtk::Label, list: &gtk::ListBox) {
    let err_w = err_label.downgrade();
    let list_w = list.downgrade();
    let c = client.clone();
    glib::spawn_future_local(async move {
        let res = spawn_blocking(move || c.contacts()).await.unwrap();
        let Some(list) = list_w.upgrade() else {
            return;
        };
        match res {
            Ok(rows) => fill_contacts_list(&list, rows),
            Err(e) => {
                if let Some(el) = err_w.upgrade() {
                    show_error(&el, &e);
                }
            }
        }
    });
}

fn refresh_groups(client: &Arc<GaldradClient>, err_label: &gtk::Label, list: &gtk::ListBox) {
    let err_w = err_label.downgrade();
    let list_w = list.downgrade();
    let c = client.clone();
    glib::spawn_future_local(async move {
        let res = spawn_blocking(move || c.groups()).await.unwrap();
        let Some(list) = list_w.upgrade() else {
            return;
        };
        match res {
            Ok(rows) => fill_groups_list(&list, rows),
            Err(e) => {
                if let Some(el) = err_w.upgrade() {
                    show_error(&el, &e);
                }
            }
        }
    });
}

fn refresh_audit(client: &Arc<GaldradClient>, err_label: &gtk::Label, tv: &gtk::TextView) {
    let err_w = err_label.downgrade();
    let tv_w = tv.downgrade();
    let c = client.clone();
    glib::spawn_future_local(async move {
        let res = spawn_blocking(move || c.audit_pretty()).await.unwrap();
        let Some(tv) = tv_w.upgrade() else {
            return;
        };
        match res {
            Ok(s) => set_text_view(&tv, &s),
            Err(e) => {
                if let Some(el) = err_w.upgrade() {
                    show_error(&el, &e);
                }
            }
        }
    });
}

fn show_error(label: &gtk::Label, msg: &str) {
    label.set_text(msg);
    label.set_visible(true);
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

fn overview_tab(health: &gtk::TextView, device: &gtk::TextView) -> gtk::Box {
    let bx = gtk::Box::new(gtk::Orientation::Vertical, 12);
    bx.set_margin_top(12);
    bx.set_margin_bottom(12);
    bx.set_margin_start(12);
    bx.set_margin_end(12);

    let lh = gtk::Label::new(Some("GET /health"));
    lh.set_halign(gtk::Align::Start);
    lh.add_css_class("heading");
    bx.append(&lh);
    bx.append(&scrolled(health));

    let ld = gtk::Label::new(Some("GET /device/status"));
    ld.set_halign(gtk::Align::Start);
    ld.add_css_class("heading");
    bx.append(&ld);
    bx.append(&scrolled(device));

    bx
}

fn clear_list(list: &gtk::ListBox) {
    while let Some(row) = list.first_child() {
        list.remove(&row);
    }
}

fn list_row_title_sub(title: &str, subtitle: &str) -> gtk::ListBoxRow {
    let row = gtk::ListBoxRow::new();
    let bx = gtk::Box::new(gtk::Orientation::Vertical, 4);
    bx.set_margin_top(8);
    bx.set_margin_bottom(8);
    bx.set_margin_start(12);
    bx.set_margin_end(12);
    let t = gtk::Label::new(Some(title));
    t.set_halign(gtk::Align::Start);
    t.add_css_class("title");
    let s = gtk::Label::new(Some(subtitle));
    s.set_halign(gtk::Align::Start);
    s.add_css_class("dim-label");
    bx.append(&t);
    bx.append(&s);
    row.set_child(Some(&bx));
    row
}

fn fill_contacts_list(list: &gtk::ListBox, rows: Vec<IdentityRow>) {
    clear_list(list);
    if rows.is_empty() {
        list.append(&list_row_title_sub(
            "No contacts",
            "Add contacts with the galdra CLI or POST /contacts when galdrad is running.",
        ));
        return;
    }
    for r in rows {
        let title = if !r.display_name.is_empty() {
            r.display_name.clone()
        } else {
            r.email
                .clone()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| r.id.clone())
        };
        let mut sub = format!("id: {}", r.id);
        if let Some(c) = &r.callsign {
            sub.push_str(&format!(" · {c}"));
        }
        if let Some(e) = &r.email {
            sub.push_str(&format!(" · {e}"));
        }
        if let Some(d) = r.dmr_id {
            sub.push_str(&format!(" · DMR {d}"));
        }
        if let Some(a) = &r.radio_affiliation {
            sub.push_str(&format!(" · {a}"));
        }
        if let Some(s) = &r.street {
            sub.push_str(&format!(" · {s}"));
        }
        if let Some(ct) = &r.country {
            sub.push_str(&format!(" · {ct}"));
        }
        if let Some(pc) = &r.postal_code {
            sub.push_str(&format!(" · {pc}"));
        }
        if let Some(rg) = &r.region {
            sub.push_str(&format!(" · {rg}"));
        }
        if let Some(f) = &r.fluxer_id {
            sub.push_str(&format!(" · Fluxer {f}"));
        }
        if let Some(d) = &r.discord_id {
            sub.push_str(&format!(" · Discord {d}"));
        }
        if let Some(i) = &r.irc_id {
            sub.push_str(&format!(" · IRC {i}"));
        }
        list.append(&list_row_title_sub(&title, &sub));
    }
}

fn fill_groups_list(list: &gtk::ListBox, rows: Vec<GroupRow>) {
    clear_list(list);
    if rows.is_empty() {
        list.append(&list_row_title_sub(
            "No groups",
            "Create groups with the galdra CLI or POST /groups.",
        ));
        return;
    }
    for r in rows {
        list.append(&list_row_title_sub(
            &r.name,
            &format!("{} members", r.member_count),
        ));
    }
}
