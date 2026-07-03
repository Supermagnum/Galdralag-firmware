//! Axum router and JSON handlers wrapping `galdra-core-host`.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use galdra_core_host::audit::{self, AuditAction, AuditEntry, AuditFilter, AuditRecord};
use galdra_core_host::cipher_envelope::{
    open_plaintext_from_openpgp_literal, parse_hex_fixed, seal_plaintext_with_profile,
    wrap_inner_with_cess_mode_a,
};
use galdra_core_host::cipher_profile::CipherProfileError;
use galdra_core_host::contacts::{self, ContactFilter, ContactUpdate, Identity, NewContact};
use galdra_core_host::db::Db;
use galdra_core_host::device::Device;
use galdra_core_host::encrypt::{self, encrypt_openpgp, try_decrypt_session_key_from_cert};
use galdra_core_host::groups::{self, GroupSummary, GroupWithMembers};
use galdra_core_host::profiles::{
    audit_crypto_detail_multiline, build_profile_from_options, parse_curve_wire, parse_layer_name,
    ProfileStore, ProfileSummary,
};
use galdra_core_host::shamir_ops::{shamir_recover_key, shamir_split_key, ShamirShareExport};
use galdra_core_host::GaldraError;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::policy::StandardPolicy;
use serde::Deserialize;
use sha2::digest::Digest;
use sha2::Sha256;
use tower_http::trace::TraceLayer;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::error::ApiError;
use crate::state::AppState;

async fn run_db<T, F>(state: &AppState, f: F) -> Result<T, GaldraError>
where
    F: FnOnce(&mut Db) -> Result<T, GaldraError> + Send + 'static,
    T: Send + 'static,
{
    let db = state.db.clone();
    tokio::task::spawn_blocking(move || {
        let mut g = db.lock().unwrap();
        f(&mut g)
    })
    .await
    .map_err(|e| GaldraError::Config(format!("join: {e}")))?
}

async fn run_db_ro<T, F>(state: &AppState, f: F) -> Result<T, GaldraError>
where
    F: FnOnce(&Db) -> Result<T, GaldraError> + Send + 'static,
    T: Send + 'static,
{
    let db = state.db.clone();
    tokio::task::spawn_blocking(move || {
        let g = db.lock().unwrap();
        f(&g)
    })
    .await
    .map_err(|e| GaldraError::Config(format!("join: {e}")))?
}

const PLACEHOLDER_SENDER_FP: &str = "0000000000000000000000000000000000000000";

fn identity_to_cert(id: &Identity) -> Result<sequoia_openpgp::Cert, GaldraError> {
    let bytes = id
        .pgp_pubkey
        .as_ref()
        .ok_or_else(|| GaldraError::OpenPgp(format!("contact {} has no OpenPGP key", id.id)))?;
    sequoia_openpgp::Cert::from_bytes(bytes).map_err(|e| GaldraError::OpenPgp(e.to_string()))
}

fn resolve_identity(db: &Db, id: &str) -> Result<Identity, GaldraError> {
    contacts::resolve_contact_identifier(db, id)
}

#[utoipa::path(get, path = "/health", responses((status = 200, description = "Liveness")))]
async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok" }))
}

#[derive(Debug, Deserialize)]
pub struct ListContactsQuery {
    pub expired: Option<bool>,
    pub org: Option<String>,
    pub role: Option<String>,
}

#[utoipa::path(
    get,
    path = "/contacts",
    params(
        ("expired" = Option<bool>, Query, description = "List only expired keys"),
        ("org" = Option<String>, Query, description = "Organisation filter"),
        ("role" = Option<String>, Query, description = "Role filter"),
    ),
    responses((status = 200, description = "Contact rows"))
)]
async fn list_contacts(
    State(state): State<AppState>,
    Query(q): Query<ListContactsQuery>,
) -> Result<Json<Vec<Identity>>, ApiError> {
    let filter = ContactFilter {
        expired: q.expired.unwrap_or(false),
        organisation: q.org,
        role: q.role,
    };
    let list = run_db_ro(&state, move |db| contacts::contact_list(db, filter)).await?;
    Ok(Json(list))
}

#[utoipa::path(
    get,
    path = "/contacts/{id}",
    params((
        "id" = String,
        Path,
        description = "Contact row UUID, callsign, e-mail, 40-hex OpenPGP fingerprint, Fluxer / Discord / IRC id, or DMR id (1..=16777215)"
    )),
    responses((status = 200, description = "Contact row"))
)]
async fn get_contact(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Identity>, ApiError> {
    let id_s = id.clone();
    let c = run_db_ro(&state, move |db| resolve_identity(db, &id_s)).await?;
    Ok(Json(c))
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CreateContactBody {
    pub email: String,
    pub name: Option<String>,
    pub callsign: Option<String>,
    pub badge: Option<String>,
    pub org: Option<String>,
    pub role: Option<String>,
    pub note: Option<String>,
    pub dmr_id: Option<i64>,
    pub radio_affiliation: Option<String>,
    pub street: Option<String>,
    pub country: Option<String>,
    pub postal_code: Option<String>,
    pub region: Option<String>,
    pub fluxer_id: Option<String>,
    pub discord_id: Option<String>,
    pub irc_id: Option<String>,
}

#[utoipa::path(
    post,
    path = "/contacts",
    request_body = CreateContactBody,
    responses((status = 200, description = "Created contact"))
)]
async fn create_contact(
    State(state): State<AppState>,
    Json(body): Json<CreateContactBody>,
) -> Result<Json<Identity>, ApiError> {
    let email = body.email.trim().to_string();
    if email.is_empty() {
        return Err(GaldraError::Config("email is required".into()).into());
    }
    let nc = NewContact {
        display_name: body.name.unwrap_or_default(),
        email,
        callsign: body.callsign,
        badge_number: body.badge,
        organisation: body.org,
        department: None,
        role: body.role,
        note: body.note,
        dmr_id: body.dmr_id,
        radio_affiliation: body.radio_affiliation,
        street: body.street,
        country: body.country,
        postal_code: body.postal_code,
        region: body.region,
        fluxer_id: body.fluxer_id,
        discord_id: body.discord_id,
        irc_id: body.irc_id,
    };
    let out = run_db(&state, move |db| contacts::contact_add(db, nc)).await?;
    Ok(Json(out))
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpdateContactBody {
    pub name: Option<String>,
    pub email: Option<String>,
    pub callsign: Option<String>,
    pub badge: Option<String>,
    pub org: Option<String>,
    pub role: Option<String>,
    pub note: Option<String>,
    pub dmr_id: Option<i64>,
    pub radio_affiliation: Option<String>,
    pub street: Option<String>,
    pub country: Option<String>,
    pub postal_code: Option<String>,
    pub region: Option<String>,
    pub fluxer_id: Option<String>,
    pub discord_id: Option<String>,
    pub irc_id: Option<String>,
}

async fn update_contact(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<UpdateContactBody>,
) -> Result<Json<Identity>, ApiError> {
    let id_s = id.clone();
    let u = ContactUpdate {
        display_name: body.name,
        callsign: body.callsign,
        email: body.email,
        badge_number: body.badge,
        organisation: body.org,
        department: None,
        role: body.role,
        note: body.note,
        dmr_id: body.dmr_id,
        radio_affiliation: body.radio_affiliation,
        street: body.street,
        country: body.country,
        postal_code: body.postal_code,
        region: body.region,
        fluxer_id: body.fluxer_id,
        discord_id: body.discord_id,
        irc_id: body.irc_id,
    };
    let out = run_db(&state, move |db| {
        let c = resolve_identity(db, &id_s)?;
        contacts::contact_update(db, &c.id, u)
    })
    .await?;
    Ok(Json(out))
}

async fn delete_contact(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let id_s = id.clone();
    run_db(&state, move |db| {
        let c = resolve_identity(db, &id_s)?;
        contacts::contact_delete(db, &c.id)
    })
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(get, path = "/groups", responses((status = 200, description = "Group list")))]
async fn list_groups(State(state): State<AppState>) -> Result<Json<Vec<GroupSummary>>, ApiError> {
    let list = run_db_ro(&state, groups::group_list).await?;
    Ok(Json(list))
}

#[utoipa::path(
    get,
    path = "/groups/{name}",
    params(("name" = String, Path, description = "Group name")),
    responses((status = 200, description = "Group with members"))
)]
async fn get_group(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<GroupWithMembers>, ApiError> {
    let name = name.clone();
    let g = run_db_ro(&state, move |db| groups::group_get(db, &name)).await?;
    Ok(Json(g))
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CreateGroupBody {
    pub name: String,
    pub description: Option<String>,
    pub hidden_recipients: Option<bool>,
}

async fn create_group(
    State(state): State<AppState>,
    Json(body): Json<CreateGroupBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let name = body.name.clone();
    let name_out = name.clone();
    let desc = body.description.clone();
    let hidden = body.hidden_recipients.unwrap_or(false);
    run_db(&state, move |db| {
        groups::group_create(db, &name, desc.as_deref(), hidden)
    })
    .await?;
    Ok(Json(serde_json::json!({ "name": name_out })))
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct AddMembersBody {
    pub identifiers: Vec<String>,
    pub expires: Option<String>,
}

async fn add_group_members(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(body): Json<AddMembersBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let group = name.clone();
    let ids = body.identifiers.clone();
    let added = ids.len();
    let exp = body
        .expires
        .as_ref()
        .map(|s| {
            DateTime::parse_from_rfc3339(s)
                .map(|d| d.with_timezone(&Utc))
                .map_err(|e| GaldraError::Config(e.to_string()))
        })
        .transpose()?;
    run_db(&state, move |db| {
        for id_str in &ids {
            let c = resolve_identity(db, id_str)?;
            groups::group_add_member(db, &group, &c.id, None, exp)?;
        }
        Ok(())
    })
    .await?;
    Ok(Json(serde_json::json!({ "added": added })))
}

async fn remove_group_member(
    State(state): State<AppState>,
    Path((name, id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let name = name.clone();
    let id_s = id.clone();
    run_db(&state, move |db| {
        let c = resolve_identity(db, &id_s)?;
        groups::group_remove_member(db, &name, &c.id)
    })
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(get, path = "/device/status", responses((status = 200, description = "Token summary")))]
async fn device_status() -> Result<Json<serde_json::Value>, ApiError> {
    let openpgp = galdra_core_host::openpgp_pcsc::scan_openpgp_card_via_pcsc();
    let v = match Device::connect() {
        Ok(dev) => {
            let st = dev.status().map_err(ApiError::from)?;
            let info = dev.info().map_err(ApiError::from)?;
            serde_json::json!({
                "connected": true,
                "locked": st.locked,
                "serial": dev.serial(),
                "status": st,
                "info": info,
                "openpgp_card": openpgp,
            })
        }
        Err(GaldraError::DeviceNotConnected) => serde_json::json!({
            "connected": false,
            "locked": true,
            "serial": serde_json::Value::Null,
            "openpgp_card": openpgp,
        }),
        Err(e) => return Err(ApiError(e)),
    };
    Ok(Json(v))
}

#[derive(Debug, Deserialize)]
pub struct AuditQuery {
    pub since: Option<String>,
    pub action: Option<String>,
    pub limit: Option<u64>,
}

#[utoipa::path(get, path = "/audit", responses((status = 200, description = "Audit rows")))]
async fn list_audit(
    State(state): State<AppState>,
    Query(q): Query<AuditQuery>,
) -> Result<Json<Vec<AuditRecord>>, ApiError> {
    let since_dt = if let Some(s) = &q.since {
        Some(
            DateTime::parse_from_rfc3339(s)
                .map_err(|e| GaldraError::Config(e.to_string()))?
                .with_timezone(&Utc),
        )
    } else {
        None
    };
    let act = if let Some(a) = &q.action {
        Some(
            AuditAction::from_wire(a)
                .ok_or_else(|| GaldraError::Config(format!("unknown audit action: {a}")))?,
        )
    } else {
        None
    };
    let filter = AuditFilter {
        since: since_dt,
        action: act,
        limit: q.limit,
    };
    let rows = run_db_ro(&state, move |db| audit::audit_query(db, filter)).await?;
    Ok(Json(rows))
}

#[derive(Debug, Deserialize)]
pub struct EncryptBody {
    pub group: String,
    pub plaintext_b64: String,
    pub profile: Option<String>,
    pub sign: Option<bool>,
    /// 64 hex chars: CESS `K_outer` (32 bytes); requires `cess_nonce_hex`.
    pub cess_k_outer_hex: Option<String>,
    /// 24 hex chars: 12-byte nonce for CESS Mode A outer.
    pub cess_nonce_hex: Option<String>,
}

async fn encrypt_msg(
    State(state): State<AppState>,
    Json(body): Json<EncryptBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if body.sign.unwrap_or(false) {
        return Err(ApiError(GaldraError::Config(
            "cleartext signing during encrypt requires a connected token (not yet integrated)"
                .to_string(),
        )));
    }
    let plain = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        body.plaintext_b64.as_str(),
    )
    .map_err(|e| GaldraError::Config(format!("base64: {e}")))?;
    let group = body.group.clone();
    let profile_name = body
        .profile
        .clone()
        .unwrap_or_else(|| "standard".to_string());
    let cess_k_outer_hex = body.cess_k_outer_hex.clone();
    let cess_nonce_hex = body.cess_nonce_hex.clone();
    let out = run_db(&state, move |db| {
        let policy = StandardPolicy::new();
        let store = ProfileStore::load(db)?;
        let cipher_profile = store
            .get_owned(&profile_name)
            .ok_or_else(|| GaldraError::ProfileNotFound(profile_name.clone()))?;
        let cess_k_outer: Option<[u8; 32]> = match (&cess_k_outer_hex, &cess_nonce_hex) {
            (None, None) => None,
            (Some(_), None) | (None, Some(_)) => {
                return Err(GaldraError::Config(
                    "CESS Mode A requires both cess_k_outer_hex and cess_nonce_hex".to_string(),
                ));
            }
            (Some(kh), Some(nh)) => {
                let k = parse_hex_fixed::<32>("cess_k_outer_hex", kh)?;
                let _ = parse_hex_fixed::<12>("cess_nonce_hex", nh)?;
                Some(k)
            }
        };
        let idents = groups::group_active_members(db, &group)?;
        let mut certs = Vec::new();
        for id in &idents {
            certs.push(identity_to_cert(id)?);
        }
        let g = groups::group_get(db, &group)?;
        let mut sealed =
            seal_plaintext_with_profile(&cipher_profile, &plain, PLACEHOLDER_SENDER_FP)?;
        if let Some(ref k_outer) = cess_k_outer {
            let nonce =
                parse_hex_fixed::<12>("cess_nonce_hex", cess_nonce_hex.as_ref().expect("paired"))?;
            sealed = wrap_inner_with_cess_mode_a(&sealed, cipher_profile.name(), k_outer, &nonce)?;
        }
        let ct = encrypt_openpgp(&policy, &sealed, None, &certs, g.hidden_recipients, true)?;
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, ct.as_slice());
        Ok::<_, GaldraError>(b64)
    })
    .await?;
    Ok(Json(serde_json::json!({ "ciphertext_b64": out })))
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CreateProfileBody {
    pub name: String,
    pub description: Option<String>,
    pub curve: String,
    pub layers: Vec<String>,
    pub shamir_threshold: Option<u8>,
    pub shamir_total: Option<u8>,
    /// When false, the profile allows Galdralag `G:` fingerprints (default: true).
    pub ephemeral_ecdh: Option<bool>,
}

async fn list_profiles(State(state): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    let rows = run_db_ro(&state, move |db| {
        let store = ProfileStore::load(db)?;
        Ok::<_, GaldraError>(store.list())
    })
    .await?;
    Ok(Json(serde_json::json!({ "profiles": rows })))
}

async fn get_profile(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let name_c = name.clone();
    let v = run_db_ro(&state, move |db| {
        let store = ProfileStore::load(db)?;
        let p = store
            .get(&name_c)
            .ok_or_else(|| GaldraError::ProfileNotFound(name_c.clone()))?;
        let s = ProfileSummary::from_profile(p, store.is_builtin(&name_c));
        Ok::<_, GaldraError>(s)
    })
    .await?;
    Ok(Json(serde_json::json!(v)))
}

async fn create_profile(
    State(state): State<AppState>,
    Json(body): Json<CreateProfileBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let name = body.name.clone();
    let name_out = name.clone();
    let desc = body.description.clone().unwrap_or_default();
    let curve_s = body.curve.clone();
    let layers_in = body.layers.clone();
    let kt = body.shamir_threshold.unwrap_or(1);
    let nt = body.shamir_total.unwrap_or(1);
    run_db(&state, move |db| {
        if layers_in.is_empty() {
            return Err(GaldraError::Config("layers must not be empty".to_string()));
        }
        let mut layers = Vec::new();
        for s in &layers_in {
            let l = parse_layer_name(s)?;
            if layers.contains(&l) {
                return Err(GaldraError::CipherProfile(format!(
                    "{:?}",
                    CipherProfileError::DuplicateCipher
                )));
            }
            layers.push(l);
        }
        let curve = parse_curve_wire(&curve_s)?;
        let ecdh = body.ephemeral_ecdh.unwrap_or(true);
        let profile = build_profile_from_options(&name, &desc, curve, &layers, kt, nt, ecdh)?;
        let mut store = ProfileStore::load(db)?;
        store.add(db, profile)?;
        Ok::<_, GaldraError>(())
    })
    .await?;
    Ok(Json(serde_json::json!({ "name": name_out })))
}

async fn delete_profile(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<StatusCode, ApiError> {
    let name_c = name.clone();
    run_db(&state, move |db| {
        let mut store = ProfileStore::load(db)?;
        if store.is_builtin(&name_c) {
            return Err(GaldraError::Config(
                "built-in profiles cannot be removed".to_string(),
            ));
        }
        store.remove(db, &name_c)?;
        Ok::<_, GaldraError>(())
    })
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
pub struct ShamirSplitBody {
    pub slot: u32,
    pub profile: String,
}

async fn shamir_split_handler(
    State(state): State<AppState>,
    Json(body): Json<ShamirSplitBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let profile = body.profile.clone();
    let slot = body.slot;
    let arms = run_db(&state, move |db| {
        let store = ProfileStore::load(db)?;
        let p = store
            .get_owned(&profile)
            .ok_or_else(|| GaldraError::ProfileNotFound(profile.clone()))?;
        let dev = Device::connect()?;
        let shares = shamir_split_key(&dev, &p, slot)?;
        Ok::<_, GaldraError>(
            shares
                .into_iter()
                .map(|s| s.to_armoured())
                .collect::<Vec<_>>(),
        )
    })
    .await?;
    Ok(Json(serde_json::json!(arms)))
}

#[derive(Debug, Deserialize)]
pub struct ShamirRecoverBody {
    pub slot: u32,
    pub shares: Vec<String>,
}

async fn shamir_recover_handler(
    State(state): State<AppState>,
    Json(body): Json<ShamirRecoverBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let slot = body.slot;
    let share_texts = body.shares.clone();
    run_db(&state, move |_db| {
        let mut exports = Vec::new();
        for t in &share_texts {
            exports.push(ShamirShareExport::from_armoured(t)?);
        }
        let dev = Device::connect()?;
        shamir_recover_key(&dev, &exports, slot)?;
        Ok::<_, GaldraError>(())
    })
    .await?;
    Ok(Json(serde_json::json!({ "ok": true, "slot": slot })))
}

#[derive(Debug, Deserialize)]
pub struct ShamirShareInfoQuery {
    pub armoured: String,
}

async fn shamir_share_info(
    Query(q): Query<ShamirShareInfoQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let ex = ShamirShareExport::from_armoured(&q.armoured).map_err(ApiError::from)?;
    Ok(Json(serde_json::json!({
        "profile": ex.profile_name,
        "threshold": ex.threshold,
        "total": ex.total,
        "index": ex.index,
        "fingerprint": ex.fingerprint,
        "created": ex.created_at_rfc3339,
    })))
}

fn session_id_from_ciphertext(ciphertext: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(ciphertext);
    let out = h.finalize();
    hex::encode(&out[..8])
}

#[derive(Debug, Deserialize)]
pub struct DecryptBody {
    pub recipient: String,
    pub ciphertext_b64: String,
    pub profile: Option<String>,
    /// 64 hex chars: CESS `K_outer` when the inner literal is Mode A wrapped.
    pub cess_k_outer_hex: Option<String>,
}

async fn decrypt_msg(
    State(state): State<AppState>,
    Json(body): Json<DecryptBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let recipient = body.recipient.clone();
    let ciphertext = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        body.ciphertext_b64.as_str(),
    )
    .map_err(|e| GaldraError::Config(format!("base64: {e}")))?;
    let profile_hint = body.profile.clone();
    let cess_k_outer_hex = body.cess_k_outer_hex.clone();
    let out = run_db(&state, move |db| {
        let policy = StandardPolicy::new();
        let id = resolve_identity(db, &recipient)?;
        let cert = identity_to_cert(&id)?;
        let try_decrypt = |pkesk: &sequoia_openpgp::packet::PKESK,
                           sym: Option<sequoia_openpgp::types::SymmetricAlgorithm>| {
            try_decrypt_session_key_from_cert(&policy, &cert, pkesk, sym)
        };
        let inner = encrypt::decrypt_openpgp(&policy, &ciphertext, &cert, try_decrypt, &[])
            .map_err(|e| {
                if matches!(e, GaldraError::OpenPgp(_)) {
                    GaldraError::Config(
                        "decryption failed — host stores public keys only; use a connected token with decryption support (integration pending)".to_string(),
                    )
                } else {
                    e
                }
            })?;
        let cess_k_outer: Option<[u8; 32]> = match cess_k_outer_hex.as_ref() {
            None => None,
            Some(s) => Some(parse_hex_fixed::<32>("cess_k_outer_hex", s)?),
        };
        let store = ProfileStore::load(db)?;
        let (plain, pname) = match open_plaintext_from_openpgp_literal(
            &inner,
            cess_k_outer.as_ref(),
            |n| store.get_owned(n),
        ) {
            Ok(pair) => {
                if let Some(ref hint) = profile_hint {
                    if hint != &pair.1 {
                        // mismatch is informational; ciphertext profile wins
                    }
                }
                pair
            }
            Err(GaldraError::ProfileNotFound(name)) => {
                return Err(GaldraError::ProfileNotFound(name));
            }
            Err(e) => return Err(e),
        };
        let sid = session_id_from_ciphertext(&ciphertext);
        let detail = if let Some(p) = store.get(&pname) {
            audit_crypto_detail_multiline(p, 1, &sid)
        } else {
            format!("profile:{pname}\nsession_id:{sid} (profile definition missing from registry)")
        };
        audit::audit_append(
            db,
            AuditEntry {
                timestamp: chrono::Utc::now(),
                operator: None,
                action: AuditAction::Decrypt,
                subject: Some(id.id.clone()),
                detail: Some(detail),
                device_serial: None,
            },
        )?;
        let b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            plain.as_slice(),
        );
        Ok::<_, GaldraError>((b64, pname))
    })
    .await?;
    Ok(Json(serde_json::json!({
        "plaintext_b64": out.0,
        "profile": out.1,
    })))
}

async fn stub_sign(State(_): State<AppState>) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(serde_json::json!({
            "error": "sign is not implemented in galdrad yet",
        })),
    )
}

async fn stub_verify(State(_): State<AppState>) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(serde_json::json!({
            "error": "verify is not implemented in galdrad yet",
        })),
    )
}

#[derive(OpenApi)]
#[openapi(
    paths(
        health,
        list_contacts,
        get_contact,
        list_groups,
        get_group,
        device_status,
        list_audit,
    ),
    info(
        title = "galdrad",
        description = "Local Galdra REST API (JSON over HTTP)",
        version = "0.1.0",
    ),
    components(schemas(CreateContactBody, UpdateContactBody, CreateGroupBody, AddMembersBody))
)]
pub struct ApiDoc;

pub fn router(state: AppState) -> Router {
    let api = Router::new()
        .route("/health", get(health))
        .route("/contacts", get(list_contacts).post(create_contact))
        .route(
            "/contacts/:id",
            get(get_contact)
                .patch(update_contact)
                .delete(delete_contact),
        )
        .route("/groups", get(list_groups).post(create_group))
        .route("/groups/:name", get(get_group))
        .route("/groups/:name/members", post(add_group_members))
        .route("/groups/:name/members/:id", delete(remove_group_member))
        .route("/device/status", get(device_status))
        .route("/audit", get(list_audit))
        .route("/profiles", get(list_profiles).post(create_profile))
        .route("/profiles/:name", get(get_profile).delete(delete_profile))
        .route("/shamir/split", post(shamir_split_handler))
        .route("/shamir/recover", post(shamir_recover_handler))
        .route("/shamir/share-info", get(shamir_share_info))
        .route("/encrypt", post(encrypt_msg))
        .route("/decrypt", post(decrypt_msg))
        .route("/sign", post(stub_sign))
        .route("/verify", post(stub_verify))
        .with_state(state)
        .layer(TraceLayer::new_for_http());

    Router::new()
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
        .merge(api)
}
