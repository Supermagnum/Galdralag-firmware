//! Axum router and JSON handlers wrapping `galdra-core-host`.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use galdra_core_host::audit::{self, AuditAction, AuditFilter, AuditRecord};
use galdra_core_host::contacts::{
    self, ContactFilter, ContactUpdate, Identity, NewContact,
};
use galdra_core_host::db::Db;
use galdra_core_host::device::Device;
use galdra_core_host::groups::{self, GroupSummary, GroupWithMembers};
use galdra_core_host::GaldraError;
use serde::Deserialize;
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

fn resolve_identity(db: &Db, id: &str) -> Result<Identity, GaldraError> {
    if let Ok(c) = contacts::contact_get_by_id(db, id) {
        return Ok(c);
    }
    if let Ok(c) = contacts::contact_get_by_callsign(db, id) {
        return Ok(c);
    }
    contacts::contact_get_by_email(db, id)
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
    params(("id" = String, Path, description = "Contact id, callsign, or email")),
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
    pub identifier: String,
    pub name: Option<String>,
    pub email: Option<String>,
    pub callsign: Option<String>,
    pub badge: Option<String>,
    pub org: Option<String>,
    pub role: Option<String>,
    pub note: Option<String>,
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
    let nc = NewContact {
        display_name: body.name.unwrap_or_else(|| body.identifier.clone()),
        callsign: body.callsign,
        email: body.email,
        badge_number: body.badge,
        organisation: body.org,
        department: None,
        role: body.role,
        note: body.note,
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
    let list = run_db_ro(&state, move |db| groups::group_list(db)).await?;
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
            })
        }
        Err(GaldraError::DeviceNotConnected) => serde_json::json!({
            "connected": false,
            "locked": true,
            "serial": serde_json::Value::Null,
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
            AuditAction::from_wire(a).ok_or_else(|| {
                GaldraError::Config(format!("unknown audit action: {a}"))
            })?,
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

async fn stub_encrypt(State(_): State<AppState>) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(serde_json::json!({
            "error": "encrypt is not implemented in galdrad yet",
        })),
    )
}

async fn stub_decrypt(State(_): State<AppState>) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(serde_json::json!({
            "error": "decrypt is not implemented in galdrad yet",
        })),
    )
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
    components(schemas(CreateContactBody, UpdateContactBody, CreateGroupBody, AddMembersBody)),
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
        .route("/encrypt", post(stub_encrypt))
        .route("/decrypt", post(stub_decrypt))
        .route("/sign", post(stub_sign))
        .route("/verify", post(stub_verify))
        .with_state(state)
        .layer(TraceLayer::new_for_http());

    Router::new()
        .merge(
            SwaggerUi::new("/swagger-ui")
                .url("/api-docs/openapi.json", ApiDoc::openapi()),
        )
        .merge(api)
}
