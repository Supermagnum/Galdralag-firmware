//! HTTP error mapping for [`galdra_core_host::GaldraError`].

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use galdra_core_host::GaldraError;

#[derive(Debug)]
pub struct ApiError(pub GaldraError);

impl From<GaldraError> for ApiError {
    fn from(e: GaldraError) -> Self {
        ApiError(e)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match &self.0 {
            GaldraError::ContactNotFound(_)
            | GaldraError::GroupNotFound(_)
            | GaldraError::MembershipExpired { .. } => StatusCode::NOT_FOUND,
            GaldraError::Config(_)
            | GaldraError::PinTooShort
            | GaldraError::PinNotAlphanumeric
            | GaldraError::Serialise(_) => StatusCode::BAD_REQUEST,
            GaldraError::UserAborted => StatusCode::CONFLICT,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        let body = serde_json::json!({ "error": self.0.to_string() });
        (status, Json(body)).into_response()
    }
}
