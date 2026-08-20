//! Bearer-token authentication against the durable auth store.

use crate::state::AppState;
use crate::users::TokenRecord;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::StatusCode;
use safehub_types::UserId;

/// Authenticated user extracted from `Authorization: Bearer …`.
#[derive(Clone, Debug)]
pub struct AuthUser {
    pub user: UserId,
    pub token: TokenRecord,
}

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(StatusCode::UNAUTHORIZED)?;
        let token = header
            .strip_prefix("Bearer ")
            .ok_or(StatusCode::UNAUTHORIZED)?;
        let auth = state.auth.read().await;
        let rec = auth
            .lookup_token(token)
            .cloned()
            .ok_or(StatusCode::UNAUTHORIZED)?;
        Ok(AuthUser {
            user: UserId(rec.user.clone()),
            token: rec,
        })
    }
}
