use axum::{
    extract::{Path, State},
    Json,
};
use uuid::Uuid;

use crate::error::ApiError;
use crate::models::common::SuccessResponse;
use crate::models::tokens::{MintTokenRequest, MintTokenResponse, TokenListResponse, TokenSummary};
use crate::state::AppState;

#[utoipa::path(
    post,
    security(("bearer_auth" = [])),
    path = "/api/v1/tokens",
    tag = "tokens",
    request_body = MintTokenRequest,
    responses(
        (status = 200, description = "Token minted", body = MintTokenResponse),
        (status = 400, description = "Invalid request (empty session_ids)"),
        (status = 404, description = "One of the requested sessions doesn't exist")
    )
)]
pub async fn mint_token(
    State(state): State<AppState>,
    Json(request): Json<MintTokenRequest>,
) -> Result<Json<MintTokenResponse>, ApiError> {
    if request.session_ids.is_empty() {
        return Err(ApiError::BadRequest(
            "session_ids must not be empty".to_string(),
        ));
    }

    for session_id in &request.session_ids {
        state
            .session_manager()
            .get_session(session_id)
            .await
            .map_err(|e| ApiError::Internal(e.to_string()))?
            .ok_or_else(|| ApiError::SessionNotFound(session_id.clone()))?;
    }

    let id = Uuid::new_v4().to_string();
    let expires_in_hours = request.expires_in_hours.unwrap_or(24 * 30).max(1);
    let expires_at = chrono::Utc::now() + chrono::Duration::hours(expires_in_hours);

    let store = crate::db::tokens::TokenStore::new(state.session_manager().pool());
    store
        .create(
            &id,
            request.name.as_deref(),
            Some(expires_at),
            &request.session_ids,
        )
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let jwt_auth = crate::middleware::jwt::JwtAuth::new();
    let token = jwt_auth
        .generate_token(&id, "superadmin", expires_in_hours, Some(&id))
        .map_err(|e| ApiError::Internal(format!("failed to generate token: {e}")))?;

    Ok(Json(MintTokenResponse {
        id,
        token,
        name: request.name,
        session_ids: request.session_ids,
        expires_at: expires_at.timestamp(),
    }))
}

#[utoipa::path(
    get,
    security(("bearer_auth" = [])),
    path = "/api/v1/tokens",
    tag = "tokens",
    responses(
        (status = 200, description = "List of minted tokens (metadata only, never the bearer value)", body = TokenListResponse)
    )
)]
pub async fn list_tokens(
    State(state): State<AppState>,
) -> Result<Json<TokenListResponse>, ApiError> {
    let store = crate::db::tokens::TokenStore::new(state.session_manager().pool());
    let records = store
        .list(1000, 0)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    let count = records.len();
    let tokens = records
        .into_iter()
        .map(|r| TokenSummary {
            id: r.id,
            name: r.name,
            session_ids: r.session_ids,
            created_at: r.created_at,
            expires_at: r.expires_at,
            revoked: r.revoked_at.is_some(),
        })
        .collect();
    Ok(Json(TokenListResponse { tokens, count }))
}

#[utoipa::path(
    post,
    security(("bearer_auth" = [])),
    path = "/api/v1/tokens/{id}/revoke",
    tag = "tokens",
    params(
        ("id" = String, Path, description = "Token id, as returned by POST /tokens")
    ),
    responses(
        (status = 200, description = "Token revoked", body = SuccessResponse),
        (status = 404, description = "Token not found or already revoked")
    )
)]
pub async fn revoke_token(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<SuccessResponse>, ApiError> {
    let store = crate::db::tokens::TokenStore::new(state.session_manager().pool());
    let revoked = store
        .revoke(&id)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    if revoked {
        Ok(Json(SuccessResponse::with_message("Token revoked")))
    } else {
        Err(ApiError::TokenNotFound(id))
    }
}
