//! NHI credential management handlers.
//!
//! Provides endpoints for credential lifecycle:
//! - `POST /nhi/{id}/credentials` — Issue a new credential
//! - `GET /nhi/{id}/credentials` — List credentials for an NHI
//! - `POST /nhi/{id}/credentials/{credential_id}/rotate` — Rotate a credential
//! - `DELETE /nhi/{id}/credentials/{credential_id}` — Revoke a credential

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, post},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use xavyo_auth::JwtClaims;
use xavyo_core::TenantId;
use xavyo_db::models::NhiCredential;

use crate::error::NhiApiError;
use crate::services::nhi_credential_service::NhiCredentialService;
use crate::services::nhi_user_permission_service::NhiUserPermissionService;
use crate::state::NhiState;

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

/// Request body for issuing a new credential.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct IssueCredentialRequest {
    /// Type of credential: "api_key", "secret", or "certificate".
    pub credential_type: String,
    /// Validity period in days. Defaults to 90.
    pub valid_days: Option<i64>,
}

/// Request body for rotating a credential.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RotateCredentialRequest {
    /// Grace period in hours for the old credential. Defaults to 24.
    pub grace_period_hours: Option<i64>,
}

/// Response returned when a credential is issued or rotated.
///
/// The `secret` field contains the plaintext credential, which is returned
/// exactly once and never stored.
#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CredentialIssuedResponse {
    pub credential: NhiCredential,
    pub secret: String,
}

/// Pagination query parameters.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
pub struct PaginationQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `POST /nhi/{id}/credentials` — Issue a new credential for an NHI.
///
/// Requires admin role. Returns the credential record and the plaintext secret
/// (returned exactly once).
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/nhi/{nhi_id}/credentials",
    tag = "NHI Credentials",
    operation_id = "issueNhiCredential",
    params(
        ("nhi_id" = Uuid, Path, description = "NHI identity ID")
    ),
    request_body = IssueCredentialRequest,
    responses(
        (status = 201, description = "Credential issued successfully", body = CredentialIssuedResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "NHI identity not found")
    ),
    security(("bearerAuth" = []))
))]
pub async fn issue_credential(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path(nhi_id): Path<Uuid>,
    Json(body): Json<IssueCredentialRequest>,
) -> Result<impl IntoResponse, NhiApiError> {
    let tenant_uuid = *tenant_id.as_uuid();
    NhiUserPermissionService::enforce_access(&state.pool, tenant_uuid, &claims, nhi_id, "manage")
        .await?;
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| NhiApiError::BadRequest("invalid user ID in token".to_string()))?;

    let valid_days = body.valid_days.unwrap_or(90);
    if !(1..=3650).contains(&valid_days) {
        return Err(NhiApiError::BadRequest(
            "valid_days must be between 1 and 3650".to_string(),
        ));
    }

    let valid_types = ["api_key", "secret", "certificate"];
    if !valid_types.contains(&body.credential_type.as_str()) {
        return Err(NhiApiError::BadRequest(format!(
            "credential_type must be one of: {}",
            valid_types.join(", ")
        )));
    }

    let (credential, secret) = NhiCredentialService::issue(
        &state.pool,
        tenant_uuid,
        nhi_id,
        body.credential_type,
        valid_days,
        user_id,
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(CredentialIssuedResponse { credential, secret }),
    ))
}

/// `GET /nhi/{id}/credentials` — List credentials for an NHI.
///
/// Requires admin role. The `credential_hash` field is excluded from the response
/// via `#[serde(skip_serializing)]` on the model.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/nhi/{nhi_id}/credentials",
    tag = "NHI Credentials",
    operation_id = "listNhiCredentials",
    params(
        ("nhi_id" = Uuid, Path, description = "NHI identity ID"),
        PaginationQuery
    ),
    responses(
        (status = 200, description = "List of credentials", body = Vec<NhiCredential>),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Forbidden")
    ),
    security(("bearerAuth" = []))
))]
pub async fn list_credentials(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path(nhi_id): Path<Uuid>,
    Query(pagination): Query<PaginationQuery>,
) -> Result<impl IntoResponse, NhiApiError> {
    let tenant_uuid = *tenant_id.as_uuid();
    NhiUserPermissionService::enforce_access(&state.pool, tenant_uuid, &claims, nhi_id, "manage")
        .await?;

    let limit = pagination.limit.unwrap_or(20).min(100);
    let offset = pagination.offset.unwrap_or(0).max(0);

    let credentials =
        NhiCredential::list_by_nhi(&state.pool, tenant_uuid, nhi_id, limit, offset).await?;

    Ok(Json(credentials))
}

/// `POST /nhi/{id}/credentials/{credential_id}/rotate` — Rotate a credential.
///
/// Requires admin role. Issues a new credential and sets the old one to expire
/// after the specified grace period. Returns the new credential with its plaintext.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/nhi/{nhi_id}/credentials/{credential_id}/rotate",
    tag = "NHI Credentials",
    operation_id = "rotateNhiCredential",
    params(
        ("nhi_id" = Uuid, Path, description = "NHI identity ID"),
        ("credential_id" = Uuid, Path, description = "Credential ID to rotate")
    ),
    request_body = RotateCredentialRequest,
    responses(
        (status = 201, description = "Credential rotated successfully", body = CredentialIssuedResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Credential not found")
    ),
    security(("bearerAuth" = []))
))]
pub async fn rotate_credential(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path((nhi_id, credential_id)): Path<(Uuid, Uuid)>,
    Json(body): Json<RotateCredentialRequest>,
) -> Result<impl IntoResponse, NhiApiError> {
    let tenant_uuid = *tenant_id.as_uuid();
    NhiUserPermissionService::enforce_access(&state.pool, tenant_uuid, &claims, nhi_id, "manage")
        .await?;
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| NhiApiError::BadRequest("invalid user ID in token".to_string()))?;

    let grace_period_hours = body.grace_period_hours.unwrap_or(24);
    if !(0..=720).contains(&grace_period_hours) {
        return Err(NhiApiError::BadRequest(
            "grace_period_hours must be between 0 and 720".to_string(),
        ));
    }

    // Look up the old credential to get its type for the new one
    let old_cred = NhiCredential::find_by_id(&state.pool, tenant_uuid, credential_id)
        .await?
        .ok_or(NhiApiError::NotFound)?;

    let (credential, secret) = NhiCredentialService::rotate(
        &state.pool,
        tenant_uuid,
        nhi_id,
        credential_id,
        old_cred.credential_type,
        90, // default valid_days for rotated credential
        grace_period_hours,
        user_id,
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(CredentialIssuedResponse { credential, secret }),
    ))
}

/// `DELETE /nhi/{id}/credentials/{credential_id}` — Revoke a credential.
///
/// Requires admin role. Sets the credential's `is_active` flag to false.
#[cfg_attr(feature = "openapi", utoipa::path(
    delete,
    path = "/nhi/{nhi_id}/credentials/{credential_id}",
    tag = "NHI Credentials",
    operation_id = "revokeNhiCredential",
    params(
        ("nhi_id" = Uuid, Path, description = "NHI identity ID"),
        ("credential_id" = Uuid, Path, description = "Credential ID to revoke")
    ),
    responses(
        (status = 204, description = "Credential revoked successfully"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Credential not found")
    ),
    security(("bearerAuth" = []))
))]
pub async fn revoke_credential(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path((nhi_id, credential_id)): Path<(Uuid, Uuid)>,
) -> Result<impl IntoResponse, NhiApiError> {
    let tenant_uuid = *tenant_id.as_uuid();
    NhiUserPermissionService::enforce_access(&state.pool, tenant_uuid, &claims, nhi_id, "manage")
        .await?;

    let revoked = NhiCredentialService::revoke(&state.pool, tenant_uuid, credential_id).await?;

    if revoked {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(NhiApiError::NotFound)
    }
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Creates the credential management routes.
///
/// Mounts under `/nhi`:
/// - `POST /:id/credentials` — Issue
/// - `GET /:id/credentials` — List
/// - `POST /:id/credentials/:cred_id/rotate` — Rotate
/// - `DELETE /:id/credentials/:cred_id` — Revoke
pub fn credential_routes(state: NhiState) -> Router {
    Router::new()
        .route(
            "/:id/credentials",
            post(issue_credential).get(list_credentials),
        )
        .route(
            "/:id/credentials/:credential_id/rotate",
            post(rotate_credential),
        )
        .route("/:id/credentials/:credential_id", delete(revoke_credential))
        .with_state(state)
}
