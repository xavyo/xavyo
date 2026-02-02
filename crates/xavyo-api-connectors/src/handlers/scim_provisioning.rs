//! HTTP handlers for SCIM provisioning state management (F087 - US6).
//!
//! Provides endpoints to view provisioning state per resource per target
//! and to retry failed provisioning operations.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use xavyo_auth::JwtClaims;
use xavyo_db::models::{ScimProvisioningState, ScimTarget};

use crate::error::{ConnectorApiError, Result};
use crate::handlers::scim_targets::ScimTargetState;

/// Query parameters for listing provisioning state.
#[derive(Debug, Deserialize, IntoParams)]
pub struct ListProvisioningStateQuery {
    pub resource_type: Option<String>,
    pub status: Option<String>,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    50
}

/// Response for provisioning state listing.
#[derive(Debug, Serialize, ToSchema)]
pub struct ProvisioningStateListResponse {
    pub target_id: Uuid,
    pub items: Vec<ScimProvisioningState>,
    pub total_count: i64,
    pub limit: i64,
    pub offset: i64,
}

/// Response for a retry operation.
#[derive(Debug, Serialize, ToSchema)]
pub struct RetryResponse {
    pub state_id: Uuid,
    pub status: String,
    pub message: String,
}

/// Extract tenant_id from JWT claims.
fn extract_tenant_id(claims: &JwtClaims) -> Result<Uuid> {
    claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(ConnectorApiError::Unauthorized {
            message: "Missing tenant_id in claims".to_string(),
        })
}

/// GET /admin/scim-targets/:id/provisioning-state — List provisioning state entries.
#[utoipa::path(
    get,
    path = "/admin/scim-targets/{target_id}/provisioning-state",
    tag = "SCIM Target Provisioning",
    params(
        ("target_id" = Uuid, Path, description = "SCIM target ID"),
        ListProvisioningStateQuery
    ),
    responses(
        (status = 200, description = "Provisioning state list", body = ProvisioningStateListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Target not found")
    ),
    security(("bearerAuth" = []))
)]
pub async fn list_provisioning_state(
    State(state): State<ScimTargetState>,
    Extension(claims): Extension<JwtClaims>,
    Path(target_id): Path<Uuid>,
    Query(query): Query<ListProvisioningStateQuery>,
) -> Result<Json<ProvisioningStateListResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;
    let pool = state.scim_target_service.pool();

    // Verify target exists.
    ScimTarget::get_by_id(pool, tenant_id, target_id)
        .await?
        .ok_or_else(|| ConnectorApiError::NotFound {
            resource: "scim_target".to_string(),
            id: target_id.to_string(),
        })?;

    let limit = query.limit.clamp(1, 100);
    let offset = query.offset.max(0);

    let (items, total_count) = ScimProvisioningState::list_by_target(
        pool,
        tenant_id,
        target_id,
        query.resource_type.as_deref(),
        query.status.as_deref(),
        limit,
        offset,
    )
    .await?;

    Ok(Json(ProvisioningStateListResponse {
        target_id,
        items,
        total_count,
        limit,
        offset,
    }))
}

/// POST /admin/scim-targets/:id/provisioning-state/:state_id/retry — Retry a failed operation.
#[utoipa::path(
    post,
    path = "/admin/scim-targets/{target_id}/provisioning-state/{state_id}/retry",
    tag = "SCIM Target Provisioning",
    params(
        ("target_id" = Uuid, Path, description = "SCIM target ID"),
        ("state_id" = Uuid, Path, description = "Provisioning state ID")
    ),
    responses(
        (status = 202, description = "Retry initiated", body = RetryResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Target or state not found"),
        (status = 409, description = "State not in error status")
    ),
    security(("bearerAuth" = []))
)]
pub async fn retry_provisioning(
    State(state): State<ScimTargetState>,
    Extension(claims): Extension<JwtClaims>,
    Path((target_id, state_id)): Path<(Uuid, Uuid)>,
) -> Result<(StatusCode, Json<RetryResponse>)> {
    let tenant_id = extract_tenant_id(&claims)?;
    let pool = state.scim_target_service.pool();

    // Verify target exists.
    ScimTarget::get_by_id(pool, tenant_id, target_id)
        .await?
        .ok_or_else(|| ConnectorApiError::NotFound {
            resource: "scim_target".to_string(),
            id: target_id.to_string(),
        })?;

    // Look up the provisioning state.
    let prov_state = ScimProvisioningState::get_by_id(pool, tenant_id, state_id)
        .await?
        .ok_or_else(|| ConnectorApiError::NotFound {
            resource: "scim_provisioning_state".to_string(),
            id: state_id.to_string(),
        })?;

    // Verify the state belongs to the correct target.
    if prov_state.target_id != target_id {
        return Err(ConnectorApiError::NotFound {
            resource: "scim_provisioning_state".to_string(),
            id: state_id.to_string(),
        });
    }

    // Only error state can be retried.
    if prov_state.status != "error" {
        return Err(ConnectorApiError::Conflict(format!(
            "Cannot retry provisioning state in '{}' status; only 'error' state can be retried",
            prov_state.status,
        )));
    }

    // Reset to pending for retry.
    ScimProvisioningState::mark_pending_retry(pool, tenant_id, state_id).await?;

    Ok((
        StatusCode::ACCEPTED,
        Json(RetryResponse {
            state_id,
            status: "pending".to_string(),
            message: "Provisioning state reset to pending for retry".to_string(),
        }),
    ))
}
