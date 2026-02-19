//! NHI activity summary handler.
//!
//! Provides `GET /nhi/{nhi_id}/activity-summary` to surface
//! tool/agent usage data from the ext-authz activity counters.

use axum::{
    extract::{Path, State},
    response::IntoResponse,
    Extension, Json,
};
use uuid::Uuid;
use xavyo_auth::JwtClaims;
use xavyo_core::TenantId;
use xavyo_db::models::NhiActivityCounter;

use crate::error::NhiApiError;
use crate::state::NhiState;

/// GET /nhi/{nhi_id}/activity-summary
///
/// Returns activity statistics for a given NHI identity:
/// - `last_activity_at` from `nhi_identities`
/// - `total_calls_24h` and `total_calls_7d` from `nhi_activity_counters`
pub async fn activity_summary_handler(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path(nhi_id): Path<Uuid>,
) -> Result<impl IntoResponse, NhiApiError> {
    if !claims.has_role("admin") {
        return Err(NhiApiError::Forbidden);
    }

    let tenant_uuid = *tenant_id.as_uuid();

    let summary = NhiActivityCounter::get_summary(&state.pool, tenant_uuid, nhi_id)
        .await
        .map_err(NhiApiError::Database)?
        .ok_or(NhiApiError::NotFound)?;

    Ok(Json(summary))
}
