//! Certification campaign handlers.
//!
//! Provides endpoints for NHI certification:
//! - `POST /certifications` — Create a certification campaign
//! - `GET /certifications` — List certification campaigns
//! - `POST /certifications/:campaign_id/certify/:nhi_id` — Certify an NHI
//! - `POST /certifications/:campaign_id/revoke/:nhi_id` — Revoke certification (deprecates NHI)

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Extension, Json, Router,
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use xavyo_auth::JwtClaims;
use xavyo_core::TenantId;
use xavyo_db::models::{CreateNhiCertificationCampaign, NhiCertificationCampaign, NhiIdentity};
use xavyo_nhi::NhiLifecycleState;

use crate::error::NhiApiError;
use crate::services::nhi_lifecycle_service::NhiLifecycleService;
use crate::state::NhiState;

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateCampaignRequest {
    pub name: String,
    pub description: Option<String>,
    pub scope: Option<String>,
    pub nhi_type_filter: Option<String>,
    pub specific_nhi_ids: Option<Vec<Uuid>>,
    pub due_date: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CertifyResponse {
    pub nhi_id: Uuid,
    pub certified_by: Uuid,
    pub certified_at: DateTime<Utc>,
    pub next_certification_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RevokeResponse {
    pub nhi_id: Uuid,
    pub revoked: bool,
    pub new_state: String,
}

#[derive(Debug, Deserialize)]
pub struct ListCampaignsQuery {
    pub status: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// POST /certifications — Create a certification campaign.
async fn create_campaign(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Json(req): Json<CreateCampaignRequest>,
) -> Result<impl IntoResponse, NhiApiError> {
    if !claims.has_role("admin") {
        return Err(NhiApiError::Forbidden);
    }

    let tenant_uuid = *tenant_id.as_uuid();
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| NhiApiError::BadRequest("Invalid user ID".into()))?;

    if req.name.is_empty() {
        return Err(NhiApiError::BadRequest("Campaign name is required".into()));
    }

    // Validate scope consistency
    let scope = req.scope.as_deref().unwrap_or("all");
    match scope {
        "by_type" => {
            if req.nhi_type_filter.as_ref().is_none_or(|s| s.is_empty()) {
                return Err(NhiApiError::BadRequest(
                    "nhi_type_filter is required when scope is 'by_type'".into(),
                ));
            }
        }
        "specific" => {
            if req.specific_nhi_ids.as_ref().is_none_or(|v| v.is_empty()) {
                return Err(NhiApiError::BadRequest(
                    "specific_nhi_ids is required when scope is 'specific'".into(),
                ));
            }
        }
        "all" => {}
        other => {
            return Err(NhiApiError::BadRequest(format!(
                "Invalid scope '{}'. Must be 'all', 'by_type', or 'specific'",
                other
            )));
        }
    }

    let input = CreateNhiCertificationCampaign {
        name: req.name,
        description: req.description,
        scope: req.scope,
        nhi_type_filter: req.nhi_type_filter,
        specific_nhi_ids: req.specific_nhi_ids,
        due_date: req.due_date,
        created_by: Some(user_id),
    };

    let campaign = NhiCertificationCampaign::create(&state.pool, tenant_uuid, input)
        .await
        .map_err(NhiApiError::Database)?;

    Ok((StatusCode::CREATED, Json(campaign)))
}

/// GET /certifications — List certification campaigns for tenant.
async fn list_campaigns(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Query(query): Query<ListCampaignsQuery>,
) -> Result<impl IntoResponse, NhiApiError> {
    let tenant_uuid = *tenant_id.as_uuid();
    let limit = query.limit.unwrap_or(20).clamp(1, 100);
    let offset = query.offset.unwrap_or(0).max(0);

    let campaigns = NhiCertificationCampaign::list_by_tenant(
        &state.pool,
        tenant_uuid,
        query.status.as_deref(),
        limit,
        offset,
    )
    .await
    .map_err(NhiApiError::Database)?;

    Ok(Json(campaigns))
}

/// POST /certifications/:campaign_id/certify/:nhi_id — Certify an NHI entity.
async fn certify_nhi(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path((campaign_id, nhi_id)): Path<(Uuid, Uuid)>,
) -> Result<impl IntoResponse, NhiApiError> {
    if !claims.has_role("admin") {
        return Err(NhiApiError::Forbidden);
    }

    let tenant_uuid = *tenant_id.as_uuid();
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| NhiApiError::BadRequest("Invalid user ID".into()))?;

    // Verify campaign exists, is active, and not past due
    let campaign = NhiCertificationCampaign::find_by_id(&state.pool, tenant_uuid, campaign_id)
        .await
        .map_err(NhiApiError::Database)?
        .ok_or(NhiApiError::NotFound)?;

    if campaign.status != "active" {
        return Err(NhiApiError::BadRequest(format!(
            "Campaign is {} and cannot accept certifications",
            campaign.status
        )));
    }
    if let Some(due) = campaign.due_date {
        if Utc::now() > due {
            return Err(NhiApiError::BadRequest(
                "Campaign deadline has passed".into(),
            ));
        }
    }

    // Verify the NHI exists
    let nhi = NhiIdentity::find_by_id(&state.pool, tenant_uuid, nhi_id)
        .await
        .map_err(NhiApiError::Database)?
        .ok_or(NhiApiError::NotFound)?;

    // Validate NHI is in campaign scope
    match campaign.scope.as_str() {
        "by_type" => {
            if let Some(ref filter_type) = campaign.nhi_type_filter {
                if nhi.nhi_type.to_string() != *filter_type {
                    return Err(NhiApiError::BadRequest(format!(
                        "NHI type '{}' does not match campaign filter '{}'",
                        nhi.nhi_type, filter_type
                    )));
                }
            }
        }
        "specific" => {
            let allowed = campaign.specific_nhi_ids.as_deref().unwrap_or_default();
            if !allowed.contains(&nhi_id) {
                return Err(NhiApiError::BadRequest(
                    "NHI is not in the scope of this campaign".into(),
                ));
            }
        }
        _ => {} // "all" or any other scope — no additional check
    }

    // Set next certification 90 days from now
    let now = Utc::now();
    let next_cert = Some(now + Duration::days(90));

    let updated =
        NhiIdentity::update_certification(&state.pool, tenant_uuid, nhi_id, user_id, next_cert)
            .await
            .map_err(NhiApiError::Database)?;

    if !updated {
        return Err(NhiApiError::NotFound);
    }

    Ok((
        StatusCode::OK,
        Json(CertifyResponse {
            nhi_id,
            certified_by: user_id,
            certified_at: now,
            next_certification_at: next_cert,
        }),
    ))
}

/// POST /certifications/:campaign_id/revoke/:nhi_id — Revoke certification,
/// transitioning the NHI to Deprecated state.
async fn revoke_certification(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path((campaign_id, nhi_id)): Path<(Uuid, Uuid)>,
) -> Result<impl IntoResponse, NhiApiError> {
    if !claims.has_role("admin") {
        return Err(NhiApiError::Forbidden);
    }

    let tenant_uuid = *tenant_id.as_uuid();

    // Verify campaign exists and is active
    let campaign = NhiCertificationCampaign::find_by_id(&state.pool, tenant_uuid, campaign_id)
        .await
        .map_err(NhiApiError::Database)?
        .ok_or(NhiApiError::NotFound)?;

    if campaign.status != "active" {
        return Err(NhiApiError::BadRequest(format!(
            "Campaign is {} and cannot process revocations",
            campaign.status
        )));
    }

    // Transition to Deprecated
    let updated = NhiLifecycleService::transition(
        &state.pool,
        tenant_uuid,
        nhi_id,
        NhiLifecycleState::Deprecated,
        Some("Certification revoked".into()),
    )
    .await?;

    Ok((
        StatusCode::OK,
        Json(RevokeResponse {
            nhi_id,
            revoked: true,
            new_state: updated.lifecycle_state.to_string(),
        }),
    ))
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Creates the certification routes sub-router.
///
/// Routes:
/// - `POST /certifications`
/// - `GET /certifications`
/// - `POST /certifications/:campaign_id/certify/:nhi_id`
/// - `POST /certifications/:campaign_id/revoke/:nhi_id`
pub fn certification_routes(state: NhiState) -> Router {
    Router::new()
        .route("/certifications", post(create_campaign))
        .route("/certifications", get(list_campaigns))
        .route(
            "/certifications/:campaign_id/certify/:nhi_id",
            post(certify_nhi),
        )
        .route(
            "/certifications/:campaign_id/revoke/:nhi_id",
            post(revoke_certification),
        )
        .with_state(state)
}
