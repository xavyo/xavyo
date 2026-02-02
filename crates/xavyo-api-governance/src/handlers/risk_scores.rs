//! Risk score handlers for governance API.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use uuid::Uuid;

use xavyo_auth::JwtClaims;

use crate::error::{ApiGovernanceError, ApiResult};
use crate::models::{
    BatchCalculateResponse, CalculateScoreRequest, EnforcementPolicyResponse, ListRiskScoresQuery,
    RiskEnforcementResponse, RiskScoreHistoryQuery, RiskScoreHistoryResponse,
    RiskScoreListResponse, RiskScoreResponse, RiskScoreSortOption, RiskScoreSummary,
    UpsertEnforcementPolicyRequest,
};
use crate::router::GovernanceState;

/// Get the risk score for a specific user.
#[utoipa::path(
    get,
    path = "/governance/users/{user_id}/risk-score",
    tag = "Governance - Risk Scoring",
    params(
        ("user_id" = Uuid, Path, description = "User ID")
    ),
    responses(
        (status = 200, description = "User's risk score", body = RiskScoreResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Risk score not found for user"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_user_risk_score(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(user_id): Path<Uuid>,
) -> ApiResult<Json<RiskScoreResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let score = state
        .risk_score_service
        .get_user_score(tenant_id, user_id)
        .await?;

    Ok(Json(score))
}

/// Calculate (or recalculate) the risk score for a specific user.
#[utoipa::path(
    post,
    path = "/governance/users/{user_id}/risk-score/calculate",
    tag = "Governance - Risk Scoring",
    params(
        ("user_id" = Uuid, Path, description = "User ID")
    ),
    request_body = CalculateScoreRequest,
    responses(
        (status = 200, description = "Calculated risk score", body = RiskScoreResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn calculate_user_risk_score(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(user_id): Path<Uuid>,
    Json(request): Json<CalculateScoreRequest>,
) -> ApiResult<Json<RiskScoreResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let score = state
        .risk_score_service
        .calculate_score(tenant_id, user_id, request.include_peer_comparison)
        .await?;

    Ok(Json(score))
}

/// Get risk score history for a user.
#[utoipa::path(
    get,
    path = "/governance/users/{user_id}/risk-score/history",
    tag = "Governance - Risk Scoring",
    params(
        ("user_id" = Uuid, Path, description = "User ID"),
        RiskScoreHistoryQuery
    ),
    responses(
        (status = 200, description = "Risk score history with trend", body = RiskScoreHistoryResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Risk score not found for user"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_user_risk_score_history(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(user_id): Path<Uuid>,
    Query(query): Query<RiskScoreHistoryQuery>,
) -> ApiResult<Json<RiskScoreHistoryResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = query.limit.unwrap_or(90);

    let history = state
        .risk_score_service
        .get_score_history(tenant_id, user_id, query.start_date, query.end_date, limit)
        .await?;

    Ok(Json(history))
}

/// List all risk scores with filtering and pagination.
#[utoipa::path(
    get,
    path = "/governance/risk-scores",
    tag = "Governance - Risk Scoring",
    params(ListRiskScoresQuery),
    responses(
        (status = 200, description = "List of risk scores", body = RiskScoreListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_risk_scores(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListRiskScoresQuery>,
) -> ApiResult<Json<RiskScoreListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0);
    let sort_by = query.sort_by.unwrap_or(RiskScoreSortOption::ScoreDesc);

    let response = state
        .risk_score_service
        .list_scores(
            tenant_id,
            query.risk_level,
            query.min_score,
            query.max_score,
            sort_by,
            limit,
            offset,
        )
        .await?;

    Ok(Json(response))
}

/// Get risk score summary for the tenant.
#[utoipa::path(
    get,
    path = "/governance/risk-scores/summary",
    tag = "Governance - Risk Scoring",
    responses(
        (status = 200, description = "Risk score summary", body = RiskScoreSummary),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_risk_score_summary(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
) -> ApiResult<Json<RiskScoreSummary>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let summary = state.risk_score_service.get_summary(tenant_id).await?;

    Ok(Json(summary))
}

/// Batch calculate risk scores for all users.
#[utoipa::path(
    post,
    path = "/governance/risk-scores/calculate-all",
    tag = "Governance - Risk Scoring",
    request_body = CalculateScoreRequest,
    responses(
        (status = 200, description = "Batch calculation result", body = BatchCalculateResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn calculate_all_risk_scores(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CalculateScoreRequest>,
) -> ApiResult<Json<BatchCalculateResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let result = state
        .risk_score_service
        .calculate_all_scores(tenant_id, request.include_peer_comparison)
        .await?;

    Ok(Json(result))
}

/// Save daily snapshot of risk score for a user.
#[utoipa::path(
    post,
    path = "/governance/users/{user_id}/risk-score/snapshot",
    tag = "Governance - Risk Scoring",
    params(
        ("user_id" = Uuid, Path, description = "User ID")
    ),
    responses(
        (status = 204, description = "Snapshot saved successfully"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Risk score not found for user"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn save_risk_score_snapshot(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(user_id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    state
        .risk_score_service
        .save_daily_snapshot(tenant_id, user_id)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Get risk enforcement action required for a user.
///
/// Returns the action that should be taken based on the user's risk score
/// and configured thresholds (Alert, RequireMFA, or Block).
#[utoipa::path(
    get,
    path = "/governance/users/{user_id}/risk-enforcement",
    tag = "Governance - Risk Scoring",
    params(
        ("user_id" = Uuid, Path, description = "User ID")
    ),
    responses(
        (status = 200, description = "Risk enforcement action", body = RiskEnforcementResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Risk score not found for user"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_user_risk_enforcement(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(user_id): Path<Uuid>,
) -> ApiResult<Json<RiskEnforcementResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let enforcement = state
        .risk_score_service
        .get_enforcement_action(tenant_id, user_id)
        .await?;

    Ok(Json(enforcement))
}

// --- Enforcement Policy handlers (F073) ---

/// Get the risk enforcement policy for the current tenant.
#[utoipa::path(
    get,
    path = "/governance/risk/enforcement-policy",
    tag = "Governance - Risk Management",
    responses(
        (status = 200, description = "Enforcement policy", body = EnforcementPolicyResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_enforcement_policy(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
) -> ApiResult<Json<EnforcementPolicyResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let policy = xavyo_db::GovRiskEnforcementPolicy::get_or_default(state.pool(), tenant_id)
        .await
        .map_err(|e| ApiGovernanceError::Internal(e.to_string()))?;

    Ok(Json(EnforcementPolicyResponse::from(policy)))
}

/// Create or update the risk enforcement policy for the current tenant.
#[utoipa::path(
    put,
    path = "/governance/risk/enforcement-policy",
    tag = "Governance - Risk Management",
    request_body = UpsertEnforcementPolicyRequest,
    responses(
        (status = 200, description = "Enforcement policy updated", body = EnforcementPolicyResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn upsert_enforcement_policy(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<UpsertEnforcementPolicyRequest>,
) -> ApiResult<Json<EnforcementPolicyResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    // Validate speed range
    if let Some(speed) = request.impossible_travel_speed_kmh {
        if !(100..=2000).contains(&speed) {
            return Err(ApiGovernanceError::Validation(
                "impossible_travel_speed_kmh must be between 100 and 2000".to_string(),
            ));
        }
    }

    // Parse enforcement mode
    let enforcement_mode = match request.enforcement_mode.as_deref() {
        Some("disabled") => Some(xavyo_db::EnforcementMode::Disabled),
        Some("monitor") => Some(xavyo_db::EnforcementMode::Monitor),
        Some("enforce") => Some(xavyo_db::EnforcementMode::Enforce),
        Some(other) => {
            return Err(ApiGovernanceError::Validation(format!(
                "Invalid enforcement_mode '{}'. Must be 'disabled', 'monitor', or 'enforce'.",
                other
            )));
        }
        None => None,
    };

    let input = xavyo_db::UpsertEnforcementPolicy {
        enforcement_mode,
        fail_open: request.fail_open,
        impossible_travel_speed_kmh: request.impossible_travel_speed_kmh,
        impossible_travel_enabled: request.impossible_travel_enabled,
    };

    let policy = xavyo_db::GovRiskEnforcementPolicy::upsert(state.pool(), tenant_id, &input)
        .await
        .map_err(|e| ApiGovernanceError::Internal(e.to_string()))?;

    Ok(Json(EnforcementPolicyResponse::from(policy)))
}
