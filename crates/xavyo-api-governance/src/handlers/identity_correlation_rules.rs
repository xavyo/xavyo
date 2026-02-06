//! HTTP handlers for identity correlation rule management (F062).
//!
//! These handlers manage tenant-wide correlation rules for duplicate detection,
//! distinct from the connector-scoped correlation rules in F067.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use rust_decimal::Decimal;
use uuid::Uuid;

use xavyo_auth::JwtClaims;
use xavyo_db::models::{
    CorrelationRuleFilter, CreateGovCorrelationRule, GovMatchType, UpdateGovCorrelationRule,
};

use crate::error::{ApiGovernanceError, ApiResult};
use crate::models::{
    CorrelationRuleResponse, CreateCorrelationRuleRequest, UpdateCorrelationRuleRequest,
};
use crate::router::GovernanceState;

/// Query parameters for listing identity correlation rules.
#[derive(Debug, Clone, Default, serde::Deserialize, utoipa::IntoParams)]
pub struct ListIdentityCorrelationRulesQuery {
    /// Filter by match type.
    pub match_type: Option<GovMatchType>,
    /// Filter by active status.
    pub is_active: Option<bool>,
    /// Filter by attribute.
    pub attribute: Option<String>,
    /// Maximum results to return.
    #[serde(default = "default_limit")]
    pub limit: i64,
    /// Results to skip.
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    50
}

/// Response for listing identity correlation rules.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct IdentityCorrelationRuleListResponse {
    pub items: Vec<CorrelationRuleResponse>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

/// List identity correlation rules for duplicate detection.
#[utoipa::path(
    get,
    path = "/governance/identity-correlation-rules",
    tag = "Governance - Identity Merge",
    params(ListIdentityCorrelationRulesQuery),
    responses(
        (status = 200, description = "Correlation rules retrieved", body = IdentityCorrelationRuleListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_identity_correlation_rules(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListIdentityCorrelationRulesQuery>,
) -> ApiResult<Json<IdentityCorrelationRuleListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let filter = CorrelationRuleFilter {
        match_type: query.match_type,
        is_active: query.is_active,
        attribute: query.attribute,
        connector_id: None,
        tier: None,
    };

    let limit = query.limit.min(100);
    let offset = query.offset.max(0);

    let (rules, total) = state
        .identity_correlation_rule_service
        .list(tenant_id, &filter, limit, offset)
        .await?;

    let items: Vec<CorrelationRuleResponse> = rules
        .into_iter()
        .map(|r| CorrelationRuleResponse {
            id: r.id,
            name: r.name,
            attribute: r.attribute,
            match_type: r.match_type,
            algorithm: r.algorithm,
            threshold: r.threshold.map(|t| t.to_string().parse().unwrap_or(0.0)),
            weight: r.weight.to_string().parse().unwrap_or(1.0),
            is_active: r.is_active,
            priority: r.priority,
            created_at: r.created_at,
            updated_at: r.updated_at,
        })
        .collect();

    Ok(Json(IdentityCorrelationRuleListResponse {
        items,
        total,
        limit,
        offset,
    }))
}

/// Get an identity correlation rule by ID.
#[utoipa::path(
    get,
    path = "/governance/identity-correlation-rules/{id}",
    tag = "Governance - Identity Merge",
    params(
        ("id" = Uuid, Path, description = "Correlation rule ID")
    ),
    responses(
        (status = 200, description = "Correlation rule retrieved", body = CorrelationRuleResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Correlation rule not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_identity_correlation_rule(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<CorrelationRuleResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let rule = state
        .identity_correlation_rule_service
        .get(tenant_id, id)
        .await?;

    Ok(Json(CorrelationRuleResponse {
        id: rule.id,
        name: rule.name,
        attribute: rule.attribute,
        match_type: rule.match_type,
        algorithm: rule.algorithm,
        threshold: rule.threshold.map(|t| t.to_string().parse().unwrap_or(0.0)),
        weight: rule.weight.to_string().parse().unwrap_or(1.0),
        is_active: rule.is_active,
        priority: rule.priority,
        created_at: rule.created_at,
        updated_at: rule.updated_at,
    }))
}

/// Create an identity correlation rule.
#[utoipa::path(
    post,
    path = "/governance/identity-correlation-rules",
    tag = "Governance - Identity Merge",
    request_body = CreateCorrelationRuleRequest,
    responses(
        (status = 201, description = "Correlation rule created", body = CorrelationRuleResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_identity_correlation_rule(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateCorrelationRuleRequest>,
) -> ApiResult<(StatusCode, Json<CorrelationRuleResponse>)> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let input = CreateGovCorrelationRule {
        name: request.name,
        attribute: request.attribute,
        match_type: request.match_type,
        algorithm: request.algorithm,
        threshold: request
            .threshold
            .map(|t| Decimal::try_from(t).unwrap_or_default()),
        weight: request
            .weight
            .map(|w| Decimal::try_from(w).unwrap_or_default()),
        priority: request.priority,
        connector_id: None,
        source_attribute: None,
        target_attribute: None,
        expression: None,
        tier: None,
        is_definitive: None,
        normalize: None,
    };

    let rule = state
        .identity_correlation_rule_service
        .create(tenant_id, input)
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(CorrelationRuleResponse {
            id: rule.id,
            name: rule.name,
            attribute: rule.attribute,
            match_type: rule.match_type,
            algorithm: rule.algorithm,
            threshold: rule.threshold.map(|t| t.to_string().parse().unwrap_or(0.0)),
            weight: rule.weight.to_string().parse().unwrap_or(1.0),
            is_active: rule.is_active,
            priority: rule.priority,
            created_at: rule.created_at,
            updated_at: rule.updated_at,
        }),
    ))
}

/// Update an identity correlation rule.
#[utoipa::path(
    put,
    path = "/governance/identity-correlation-rules/{id}",
    tag = "Governance - Identity Merge",
    params(
        ("id" = Uuid, Path, description = "Correlation rule ID")
    ),
    request_body = UpdateCorrelationRuleRequest,
    responses(
        (status = 200, description = "Correlation rule updated", body = CorrelationRuleResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Correlation rule not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_identity_correlation_rule(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateCorrelationRuleRequest>,
) -> ApiResult<Json<CorrelationRuleResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let input = UpdateGovCorrelationRule {
        name: request.name,
        algorithm: request.algorithm,
        threshold: request
            .threshold
            .map(|t| Decimal::try_from(t).unwrap_or_default()),
        weight: request
            .weight
            .map(|w| Decimal::try_from(w).unwrap_or_default()),
        is_active: request.is_active,
        priority: None,
        source_attribute: None,
        target_attribute: None,
        expression: None,
        tier: None,
        is_definitive: None,
        normalize: None,
    };

    let rule = state
        .identity_correlation_rule_service
        .update(tenant_id, id, input)
        .await?;

    Ok(Json(CorrelationRuleResponse {
        id: rule.id,
        name: rule.name,
        attribute: rule.attribute,
        match_type: rule.match_type,
        algorithm: rule.algorithm,
        threshold: rule.threshold.map(|t| t.to_string().parse().unwrap_or(0.0)),
        weight: rule.weight.to_string().parse().unwrap_or(1.0),
        is_active: rule.is_active,
        priority: rule.priority,
        created_at: rule.created_at,
        updated_at: rule.updated_at,
    }))
}

/// Delete an identity correlation rule.
#[utoipa::path(
    delete,
    path = "/governance/identity-correlation-rules/{id}",
    tag = "Governance - Identity Merge",
    params(
        ("id" = Uuid, Path, description = "Correlation rule ID")
    ),
    responses(
        (status = 204, description = "Correlation rule deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Correlation rule not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_identity_correlation_rule(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    state
        .identity_correlation_rule_service
        .delete(tenant_id, id)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}
