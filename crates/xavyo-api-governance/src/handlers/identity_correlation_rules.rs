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
    CorrelationRuleFilter, CreateGovCorrelationRule, GovCorrelationRule, GovMatchType,
    UpdateGovCorrelationRule,
};

use crate::error::{ApiGovernanceError, ApiResult};
use crate::models::{
    CorrelationRuleResponse, CreateCorrelationRuleRequest, UpdateCorrelationRuleRequest,
};
use crate::router::GovernanceState;

fn f64_to_decimal(value: f64, field: &str) -> Result<Decimal, ApiGovernanceError> {
    Decimal::try_from(value)
        .map_err(|_| ApiGovernanceError::Validation(format!("Invalid {field} value")))
}

fn decimal_to_f64(value: Decimal, field: &str) -> Result<f64, ApiGovernanceError> {
    value
        .to_string()
        .parse()
        .map_err(|_| ApiGovernanceError::Validation(format!("Invalid stored {field} value")))
}

fn map_correlation_rule(
    rule: GovCorrelationRule,
) -> Result<CorrelationRuleResponse, ApiGovernanceError> {
    Ok(CorrelationRuleResponse {
        id: rule.id,
        name: rule.name,
        attribute: rule.attribute,
        match_type: rule.match_type,
        algorithm: rule.algorithm,
        threshold: rule
            .threshold
            .map(|t| decimal_to_f64(t, "threshold"))
            .transpose()?,
        weight: decimal_to_f64(rule.weight, "weight")?,
        is_active: rule.is_active,
        priority: rule.priority,
        created_at: rule.created_at,
        updated_at: rule.updated_at,
    })
}

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
        .map(map_correlation_rule)
        .collect::<Result<Vec<_>, _>>()?;

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

    Ok(Json(map_correlation_rule(rule)?))
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
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }
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
            .map(|t| f64_to_decimal(t, "threshold"))
            .transpose()?,
        weight: request
            .weight
            .map(|w| f64_to_decimal(w, "weight"))
            .transpose()?,
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

    Ok((StatusCode::CREATED, Json(map_correlation_rule(rule)?)))
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
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let input = UpdateGovCorrelationRule {
        name: request.name,
        algorithm: request.algorithm,
        threshold: request
            .threshold
            .map(|t| f64_to_decimal(t, "threshold"))
            .transpose()?,
        weight: request
            .weight
            .map(|w| f64_to_decimal(w, "weight"))
            .transpose()?,
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

    Ok(Json(map_correlation_rule(rule)?))
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
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimal_helpers_do_not_default() {
        let d = f64_to_decimal(0.75, "threshold").unwrap();
        assert_eq!(decimal_to_f64(d, "threshold").unwrap(), 0.75);
        assert!(f64_to_decimal(f64::NAN, "weight").is_err());
        assert!(f64_to_decimal(f64::INFINITY, "weight").is_err());
        let src = include_str!("identity_correlation_rules.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            !production.contains("unwrap_or(0.0)") && !production.contains("unwrap_or(1.0)"),
            "correlation rule decimals must not default on parse failure"
        );
        assert!(
            !production.contains("unwrap_or_default()"),
            "correlation rule writes must not default invalid decimals"
        );
    }
}
