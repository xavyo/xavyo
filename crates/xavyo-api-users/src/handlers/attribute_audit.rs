//! Attribute audit handlers (F070).
//!
//! Endpoint for auditing users missing required custom attributes.

use crate::error::ApiUsersError;
use crate::models::MissingAttributeAuditResponse;
use crate::services::AttributeAuditService;
use axum::{extract::Query, Extension, Json};
use serde::Deserialize;
use std::sync::Arc;
use utoipa::IntoParams;
use xavyo_auth::JwtClaims;

/// Query parameters for the missing required attributes audit.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct AuditMissingQuery {
    /// Filter to a specific attribute name.
    #[serde(default)]
    pub attribute_name: Option<String>,

    /// Pagination offset (default: 0).
    #[serde(default)]
    pub offset: Option<i64>,

    /// Page size (default: 20, max: 100).
    #[serde(default)]
    pub limit: Option<i64>,
}

/// Audit users missing required custom attributes.
#[utoipa::path(
    get,
    path = "/admin/attribute-definitions/audit/missing-required",
    params(AuditMissingQuery),
    responses(
        (status = 200, description = "Audit results", body = MissingAttributeAuditResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "Attribute Audit"
)]
pub async fn audit_missing_required_attributes(
    Extension(claims): Extension<JwtClaims>,
    Extension(service): Extension<Arc<AttributeAuditService>>,
    Query(query): Query<AuditMissingQuery>,
) -> Result<Json<MissingAttributeAuditResponse>, ApiUsersError> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiUsersError::Unauthorized)?
        .as_uuid();

    let offset = query.offset.unwrap_or(0).max(0);
    let limit = query.limit.unwrap_or(20).clamp(1, 100);

    tracing::info!(
        admin_id = %claims.sub,
        tenant_id = %tenant_id,
        attribute_name = ?query.attribute_name,
        offset = offset,
        limit = limit,
        "Auditing missing required attributes"
    );

    let response = service
        .audit_missing_required(tenant_id, query.attribute_name.as_deref(), offset, limit)
        .await?;

    Ok(Json(response))
}
