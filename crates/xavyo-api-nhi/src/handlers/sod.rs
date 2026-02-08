//! Separation of Duties (SoD) validation handlers.
//!
//! Provides endpoints for SoD rule management and validation on tool permissions:
//! - `POST /sod/check` — Check if granting a permission would violate SoD rules
//! - `POST /sod/rules` — Create a SoD rule
//! - `GET /sod/rules` — List SoD rules
//! - `DELETE /sod/rules/{id}` — Delete a SoD rule
//!
//! SoD rules define tool permission combinations that are prohibited or warned about.
//! For example, an agent should not have both "create-payment" and "approve-payment" tools.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, post},
    Extension, Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use xavyo_auth::JwtClaims;
use xavyo_core::TenantId;

use crate::error::NhiApiError;
use crate::state::NhiState;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Enforcement level for a SoD rule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum SodEnforcement {
    /// Block the permission grant entirely.
    Prevent,
    /// Allow the grant but return a warning.
    Warn,
}

/// A Separation of Duties rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SodRule {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub tool_id_a: Uuid,
    pub tool_id_b: Uuid,
    pub enforcement: SodEnforcement,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
    pub created_by: Option<Uuid>,
}

/// Request to create a SoD rule.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreateSodRuleRequest {
    pub tool_id_a: Uuid,
    pub tool_id_b: Uuid,
    pub enforcement: SodEnforcement,
    pub description: Option<String>,
}

/// Request to check SoD violations.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SodCheckRequest {
    pub agent_id: Uuid,
    pub tool_id: Uuid,
}

/// A single SoD violation found during a check.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SodViolation {
    pub rule_id: Uuid,
    pub conflicting_tool_id: Uuid,
    pub enforcement: SodEnforcement,
    pub description: Option<String>,
}

/// Result of a SoD check.
#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SodCheckResult {
    pub violations: Vec<SodViolation>,
    pub is_allowed: bool,
}

/// Pagination query parameters.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
pub struct PaginationQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// Paginated response.
#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "openapi", aliases(
    PaginatedSodRuleResponse = PaginatedResponse<SodRule>,
))]
pub struct PaginatedResponse<T: Serialize> {
    pub data: Vec<T>,
    pub limit: i64,
    pub offset: i64,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// POST /sod/rules — Create a SoD rule.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/nhi/sod/rules",
    tag = "NHI SoD",
    operation_id = "createNhiSodRule",
    request_body = CreateSodRuleRequest,
    responses(
        (status = 201, description = "SoD rule created", body = SodRule),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Forbidden")
    ),
    security(("bearerAuth" = []))
))]
pub async fn create_sod_rule(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateSodRuleRequest>,
) -> Result<impl IntoResponse, NhiApiError> {
    if !claims.has_role("admin") {
        return Err(NhiApiError::Forbidden);
    }

    let tenant_uuid = *tenant_id.as_uuid();
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| NhiApiError::BadRequest("Invalid user ID".into()))?;

    if request.tool_id_a == request.tool_id_b {
        return Err(NhiApiError::BadRequest(
            "tool_id_a and tool_id_b must be different".into(),
        ));
    }

    // Normalize ordering to prevent duplicate rules (a,b) vs (b,a)
    let (tool_a, tool_b) = if request.tool_id_a < request.tool_id_b {
        (request.tool_id_a, request.tool_id_b)
    } else {
        (request.tool_id_b, request.tool_id_a)
    };

    let enforcement_str = match request.enforcement {
        SodEnforcement::Prevent => "prevent",
        SodEnforcement::Warn => "warn",
    };

    let rule: SodRule = sqlx::query_as::<_, SodRuleRow>(
        r"INSERT INTO nhi_sod_rules (tenant_id, tool_id_a, tool_id_b, enforcement, description, created_by)
          VALUES ($1, $2, $3, $4, $5, $6)
          ON CONFLICT (tenant_id, tool_id_a, tool_id_b)
          DO UPDATE SET enforcement = EXCLUDED.enforcement,
                        description = EXCLUDED.description
          RETURNING *",
    )
    .bind(tenant_uuid)
    .bind(tool_a)
    .bind(tool_b)
    .bind(enforcement_str)
    .bind(&request.description)
    .bind(user_id)
    .fetch_one(&state.pool)
    .await
    .map(SodRule::from)
    .map_err(NhiApiError::Database)?;

    Ok((StatusCode::CREATED, Json(rule)))
}

/// GET /sod/rules — List SoD rules for the tenant.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/nhi/sod/rules",
    tag = "NHI SoD",
    operation_id = "listNhiSodRules",
    params(PaginationQuery),
    responses(
        (status = 200, description = "List of SoD rules", body = PaginatedSodRuleResponse),
        (status = 401, description = "Authentication required")
    ),
    security(("bearerAuth" = []))
))]
pub async fn list_sod_rules(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Query(query): Query<PaginationQuery>,
) -> Result<Json<PaginatedResponse<SodRule>>, NhiApiError> {
    let tenant_uuid = *tenant_id.as_uuid();
    let limit = query.limit.unwrap_or(20).clamp(1, 100);
    let offset = query.offset.unwrap_or(0).max(0);

    let rows: Vec<SodRuleRow> = sqlx::query_as(
        r"SELECT * FROM nhi_sod_rules
          WHERE tenant_id = $1
          ORDER BY created_at DESC
          LIMIT $2 OFFSET $3",
    )
    .bind(tenant_uuid)
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.pool)
    .await
    .map_err(NhiApiError::Database)?;

    let data = rows.into_iter().map(SodRule::from).collect();

    Ok(Json(PaginatedResponse {
        data,
        limit,
        offset,
    }))
}

/// DELETE /sod/rules/{id} — Delete a SoD rule.
#[cfg_attr(feature = "openapi", utoipa::path(
    delete,
    path = "/nhi/sod/rules/{id}",
    tag = "NHI SoD",
    operation_id = "deleteNhiSodRule",
    params(
        ("id" = Uuid, Path, description = "SoD rule ID")
    ),
    responses(
        (status = 204, description = "SoD rule deleted"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "SoD rule not found")
    ),
    security(("bearerAuth" = []))
))]
pub async fn delete_sod_rule(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, NhiApiError> {
    if !claims.has_role("admin") {
        return Err(NhiApiError::Forbidden);
    }

    let tenant_uuid = *tenant_id.as_uuid();

    let result = sqlx::query(r"DELETE FROM nhi_sod_rules WHERE tenant_id = $1 AND id = $2")
        .bind(tenant_uuid)
        .bind(id)
        .execute(&state.pool)
        .await
        .map_err(NhiApiError::Database)?;

    if result.rows_affected() == 0 {
        return Err(NhiApiError::NotFound);
    }

    Ok(StatusCode::NO_CONTENT)
}

/// POST /sod/check — Check if granting a tool permission would violate SoD rules.
///
/// Queries the agent's existing tool permissions and checks against all SoD rules
/// to detect conflicts. Returns the list of violations and whether the grant is allowed.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/nhi/sod/check",
    tag = "NHI SoD",
    operation_id = "checkNhiSod",
    request_body = SodCheckRequest,
    responses(
        (status = 200, description = "SoD check result", body = SodCheckResult),
        (status = 401, description = "Authentication required")
    ),
    security(("bearerAuth" = []))
))]
pub async fn check_sod(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Json(request): Json<SodCheckRequest>,
) -> Result<Json<SodCheckResult>, NhiApiError> {
    let tenant_uuid = *tenant_id.as_uuid();

    // Get the agent's current tool permissions (non-expired)
    let existing_tool_ids: Vec<Uuid> = sqlx::query_scalar(
        r"SELECT tool_nhi_id FROM nhi_tool_permissions
          WHERE tenant_id = $1
            AND agent_nhi_id = $2
            AND (expires_at IS NULL OR expires_at > NOW())",
    )
    .bind(tenant_uuid)
    .bind(request.agent_id)
    .fetch_all(&state.pool)
    .await
    .map_err(NhiApiError::Database)?;

    // If the agent has no existing permissions, no SoD violations possible
    if existing_tool_ids.is_empty() {
        return Ok(Json(SodCheckResult {
            violations: Vec::new(),
            is_allowed: true,
        }));
    }

    // Query SoD rules where the new tool_id is one side and any existing tool is the other
    let rules: Vec<SodRuleRow> = sqlx::query_as(
        r"SELECT * FROM nhi_sod_rules
          WHERE tenant_id = $1
            AND (
              (tool_id_a = $2 AND tool_id_b = ANY($3))
              OR
              (tool_id_b = $2 AND tool_id_a = ANY($3))
            )",
    )
    .bind(tenant_uuid)
    .bind(request.tool_id)
    .bind(&existing_tool_ids)
    .fetch_all(&state.pool)
    .await
    .map_err(NhiApiError::Database)?;

    let violations: Vec<SodViolation> = rules
        .into_iter()
        .map(|row| {
            let conflicting_tool_id = if row.tool_id_a == request.tool_id {
                row.tool_id_b
            } else {
                row.tool_id_a
            };
            let enforcement = parse_enforcement(&row.enforcement);
            SodViolation {
                rule_id: row.id,
                conflicting_tool_id,
                enforcement,
                description: row.description,
            }
        })
        .collect();

    let is_allowed = !violations
        .iter()
        .any(|v| v.enforcement == SodEnforcement::Prevent);

    Ok(Json(SodCheckResult {
        violations,
        is_allowed,
    }))
}

// ---------------------------------------------------------------------------
// Internal DB row type
// ---------------------------------------------------------------------------

#[derive(Debug, sqlx::FromRow)]
struct SodRuleRow {
    id: Uuid,
    tenant_id: Uuid,
    tool_id_a: Uuid,
    tool_id_b: Uuid,
    enforcement: String,
    description: Option<String>,
    created_at: DateTime<Utc>,
    created_by: Option<Uuid>,
}

impl From<SodRuleRow> for SodRule {
    fn from(row: SodRuleRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            tool_id_a: row.tool_id_a,
            tool_id_b: row.tool_id_b,
            enforcement: parse_enforcement(&row.enforcement),
            description: row.description,
            created_at: row.created_at,
            created_by: row.created_by,
        }
    }
}

fn parse_enforcement(s: &str) -> SodEnforcement {
    match s {
        "prevent" => SodEnforcement::Prevent,
        _ => SodEnforcement::Warn,
    }
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn sod_routes(state: NhiState) -> Router {
    Router::new()
        .route("/sod/rules", post(create_sod_rule).get(list_sod_rules))
        .route("/sod/rules/:id", delete(delete_sod_rule))
        .route("/sod/check", post(check_sod))
        .with_state(state)
}
