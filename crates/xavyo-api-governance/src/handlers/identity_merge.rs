//! Identity Merge handlers for governance API (F062).

use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use sqlx::types::Decimal;
use uuid::Uuid;

use chrono::{DateTime, Utc};
use xavyo_auth::JwtClaims;
use xavyo_db::models::{DuplicateCandidateFilter, GovMergeOperation, MergeOperationFilter};

use crate::error::{ApiGovernanceError, ApiResult};
use crate::models::{
    BatchMergeRequest, BatchMergeResponse, DetectionScanResponse, DismissDuplicateRequest,
    DuplicateCandidateResponse, DuplicateDetailResponse, ListDuplicatesQuery, ListMergeAuditsQuery,
    MergeAuditDetailResponse, MergeAuditSummaryResponse, MergeExecuteRequest,
    MergeOperationResponse, MergePaginatedResponse, MergePreviewRequest, MergePreviewResponse,
    RunDetectionScanRequest,
};
use crate::router::GovernanceState;
use crate::services::DuplicateDetectionService;

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

fn map_duplicate_candidate(
    candidate: xavyo_db::models::GovDuplicateCandidate,
) -> Result<DuplicateCandidateResponse, ApiGovernanceError> {
    Ok(DuplicateCandidateResponse {
        id: candidate.id,
        identity_a_id: candidate.identity_a_id,
        identity_b_id: candidate.identity_b_id,
        confidence_score: decimal_to_f64(candidate.confidence_score, "confidence_score")?,
        status: candidate.status,
        detected_at: candidate.detected_at,
    })
}

// ============================================================================
// Duplicate Candidate Handlers
// ============================================================================

/// List duplicate candidates with filtering.
#[utoipa::path(
    get,
    path = "/governance/duplicates",
    tag = "Governance - Identity Merge",
    params(ListDuplicatesQuery),
    responses(
        (status = 200, description = "List of duplicate candidates", body = MergePaginatedDuplicateCandidateResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_duplicates(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListDuplicatesQuery>,
) -> ApiResult<Json<MergePaginatedResponse<DuplicateCandidateResponse>>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0).max(0);

    let filter = DuplicateCandidateFilter {
        status: query.status,
        min_confidence: query
            .min_confidence
            .map(|v| f64_to_decimal(v, "min_confidence"))
            .transpose()?,
        max_confidence: query
            .max_confidence
            .map(|v| f64_to_decimal(v, "max_confidence"))
            .transpose()?,
        identity_id: query.identity_id,
    };

    let (candidates, total) = state
        .identity_merge_service
        .list_duplicates(tenant_id, &filter, limit, offset)
        .await?;

    let items: Vec<DuplicateCandidateResponse> = candidates
        .into_iter()
        .map(map_duplicate_candidate)
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Json(MergePaginatedResponse {
        items,
        total,
        limit,
        offset,
    }))
}

/// Get a duplicate candidate with detailed comparison.
#[utoipa::path(
    get,
    path = "/governance/duplicates/{id}",
    tag = "Governance - Identity Merge",
    params(
        ("id" = Uuid, Path, description = "Duplicate candidate ID")
    ),
    responses(
        (status = 200, description = "Duplicate candidate details with comparison", body = DuplicateDetailResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Duplicate candidate not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_duplicate(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<DuplicateDetailResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let detail = state
        .identity_merge_service
        .get_duplicate_detail(tenant_id, id)
        .await?;

    Ok(Json(detail))
}

/// Dismiss a duplicate candidate as a false positive.
#[utoipa::path(
    post,
    path = "/governance/duplicates/{id}/dismiss",
    tag = "Governance - Identity Merge",
    params(
        ("id" = Uuid, Path, description = "Duplicate candidate ID")
    ),
    request_body = DismissDuplicateRequest,
    responses(
        (status = 200, description = "Duplicate dismissed"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Duplicate candidate not found"),
        (status = 409, description = "Duplicate already dismissed or merged"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn dismiss_duplicate(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<DismissDuplicateRequest>,
) -> ApiResult<Json<DuplicateCandidateResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let candidate = state
        .identity_merge_service
        .dismiss_duplicate(tenant_id, id, user_id, &request.reason)
        .await?;

    Ok(Json(map_duplicate_candidate(candidate)?))
}

/// Run a duplicate detection scan.
#[utoipa::path(
    post,
    path = "/governance/duplicates/detect",
    tag = "Governance - Identity Merge",
    request_body = RunDetectionScanRequest,
    responses(
        (status = 200, description = "Detection scan completed", body = DetectionScanResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn detect_duplicates(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<RunDetectionScanRequest>,
) -> ApiResult<Json<DetectionScanResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    // Use default rules from the service
    let rules = DuplicateDetectionService::default_rules();

    // Get min confidence threshold (default to 70.0)
    let min_confidence = request.min_confidence.unwrap_or(70.0);

    let result = state
        .duplicate_detection_service
        .run_detection_scan(tenant_id, &rules, min_confidence)
        .await?;

    Ok(Json(DetectionScanResponse {
        scan_id: result.scan_id,
        users_processed: result.users_processed,
        duplicates_found: result.duplicates_found,
        new_duplicates: result.new_duplicates,
        duration_ms: result.duration_ms,
    }))
}

// ============================================================================
// Merge Operation Handlers
// ============================================================================

/// Preview a merge operation.
#[utoipa::path(
    post,
    path = "/governance/merges/preview",
    tag = "Governance - Identity Merge",
    request_body = MergePreviewRequest,
    responses(
        (status = 200, description = "Merge preview with impact assessment", body = MergePreviewResponse),
        (status = 400, description = "Invalid request (same identity)"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Identity not found"),
        (status = 409, description = "Merge already in progress"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn preview_merge(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<MergePreviewRequest>,
) -> ApiResult<Json<MergePreviewResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let preview = state
        .identity_merge_service
        .preview(tenant_id, &request)
        .await?;

    Ok(Json(preview))
}

/// Execute a merge operation.
#[utoipa::path(
    post,
    path = "/governance/merges/execute",
    tag = "Governance - Identity Merge",
    request_body = MergeExecuteRequest,
    responses(
        (status = 200, description = "Merge executed successfully", body = MergeOperationResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Identity not found"),
        (status = 409, description = "Merge already in progress or SoD violation"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn execute_merge(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<MergeExecuteRequest>,
) -> ApiResult<Json<MergeOperationResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let result = state
        .identity_merge_service
        .execute(tenant_id, user_id, &request)
        .await?;

    // Fetch the operation to return
    let operation = state
        .identity_merge_service
        .get_operation(tenant_id, result.operation_id)
        .await?;

    Ok(Json(MergeOperationResponse {
        id: operation.id,
        source_identity_id: operation.source_identity_id,
        target_identity_id: operation.target_identity_id,
        status: operation.status,
        entitlement_strategy: operation.entitlement_strategy,
        operator_id: operation.operator_id,
        started_at: operation.started_at,
        completed_at: operation.completed_at,
    }))
}

/// Get a merge operation by ID.
#[utoipa::path(
    get,
    path = "/governance/merges/{id}",
    tag = "Governance - Identity Merge",
    params(
        ("id" = Uuid, Path, description = "Merge operation ID")
    ),
    responses(
        (status = 200, description = "Merge operation details", body = MergeOperationResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Merge operation not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_merge_operation(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<MergeOperationResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let operation = state
        .identity_merge_service
        .get_operation(tenant_id, id)
        .await?;

    Ok(Json(MergeOperationResponse {
        id: operation.id,
        source_identity_id: operation.source_identity_id,
        target_identity_id: operation.target_identity_id,
        status: operation.status,
        entitlement_strategy: operation.entitlement_strategy,
        operator_id: operation.operator_id,
        started_at: operation.started_at,
        completed_at: operation.completed_at,
    }))
}

/// List merge operations with filtering.
#[utoipa::path(
    get,
    path = "/governance/merges",
    tag = "Governance - Identity Merge",
    params(
        ("status" = Option<String>, Query, description = "Filter by status"),
        ("identity_id" = Option<Uuid>, Query, description = "Filter by identity ID"),
        ("limit" = Option<i64>, Query, description = "Maximum results"),
        ("offset" = Option<i64>, Query, description = "Skip results")
    ),
    responses(
        (status = 200, description = "List of merge operations", body = MergePaginatedMergeOperationResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_merge_operations(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListMergeOperationsQuery>,
) -> ApiResult<Json<MergePaginatedResponse<MergeOperationResponse>>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0).max(0);

    let filter = MergeOperationFilter {
        status: query.status,
        identity_id: query.identity_id,
        ..Default::default()
    };

    let (operations, total) = state
        .identity_merge_service
        .list_operations(tenant_id, &filter, limit, offset)
        .await?;

    let items: Vec<MergeOperationResponse> = operations
        .into_iter()
        .map(|op| MergeOperationResponse {
            id: op.id,
            source_identity_id: op.source_identity_id,
            target_identity_id: op.target_identity_id,
            status: op.status,
            entitlement_strategy: op.entitlement_strategy,
            operator_id: op.operator_id,
            started_at: op.started_at,
            completed_at: op.completed_at,
        })
        .collect();

    Ok(Json(MergePaginatedResponse {
        items,
        total,
        limit,
        offset,
    }))
}

// ============================================================================
// Query Parameters
// ============================================================================

/// Query parameters for listing merge operations.
#[derive(Debug, Clone, serde::Deserialize, Default, utoipa::IntoParams)]
pub struct ListMergeOperationsQuery {
    pub status: Option<xavyo_db::models::GovMergeOperationStatus>,
    pub identity_id: Option<Uuid>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

// ============================================================================
// Merge Audit Handlers (US5)
// ============================================================================

/// List merge audit records with filtering.
#[utoipa::path(
    get,
    path = "/governance/merges/audit",
    tag = "Governance - Identity Merge",
    params(ListMergeAuditsQuery),
    responses(
        (status = 200, description = "List of merge audit records", body = MergePaginatedMergeAuditSummaryResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_merge_audits(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListMergeAuditsQuery>,
) -> ApiResult<Json<MergePaginatedResponse<MergeAuditSummaryResponse>>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0).max(0);

    let filter = xavyo_db::models::MergeAuditFilter {
        operation_id: None,
        identity_id: query.identity_id,
        operator_id: query.operator_id,
        from_date: query.from_date,
        to_date: query.to_date,
    };

    let (audits, total) = state
        .merge_audit_service
        .list(tenant_id, &filter, limit, offset)
        .await?;

    let op_ids: Vec<Uuid> = audits.iter().map(|a| a.operation_id).collect();
    let operations = GovMergeOperation::find_by_ids(&state.pool, tenant_id, &op_ids)
        .await
        .map_err(xavyo_governance::error::GovernanceError::Database)?;
    let ops_by_id: std::collections::HashMap<Uuid, GovMergeOperation> =
        operations.into_iter().map(|op| (op.id, op)).collect();

    let items: Vec<MergeAuditSummaryResponse> = audits
        .into_iter()
        .filter_map(|a| {
            let op = ops_by_id.get(&a.operation_id)?;
            merge_audit_summary(
                a.id,
                a.operation_id,
                op.source_identity_id,
                op.target_identity_id,
                op.operator_id,
                a.created_at,
            )
        })
        .collect();

    Ok(Json(MergePaginatedResponse {
        items,
        total,
        limit,
        offset,
    }))
}

/// Build a merge-audit list row. Missing operator or identity IDs are omitted
/// rather than reported as `Uuid::nil()`.
pub fn merge_audit_summary(
    id: Uuid,
    operation_id: Uuid,
    source_identity_id: Uuid,
    target_identity_id: Uuid,
    operator_id: Uuid,
    created_at: DateTime<Utc>,
) -> Option<MergeAuditSummaryResponse> {
    if source_identity_id.is_nil() || target_identity_id.is_nil() || operator_id.is_nil() {
        return None;
    }
    Some(MergeAuditSummaryResponse {
        id,
        operation_id,
        source_identity_id,
        target_identity_id,
        operator_id,
        created_at,
    })
}

/// Get a detailed merge audit record by ID.
#[utoipa::path(
    get,
    path = "/governance/merges/audit/{id}",
    tag = "Governance - Identity Merge",
    params(
        ("id" = Uuid, Path, description = "Audit record ID")
    ),
    responses(
        (status = 200, description = "Detailed merge audit record", body = MergeAuditDetailResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Audit record not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_merge_audit(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<MergeAuditDetailResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let audit = state.merge_audit_service.get(tenant_id, id).await?;

    Ok(Json(MergeAuditDetailResponse {
        id: audit.id,
        operation_id: audit.operation_id,
        source_snapshot: audit.source_snapshot,
        target_snapshot: audit.target_snapshot,
        merged_snapshot: audit.merged_snapshot,
        attribute_decisions: audit.attribute_decisions,
        entitlement_decisions: audit.entitlement_decisions,
        sod_violations: audit.sod_violations,
        created_at: audit.created_at,
    }))
}

// ============================================================================
// Batch Merge Handlers (US3)
// ============================================================================

/// Execute a batch merge operation.
#[utoipa::path(
    post,
    path = "/governance/merges/batch",
    tag = "Governance - Identity Merge",
    request_body = BatchMergeRequest,
    responses(
        (status = 200, description = "Batch merge executed", body = BatchMergeResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn execute_batch_merge(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<BatchMergeRequest>,
) -> ApiResult<Json<BatchMergeResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let result = state
        .batch_merge_service
        .execute(tenant_id, user_id, &request)
        .await?;

    Ok(Json(result))
}

/// Preview batch merge candidates.
#[utoipa::path(
    post,
    path = "/governance/merges/batch/preview",
    tag = "Governance - Identity Merge",
    request_body = BatchMergePreviewRequest,
    responses(
        (status = 200, description = "Batch merge preview", body = BatchMergePreviewResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn preview_batch_merge(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<BatchMergePreviewRequest>,
) -> ApiResult<Json<BatchMergePreviewResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let preview = state
        .batch_merge_service
        .preview(
            tenant_id,
            request.candidate_ids.as_deref(),
            request.min_confidence,
            request.entitlement_strategy,
            request.attribute_rule,
            request.limit.unwrap_or(100),
            request.offset.unwrap_or(0),
        )
        .await?;

    Ok(Json(BatchMergePreviewResponse {
        total_candidates: preview.total_candidates,
        candidates: preview
            .candidates
            .into_iter()
            .map(|c| BatchMergeCandidatePreviewResponse {
                candidate_id: c.candidate_id,
                source_identity_id: c.source_identity_id,
                target_identity_id: c.target_identity_id,
                confidence_score: c.confidence_score,
            })
            .collect(),
        entitlement_strategy: preview.entitlement_strategy,
        attribute_rule: preview.attribute_rule,
    }))
}

/// Get batch merge job status (synchronous - returns immediately after execution).
/// Note: Since batch merge executes synchronously, jobs are not persisted.
/// This endpoint returns 404 for any `job_id` as jobs complete immediately.
#[utoipa::path(
    get,
    path = "/governance/merges/batch/{job_id}",
    tag = "Governance - Identity Merge",
    params(
        ("job_id" = Uuid, Path, description = "Batch merge job ID")
    ),
    responses(
        (status = 404, description = "Job not found - batch merges execute synchronously"),
        (status = 401, description = "Unauthorized")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_batch_job(
    Extension(claims): Extension<JwtClaims>,
    Path(_job_id): Path<Uuid>,
) -> ApiResult<Json<BatchMergeResponse>> {
    // Verify authentication
    let _tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    // Batch jobs are not persisted - they execute synchronously
    // Return 404 as jobs are not stored after completion
    Err(ApiGovernanceError::NotFound(
        "Batch job not found - batch merges execute synchronously and results are returned immediately".to_string()
    ))
}

/// Request for batch merge preview.
#[derive(Debug, Clone, serde::Deserialize, utoipa::IntoParams, utoipa::ToSchema)]
pub struct BatchMergePreviewRequest {
    pub candidate_ids: Option<Vec<Uuid>>,
    pub min_confidence: Option<f64>,
    pub entitlement_strategy: xavyo_db::models::GovEntitlementStrategy,
    pub attribute_rule: crate::models::AttributeResolutionRule,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// Response for batch merge preview.
#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema)]
pub struct BatchMergePreviewResponse {
    pub total_candidates: i64,
    pub candidates: Vec<BatchMergeCandidatePreviewResponse>,
    pub entitlement_strategy: xavyo_db::models::GovEntitlementStrategy,
    pub attribute_rule: crate::models::AttributeResolutionRule,
}

/// Preview of a single candidate for batch merge.
#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema)]
pub struct BatchMergeCandidatePreviewResponse {
    pub candidate_id: Uuid,
    pub source_identity_id: Uuid,
    pub target_identity_id: Uuid,
    pub confidence_score: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_audit_summary_rejects_nil_operator() {
        let source = Uuid::new_v4();
        let target = Uuid::new_v4();
        assert!(merge_audit_summary(
            Uuid::new_v4(),
            Uuid::new_v4(),
            source,
            target,
            Uuid::nil(),
            Utc::now(),
        )
        .is_none());
    }

    #[test]
    fn merge_audit_summary_keeps_real_operator() {
        let operator = Uuid::new_v4();
        let source = Uuid::new_v4();
        let target = Uuid::new_v4();
        let row = merge_audit_summary(
            Uuid::new_v4(),
            Uuid::new_v4(),
            source,
            target,
            operator,
            Utc::now(),
        )
        .expect("real ids");
        assert_eq!(row.operator_id, operator);
        assert_eq!(row.source_identity_id, source);
        assert_eq!(row.target_identity_id, target);
        assert!(!row.operator_id.is_nil());
    }

    #[test]
    fn list_merge_audits_does_not_emit_nil_operator() {
        let src = include_str!("identity_merge.rs");
        let production = src.split("mod tests").next().expect("production source");
        let needle = format!("operator_id: {}()", "Uuid::nil");
        assert!(
            !production.contains(&needle),
            "audit list must not advertise a nil operator"
        );
        assert!(
            production.contains("merge_audit_summary"),
            "audit list must map operator from the merge operation"
        );
    }

    #[test]
    fn duplicate_decimals_do_not_default_on_parse_error() {
        assert!(f64_to_decimal(f64::NAN, "min_confidence").is_err());
        let src = include_str!("identity_merge.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            !production.contains("unwrap_or(0.0)")
                && !production.contains("Decimal::try_from(v).unwrap_or_default()"),
            "duplicate confidence must not default on parse failure"
        );
    }
}
