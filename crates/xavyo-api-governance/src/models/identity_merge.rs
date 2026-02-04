//! Request and response models for Identity Merge API.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use xavyo_db::models::{
    GovDuplicateStatus, GovEntitlementStrategy, GovFuzzyAlgorithm, GovMatchType,
    GovMergeOperationStatus,
};

// ============================================================================
// Correlation Rule DTOs
// ============================================================================

/// Request to create a correlation rule.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreateCorrelationRuleRequest {
    pub name: String,
    pub attribute: String,
    pub match_type: GovMatchType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<GovFuzzyAlgorithm>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub weight: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<i32>,
}

/// Request to update a correlation rule.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UpdateCorrelationRuleRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<GovFuzzyAlgorithm>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub weight: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_active: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<i32>,
}

/// Response for a correlation rule.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CorrelationRuleResponse {
    pub id: Uuid,
    pub name: String,
    pub attribute: String,
    pub match_type: GovMatchType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<GovFuzzyAlgorithm>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold: Option<f64>,
    pub weight: f64,
    pub is_active: bool,
    pub priority: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ============================================================================
// Duplicate Candidate DTOs
// ============================================================================

/// Query parameters for listing duplicates.
#[derive(Debug, Clone, Serialize, Deserialize, Default, IntoParams)]
pub struct ListDuplicatesQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<GovDuplicateStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_confidence: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_confidence: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_id: Option<Uuid>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// Response for a duplicate candidate in list.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DuplicateCandidateResponse {
    pub id: Uuid,
    pub identity_a_id: Uuid,
    pub identity_b_id: Uuid,
    pub confidence_score: f64,
    pub status: GovDuplicateStatus,
    pub detected_at: DateTime<Utc>,
}

/// Detailed duplicate comparison response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DuplicateDetailResponse {
    pub id: Uuid,
    pub identity_a_id: Uuid,
    pub identity_b_id: Uuid,
    pub confidence_score: f64,
    pub identity_a: IdentitySummary,
    pub identity_b: IdentitySummary,
    pub attribute_comparison: Vec<AttributeComparison>,
    pub rule_matches: Vec<RuleMatchResponse>,
}

/// Summary of an identity for comparison.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct IdentitySummary {
    pub id: Uuid,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub department: Option<String>,
    pub attributes: serde_json::Value,
}

/// Attribute comparison between two identities.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AttributeComparison {
    pub attribute: String,
    pub value_a: Option<serde_json::Value>,
    pub value_b: Option<serde_json::Value>,
    pub is_different: bool,
}

/// Rule match details.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RuleMatchResponse {
    pub rule_id: Uuid,
    pub rule_name: String,
    pub attribute: String,
    pub similarity: f64,
    pub weighted_score: f64,
}

/// Request to dismiss a duplicate.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DismissDuplicateRequest {
    pub reason: String,
}

// ============================================================================
// Merge Operation DTOs
// ============================================================================

/// Request to preview a merge operation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MergePreviewRequest {
    pub source_identity_id: Uuid,
    pub target_identity_id: Uuid,
    pub entitlement_strategy: GovEntitlementStrategy,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attribute_selections: Option<serde_json::Value>,
}

/// Response for merge preview.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MergePreviewResponse {
    pub source_identity: IdentitySummary,
    pub target_identity: IdentitySummary,
    pub merged_preview: IdentitySummary,
    pub entitlements_preview: EntitlementsPreview,
    pub sod_check: MergeSodCheckResponse,
}

/// Entitlements preview showing consolidation result.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EntitlementsPreview {
    pub source_only: Vec<MergeEntitlementSummary>,
    pub target_only: Vec<MergeEntitlementSummary>,
    pub common: Vec<MergeEntitlementSummary>,
    pub merged: Vec<MergeEntitlementSummary>,
}

/// Summary of an entitlement.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MergeEntitlementSummary {
    pub id: Uuid,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
}

/// `SoD` check result for merge operations.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MergeSodCheckResponse {
    pub has_violations: bool,
    pub can_override: bool,
    pub violations: Vec<MergeSodViolationResponse>,
}

/// `SoD` violation details for merge operations.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MergeSodViolationResponse {
    /// The `SoD` rule that would be violated.
    pub rule_id: Uuid,
    /// The name of the `SoD` rule.
    pub rule_name: String,
    /// Severity level of the violation.
    pub severity: String,
    /// The entitlement being added that causes the violation.
    pub entitlement_being_added: Uuid,
    /// The existing entitlement that conflicts.
    pub conflicting_entitlement_id: Uuid,
    /// Whether an exemption exists for this violation.
    pub has_exemption: bool,
}

/// Request to execute a merge operation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MergeExecuteRequest {
    pub source_identity_id: Uuid,
    pub target_identity_id: Uuid,
    pub entitlement_strategy: GovEntitlementStrategy,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attribute_selections: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entitlement_selections: Option<Vec<Uuid>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sod_override_reason: Option<String>,
}

/// Response for a merge operation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MergeOperationResponse {
    pub id: Uuid,
    pub source_identity_id: Uuid,
    pub target_identity_id: Uuid,
    pub status: GovMergeOperationStatus,
    pub entitlement_strategy: GovEntitlementStrategy,
    pub operator_id: Uuid,
    pub started_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<DateTime<Utc>>,
}

// ============================================================================
// Batch Merge DTOs
// ============================================================================

/// Request for batch merge operation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BatchMergeRequest {
    pub candidate_ids: Vec<Uuid>,
    pub entitlement_strategy: GovEntitlementStrategy,
    pub attribute_rule: AttributeResolutionRule,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_confidence: Option<f64>,
    #[serde(default)]
    pub skip_sod_violations: bool,
}

/// Rule for automatic attribute resolution.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AttributeResolutionRule {
    /// Use values from the newer record.
    NewestWins,
    /// Use values from the older record.
    OldestWins,
    /// Prefer non-null values.
    PreferNonNull,
}

/// Response for batch merge initiation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BatchMergeResponse {
    pub job_id: Uuid,
    pub status: BatchMergeStatus,
    pub total_pairs: i32,
    pub processed: i32,
    pub successful: i32,
    pub failed: i32,
    pub skipped: i32,
}

/// Status of batch merge job.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum BatchMergeStatus {
    Queued,
    Running,
    Completed,
    Failed,
}

// ============================================================================
// Merge Audit DTOs
// ============================================================================

/// Query parameters for searching audit records.
#[derive(Debug, Clone, Serialize, Deserialize, Default, IntoParams)]
pub struct ListMergeAuditsQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operator_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_date: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_date: Option<DateTime<Utc>>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// Summary response for merge audit in list.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MergeAuditSummaryResponse {
    pub id: Uuid,
    pub operation_id: Uuid,
    pub source_identity_id: Uuid,
    pub target_identity_id: Uuid,
    pub operator_id: Uuid,
    pub created_at: DateTime<Utc>,
}

/// Detailed audit record response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MergeAuditDetailResponse {
    pub id: Uuid,
    pub operation_id: Uuid,
    pub source_snapshot: serde_json::Value,
    pub target_snapshot: serde_json::Value,
    pub merged_snapshot: serde_json::Value,
    pub attribute_decisions: serde_json::Value,
    pub entitlement_decisions: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sod_violations: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

// ============================================================================
// Detection DTOs
// ============================================================================

/// Request to trigger duplicate detection.
#[derive(Debug, Clone, Serialize, Deserialize, Default, ToSchema)]
pub struct TriggerDetectionRequest {
    /// Limit scan to specific identity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_id: Option<Uuid>,
}

/// Response for detection job.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DetectionJobResponse {
    pub job_id: Uuid,
    pub status: DetectionJobStatus,
    pub started_at: DateTime<Utc>,
}

/// Status of detection job.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum DetectionJobStatus {
    Queued,
    Running,
    Completed,
}

/// Response for a completed detection scan.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DetectionScanResponse {
    /// Unique identifier for this scan.
    pub scan_id: Uuid,
    /// Number of users scanned.
    pub users_processed: usize,
    /// Total number of duplicate pairs found.
    pub duplicates_found: usize,
    /// Number of new duplicates detected (not previously found).
    pub new_duplicates: usize,
    /// Scan duration in milliseconds.
    pub duration_ms: u64,
}

/// Request to run a detection scan with optional configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default, ToSchema)]
pub struct RunDetectionScanRequest {
    /// Minimum confidence threshold (0.0 to 100.0). Defaults to 70.0.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_confidence: Option<f64>,
}

// ============================================================================
// Paginated Response
// ============================================================================

/// Paginated response wrapper for identity merge.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MergePaginatedResponse<T> {
    pub items: Vec<T>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

// ============================================================================
// Error Response
// ============================================================================

/// Error response for identity merge operations.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MergeErrorResponse {
    pub error: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending_operation_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub violations: Option<Vec<MergeSodViolationResponse>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_correlation_rule_request_serialization() {
        let request = CreateCorrelationRuleRequest {
            name: "Email Match".to_string(),
            attribute: "email".to_string(),
            match_type: GovMatchType::Exact,
            algorithm: None,
            threshold: None,
            weight: Some(50.0),
            priority: Some(100),
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("Email Match"));
        assert!(!json.contains("algorithm")); // Should be skipped
    }

    #[test]
    fn test_merge_preview_request_serialization() {
        let request = MergePreviewRequest {
            source_identity_id: Uuid::new_v4(),
            target_identity_id: Uuid::new_v4(),
            entitlement_strategy: GovEntitlementStrategy::Union,
            attribute_selections: None,
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("union"));
    }

    #[test]
    fn test_attribute_resolution_rule_serialization() {
        let rule = AttributeResolutionRule::NewestWins;
        let json = serde_json::to_string(&rule).unwrap();
        assert_eq!(json, "\"newest_wins\"");
    }
}
