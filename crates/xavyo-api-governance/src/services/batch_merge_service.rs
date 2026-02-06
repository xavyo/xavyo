//! Batch Merge Service (F062).
//!
//! Provides batch merge operations for bulk cleanup of duplicate identities:
//! - Preview candidates with filtering
//! - Configurable attribute resolution rules
//! - Batch execution with progress tracking
//! - Result summary (successful, failed, skipped)

use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

use xavyo_db::models::{
    DuplicateCandidateFilter, GovDuplicateCandidate, GovDuplicateStatus, GovEntitlementStrategy,
};
use xavyo_governance::error::{GovernanceError, Result};

use crate::models::{
    AttributeResolutionRule, BatchMergeRequest, BatchMergeResponse, BatchMergeStatus,
    MergeExecuteRequest,
};

use super::IdentityMergeService;

/// Result of a single merge operation in a batch.
#[derive(Debug, Clone)]
pub struct BatchMergeItemResult {
    /// Candidate ID that was processed.
    pub candidate_id: Uuid,
    /// Whether the merge was successful.
    pub success: bool,
    /// Error message if failed.
    pub error: Option<String>,
    /// Whether it was skipped (e.g., `SoD` violation).
    pub skipped: bool,
    /// The merge operation ID if successful.
    pub merge_operation_id: Option<Uuid>,
}

/// Preview of batch merge candidates.
#[derive(Debug, Clone)]
pub struct BatchMergePreview {
    /// Total number of candidates matching criteria.
    pub total_candidates: i64,
    /// Candidates that will be processed.
    pub candidates: Vec<BatchMergeCandidatePreview>,
    /// Estimated entitlement strategy applied.
    pub entitlement_strategy: GovEntitlementStrategy,
    /// Attribute resolution rule to use.
    pub attribute_rule: AttributeResolutionRule,
}

/// Preview of a single candidate for batch merge.
#[derive(Debug, Clone)]
pub struct BatchMergeCandidatePreview {
    /// Candidate ID.
    pub candidate_id: Uuid,
    /// Source identity ID.
    pub source_identity_id: Uuid,
    /// Target identity ID.
    pub target_identity_id: Uuid,
    /// Confidence score.
    pub confidence_score: f64,
}

/// Service for batch merge operations.
pub struct BatchMergeService {
    pool: PgPool,
    identity_merge_service: Arc<IdentityMergeService>,
}

impl BatchMergeService {
    /// Create a new batch merge service.
    #[must_use]
    pub fn new(pool: PgPool, identity_merge_service: Arc<IdentityMergeService>) -> Self {
        Self {
            pool,
            identity_merge_service,
        }
    }

    /// Preview batch merge candidates.
    ///
    /// Returns a list of candidates that would be processed by the batch merge.
    pub async fn preview(
        &self,
        tenant_id: Uuid,
        candidate_ids: Option<&[Uuid]>,
        min_confidence: Option<f64>,
        entitlement_strategy: GovEntitlementStrategy,
        attribute_rule: AttributeResolutionRule,
        limit: i64,
        offset: i64,
    ) -> Result<BatchMergePreview> {
        let filter = DuplicateCandidateFilter {
            status: Some(GovDuplicateStatus::Pending),
            min_confidence: min_confidence
                .map(|c| rust_decimal::Decimal::try_from(c * 100.0).unwrap_or_default()),
            ..Default::default()
        };

        let candidates = if let Some(ids) = candidate_ids {
            // Fetch specific candidates
            let mut result = Vec::new();
            for id in ids {
                if let Some(candidate) =
                    GovDuplicateCandidate::find_by_id(&self.pool, tenant_id, *id)
                        .await
                        .map_err(GovernanceError::Database)?
                {
                    if candidate.status == GovDuplicateStatus::Pending {
                        result.push(candidate);
                    }
                }
            }
            result
        } else {
            // Fetch by filter
            GovDuplicateCandidate::list_by_tenant(&self.pool, tenant_id, &filter, limit, offset)
                .await
                .map_err(GovernanceError::Database)?
        };

        let total = GovDuplicateCandidate::count_by_tenant(&self.pool, tenant_id, &filter)
            .await
            .map_err(GovernanceError::Database)?;

        let preview_items: Vec<BatchMergeCandidatePreview> = candidates
            .into_iter()
            .map(|c| BatchMergeCandidatePreview {
                candidate_id: c.id,
                source_identity_id: c.identity_a_id,
                target_identity_id: c.identity_b_id,
                confidence_score: c.confidence_score.to_string().parse().unwrap_or(0.0),
            })
            .collect();

        Ok(BatchMergePreview {
            total_candidates: total,
            candidates: preview_items,
            entitlement_strategy,
            attribute_rule,
        })
    }

    /// Execute batch merge operations.
    ///
    /// Processes each candidate and returns a summary of results.
    pub async fn execute(
        &self,
        tenant_id: Uuid,
        operator_id: Uuid,
        request: &BatchMergeRequest,
    ) -> Result<BatchMergeResponse> {
        let job_id = Uuid::new_v4();

        // Get candidates to process
        let candidates = if request.candidate_ids.is_empty() {
            // Fetch by min_confidence filter
            let filter = DuplicateCandidateFilter {
                status: Some(GovDuplicateStatus::Pending),
                min_confidence: request
                    .min_confidence
                    .map(|c| rust_decimal::Decimal::try_from(c * 100.0).unwrap_or_default()),
                ..Default::default()
            };
            GovDuplicateCandidate::list_by_tenant(&self.pool, tenant_id, &filter, 1000, 0)
                .await
                .map_err(GovernanceError::Database)?
        } else {
            // Fetch specific candidates
            let mut result = Vec::new();
            for id in &request.candidate_ids {
                if let Some(candidate) =
                    GovDuplicateCandidate::find_by_id(&self.pool, tenant_id, *id)
                        .await
                        .map_err(GovernanceError::Database)?
                {
                    if candidate.status == GovDuplicateStatus::Pending {
                        result.push(candidate);
                    }
                }
            }
            result
        };

        let total_pairs = candidates.len() as i32;
        let mut processed = 0;
        let mut successful = 0;
        let mut failed = 0;
        let mut skipped = 0;
        let mut _results: Vec<BatchMergeItemResult> = Vec::new();

        // Process each candidate
        for candidate in candidates {
            processed += 1;

            // Determine source and target based on attribute rule
            let (source_id, target_id) = self
                .determine_merge_direction(
                    tenant_id,
                    candidate.identity_a_id,
                    candidate.identity_b_id,
                    request.attribute_rule,
                )
                .await;

            // Build attribute selections based on rule
            let attribute_selections = self.build_attribute_selections(request.attribute_rule);

            // Create merge request
            let merge_request = MergeExecuteRequest {
                source_identity_id: source_id,
                target_identity_id: target_id,
                entitlement_strategy: request.entitlement_strategy,
                attribute_selections,
                entitlement_selections: None,
                sod_override_reason: None,
            };

            // Execute merge
            match self
                .identity_merge_service
                .execute(tenant_id, operator_id, &merge_request)
                .await
            {
                Ok(result) => {
                    successful += 1;
                    _results.push(BatchMergeItemResult {
                        candidate_id: candidate.id,
                        success: true,
                        error: None,
                        skipped: false,
                        merge_operation_id: Some(result.operation_id),
                    });
                }
                Err(e) => {
                    // Check if it's a SoD violation and skip_sod_violations is set
                    let is_sod_violation = e.is_sod_violation();
                    if is_sod_violation && request.skip_sod_violations {
                        skipped += 1;
                        _results.push(BatchMergeItemResult {
                            candidate_id: candidate.id,
                            success: false,
                            error: Some("SoD violation - skipped".to_string()),
                            skipped: true,
                            merge_operation_id: None,
                        });
                    } else {
                        failed += 1;
                        _results.push(BatchMergeItemResult {
                            candidate_id: candidate.id,
                            success: false,
                            error: Some(e.to_string()),
                            skipped: false,
                            merge_operation_id: None,
                        });
                    }
                }
            }
        }

        // Determine final status
        let status = if failed > 0 && successful == 0 {
            BatchMergeStatus::Failed
        } else {
            BatchMergeStatus::Completed
        };

        Ok(BatchMergeResponse {
            job_id,
            status,
            total_pairs,
            processed,
            successful,
            failed,
            skipped,
        })
    }

    /// Determine merge direction based on attribute rule.
    ///
    /// Returns (`source_id`, `target_id`) where source will be archived.
    async fn determine_merge_direction(
        &self,
        tenant_id: Uuid,
        identity_a_id: Uuid,
        identity_b_id: Uuid,
        rule: AttributeResolutionRule,
    ) -> (Uuid, Uuid) {
        // For newest/oldest_wins, we need to determine which identity is newer
        // Based on created_at timestamp from users table

        let user_a = sqlx::query_scalar::<_, chrono::DateTime<chrono::Utc>>(
            "SELECT created_at FROM users WHERE id = $1 AND tenant_id = $2",
        )
        .bind(identity_a_id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .ok()
        .flatten();

        let user_b = sqlx::query_scalar::<_, chrono::DateTime<chrono::Utc>>(
            "SELECT created_at FROM users WHERE id = $1 AND tenant_id = $2",
        )
        .bind(identity_b_id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .ok()
        .flatten();

        match (user_a, user_b) {
            (Some(a_created), Some(b_created)) => {
                let a_is_newer = a_created > b_created;
                match rule {
                    AttributeResolutionRule::NewestWins => {
                        // Keep newer (target), archive older (source)
                        if a_is_newer {
                            (identity_b_id, identity_a_id) // Archive B, keep A
                        } else {
                            (identity_a_id, identity_b_id) // Archive A, keep B
                        }
                    }
                    AttributeResolutionRule::OldestWins => {
                        // Keep older (target), archive newer (source)
                        if a_is_newer {
                            (identity_a_id, identity_b_id) // Archive A (newer), keep B (older)
                        } else {
                            (identity_b_id, identity_a_id) // Archive B (newer), keep A (older)
                        }
                    }
                    AttributeResolutionRule::PreferNonNull => {
                        // For PreferNonNull, direction doesn't matter for merge direction
                        // as the attribute handling is done at merge time.
                        // Default to keeping the newer record as target.
                        if a_is_newer {
                            (identity_b_id, identity_a_id) // Archive B, keep A
                        } else {
                            (identity_a_id, identity_b_id) // Archive A, keep B
                        }
                    }
                }
            }
            _ => {
                // Fallback: use alphabetical order by ID
                if identity_a_id < identity_b_id {
                    (identity_a_id, identity_b_id)
                } else {
                    (identity_b_id, identity_a_id)
                }
            }
        }
    }

    /// Build attribute selections based on resolution rule.
    fn build_attribute_selections(
        &self,
        _rule: AttributeResolutionRule,
    ) -> Option<serde_json::Value> {
        // For automatic resolution, we don't need explicit selections
        // The merge will use target values by default
        // Custom attribute selections would be needed for manual selection
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_batch_merge_item_result() {
        let result = BatchMergeItemResult {
            candidate_id: Uuid::new_v4(),
            success: true,
            error: None,
            skipped: false,
            merge_operation_id: Some(Uuid::new_v4()),
        };
        assert!(result.success);
        assert!(result.merge_operation_id.is_some());
    }

    #[test]
    fn test_batch_merge_preview() {
        let preview = BatchMergePreview {
            total_candidates: 10,
            candidates: vec![],
            entitlement_strategy: GovEntitlementStrategy::Union,
            attribute_rule: AttributeResolutionRule::NewestWins,
        };
        assert_eq!(preview.total_candidates, 10);
    }

    #[test]
    fn test_attribute_resolution_rules() {
        // Just test that the enum values exist
        let _ = AttributeResolutionRule::NewestWins;
        let _ = AttributeResolutionRule::OldestWins;
        let _ = AttributeResolutionRule::PreferNonNull;
    }
}
