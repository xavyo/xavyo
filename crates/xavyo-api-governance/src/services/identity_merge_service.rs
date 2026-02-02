//! Identity Merge Service (F062).
//!
//! Provides core merge functionality for User Story 1:
//! - Merge preview (side-by-side comparison)
//! - Merge execution with attribute selection
//! - Entitlement consolidation
//! - Identity archival
//! - Session invalidation for archived identity
//! - External reference preservation
//! - Group membership transfer (edge case from IGA standards)
//! - Pending access request handling (edge case from IGA standards)
//! - Ownership transfer for resources (edge case from IGA standards)
//!
//! SoD integration (User Story 4):
//! - SoD violation detection during merge preview
//! - SoD blocking/override during merge execution

use serde_json::json;
use sqlx::PgPool;
use std::collections::HashSet;
use std::sync::Arc;
use uuid::Uuid;

use xavyo_db::models::{
    CreateGovMergeOperation, GovArchivedIdentity, GovDuplicateCandidate, GovEntitlementStrategy,
    GovMergeAudit, GovMergeOperation,
};
use xavyo_governance::error::{GovernanceError, Result};

use crate::models::{
    AttributeComparison, DuplicateDetailResponse, EntitlementsPreview, IdentitySummary,
    MergeEntitlementSummary, MergeExecuteRequest, MergeOperationResponse, MergePreviewRequest,
    MergePreviewResponse, MergeSodCheckResponse, MergeSodViolationResponse, RuleMatchResponse,
};
use crate::services::SodEnforcementService;

/// Result of a merge execution.
#[derive(Debug, Clone)]
pub struct MergeResult {
    /// The merge operation ID.
    pub operation_id: Uuid,
    /// The target identity ID (the one that was kept).
    pub target_identity_id: Uuid,
    /// The archived identity ID (reference to archived record).
    pub archived_identity_id: Uuid,
    /// Number of entitlements added to target.
    pub entitlements_added: usize,
    /// Number of entitlements removed from source.
    pub entitlements_removed: usize,
    /// Whether any SoD violations were overridden.
    pub sod_overridden: bool,
    /// Number of group memberships transferred.
    pub groups_transferred: usize,
    /// Number of pending access requests cancelled.
    pub access_requests_cancelled: usize,
    /// Number of ownership records transferred.
    pub ownerships_transferred: usize,
    /// External references that were preserved.
    pub external_references_preserved: serde_json::Value,
}

/// Service for identity merge operations.
pub struct IdentityMergeService {
    pool: PgPool,
    sod_enforcement_service: Arc<SodEnforcementService>,
}

impl IdentityMergeService {
    /// Create a new identity merge service.
    pub fn new(pool: PgPool) -> Self {
        Self {
            sod_enforcement_service: Arc::new(SodEnforcementService::new(pool.clone())),
            pool,
        }
    }

    /// Create a new identity merge service with a custom SoD service.
    pub fn with_sod_service(pool: PgPool, sod_service: Arc<SodEnforcementService>) -> Self {
        Self {
            pool,
            sod_enforcement_service: sod_service,
        }
    }

    /// Get the database pool reference.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    // =========================================================================
    // Merge Preview (T015)
    // =========================================================================

    /// Generate a merge preview showing the comparison and proposed result.
    ///
    /// This allows administrators to see the differences between two identities
    /// and preview what the merged identity would look like.
    pub async fn preview(
        &self,
        tenant_id: Uuid,
        request: &MergePreviewRequest,
    ) -> Result<MergePreviewResponse> {
        // Validate identities are different
        if request.source_identity_id == request.target_identity_id {
            return Err(GovernanceError::MergeIdentitiesMustBeDifferent);
        }

        // Check for circular merge
        let has_circular = GovMergeOperation::has_pending_merge_involving(
            &self.pool,
            tenant_id,
            request.target_identity_id,
            request.source_identity_id,
        )
        .await
        .map_err(GovernanceError::Database)?;

        if has_circular {
            return Err(GovernanceError::CircularMergeDetected {
                source_id: request.source_identity_id,
                target_id: request.target_identity_id,
            });
        }

        // Get identity summaries (simplified - would fetch from users table)
        let source_summary = self
            .get_identity_summary(tenant_id, request.source_identity_id)
            .await?;
        let target_summary = self
            .get_identity_summary(tenant_id, request.target_identity_id)
            .await?;

        // Generate merged preview based on attribute selections
        let merged_preview = self.generate_merged_preview(
            &source_summary,
            &target_summary,
            &request.attribute_selections,
        )?;

        // Get entitlement previews
        let entitlements_preview = self
            .preview_entitlement_consolidation(
                tenant_id,
                request.source_identity_id,
                request.target_identity_id,
                request.entitlement_strategy,
            )
            .await?;

        // Check for SoD violations (T055: SoD check during merge preview)
        let sod_check = self
            .check_merge_sod_violations(
                tenant_id,
                request.target_identity_id,
                &entitlements_preview.source_only,
            )
            .await?;

        Ok(MergePreviewResponse {
            source_identity: source_summary,
            target_identity: target_summary,
            merged_preview,
            entitlements_preview,
            sod_check,
        })
    }

    /// Get detailed comparison for a duplicate candidate.
    pub async fn get_duplicate_detail(
        &self,
        tenant_id: Uuid,
        candidate_id: Uuid,
    ) -> Result<DuplicateDetailResponse> {
        let candidate = GovDuplicateCandidate::find_by_id(&self.pool, tenant_id, candidate_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::DuplicateNotFound(candidate_id))?;

        let identity_a = self
            .get_identity_summary(tenant_id, candidate.identity_a_id)
            .await?;
        let identity_b = self
            .get_identity_summary(tenant_id, candidate.identity_b_id)
            .await?;

        let attribute_comparison = self.compare_attributes(&identity_a, &identity_b);

        let rule_matches = candidate
            .get_rule_matches()
            .map(|rm| {
                rm.matches
                    .iter()
                    .map(|m| RuleMatchResponse {
                        rule_id: m.rule_id,
                        rule_name: m.rule_name.clone(),
                        attribute: m.attribute.clone(),
                        similarity: m.similarity,
                        weighted_score: m.weighted_score,
                    })
                    .collect()
            })
            .unwrap_or_default();

        Ok(DuplicateDetailResponse {
            id: candidate.id,
            identity_a_id: candidate.identity_a_id,
            identity_b_id: candidate.identity_b_id,
            confidence_score: candidate
                .confidence_score
                .to_string()
                .parse::<f64>()
                .unwrap_or(0.0),
            identity_a,
            identity_b,
            attribute_comparison,
            rule_matches,
        })
    }

    // =========================================================================
    // Merge Execution (T016)
    // =========================================================================

    /// Execute a merge operation.
    ///
    /// This performs the actual merge:
    /// 1. Validates the request and checks for conflicts
    /// 2. Creates the merge operation record
    /// 3. Updates target identity with selected attributes
    /// 4. Consolidates entitlements
    /// 5. Archives the source identity
    /// 6. Invalidates source identity sessions
    /// 7. Creates audit record
    /// 8. Updates duplicate candidate status (if applicable)
    pub async fn execute(
        &self,
        tenant_id: Uuid,
        operator_id: Uuid,
        request: &MergeExecuteRequest,
    ) -> Result<MergeResult> {
        // Validate identities exist and are different
        if request.source_identity_id == request.target_identity_id {
            return Err(GovernanceError::MergeIdentitiesMustBeDifferent);
        }

        // Check for circular merge
        let has_circular = GovMergeOperation::has_pending_merge_involving(
            &self.pool,
            tenant_id,
            request.target_identity_id,
            request.source_identity_id,
        )
        .await
        .map_err(GovernanceError::Database)?;

        if has_circular {
            return Err(GovernanceError::CircularMergeDetected {
                source_id: request.source_identity_id,
                target_id: request.target_identity_id,
            });
        }

        // Check for pending merge involving either identity
        let has_pending_source = GovMergeOperation::has_pending_involving(
            &self.pool,
            tenant_id,
            request.source_identity_id,
        )
        .await
        .map_err(GovernanceError::Database)?;

        let has_pending_target = GovMergeOperation::has_pending_involving(
            &self.pool,
            tenant_id,
            request.target_identity_id,
        )
        .await
        .map_err(GovernanceError::Database)?;

        if has_pending_source || has_pending_target {
            return Err(GovernanceError::MergeAlreadyInProgress {
                identity_id: if has_pending_source {
                    request.source_identity_id
                } else {
                    request.target_identity_id
                },
            });
        }

        // Get source identity summary for snapshot
        let source_summary = self
            .get_identity_summary(tenant_id, request.source_identity_id)
            .await?;
        let target_summary = self
            .get_identity_summary(tenant_id, request.target_identity_id)
            .await?;

        // Preview entitlements for consolidation (for audit trail and SoD check)
        let entitlements_preview = self
            .preview_entitlement_consolidation(
                tenant_id,
                request.source_identity_id,
                request.target_identity_id,
                request.entitlement_strategy,
            )
            .await?;

        // SoD check (T055-T058: Check for violations before merge)
        let sod_check = self
            .check_merge_sod_violations(
                tenant_id,
                request.target_identity_id,
                &entitlements_preview.source_only,
            )
            .await?;

        // T057: Block merge if SoD violations exist and no override provided
        // T058: Allow with reason capture if override is provided
        let sod_overridden = if sod_check.has_violations {
            if !sod_check.can_override {
                // Hard block - violations cannot be overridden
                // Use the first violation for the error details
                if let Some(v) = sod_check.violations.first() {
                    return Err(GovernanceError::SodViolationBlocked {
                        rule_id: v.rule_id,
                        rule_name: v.rule_name.clone(),
                        severity: v.severity.clone(),
                        conflicting_entitlement_id: v.conflicting_entitlement_id,
                    });
                }
            }

            // Check if override reason was provided
            if request.sod_override_reason.is_none() {
                return Err(GovernanceError::SodOverrideReasonRequired);
            }

            tracing::info!(
                tenant_id = %tenant_id,
                source_id = %request.source_identity_id,
                target_id = %request.target_identity_id,
                override_reason = ?request.sod_override_reason,
                violations = sod_check.violations.len(),
                "SoD violations overridden during merge"
            );

            true
        } else {
            false
        };

        // Start transaction
        let mut tx = self.pool.begin().await.map_err(GovernanceError::Database)?;

        // 1. Find duplicate candidate if exists
        let candidate_id = self
            .find_duplicate_candidate(
                tenant_id,
                request.source_identity_id,
                request.target_identity_id,
            )
            .await?;

        // 2. Create merge operation record
        let operation_input = CreateGovMergeOperation {
            candidate_id,
            source_identity_id: request.source_identity_id,
            target_identity_id: request.target_identity_id,
            entitlement_strategy: request.entitlement_strategy,
            attribute_selections: request
                .attribute_selections
                .clone()
                .unwrap_or_else(|| json!({})),
            entitlement_selections: request
                .entitlement_selections
                .as_ref()
                .map(|v| serde_json::to_value(v).unwrap_or_default()),
            operator_id,
        };

        let operation = GovMergeOperation::create_with_tx(&mut *tx, tenant_id, operation_input)
            .await
            .map_err(GovernanceError::Database)?;

        // 3. Transfer entitlements based on strategy
        let entitlements_added = self
            .transfer_entitlements(
                &mut *tx,
                tenant_id,
                request.source_identity_id,
                request.target_identity_id,
                request.entitlement_strategy,
                request.entitlement_selections.as_ref(),
            )
            .await?;
        let entitlements_removed = 0; // Source entitlements are archived, not removed

        // 4. Transfer group memberships (IGA edge case)
        let groups_transferred = self
            .transfer_group_memberships(
                &mut *tx,
                tenant_id,
                request.source_identity_id,
                request.target_identity_id,
            )
            .await
            .unwrap_or(0);

        // 5. Handle pending access requests (IGA edge case)
        let access_requests_cancelled = self
            .handle_pending_access_requests(
                &mut *tx,
                tenant_id,
                request.source_identity_id,
                request.target_identity_id,
            )
            .await
            .unwrap_or(0);

        // 6. Transfer resource ownerships (IGA edge case)
        let ownerships_transferred = self
            .transfer_ownerships(
                &mut tx,
                tenant_id,
                request.source_identity_id,
                request.target_identity_id,
            )
            .await
            .unwrap_or(0);

        // 7. Collect external references for archive
        let external_references = self
            .collect_external_references(tenant_id, request.source_identity_id)
            .await;

        // 8. Archive source identity with full external references
        let archived = GovArchivedIdentity::create_with_tx(
            &mut *tx,
            tenant_id,
            request.source_identity_id,
            operation.id,
            serde_json::to_value(&source_summary).unwrap_or_default(),
            external_references.clone(),
        )
        .await
        .map_err(GovernanceError::Database)?;

        // 9. Create audit record
        let merged_preview = self.generate_merged_preview(
            &source_summary,
            &target_summary,
            &request.attribute_selections,
        )?;

        GovMergeAudit::create_with_tx(
            &mut *tx,
            tenant_id,
            operation.id,
            serde_json::to_value(&source_summary).unwrap_or_default(),
            serde_json::to_value(&target_summary).unwrap_or_default(),
            serde_json::to_value(&merged_preview).unwrap_or_default(),
            request
                .attribute_selections
                .clone()
                .unwrap_or_else(|| json!({})),
            json!({
                "strategy": format!("{:?}", request.entitlement_strategy).to_lowercase(),
                "added_count": entitlements_added,
                "removed_count": entitlements_removed
            }),
            None,
        )
        .await
        .map_err(GovernanceError::Database)?;

        // 10. Complete merge operation
        GovMergeOperation::complete_with_tx(&mut *tx, tenant_id, operation.id)
            .await
            .map_err(GovernanceError::Database)?;

        // 11. Update duplicate candidate status (if applicable)
        if let Some(cand_id) = candidate_id {
            GovDuplicateCandidate::mark_merged_with_tx(&mut *tx, tenant_id, cand_id)
                .await
                .map_err(GovernanceError::Database)?;
        }

        // Commit transaction
        tx.commit().await.map_err(GovernanceError::Database)?;

        // 12. Invalidate sessions (outside transaction)
        self.invalidate_sessions(tenant_id, request.source_identity_id)
            .await?;

        tracing::info!(
            tenant_id = %tenant_id,
            operation_id = %operation.id,
            source_id = %request.source_identity_id,
            target_id = %request.target_identity_id,
            entitlements_added = entitlements_added,
            groups_transferred = groups_transferred,
            access_requests_cancelled = access_requests_cancelled,
            ownerships_transferred = ownerships_transferred,
            sod_overridden = sod_overridden,
            "Identity merge completed"
        );

        Ok(MergeResult {
            operation_id: operation.id,
            target_identity_id: request.target_identity_id,
            archived_identity_id: archived.id,
            entitlements_added,
            entitlements_removed,
            sod_overridden,
            groups_transferred,
            access_requests_cancelled,
            ownerships_transferred,
            external_references_preserved: external_references,
        })
    }

    /// Get a merge operation by ID.
    pub async fn get_operation(
        &self,
        tenant_id: Uuid,
        operation_id: Uuid,
    ) -> Result<MergeOperationResponse> {
        let operation = GovMergeOperation::find_by_id(&self.pool, tenant_id, operation_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::MergeOperationNotFound(operation_id))?;

        Ok(MergeOperationResponse {
            id: operation.id,
            source_identity_id: operation.source_identity_id,
            target_identity_id: operation.target_identity_id,
            status: operation.status,
            entitlement_strategy: operation.entitlement_strategy,
            operator_id: operation.operator_id,
            started_at: operation.started_at,
            completed_at: operation.completed_at,
        })
    }

    // =========================================================================
    // Helper Methods
    // =========================================================================

    #[allow(clippy::type_complexity)]
    async fn get_identity_summary(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<IdentitySummary> {
        // Fetch user from database
        let row: Option<(
            Option<String>,
            Option<String>,
            Option<String>,
            Option<serde_json::Value>,
        )> = sqlx::query_as(
            r#"
            SELECT email, display_name, department, attributes
            FROM users
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(user_id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        match row {
            Some((email, display_name, department, attributes)) => Ok(IdentitySummary {
                id: user_id,
                email,
                display_name,
                department,
                attributes: attributes.unwrap_or_else(|| json!({})),
            }),
            None => Err(GovernanceError::IdentityNotFound(user_id)),
        }
    }

    fn generate_merged_preview(
        &self,
        source: &IdentitySummary,
        target: &IdentitySummary,
        attribute_selections: &Option<serde_json::Value>,
    ) -> Result<IdentitySummary> {
        // Start with target identity (the one being kept)
        let mut merged = target.clone();

        // Apply attribute selections if provided
        if let Some(selections) = attribute_selections {
            if let Some(obj) = selections.as_object() {
                for (attr, selection) in obj {
                    if let Some(source_choice) = selection.get("source").and_then(|s| s.as_str()) {
                        if source_choice == "source" {
                            // Use value from source identity
                            match attr.as_str() {
                                "email" => merged.email = source.email.clone(),
                                "display_name" => merged.display_name = source.display_name.clone(),
                                "department" => merged.department = source.department.clone(),
                                _ => {
                                    // Handle custom attributes
                                    if let Some(value) = source.attributes.get(attr) {
                                        if let Some(attrs) = merged.attributes.as_object_mut() {
                                            attrs.insert(attr.clone(), value.clone());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(merged)
    }

    fn compare_attributes(
        &self,
        identity_a: &IdentitySummary,
        identity_b: &IdentitySummary,
    ) -> Vec<AttributeComparison> {
        let mut comparisons = Vec::new();

        // Compare standard attributes
        comparisons.push(AttributeComparison {
            attribute: "email".to_string(),
            value_a: identity_a.email.as_ref().map(|v| json!(v)),
            value_b: identity_b.email.as_ref().map(|v| json!(v)),
            is_different: identity_a.email != identity_b.email,
        });

        comparisons.push(AttributeComparison {
            attribute: "display_name".to_string(),
            value_a: identity_a.display_name.as_ref().map(|v| json!(v)),
            value_b: identity_b.display_name.as_ref().map(|v| json!(v)),
            is_different: identity_a.display_name != identity_b.display_name,
        });

        comparisons.push(AttributeComparison {
            attribute: "department".to_string(),
            value_a: identity_a.department.as_ref().map(|v| json!(v)),
            value_b: identity_b.department.as_ref().map(|v| json!(v)),
            is_different: identity_a.department != identity_b.department,
        });

        // Compare custom attributes
        let a_attrs = identity_a.attributes.as_object();
        let b_attrs = identity_b.attributes.as_object();

        if let (Some(a_obj), Some(b_obj)) = (a_attrs, b_attrs) {
            // Collect all unique attribute keys
            let mut keys: HashSet<&String> = a_obj.keys().collect();
            keys.extend(b_obj.keys());

            for key in keys {
                let value_a = a_obj.get(key).cloned();
                let value_b = b_obj.get(key).cloned();

                comparisons.push(AttributeComparison {
                    attribute: key.clone(),
                    value_a: value_a.clone(),
                    value_b: value_b.clone(),
                    is_different: value_a != value_b,
                });
            }
        }

        comparisons
    }

    /// Check for SoD violations that would occur if source entitlements are transferred to target.
    ///
    /// This method checks each entitlement being transferred against the target's existing
    /// entitlements to detect any SoD rule violations.
    async fn check_merge_sod_violations(
        &self,
        tenant_id: Uuid,
        target_id: Uuid,
        source_only_entitlements: &[MergeEntitlementSummary],
    ) -> Result<MergeSodCheckResponse> {
        let mut all_violations = Vec::new();
        let mut has_hard_block = false;

        // Check each source entitlement being transferred
        for entitlement in source_only_entitlements {
            let check_result = self
                .sod_enforcement_service
                .check_assignment(tenant_id, target_id, entitlement.id, true)
                .await?;

            if !check_result.allowed {
                for violation in check_result.violations {
                    // Check if this is a hard block (high severity without exemption)
                    if !violation.has_exemption
                        && violation.severity == xavyo_db::models::GovSodSeverity::High
                    {
                        has_hard_block = true;
                    }

                    all_violations.push(MergeSodViolationResponse {
                        rule_id: violation.rule_id,
                        rule_name: violation.rule_name,
                        severity: format!("{:?}", violation.severity).to_lowercase(),
                        entitlement_being_added: entitlement.id,
                        conflicting_entitlement_id: violation.conflicting_entitlement_id,
                        has_exemption: violation.has_exemption,
                    });
                }
            }
        }

        // Also check for conflicts between source entitlements themselves
        // (in case two source entitlements conflict with each other)
        if source_only_entitlements.len() > 1 {
            for (i, ent_a) in source_only_entitlements.iter().enumerate() {
                for ent_b in source_only_entitlements.iter().skip(i + 1) {
                    // Check if there's a SoD rule between these two entitlements
                    let has_rule = self
                        .check_sod_rule_exists(tenant_id, ent_a.id, ent_b.id)
                        .await?;

                    if has_rule {
                        all_violations.push(MergeSodViolationResponse {
                            rule_id: Uuid::nil(), // Rule details not fetched for inter-source conflicts
                            rule_name: "Source entitlement conflict".to_string(),
                            severity: "medium".to_string(),
                            entitlement_being_added: ent_a.id,
                            conflicting_entitlement_id: ent_b.id,
                            has_exemption: false,
                        });
                    }
                }
            }
        }

        Ok(MergeSodCheckResponse {
            has_violations: !all_violations.is_empty(),
            can_override: !has_hard_block,
            violations: all_violations,
        })
    }

    /// Check if a SoD rule exists between two entitlements.
    async fn check_sod_rule_exists(
        &self,
        tenant_id: Uuid,
        entitlement_a_id: Uuid,
        entitlement_b_id: Uuid,
    ) -> Result<bool> {
        let result = sqlx::query_scalar::<_, bool>(
            r#"
            SELECT EXISTS (
                SELECT 1 FROM gov_sod_rules
                WHERE tenant_id = $1
                AND is_active = true
                AND (
                    (entitlement_a_id = $2 AND entitlement_b_id = $3)
                    OR (entitlement_a_id = $3 AND entitlement_b_id = $2)
                )
            )
            "#,
        )
        .bind(tenant_id)
        .bind(entitlement_a_id)
        .bind(entitlement_b_id)
        .fetch_one(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        Ok(result)
    }

    async fn preview_entitlement_consolidation(
        &self,
        tenant_id: Uuid,
        source_id: Uuid,
        target_id: Uuid,
        strategy: GovEntitlementStrategy,
    ) -> Result<EntitlementsPreview> {
        // Fetch entitlements for both identities (simplified query)
        let source_entitlements: Vec<MergeEntitlementSummary> =
            sqlx::query_as::<_, (Uuid, String, Option<String>)>(
                r#"
            SELECT e.id, e.name, a.name as application
            FROM gov_entitlement_assignments ea
            JOIN gov_entitlements e ON e.id = ea.entitlement_id
            LEFT JOIN gov_applications a ON a.id = e.application_id
            WHERE ea.user_id = $1 AND ea.tenant_id = $2 AND ea.is_active = true
            "#,
            )
            .bind(source_id)
            .bind(tenant_id)
            .fetch_all(&self.pool)
            .await
            .map_err(GovernanceError::Database)?
            .into_iter()
            .map(|(id, name, application)| MergeEntitlementSummary {
                id,
                name,
                application,
            })
            .collect();

        let target_entitlements: Vec<MergeEntitlementSummary> =
            sqlx::query_as::<_, (Uuid, String, Option<String>)>(
                r#"
            SELECT e.id, e.name, a.name as application
            FROM gov_entitlement_assignments ea
            JOIN gov_entitlements e ON e.id = ea.entitlement_id
            LEFT JOIN gov_applications a ON a.id = e.application_id
            WHERE ea.user_id = $1 AND ea.tenant_id = $2 AND ea.is_active = true
            "#,
            )
            .bind(target_id)
            .bind(tenant_id)
            .fetch_all(&self.pool)
            .await
            .map_err(GovernanceError::Database)?
            .into_iter()
            .map(|(id, name, application)| MergeEntitlementSummary {
                id,
                name,
                application,
            })
            .collect();

        let source_ids: HashSet<Uuid> = source_entitlements.iter().map(|e| e.id).collect();
        let target_ids: HashSet<Uuid> = target_entitlements.iter().map(|e| e.id).collect();

        // Calculate source_only, target_only, common
        let source_only: Vec<_> = source_entitlements
            .iter()
            .filter(|e| !target_ids.contains(&e.id))
            .cloned()
            .collect();

        let target_only: Vec<_> = target_entitlements
            .iter()
            .filter(|e| !source_ids.contains(&e.id))
            .cloned()
            .collect();

        let common: Vec<_> = source_entitlements
            .iter()
            .filter(|e| target_ids.contains(&e.id))
            .cloned()
            .collect();

        // Calculate merged based on strategy
        let merged = match strategy {
            GovEntitlementStrategy::Union => {
                let mut all = target_entitlements.clone();
                for ent in &source_only {
                    all.push(ent.clone());
                }
                all
            }
            GovEntitlementStrategy::Intersection => common.clone(),
            GovEntitlementStrategy::Manual => {
                // For manual, we show all entitlements; user will select
                let mut all = target_entitlements.clone();
                for ent in &source_only {
                    all.push(ent.clone());
                }
                all
            }
        };

        Ok(EntitlementsPreview {
            source_only,
            target_only,
            common,
            merged,
        })
    }

    async fn find_duplicate_candidate(
        &self,
        tenant_id: Uuid,
        source_id: Uuid,
        target_id: Uuid,
    ) -> Result<Option<Uuid>> {
        // Ensure canonical ordering
        let (id_a, id_b) = if source_id < target_id {
            (source_id, target_id)
        } else {
            (target_id, source_id)
        };

        let candidate =
            GovDuplicateCandidate::find_by_identities(&self.pool, tenant_id, id_a, id_b)
                .await
                .map_err(GovernanceError::Database)?;

        Ok(candidate.map(|c| c.id))
    }

    // =========================================================================
    // List and Dismiss Methods (API Handlers)
    // =========================================================================

    /// List duplicate candidates with filtering and pagination.
    pub async fn list_duplicates(
        &self,
        tenant_id: Uuid,
        filter: &xavyo_db::models::DuplicateCandidateFilter,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<GovDuplicateCandidate>, i64)> {
        let candidates =
            GovDuplicateCandidate::list_by_tenant(&self.pool, tenant_id, filter, limit, offset)
                .await
                .map_err(GovernanceError::Database)?;

        let total = GovDuplicateCandidate::count_by_tenant(&self.pool, tenant_id, filter)
            .await
            .map_err(GovernanceError::Database)?;

        Ok((candidates, total))
    }

    /// Dismiss a duplicate candidate as a false positive.
    pub async fn dismiss_duplicate(
        &self,
        tenant_id: Uuid,
        candidate_id: Uuid,
        dismissed_by: Uuid,
        reason: &str,
    ) -> Result<GovDuplicateCandidate> {
        use xavyo_db::models::{DismissGovDuplicateCandidate, GovDuplicateStatus};

        // Check if candidate exists and is pending
        let candidate = GovDuplicateCandidate::find_by_id(&self.pool, tenant_id, candidate_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::DuplicateNotFound(candidate_id))?;

        // Check status
        match candidate.status {
            GovDuplicateStatus::Dismissed => {
                return Err(GovernanceError::DuplicateAlreadyDismissed(candidate_id));
            }
            GovDuplicateStatus::Merged => {
                return Err(GovernanceError::DuplicateAlreadyMerged(candidate_id));
            }
            GovDuplicateStatus::Pending => {
                // OK to dismiss
            }
        }

        // Dismiss the candidate
        let dismissed = GovDuplicateCandidate::dismiss(
            &self.pool,
            tenant_id,
            candidate_id,
            DismissGovDuplicateCandidate {
                dismissed_by,
                reason: reason.to_string(),
            },
        )
        .await
        .map_err(GovernanceError::Database)?
        .ok_or(GovernanceError::DuplicateNotFound(candidate_id))?;

        Ok(dismissed)
    }

    /// List merge operations with filtering and pagination.
    pub async fn list_operations(
        &self,
        tenant_id: Uuid,
        filter: &xavyo_db::models::MergeOperationFilter,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<GovMergeOperation>, i64)> {
        let operations =
            GovMergeOperation::list_by_tenant(&self.pool, tenant_id, filter, limit, offset)
                .await
                .map_err(GovernanceError::Database)?;

        let total = GovMergeOperation::count_by_tenant(&self.pool, tenant_id, filter)
            .await
            .map_err(GovernanceError::Database)?;

        Ok((operations, total))
    }

    // =========================================================================
    // Internal Helper Methods
    // =========================================================================

    async fn invalidate_sessions(&self, tenant_id: Uuid, user_id: Uuid) -> Result<()> {
        // Invalidate all sessions for the archived identity
        // This ensures the user cannot access the system with the old identity
        let result = sqlx::query(
            r#"
            UPDATE sessions
            SET is_valid = false, invalidated_at = NOW()
            WHERE user_id = $1 AND tenant_id = $2 AND is_valid = true
            "#,
        )
        .bind(user_id)
        .bind(tenant_id)
        .execute(&self.pool)
        .await;

        // Session table may not exist in all setups - don't fail if it doesn't
        if let Ok(res) = result {
            if res.rows_affected() > 0 {
                tracing::info!(
                    tenant_id = %tenant_id,
                    user_id = %user_id,
                    count = res.rows_affected(),
                    "Invalidated sessions for archived identity"
                );
            }
        }

        Ok(())
    }

    // =========================================================================
    // Edge Case Handlers (IGA best practices parity analysis)
    // =========================================================================

    /// Transfer group memberships from source to target identity.
    ///
    /// This handles the edge case where the source identity is a member of groups
    /// that the target is not. Those memberships are transferred to ensure no
    /// access is lost during merge.
    async fn transfer_group_memberships<'e, E>(
        &self,
        executor: E,
        tenant_id: Uuid,
        source_id: Uuid,
        target_id: Uuid,
    ) -> Result<usize>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        // Transfer memberships from source to target where target is not already a member
        // Uses INSERT ... ON CONFLICT to handle duplicates gracefully
        let result = sqlx::query(
            r#"
            INSERT INTO group_memberships (id, tenant_id, group_id, user_id, created_at)
            SELECT gen_random_uuid(), gm.tenant_id, gm.group_id, $3, NOW()
            FROM group_memberships gm
            WHERE gm.user_id = $1 AND gm.tenant_id = $2
            AND NOT EXISTS (
                SELECT 1 FROM group_memberships gm2
                WHERE gm2.group_id = gm.group_id
                AND gm2.user_id = $3
                AND gm2.tenant_id = $2
            )
            ON CONFLICT DO NOTHING
            "#,
        )
        .bind(source_id)
        .bind(tenant_id)
        .bind(target_id)
        .execute(executor)
        .await;

        // Table may not exist - don't fail
        match result {
            Ok(res) => {
                let count = res.rows_affected() as usize;
                if count > 0 {
                    tracing::info!(
                        tenant_id = %tenant_id,
                        source_id = %source_id,
                        target_id = %target_id,
                        count = count,
                        "Transferred group memberships during merge"
                    );
                }
                Ok(count)
            }
            Err(e) => {
                // If table doesn't exist, log and continue
                tracing::debug!(
                    error = %e,
                    "Group membership transfer skipped (table may not exist)"
                );
                Ok(0)
            }
        }
    }

    /// Cancel or reassign pending access requests involving the source identity.
    ///
    /// When merging identities, any pending access requests made BY the source
    /// identity should be transferred to the target (requester changes).
    /// Any pending requests FOR the source identity are cancelled as the identity
    /// is being archived.
    async fn handle_pending_access_requests<'e, E>(
        &self,
        executor: E,
        tenant_id: Uuid,
        source_id: Uuid,
        target_id: Uuid,
    ) -> Result<usize>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        // Cancel requests where source is the beneficiary (they're being archived)
        let cancel_result = sqlx::query(
            r#"
            UPDATE gov_access_requests
            SET status = 'cancelled',
                updated_at = NOW(),
                metadata = COALESCE(metadata, '{}'::jsonb) ||
                    jsonb_build_object('cancelled_reason', 'identity_merged',
                                       'merged_into', $3::text)
            WHERE user_id = $1 AND tenant_id = $2
            AND status IN ('pending', 'pending_approval')
            "#,
        )
        .bind(source_id)
        .bind(tenant_id)
        .bind(target_id)
        .execute(executor)
        .await;

        match cancel_result {
            Ok(res) => {
                let count = res.rows_affected() as usize;
                if count > 0 {
                    tracing::info!(
                        tenant_id = %tenant_id,
                        source_id = %source_id,
                        count = count,
                        "Cancelled pending access requests during merge"
                    );
                }
                Ok(count)
            }
            Err(e) => {
                tracing::debug!(
                    error = %e,
                    "Access request cancellation skipped (table may not exist)"
                );
                Ok(0)
            }
        }
    }

    /// Transfer ownership of resources from source to target identity.
    ///
    /// This handles applications or entitlements that list the source identity
    /// as the owner. Ownership is transferred to the target to preserve
    /// administrative continuity.
    async fn transfer_ownerships(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        tenant_id: Uuid,
        source_id: Uuid,
        target_id: Uuid,
    ) -> Result<usize> {
        let mut total_transferred = 0;

        // Transfer application ownership
        let app_result: std::result::Result<sqlx::postgres::PgQueryResult, sqlx::Error> =
            sqlx::query(
                r#"
            UPDATE gov_applications
            SET owner_id = $3, updated_at = NOW()
            WHERE owner_id = $1 AND tenant_id = $2
            "#,
            )
            .bind(source_id)
            .bind(tenant_id)
            .bind(target_id)
            .execute(&mut **tx)
            .await;

        if let Ok(res) = app_result {
            total_transferred += res.rows_affected() as usize;
        }

        // Transfer entitlement ownership
        let ent_result: std::result::Result<sqlx::postgres::PgQueryResult, sqlx::Error> =
            sqlx::query(
                r#"
            UPDATE gov_entitlements
            SET owner_id = $3, updated_at = NOW()
            WHERE owner_id = $1 AND tenant_id = $2
            "#,
            )
            .bind(source_id)
            .bind(tenant_id)
            .bind(target_id)
            .execute(&mut **tx)
            .await;

        if let Ok(res) = ent_result {
            total_transferred += res.rows_affected() as usize;
        }

        if total_transferred > 0 {
            tracing::info!(
                tenant_id = %tenant_id,
                source_id = %source_id,
                target_id = %target_id,
                count = total_transferred,
                "Transferred resource ownerships during merge"
            );
        }

        Ok(total_transferred)
    }

    /// Collect external references for the source identity.
    ///
    /// This preserves SCIM externalId, LDAP DN, and other external system
    /// identifiers so they can be stored in the archive for reference.
    async fn collect_external_references(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> serde_json::Value {
        let mut refs = json!({});

        // Collect SCIM external IDs
        let scim_result: std::result::Result<Vec<(String, String)>, sqlx::Error> = sqlx::query_as(
            r#"
            SELECT resource_type, external_id
            FROM scim_resources
            WHERE user_id = $1 AND tenant_id = $2
            "#,
        )
        .bind(user_id)
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await;

        if let Ok(scim_refs) = scim_result {
            if !scim_refs.is_empty() {
                refs["scim"] = json!(scim_refs
                    .iter()
                    .map(|(rt, eid)| json!({"resource_type": rt, "external_id": eid}))
                    .collect::<Vec<_>>());
            }
        }

        // Collect LDAP DNs (if connector framework is available)
        let ldap_result: std::result::Result<Vec<(String, String)>, sqlx::Error> = sqlx::query_as(
            r#"
            SELECT connector_id::text, external_uid
            FROM gov_connector_accounts
            WHERE identity_id = $1 AND tenant_id = $2
            "#,
        )
        .bind(user_id)
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await;

        if let Ok(ldap_refs) = ldap_result {
            if !ldap_refs.is_empty() {
                refs["connector_accounts"] = json!(ldap_refs
                    .iter()
                    .map(|(cid, uid)| json!({"connector_id": cid, "external_uid": uid}))
                    .collect::<Vec<_>>());
            }
        }

        // Collect social login identities
        let social_result: std::result::Result<Vec<(String, String)>, sqlx::Error> =
            sqlx::query_as(
                r#"
            SELECT provider, provider_user_id
            FROM social_identities
            WHERE user_id = $1 AND tenant_id = $2
            "#,
            )
            .bind(user_id)
            .bind(tenant_id)
            .fetch_all(&self.pool)
            .await;

        if let Ok(social_refs) = social_result {
            if !social_refs.is_empty() {
                refs["social_identities"] = json!(social_refs
                    .iter()
                    .map(|(p, pid)| json!({"provider": p, "provider_user_id": pid}))
                    .collect::<Vec<_>>());
            }
        }

        refs
    }

    /// Transfer active entitlement assignments from source to target.
    ///
    /// Uses the specified strategy to determine which entitlements to transfer.
    async fn transfer_entitlements<'e, E>(
        &self,
        executor: E,
        tenant_id: Uuid,
        source_id: Uuid,
        target_id: Uuid,
        strategy: GovEntitlementStrategy,
        manual_selections: Option<&Vec<Uuid>>,
    ) -> Result<usize>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        match strategy {
            GovEntitlementStrategy::Union => {
                // Transfer all source entitlements that target doesn't have
                let result = sqlx::query(
                    r#"
                    INSERT INTO gov_entitlement_assignments
                        (id, tenant_id, entitlement_id, user_id, assigned_by, justification, is_active, created_at)
                    SELECT gen_random_uuid(), ea.tenant_id, ea.entitlement_id, $3,
                           ea.assigned_by, 'Transferred during identity merge', true, NOW()
                    FROM gov_entitlement_assignments ea
                    WHERE ea.user_id = $1 AND ea.tenant_id = $2 AND ea.is_active = true
                    AND NOT EXISTS (
                        SELECT 1 FROM gov_entitlement_assignments ea2
                        WHERE ea2.entitlement_id = ea.entitlement_id
                        AND ea2.user_id = $3
                        AND ea2.tenant_id = $2
                        AND ea2.is_active = true
                    )
                    ON CONFLICT DO NOTHING
                    "#,
                )
                .bind(source_id)
                .bind(tenant_id)
                .bind(target_id)
                .execute(executor)
                .await
                .map_err(GovernanceError::Database)?;

                Ok(result.rows_affected() as usize)
            }
            GovEntitlementStrategy::Intersection => {
                // Keep only common entitlements - no transfer needed
                Ok(0)
            }
            GovEntitlementStrategy::Manual => {
                // Transfer only selected entitlements
                if let Some(selections) = manual_selections {
                    if selections.is_empty() {
                        return Ok(0);
                    }

                    let result = sqlx::query(
                        r#"
                        INSERT INTO gov_entitlement_assignments
                            (id, tenant_id, entitlement_id, user_id, assigned_by, justification, is_active, created_at)
                        SELECT gen_random_uuid(), ea.tenant_id, ea.entitlement_id, $3,
                               ea.assigned_by, 'Transferred during identity merge (manual selection)', true, NOW()
                        FROM gov_entitlement_assignments ea
                        WHERE ea.user_id = $1 AND ea.tenant_id = $2 AND ea.is_active = true
                        AND ea.entitlement_id = ANY($4)
                        AND NOT EXISTS (
                            SELECT 1 FROM gov_entitlement_assignments ea2
                            WHERE ea2.entitlement_id = ea.entitlement_id
                            AND ea2.user_id = $3
                            AND ea2.tenant_id = $2
                            AND ea2.is_active = true
                        )
                        ON CONFLICT DO NOTHING
                        "#,
                    )
                    .bind(source_id)
                    .bind(tenant_id)
                    .bind(target_id)
                    .bind(selections)
                    .execute(executor)
                    .await
                    .map_err(GovernanceError::Database)?;

                    Ok(result.rows_affected() as usize)
                } else {
                    Ok(0)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merge_result_structure() {
        let result = MergeResult {
            operation_id: Uuid::new_v4(),
            target_identity_id: Uuid::new_v4(),
            archived_identity_id: Uuid::new_v4(),
            entitlements_added: 5,
            entitlements_removed: 2,
            sod_overridden: false,
            groups_transferred: 3,
            access_requests_cancelled: 1,
            ownerships_transferred: 2,
            external_references_preserved: json!({"scim": []}),
        };

        assert_eq!(result.entitlements_added, 5);
        assert_eq!(result.entitlements_removed, 2);
        assert!(!result.sod_overridden);
        assert_eq!(result.groups_transferred, 3);
        assert_eq!(result.access_requests_cancelled, 1);
        assert_eq!(result.ownerships_transferred, 2);
    }

    #[test]
    fn test_merge_result_with_external_references() {
        let external_refs = json!({
            "scim": [{"resource_type": "User", "external_id": "ext-123"}],
            "connector_accounts": [{"connector_id": "ldap-1", "external_uid": "cn=user,dc=example"}],
            "social_identities": [{"provider": "google", "provider_user_id": "12345"}]
        });

        let result = MergeResult {
            operation_id: Uuid::new_v4(),
            target_identity_id: Uuid::new_v4(),
            archived_identity_id: Uuid::new_v4(),
            entitlements_added: 0,
            entitlements_removed: 0,
            sod_overridden: false,
            groups_transferred: 0,
            access_requests_cancelled: 0,
            ownerships_transferred: 0,
            external_references_preserved: external_refs.clone(),
        };

        assert_eq!(
            result.external_references_preserved["scim"][0]["external_id"],
            "ext-123"
        );
        assert_eq!(
            result.external_references_preserved["connector_accounts"][0]["connector_id"],
            "ldap-1"
        );
        assert_eq!(
            result.external_references_preserved["social_identities"][0]["provider"],
            "google"
        );
    }
}
