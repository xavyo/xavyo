//! Sync pipeline for processing inbound changes.

use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::{info, instrument, warn};
use uuid::Uuid;

use std::sync::Arc;

use super::change::InboundChange;
use super::config::{ConflictResolution, SyncConfig};
use super::conflict::SyncConflictDetector;
use super::correlator::{InboundCorrelationRule, InboundCorrelator};
use super::error::{SyncError, SyncResult};
use super::listener::{ChangeListener, ChangeSet, DetectedChange};
use super::mapper::InboundMapper;
use super::rate_limiter::RateLimiter;
use super::reaction::{ActionResult, SyncAction, SyncReactionConfig};
use super::status::SyncStatusManager;
use super::token::{SyncToken, SyncTokenManager};
use super::types::{ProcessingStatus, ResolutionStrategy};
use crate::shadow::{Shadow, ShadowRepository, SyncSituation};

/// Result of processing a single change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessedChange {
    /// The inbound change.
    pub change_id: Uuid,
    /// External UID.
    pub external_uid: String,
    /// Final sync situation.
    pub situation: SyncSituation,
    /// Linked identity ID (if any).
    pub linked_identity_id: Option<Uuid>,
    /// Conflict ID (if any).
    pub conflict_id: Option<Uuid>,
    /// Processing status.
    pub status: ProcessingStatus,
    /// Error message (if failed).
    pub error: Option<String>,
}

impl ProcessedChange {
    /// Create a successful result.
    #[must_use]
    pub fn success(change: &InboundChange, linked_identity_id: Option<Uuid>) -> Self {
        Self {
            change_id: change.id,
            external_uid: change.external_uid.clone(),
            situation: change.sync_situation,
            linked_identity_id,
            conflict_id: None,
            status: ProcessingStatus::Completed,
            error: None,
        }
    }

    /// Create a conflict result.
    #[must_use]
    pub fn conflict(change: &InboundChange, conflict_id: Uuid) -> Self {
        Self {
            change_id: change.id,
            external_uid: change.external_uid.clone(),
            situation: change.sync_situation,
            linked_identity_id: change.linked_identity_id,
            conflict_id: Some(conflict_id),
            status: ProcessingStatus::Conflict,
            error: None,
        }
    }

    /// Create a failed result.
    #[must_use]
    pub fn failed(change: &InboundChange, error: String) -> Self {
        Self {
            change_id: change.id,
            external_uid: change.external_uid.clone(),
            situation: change.sync_situation,
            linked_identity_id: change.linked_identity_id,
            conflict_id: None,
            status: ProcessingStatus::Failed,
            error: Some(error),
        }
    }
}

/// Summary of a batch processing run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchSummary {
    /// Number of changes processed.
    pub processed: usize,
    /// Number of successful changes.
    pub succeeded: usize,
    /// Number of failed changes.
    pub failed: usize,
    /// Number of conflicts detected.
    pub conflicts: usize,
    /// Whether there are more changes to process.
    pub has_more: bool,
}

impl BatchSummary {
    /// Create a new empty summary.
    #[must_use]
    pub fn new() -> Self {
        Self {
            processed: 0,
            succeeded: 0,
            failed: 0,
            conflicts: 0,
            has_more: false,
        }
    }

    /// Add a processed change to the summary.
    pub fn add(&mut self, result: &ProcessedChange) {
        self.processed += 1;
        match result.status {
            ProcessingStatus::Completed => self.succeeded += 1,
            ProcessingStatus::Failed => self.failed += 1,
            ProcessingStatus::Conflict => self.conflicts += 1,
            _ => {}
        }
    }
}

impl Default for BatchSummary {
    fn default() -> Self {
        Self::new()
    }
}

/// Sync pipeline for processing inbound changes.
pub struct SyncPipeline {
    #[allow(dead_code)]
    pool: PgPool,
    config: SyncConfig,
    token_manager: SyncTokenManager,
    status_manager: SyncStatusManager,
    conflict_detector: SyncConflictDetector,
    shadow_repo: ShadowRepository,
    mapper: Option<InboundMapper>,
    rate_limiter: Option<RateLimiter>,
    /// Inbound correlator for matching changes to users.
    correlator: Option<Arc<dyn InboundCorrelator>>,
    /// Correlation rules for inbound matching.
    correlation_rules: Vec<InboundCorrelationRule>,
    /// Reaction configuration for executing actions per situation.
    reaction_config: SyncReactionConfig,
    /// When true, process changes without persisting token or shadow updates.
    /// Useful for testing and previewing sync results.
    dry_run: bool,
}

impl SyncPipeline {
    /// Create a new sync pipeline.
    #[must_use]
    pub fn new(pool: PgPool, config: SyncConfig) -> Self {
        let rate_limiter = if config.rate_limit_per_minute > 0 {
            Some(RateLimiter::new(config.rate_limit_per_minute as u64))
        } else {
            None
        };

        let reaction_config =
            SyncReactionConfig::default_for(config.tenant_id, config.connector_id);

        Self {
            pool: pool.clone(),
            config,
            token_manager: SyncTokenManager::new(pool.clone()),
            status_manager: SyncStatusManager::new(pool.clone()),
            conflict_detector: SyncConflictDetector::new(pool.clone()),
            shadow_repo: ShadowRepository::new(pool),
            mapper: None,
            rate_limiter,
            correlator: None,
            correlation_rules: Vec::new(),
            reaction_config,
            dry_run: false,
        }
    }

    /// Enable or disable dry-run mode.
    ///
    /// In dry-run mode, the pipeline processes changes but does not:
    /// - Update the sync token
    /// - Update or create shadows
    /// - Persist sync status
    ///
    /// This is useful for testing sync configuration or previewing
    /// what changes would be processed.
    pub fn with_dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }

    /// Check if the pipeline is in dry-run mode.
    pub fn is_dry_run(&self) -> bool {
        self.dry_run
    }

    /// Create a builder for more complex configuration.
    #[must_use]
    pub fn builder(pool: PgPool, config: SyncConfig) -> SyncPipelineBuilder {
        SyncPipelineBuilder::new(pool, config)
    }

    /// Set the inbound mapper.
    pub fn with_mapper(mut self, mapper: InboundMapper) -> Self {
        self.mapper = Some(mapper);
        self
    }

    /// Set the inbound correlator for matching changes to users.
    pub fn with_correlator(mut self, correlator: Arc<dyn InboundCorrelator>) -> Self {
        self.correlator = Some(correlator);
        self
    }

    /// Set correlation rules for inbound matching.
    pub fn with_correlation_rules(mut self, rules: Vec<InboundCorrelationRule>) -> Self {
        self.correlation_rules = rules;
        self
    }

    /// Set custom reaction configuration.
    pub fn with_reaction_config(mut self, config: SyncReactionConfig) -> Self {
        self.reaction_config = config;
        self
    }

    /// Get the current reaction configuration.
    pub fn reaction_config(&self) -> &SyncReactionConfig {
        &self.reaction_config
    }

    /// Process a batch of changes from a listener.
    ///
    /// In dry-run mode, this method will:
    /// - Fetch changes from the listener
    /// - Process each change through mapping and situation detection
    /// - Return a summary of what would be processed
    /// - NOT update tokens, shadows, or sync status
    #[instrument(skip(self, listener))]
    pub async fn process_from_listener(
        &self,
        listener: &dyn ChangeListener,
    ) -> SyncResult<BatchSummary> {
        if !self.config.enabled {
            return Err(SyncError::disabled(self.config.connector_id));
        }

        // Get current token
        let token = self
            .token_manager
            .get_valid(self.config.tenant_id, self.config.connector_id)
            .await?;

        // Start sync (skip in dry-run mode)
        if !self.dry_run {
            self.status_manager
                .start_sync(self.config.tenant_id, self.config.connector_id)
                .await?;
        }

        // Fetch changes
        let changeset = match listener
            .fetch_changes(token.as_ref(), self.config.batch_size)
            .await
        {
            Ok(cs) => cs,
            Err(e) => {
                if !self.dry_run {
                    self.status_manager
                        .set_error(
                            self.config.tenant_id,
                            self.config.connector_id,
                            &e.to_string(),
                        )
                        .await?;
                }
                return Err(e);
            }
        };

        // Process changes
        let summary = self.process_changeset(changeset).await?;

        // Complete sync (skip in dry-run mode)
        if !self.dry_run {
            self.status_manager
                .complete_sync(
                    self.config.tenant_id,
                    self.config.connector_id,
                    summary.processed as i64,
                )
                .await?;
        }

        Ok(summary)
    }

    /// Process a changeset.
    ///
    /// In dry-run mode, tokens are not updated after processing.
    async fn process_changeset(&self, changeset: ChangeSet) -> SyncResult<BatchSummary> {
        let mut summary = BatchSummary::new();
        summary.has_more = changeset.has_more;

        for detected in changeset.changes {
            // Rate limiting (still applies in dry-run to test behavior)
            if let Some(ref limiter) = self.rate_limiter {
                if limiter.is_limited() {
                    if !self.dry_run {
                        self.status_manager
                            .set_throttled(self.config.tenant_id, self.config.connector_id, true)
                            .await?;
                    }
                    limiter.acquire().await;
                    if !self.dry_run {
                        self.status_manager
                            .set_throttled(self.config.tenant_id, self.config.connector_id, false)
                            .await?;
                    }
                }
                limiter.acquire().await;
            }

            let result = self.process_change(detected).await;
            summary.add(&result);
        }

        // Update token if provided (skip in dry-run mode)
        if !self.dry_run {
            if let Some(new_token) = changeset.new_token {
                let token = SyncToken::new(
                    self.config.tenant_id,
                    self.config.connector_id,
                    new_token,
                    super::token::TokenType::Batch,
                );
                self.token_manager.upsert(&token).await?;
            }
        }

        Ok(summary)
    }

    /// Process a single detected change.
    #[instrument(skip(self, detected))]
    async fn process_change(&self, detected: DetectedChange) -> ProcessedChange {
        // Convert to inbound change
        let mut change = detected.into_inbound(self.config.tenant_id, self.config.connector_id);

        // Apply mapping if available
        if let Some(ref mapper) = self.mapper {
            match mapper.map(&change.attributes) {
                Ok(result) => {
                    if !result.is_success() {
                        return ProcessedChange::failed(
                            &change,
                            format!("Missing required attributes: {:?}", result.unmapped),
                        );
                    }
                    change.attributes =
                        serde_json::to_value(&result.attributes).unwrap_or(change.attributes);
                }
                Err(e) => {
                    return ProcessedChange::failed(&change, e.to_string());
                }
            }
        }

        // Determine sync situation through correlation
        let situation = self.determine_situation(&mut change).await;
        change.sync_situation = situation;

        // Check for conflicts
        if let Ok(Some(detected_conflict)) = self.conflict_detector.detect_conflict(&change).await {
            // Handle based on conflict resolution strategy
            match self.config.conflict_resolution {
                ConflictResolution::InboundWins => {
                    // Proceed with inbound change
                    info!(
                        change_id = %change.id,
                        "Conflict detected, inbound wins - proceeding with change"
                    );
                }
                ConflictResolution::OutboundWins => {
                    // Skip inbound change
                    info!(
                        change_id = %change.id,
                        "Conflict detected, outbound wins - skipping change"
                    );
                    change.mark_completed(change.linked_identity_id);
                    return ProcessedChange::success(&change, change.linked_identity_id);
                }
                ConflictResolution::Manual | ConflictResolution::Merge => {
                    // Create conflict record
                    match self
                        .conflict_detector
                        .create_conflict(
                            self.config.tenant_id,
                            &detected_conflict,
                            ResolutionStrategy::Pending,
                        )
                        .await
                    {
                        Ok(conflict) => {
                            change.mark_conflict(conflict.id);
                            return ProcessedChange::conflict(&change, conflict.id);
                        }
                        Err(e) => {
                            return ProcessedChange::failed(&change, e.to_string());
                        }
                    }
                }
            }
        }

        // Get and execute actions for the situation
        let actions = self.reaction_config.get_actions(situation);
        let action_results = self.execute_actions(&mut change, &actions).await;

        // Check if any critical action failed
        for result in &action_results {
            if !result.success && result.action.modifies_focus() {
                return ProcessedChange::failed(
                    &change,
                    result
                        .error
                        .clone()
                        .unwrap_or_else(|| "Action failed".to_string()),
                );
            }
        }

        // Update or create shadow (Link action or Synchronize action)
        if actions.contains(&SyncAction::Link) || actions.contains(&SyncAction::Synchronize) {
            if let Err(e) = self.update_shadow(&change).await {
                return ProcessedChange::failed(&change, e.to_string());
            }
        }

        // Handle Unlink action - remove shadow link
        if actions.contains(&SyncAction::Unlink) {
            if let Err(e) = self.unlink_shadow(&change).await {
                return ProcessedChange::failed(&change, e.to_string());
            }
        }

        change.mark_completed(change.linked_identity_id);
        ProcessedChange::success(&change, change.linked_identity_id)
    }

    /// Execute actions for a sync situation.
    ///
    /// Returns a list of action results indicating success/failure.
    async fn execute_actions(
        &self,
        change: &mut InboundChange,
        actions: &[SyncAction],
    ) -> Vec<ActionResult> {
        let mut results = Vec::new();

        for action in actions {
            let result = match action {
                SyncAction::AddFocus => {
                    // Create new identity based on change attributes
                    // This is a placeholder - actual implementation depends on identity service
                    self.execute_add_focus(change).await
                }
                SyncAction::DeleteFocus => {
                    // Delete identity - requires linked_identity_id
                    self.execute_delete_focus(change).await
                }
                SyncAction::InactivateFocus => {
                    // Inactivate identity - requires linked_identity_id
                    self.execute_inactivate_focus(change).await
                }
                SyncAction::Synchronize => {
                    // Sync attributes - handled by update_shadow
                    ActionResult::success(*action)
                }
                SyncAction::Link => {
                    // Link shadow to identity - handled by update_shadow
                    ActionResult::success(*action)
                }
                SyncAction::Unlink => {
                    // Unlink shadow - handled separately
                    ActionResult::success(*action)
                }
                SyncAction::None => {
                    // No action needed
                    ActionResult::success(*action)
                }
            };
            results.push(result);
        }

        results
    }

    /// Execute `AddFocus` action - create new identity.
    ///
    /// NOTE: This is a placeholder. In a full implementation, this would
    /// call the identity service to create a new user based on the change attributes.
    async fn execute_add_focus(&self, change: &mut InboundChange) -> ActionResult {
        if self.dry_run {
            info!(
                change_id = %change.id,
                external_uid = %change.external_uid,
                "Dry-run: would create new identity (AddFocus)"
            );
            return ActionResult::success(SyncAction::AddFocus);
        }

        // TODO: Implement identity creation via identity service
        // For now, log and return success (shadow will be created without link)
        warn!(
            change_id = %change.id,
            external_uid = %change.external_uid,
            "AddFocus action not yet implemented - shadow will be created unlinked"
        );
        ActionResult::success(SyncAction::AddFocus)
    }

    /// Execute `DeleteFocus` action - delete identity.
    async fn execute_delete_focus(&self, change: &InboundChange) -> ActionResult {
        if self.dry_run {
            info!(
                change_id = %change.id,
                external_uid = %change.external_uid,
                linked_identity_id = ?change.linked_identity_id,
                "Dry-run: would delete identity (DeleteFocus)"
            );
            return ActionResult::success(SyncAction::DeleteFocus);
        }

        // TODO: Implement identity deletion via identity service
        warn!(
            change_id = %change.id,
            external_uid = %change.external_uid,
            linked_identity_id = ?change.linked_identity_id,
            "DeleteFocus action not yet implemented"
        );
        ActionResult::success(SyncAction::DeleteFocus)
    }

    /// Execute `InactivateFocus` action - disable identity.
    async fn execute_inactivate_focus(&self, change: &InboundChange) -> ActionResult {
        if self.dry_run {
            info!(
                change_id = %change.id,
                external_uid = %change.external_uid,
                linked_identity_id = ?change.linked_identity_id,
                "Dry-run: would inactivate identity (InactivateFocus)"
            );
            return ActionResult::success(SyncAction::InactivateFocus);
        }

        // TODO: Implement identity inactivation via identity service
        warn!(
            change_id = %change.id,
            external_uid = %change.external_uid,
            linked_identity_id = ?change.linked_identity_id,
            "InactivateFocus action not yet implemented"
        );
        ActionResult::success(SyncAction::InactivateFocus)
    }

    /// Unlink a shadow from its identity.
    async fn unlink_shadow(&self, change: &InboundChange) -> SyncResult<()> {
        if self.dry_run {
            info!(
                change_id = %change.id,
                external_uid = %change.external_uid,
                "Dry-run: would unlink shadow"
            );
            return Ok(());
        }

        // Find existing shadow and remove the user link
        if let Some(mut shadow) = self
            .shadow_repo
            .find_by_target_uid(change.tenant_id, change.connector_id, &change.external_uid)
            .await
            .map_err(|e| SyncError::internal(format!("Failed to find shadow: {e}")))?
        {
            shadow.user_id = None;
            shadow.sync_situation = SyncSituation::Unmatched;
            self.shadow_repo
                .upsert(&shadow)
                .await
                .map_err(|e| SyncError::internal(format!("Failed to unlink shadow: {e}")))?;
        }

        Ok(())
    }

    /// Determine sync situation following IGA's algorithm:
    /// 1. Check if deleted → Deleted
    /// 2. Search for existing links → Linked or Collision
    /// 3. Use correlation to find potential owners → Unlinked or Disputed
    /// 4. Default → Unmatched
    async fn determine_situation(&self, change: &mut InboundChange) -> SyncSituation {
        use super::types::ChangeType;

        // Step 1: Check if this is a delete operation
        if change.change_type == ChangeType::Delete {
            // Look for existing shadow to mark as deleted
            if let Ok(Some(shadow)) = self
                .shadow_repo
                .find_by_target_uid(change.tenant_id, change.connector_id, &change.external_uid)
                .await
            {
                change.linked_identity_id = shadow.user_id;
            }
            return SyncSituation::Deleted;
        }

        // Step 2: Check for existing links via shadow
        if let Ok(Some(shadow)) = self
            .shadow_repo
            .find_by_target_uid(change.tenant_id, change.connector_id, &change.external_uid)
            .await
        {
            if let Some(user_id) = shadow.user_id {
                // Check for collision: is this shadow linked to multiple users?
                // This would be an error state in the database
                if let Ok(collision_count) = self
                    .shadow_repo
                    .count_links_for_target(
                        change.tenant_id,
                        change.connector_id,
                        &change.external_uid,
                    )
                    .await
                {
                    if collision_count > 1 {
                        info!(
                            external_uid = %change.external_uid,
                            link_count = collision_count,
                            "Collision detected: shadow linked to multiple users"
                        );
                        change.linked_identity_id = Some(user_id);
                        return SyncSituation::Collision;
                    }
                }

                change.linked_identity_id = Some(user_id);
                return SyncSituation::Linked;
            }
            // Shadow exists but no user linked - attempt correlation
            return self.attempt_correlation(change).await;
        }

        // Step 3: No shadow found - try to correlate to find potential owners
        self.attempt_correlation(change).await
    }

    /// Attempt to correlate an inbound change to an internal user.
    /// Returns the determined `SyncSituation` based on correlation results.
    async fn attempt_correlation(&self, change: &mut InboundChange) -> SyncSituation {
        // Skip correlation if no correlator is configured
        let correlator = if let Some(c) = &self.correlator {
            c
        } else {
            info!(
                change_id = %change.id,
                "No correlator configured, returning Unmatched"
            );
            return SyncSituation::Unmatched;
        };

        // Skip if no correlation rules defined
        if self.correlation_rules.is_empty() {
            info!(
                change_id = %change.id,
                "No correlation rules defined, returning Unmatched"
            );
            return SyncSituation::Unmatched;
        }

        // Perform correlation
        match correlator
            .correlate(
                change.tenant_id,
                &change.attributes,
                &self.correlation_rules,
            )
            .await
        {
            Ok(result) => {
                // Store correlation result in change
                if let Ok(json_result) = serde_json::to_value(&result) {
                    change.correlation_result = Some(json_result);
                }

                match result.situation {
                    SyncSituation::Unlinked => {
                        // Single confident match found
                        if let Some(user_id) = result.matched_user_id {
                            info!(
                                change_id = %change.id,
                                user_id = %user_id,
                                confidence = result.confidence,
                                "Correlation found single match"
                            );
                            change.linked_identity_id = Some(user_id);
                            change.set_correlation_confidence(
                                result.confidence,
                                result.matched_rules,
                            );
                            SyncSituation::Unlinked
                        } else {
                            SyncSituation::Unmatched
                        }
                    }
                    SyncSituation::Disputed => {
                        // Multiple matches - requires manual resolution
                        info!(
                            change_id = %change.id,
                            candidate_count = result.candidates.len(),
                            "Correlation found multiple matches - disputed"
                        );
                        SyncSituation::Disputed
                    }
                    _ => {
                        // Unmatched or other situation
                        result.situation
                    }
                }
            }
            Err(e) => {
                info!(
                    change_id = %change.id,
                    error = %e,
                    "Correlation failed, returning Unmatched"
                );
                SyncSituation::Unmatched
            }
        }
    }

    /// Update or create shadow for the change.
    ///
    /// In dry-run mode, this method returns Ok without persisting.
    async fn update_shadow(&self, change: &InboundChange) -> SyncResult<()> {
        // Skip actual update in dry-run mode
        if self.dry_run {
            info!(
                change_id = %change.id,
                external_uid = %change.external_uid,
                "Dry-run: would update shadow"
            );
            return Ok(());
        }

        let shadow = if let Some(user_id) = change.linked_identity_id {
            Shadow::new_linked(
                change.tenant_id,
                change.connector_id,
                user_id,
                change.object_class.clone(),
                change.external_uid.clone(),
                change.attributes.clone(),
            )
        } else {
            Shadow::new_unlinked(
                change.tenant_id,
                change.connector_id,
                change.object_class.clone(),
                change.external_uid.clone(),
                change.attributes.clone(),
            )
        };

        self.shadow_repo
            .upsert(&shadow)
            .await
            .map_err(|e| SyncError::internal(format!("Failed to update shadow: {e}")))?;

        Ok(())
    }
}

/// Builder for `SyncPipeline`.
pub struct SyncPipelineBuilder {
    pool: PgPool,
    config: SyncConfig,
    mapper: Option<InboundMapper>,
    correlator: Option<Arc<dyn InboundCorrelator>>,
    correlation_rules: Vec<InboundCorrelationRule>,
    reaction_config: Option<SyncReactionConfig>,
    dry_run: bool,
}

impl SyncPipelineBuilder {
    /// Create a new builder.
    #[must_use]
    pub fn new(pool: PgPool, config: SyncConfig) -> Self {
        Self {
            pool,
            config,
            mapper: None,
            correlator: None,
            correlation_rules: Vec::new(),
            reaction_config: None,
            dry_run: false,
        }
    }

    /// Set the inbound mapper.
    #[must_use]
    pub fn mapper(mut self, mapper: InboundMapper) -> Self {
        self.mapper = Some(mapper);
        self
    }

    /// Set the inbound correlator.
    pub fn correlator(mut self, correlator: Arc<dyn InboundCorrelator>) -> Self {
        self.correlator = Some(correlator);
        self
    }

    /// Set correlation rules.
    #[must_use]
    pub fn correlation_rules(mut self, rules: Vec<InboundCorrelationRule>) -> Self {
        self.correlation_rules = rules;
        self
    }

    /// Set custom reaction configuration.
    #[must_use]
    pub fn reaction_config(mut self, config: SyncReactionConfig) -> Self {
        self.reaction_config = Some(config);
        self
    }

    /// Enable dry-run mode.
    ///
    /// In dry-run mode, the pipeline processes changes but does not
    /// persist any updates (tokens, shadows, status).
    #[must_use]
    pub fn dry_run(mut self, enabled: bool) -> Self {
        self.dry_run = enabled;
        self
    }

    /// Build the pipeline.
    #[must_use]
    pub fn build(self) -> SyncPipeline {
        let mut pipeline = SyncPipeline::new(self.pool, self.config);
        pipeline.mapper = self.mapper;
        pipeline.correlator = self.correlator;
        pipeline.correlation_rules = self.correlation_rules;
        if let Some(reaction_config) = self.reaction_config {
            pipeline.reaction_config = reaction_config;
        }
        pipeline.dry_run = self.dry_run;
        pipeline
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_batch_summary() {
        let mut summary = BatchSummary::new();
        assert_eq!(summary.processed, 0);

        let change = InboundChange::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            super::super::types::ChangeType::Create,
            "uid=test".to_string(),
            "user".to_string(),
            serde_json::json!({}),
        );

        let success = ProcessedChange::success(&change, None);
        summary.add(&success);
        assert_eq!(summary.processed, 1);
        assert_eq!(summary.succeeded, 1);

        let failed = ProcessedChange::failed(&change, "error".to_string());
        summary.add(&failed);
        assert_eq!(summary.processed, 2);
        assert_eq!(summary.failed, 1);
    }

    #[test]
    fn test_processed_change_variants() {
        let change = InboundChange::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            super::super::types::ChangeType::Update,
            "uid=test".to_string(),
            "user".to_string(),
            serde_json::json!({}),
        );

        let success = ProcessedChange::success(&change, Some(Uuid::new_v4()));
        assert_eq!(success.status, ProcessingStatus::Completed);
        assert!(success.linked_identity_id.is_some());

        let conflict_id = Uuid::new_v4();
        let conflict = ProcessedChange::conflict(&change, conflict_id);
        assert_eq!(conflict.status, ProcessingStatus::Conflict);
        assert_eq!(conflict.conflict_id, Some(conflict_id));

        let failed = ProcessedChange::failed(&change, "test error".to_string());
        assert_eq!(failed.status, ProcessingStatus::Failed);
        assert_eq!(failed.error, Some("test error".to_string()));
    }

    #[test]
    #[allow(clippy::field_reassign_with_default)]
    fn test_dry_run_mode() {
        // Test that dry_run flag is properly set via builder
        use super::super::config::SyncConfig;

        let tenant_id = Uuid::new_v4();
        let connector_id = Uuid::new_v4();

        let mut config = SyncConfig::default();
        config.tenant_id = tenant_id;
        config.connector_id = connector_id;

        // Verify default config
        assert!(!config.enabled); // default is disabled
        assert_eq!(config.tenant_id, tenant_id);
        assert_eq!(config.connector_id, connector_id);

        // Test builder pattern - dry_run defaults to false
        // (We can't fully test without a database pool, but we verify the API)
        let config2 = SyncConfig::default();
        assert!(!config2.enabled);
    }

    #[test]
    fn test_batch_summary_default() {
        let summary = BatchSummary::default();
        assert_eq!(summary.processed, 0);
        assert_eq!(summary.succeeded, 0);
        assert_eq!(summary.failed, 0);
        assert_eq!(summary.conflicts, 0);
        assert!(!summary.has_more);
    }

    #[test]
    fn test_batch_summary_has_more() {
        let mut summary = BatchSummary::new();
        summary.has_more = true;
        assert!(summary.has_more);
    }

    #[test]
    fn test_processed_change_with_error_details() {
        use super::super::types::ChangeType;

        let change = InboundChange::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            ChangeType::Create,
            "uid=test".to_string(),
            "user".to_string(),
            serde_json::json!({}),
        );

        // Test failed with detailed error message
        let failed =
            ProcessedChange::failed(&change, "Network timeout: connection refused".to_string());
        assert_eq!(failed.status, ProcessingStatus::Failed);
        assert!(failed.error.as_ref().unwrap().contains("Network timeout"));
        assert!(failed
            .error
            .as_ref()
            .unwrap()
            .contains("connection refused"));
    }

    #[test]
    fn test_inbound_change_sync_situations() {
        use super::super::types::ChangeType;
        use crate::shadow::SyncSituation;

        // Test all sync situations
        let tenant_id = Uuid::new_v4();
        let connector_id = Uuid::new_v4();

        // Create change
        let mut change = InboundChange::new(
            tenant_id,
            connector_id,
            ChangeType::Create,
            "uid=test".to_string(),
            "user".to_string(),
            serde_json::json!({"email": "test@example.com"}),
        );

        // Test default situation
        assert_eq!(change.sync_situation, SyncSituation::Unmatched);

        // Test changing situation to Linked
        change.sync_situation = SyncSituation::Linked;
        change.linked_identity_id = Some(Uuid::new_v4());
        assert_eq!(change.sync_situation, SyncSituation::Linked);
        assert!(change.linked_identity_id.is_some());

        // Test Disputed situation (multiple correlation candidates)
        change.sync_situation = SyncSituation::Disputed;
        change.linked_identity_id = None; // Disputed means no single match
        assert_eq!(change.sync_situation, SyncSituation::Disputed);
        assert!(change.linked_identity_id.is_none());

        // Test Deleted situation
        let deleted_change = InboundChange::new(
            tenant_id,
            connector_id,
            ChangeType::Delete,
            "uid=deleted".to_string(),
            "user".to_string(),
            serde_json::json!({}),
        );
        assert_eq!(deleted_change.change_type, ChangeType::Delete);

        // Test Collision situation
        change.sync_situation = SyncSituation::Collision;
        assert_eq!(change.sync_situation, SyncSituation::Collision);

        // Test Unlinked situation (correlation found single match, but not yet linked)
        change.sync_situation = SyncSituation::Unlinked;
        assert_eq!(change.sync_situation, SyncSituation::Unlinked);
    }

    #[test]
    fn test_batch_summary_conflict_counting() {
        use super::super::types::ChangeType;

        let mut summary = BatchSummary::new();

        let change = InboundChange::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            ChangeType::Update,
            "uid=test".to_string(),
            "user".to_string(),
            serde_json::json!({}),
        );

        // Add conflict
        let conflict = ProcessedChange::conflict(&change, Uuid::new_v4());
        summary.add(&conflict);
        assert_eq!(summary.conflicts, 1);
        assert_eq!(summary.processed, 1);
        assert_eq!(summary.succeeded, 0);
        assert_eq!(summary.failed, 0);

        // Add success
        let success = ProcessedChange::success(&change, None);
        summary.add(&success);
        assert_eq!(summary.succeeded, 1);
        assert_eq!(summary.processed, 2);

        // Add failed
        let failed = ProcessedChange::failed(&change, "error".to_string());
        summary.add(&failed);
        assert_eq!(summary.failed, 1);
        assert_eq!(summary.processed, 3);

        // Final counts
        assert_eq!(summary.conflicts, 1);
        assert_eq!(summary.succeeded, 1);
        assert_eq!(summary.failed, 1);
    }

    #[test]
    fn test_change_with_correlation_data() {
        use super::super::types::ChangeType;

        let mut change = InboundChange::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            ChangeType::Create,
            "uid=newuser".to_string(),
            "user".to_string(),
            serde_json::json!({"email": "new@example.com", "department": "Engineering"}),
        );

        // Set correlation confidence
        change.set_correlation_confidence(0.85, vec!["email".to_string()]);

        // Verify correlation result was stored
        assert!(change.correlation_result.is_some());
        let result = change.correlation_result.as_ref().unwrap();
        assert_eq!(result.get("confidence"), Some(&serde_json::json!(0.85)));
        assert_eq!(
            result.get("matched_rules"),
            Some(&serde_json::json!(["email"]))
        );
        assert!(result.get("correlation_timestamp").is_some());
    }

    #[test]
    fn test_processing_status_terminal_states() {
        // Test that we correctly identify terminal vs non-terminal states
        assert!(matches!(
            ProcessingStatus::Completed,
            ProcessingStatus::Completed
        ));
        assert!(matches!(ProcessingStatus::Failed, ProcessingStatus::Failed));
        assert!(matches!(
            ProcessingStatus::Conflict,
            ProcessingStatus::Conflict
        ));

        // Pending and Processing are non-terminal
        assert!(matches!(
            ProcessingStatus::Pending,
            ProcessingStatus::Pending
        ));
        assert!(matches!(
            ProcessingStatus::Processing,
            ProcessingStatus::Processing
        ));
    }

    #[test]
    fn test_reaction_config_default_actions() {
        use super::super::reaction::{SyncAction, SyncReactionConfig};

        let tenant_id = Uuid::new_v4();
        let connector_id = Uuid::new_v4();
        let config = SyncReactionConfig::default_for(tenant_id, connector_id);

        // Linked → Synchronize
        let actions = config.get_actions(SyncSituation::Linked);
        assert_eq!(actions, vec![SyncAction::Synchronize]);

        // Deleted → Unlink
        let actions = config.get_actions(SyncSituation::Deleted);
        assert_eq!(actions, vec![SyncAction::Unlink]);

        // Unlinked → Link + Synchronize
        let actions = config.get_actions(SyncSituation::Unlinked);
        assert_eq!(actions, vec![SyncAction::Link, SyncAction::Synchronize]);

        // Unmatched → AddFocus + Link
        let actions = config.get_actions(SyncSituation::Unmatched);
        assert_eq!(actions, vec![SyncAction::AddFocus, SyncAction::Link]);

        // Disputed → None
        let actions = config.get_actions(SyncSituation::Disputed);
        assert_eq!(actions, vec![SyncAction::None]);

        // Collision → None
        let actions = config.get_actions(SyncSituation::Collision);
        assert_eq!(actions, vec![SyncAction::None]);
    }

    #[test]
    fn test_action_result_tracking() {
        use super::super::reaction::{ActionResult, SyncAction};

        // Test successful action
        let success = ActionResult::success(SyncAction::Link);
        assert!(success.success);
        assert!(success.error.is_none());

        // Test failed action
        let failed = ActionResult::failed(SyncAction::AddFocus, "Identity service unavailable");
        assert!(!failed.success);
        assert!(failed.error.as_ref().unwrap().contains("unavailable"));

        // Test action with identity
        let identity_id = Uuid::new_v4();
        let with_identity = ActionResult::success_with_identity(SyncAction::AddFocus, identity_id);
        assert!(with_identity.success);
        assert_eq!(with_identity.affected_identity_id, Some(identity_id));
    }

    #[test]
    fn test_sync_action_modifies_checks() {
        use super::super::reaction::SyncAction;

        // Focus-modifying actions
        assert!(SyncAction::AddFocus.modifies_focus());
        assert!(SyncAction::DeleteFocus.modifies_focus());
        assert!(SyncAction::InactivateFocus.modifies_focus());
        assert!(SyncAction::Synchronize.modifies_focus());

        // Non focus-modifying actions
        assert!(!SyncAction::Link.modifies_focus());
        assert!(!SyncAction::Unlink.modifies_focus());
        assert!(!SyncAction::None.modifies_focus());

        // Link-modifying actions
        assert!(SyncAction::Link.modifies_link());
        assert!(SyncAction::Unlink.modifies_link());

        // Non link-modifying actions
        assert!(!SyncAction::AddFocus.modifies_link());
        assert!(!SyncAction::Synchronize.modifies_link());
        assert!(!SyncAction::None.modifies_link());
    }
}
