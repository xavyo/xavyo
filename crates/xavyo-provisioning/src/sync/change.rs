//! Inbound change tracking.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::types::{ChangeType, ProcessingStatus};
use crate::shadow::SyncSituation;

/// An inbound change detected from an external system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundChange {
    /// Unique ID for this change.
    pub id: Uuid,
    /// Tenant ID.
    pub tenant_id: Uuid,
    /// Connector that detected the change.
    pub connector_id: Uuid,
    /// Type of change (create/update/delete).
    pub change_type: ChangeType,
    /// External system's unique identifier for the object.
    pub external_uid: String,
    /// Object class in the external system.
    pub object_class: String,
    /// Attributes from the external system.
    pub attributes: serde_json::Value,
    /// Synchronization situation.
    pub sync_situation: SyncSituation,
    /// Correlation result (if correlation was performed).
    pub correlation_result: Option<serde_json::Value>,
    /// Linked identity ID (if situation is Linked).
    pub linked_identity_id: Option<Uuid>,
    /// Conflict ID (if a conflict was created).
    pub conflict_id: Option<Uuid>,
    /// Processing status.
    pub processing_status: ProcessingStatus,
    /// Error message if processing failed.
    pub error_message: Option<String>,
    /// When the change was processed.
    pub processed_at: Option<DateTime<Utc>>,
    /// When the change was detected.
    pub created_at: DateTime<Utc>,
}

impl InboundChange {
    /// Create a new inbound change.
    pub fn new(
        tenant_id: Uuid,
        connector_id: Uuid,
        change_type: ChangeType,
        external_uid: String,
        object_class: String,
        attributes: serde_json::Value,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            tenant_id,
            connector_id,
            change_type,
            external_uid,
            object_class,
            attributes,
            sync_situation: SyncSituation::Unmatched,
            correlation_result: None,
            linked_identity_id: None,
            conflict_id: None,
            processing_status: ProcessingStatus::Pending,
            error_message: None,
            processed_at: None,
            created_at: Utc::now(),
        }
    }

    /// Create a builder for more complex construction.
    pub fn builder(
        tenant_id: Uuid,
        connector_id: Uuid,
        change_type: ChangeType,
        external_uid: String,
        object_class: String,
    ) -> InboundChangeBuilder {
        InboundChangeBuilder::new(
            tenant_id,
            connector_id,
            change_type,
            external_uid,
            object_class,
        )
    }

    /// Check if this change is pending processing.
    pub fn is_pending(&self) -> bool {
        self.processing_status == ProcessingStatus::Pending
    }

    /// Check if this change has been processed.
    pub fn is_processed(&self) -> bool {
        self.processing_status.is_terminal()
    }

    /// Check if this change has a conflict.
    pub fn has_conflict(&self) -> bool {
        self.conflict_id.is_some()
    }

    /// Check if this change is linked to an identity.
    pub fn is_linked(&self) -> bool {
        self.linked_identity_id.is_some() && self.sync_situation == SyncSituation::Linked
    }

    /// Mark as processing.
    pub fn mark_processing(&mut self) {
        self.processing_status = ProcessingStatus::Processing;
    }

    /// Mark as completed with optional linked identity.
    pub fn mark_completed(&mut self, linked_identity_id: Option<Uuid>) {
        self.processing_status = ProcessingStatus::Completed;
        self.processed_at = Some(Utc::now());
        if let Some(id) = linked_identity_id {
            self.linked_identity_id = Some(id);
            self.sync_situation = SyncSituation::Linked;
        }
    }

    /// Mark as failed with error message.
    pub fn mark_failed(&mut self, error: String) {
        self.processing_status = ProcessingStatus::Failed;
        self.error_message = Some(error);
        self.processed_at = Some(Utc::now());
    }

    /// Mark as conflict.
    pub fn mark_conflict(&mut self, conflict_id: Uuid) {
        self.processing_status = ProcessingStatus::Conflict;
        self.conflict_id = Some(conflict_id);
    }

    /// Update the sync situation with correlation result.
    pub fn update_situation(
        &mut self,
        situation: SyncSituation,
        linked_identity_id: Option<Uuid>,
        correlation_result: Option<serde_json::Value>,
    ) {
        self.sync_situation = situation;
        self.linked_identity_id = linked_identity_id;
        self.correlation_result = correlation_result;
    }

    /// Set correlation confidence from inbound correlation.
    pub fn set_correlation_confidence(&mut self, confidence: f64, matched_rules: Vec<String>) {
        self.correlation_result = Some(serde_json::json!({
            "confidence": confidence,
            "matched_rules": matched_rules,
            "correlation_timestamp": Utc::now().to_rfc3339()
        }));
    }
}

/// Inbound correlation result after matching external change to internal users.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundCorrelationResult {
    /// Matched user ID (if single match found).
    pub matched_user_id: Option<Uuid>,
    /// All candidate matches with confidence scores.
    pub candidates: Vec<InboundCorrelationCandidate>,
    /// Determined sync situation based on correlation.
    pub situation: SyncSituation,
    /// Overall confidence of the match.
    pub confidence: f64,
    /// Rules that contributed to the match.
    pub matched_rules: Vec<String>,
}

impl InboundCorrelationResult {
    /// Create result with no matches (Unmatched situation).
    pub fn unmatched() -> Self {
        Self {
            matched_user_id: None,
            candidates: Vec::new(),
            situation: SyncSituation::Unmatched,
            confidence: 0.0,
            matched_rules: Vec::new(),
        }
    }

    /// Create result with single confident match (Unlinked - ready to auto-link).
    pub fn single_match(user_id: Uuid, confidence: f64, matched_rules: Vec<String>) -> Self {
        Self {
            matched_user_id: Some(user_id),
            candidates: vec![InboundCorrelationCandidate {
                user_id,
                confidence,
                matched_rules: matched_rules.clone(),
            }],
            situation: SyncSituation::Unlinked,
            confidence,
            matched_rules,
        }
    }

    /// Create result with multiple matches (Disputed situation).
    pub fn disputed(candidates: Vec<InboundCorrelationCandidate>) -> Self {
        let highest_confidence = candidates.first().map(|c| c.confidence).unwrap_or(0.0);
        Self {
            matched_user_id: None,
            candidates,
            situation: SyncSituation::Disputed,
            confidence: highest_confidence,
            matched_rules: Vec::new(),
        }
    }

    /// Check if correlation found a confident single match.
    pub fn has_confident_match(&self) -> bool {
        self.matched_user_id.is_some() && self.confidence >= 0.8
    }
}

/// A candidate user match from inbound correlation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundCorrelationCandidate {
    /// User ID in xavyo.
    pub user_id: Uuid,
    /// Confidence score (0.0 to 1.0).
    pub confidence: f64,
    /// Which correlation rules matched.
    pub matched_rules: Vec<String>,
}

/// Builder for inbound changes.
#[derive(Debug)]
pub struct InboundChangeBuilder {
    tenant_id: Uuid,
    connector_id: Uuid,
    change_type: ChangeType,
    external_uid: String,
    object_class: String,
    attributes: serde_json::Value,
    sync_situation: SyncSituation,
    linked_identity_id: Option<Uuid>,
    correlation_result: Option<serde_json::Value>,
}

impl InboundChangeBuilder {
    /// Create a new builder.
    pub fn new(
        tenant_id: Uuid,
        connector_id: Uuid,
        change_type: ChangeType,
        external_uid: String,
        object_class: String,
    ) -> Self {
        Self {
            tenant_id,
            connector_id,
            change_type,
            external_uid,
            object_class,
            attributes: serde_json::json!({}),
            sync_situation: SyncSituation::Unmatched,
            linked_identity_id: None,
            correlation_result: None,
        }
    }

    /// Set attributes.
    pub fn attributes(mut self, attributes: serde_json::Value) -> Self {
        self.attributes = attributes;
        self
    }

    /// Set sync situation.
    pub fn situation(mut self, situation: SyncSituation) -> Self {
        self.sync_situation = situation;
        self
    }

    /// Set linked identity.
    pub fn linked_identity(mut self, identity_id: Uuid) -> Self {
        self.linked_identity_id = Some(identity_id);
        self.sync_situation = SyncSituation::Linked;
        self
    }

    /// Set correlation result.
    pub fn correlation_result(mut self, result: serde_json::Value) -> Self {
        self.correlation_result = Some(result);
        self
    }

    /// Build the inbound change.
    pub fn build(self) -> InboundChange {
        InboundChange {
            id: Uuid::new_v4(),
            tenant_id: self.tenant_id,
            connector_id: self.connector_id,
            change_type: self.change_type,
            external_uid: self.external_uid,
            object_class: self.object_class,
            attributes: self.attributes,
            sync_situation: self.sync_situation,
            correlation_result: self.correlation_result,
            linked_identity_id: self.linked_identity_id,
            conflict_id: None,
            processing_status: ProcessingStatus::Pending,
            error_message: None,
            processed_at: None,
            created_at: Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inbound_change_new() {
        let tenant_id = Uuid::new_v4();
        let connector_id = Uuid::new_v4();

        let change = InboundChange::new(
            tenant_id,
            connector_id,
            ChangeType::Create,
            "uid=john".to_string(),
            "inetOrgPerson".to_string(),
            serde_json::json!({"cn": "John Doe"}),
        );

        assert_eq!(change.tenant_id, tenant_id);
        assert_eq!(change.connector_id, connector_id);
        assert_eq!(change.change_type, ChangeType::Create);
        assert!(change.is_pending());
        assert!(!change.is_processed());
    }

    #[test]
    fn test_inbound_change_builder() {
        let tenant_id = Uuid::new_v4();
        let connector_id = Uuid::new_v4();
        let identity_id = Uuid::new_v4();

        let change = InboundChange::builder(
            tenant_id,
            connector_id,
            ChangeType::Update,
            "uid=jane".to_string(),
            "user".to_string(),
        )
        .attributes(serde_json::json!({"email": "jane@example.com"}))
        .linked_identity(identity_id)
        .build();

        assert_eq!(change.sync_situation, SyncSituation::Linked);
        assert_eq!(change.linked_identity_id, Some(identity_id));
        assert!(change.is_linked());
    }

    #[test]
    fn test_change_lifecycle() {
        let mut change = InboundChange::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            ChangeType::Update,
            "uid=test".to_string(),
            "user".to_string(),
            serde_json::json!({}),
        );

        assert!(change.is_pending());

        change.mark_processing();
        assert_eq!(change.processing_status, ProcessingStatus::Processing);

        let identity_id = Uuid::new_v4();
        change.mark_completed(Some(identity_id));
        assert!(change.is_processed());
        assert!(change.is_linked());
        assert!(change.processed_at.is_some());
    }

    #[test]
    fn test_change_failure() {
        let mut change = InboundChange::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            ChangeType::Delete,
            "uid=test".to_string(),
            "user".to_string(),
            serde_json::json!({}),
        );

        change.mark_failed("Connection timeout".to_string());
        assert_eq!(change.processing_status, ProcessingStatus::Failed);
        assert_eq!(change.error_message, Some("Connection timeout".to_string()));
    }

    #[test]
    fn test_change_conflict() {
        let mut change = InboundChange::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            ChangeType::Update,
            "uid=test".to_string(),
            "user".to_string(),
            serde_json::json!({}),
        );

        let conflict_id = Uuid::new_v4();
        change.mark_conflict(conflict_id);
        assert!(change.has_conflict());
        assert_eq!(change.conflict_id, Some(conflict_id));
    }
}
