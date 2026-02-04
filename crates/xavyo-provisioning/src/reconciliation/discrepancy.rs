//! Discrepancy detection for reconciliation.
//!
//! Detects differences between xavyo and target systems during reconciliation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::comparator::{CorrelationMatch, MismatchedAttributes};
use super::types::{ActionType, DiscrepancyType, ResolutionStatus};

/// Information about a detected discrepancy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscrepancyInfo {
    /// Unique identifier.
    pub id: Uuid,
    /// Reconciliation run ID.
    pub run_id: Uuid,
    /// Tenant ID.
    pub tenant_id: Uuid,
    /// Type of discrepancy.
    pub discrepancy_type: DiscrepancyType,
    /// Associated identity ID (if known).
    pub identity_id: Option<Uuid>,
    /// Identity display name (for display purposes).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_display_name: Option<String>,
    /// External account UID.
    pub external_uid: String,
    /// Mismatched attributes (for mismatch type).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mismatched_attributes: Option<MismatchedAttributes>,
    /// Resolution status.
    pub resolution_status: ResolutionStatus,
    /// Action that resolved the discrepancy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_action: Option<ActionType>,
    /// User who resolved.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_by: Option<Uuid>,
    /// Resolved user name (for display).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_by_name: Option<String>,
    /// When resolved.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_at: Option<DateTime<Utc>>,
    /// When detected.
    pub detected_at: DateTime<Utc>,
    /// Suggested remediation actions.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub suggested_actions: Vec<ActionType>,
}

impl DiscrepancyInfo {
    /// Create a new discrepancy info.
    #[must_use] 
    pub fn new(
        run_id: Uuid,
        tenant_id: Uuid,
        discrepancy_type: DiscrepancyType,
        external_uid: String,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            run_id,
            tenant_id,
            discrepancy_type,
            identity_id: None,
            identity_display_name: None,
            external_uid,
            mismatched_attributes: None,
            resolution_status: ResolutionStatus::Pending,
            resolved_action: None,
            resolved_by: None,
            resolved_by_name: None,
            resolved_at: None,
            detected_at: Utc::now(),
            suggested_actions: discrepancy_type.suggested_actions(),
        }
    }

    /// Set identity ID.
    #[must_use] 
    pub fn with_identity(mut self, identity_id: Uuid) -> Self {
        self.identity_id = Some(identity_id);
        self
    }

    /// Set identity display name.
    #[must_use] 
    pub fn with_identity_name(mut self, name: String) -> Self {
        self.identity_display_name = Some(name);
        self
    }

    /// Set mismatched attributes.
    #[must_use] 
    pub fn with_mismatches(mut self, mismatches: MismatchedAttributes) -> Self {
        self.mismatched_attributes = Some(mismatches);
        self
    }

    /// Check if this discrepancy is pending.
    #[must_use] 
    pub fn is_pending(&self) -> bool {
        self.resolution_status == ResolutionStatus::Pending
    }

    /// Check if this discrepancy is resolved.
    #[must_use] 
    pub fn is_resolved(&self) -> bool {
        self.resolution_status == ResolutionStatus::Resolved
    }

    /// Check if this discrepancy is ignored.
    #[must_use] 
    pub fn is_ignored(&self) -> bool {
        self.resolution_status == ResolutionStatus::Ignored
    }

    /// Mark as resolved.
    pub fn mark_resolved(&mut self, action: ActionType, resolved_by: Uuid) {
        self.resolution_status = ResolutionStatus::Resolved;
        self.resolved_action = Some(action);
        self.resolved_by = Some(resolved_by);
        self.resolved_at = Some(Utc::now());
    }

    /// Mark as ignored.
    pub fn mark_ignored(&mut self, by: Uuid) {
        self.resolution_status = ResolutionStatus::Ignored;
        self.resolved_by = Some(by);
        self.resolved_at = Some(Utc::now());
    }
}

/// Detector for identifying discrepancies during reconciliation.
pub struct DiscrepancyDetector {
    /// Tenant ID.
    tenant_id: Uuid,
    /// Run ID.
    run_id: Uuid,
}

impl DiscrepancyDetector {
    /// Create a new discrepancy detector.
    #[must_use] 
    pub fn new(tenant_id: Uuid, run_id: Uuid) -> Self {
        Self { tenant_id, run_id }
    }

    /// Detect missing discrepancy (identity exists, no account).
    #[must_use] 
    pub fn detect_missing(&self, identity_id: Uuid, external_uid: String) -> DiscrepancyInfo {
        DiscrepancyInfo::new(
            self.run_id,
            self.tenant_id,
            DiscrepancyType::Missing,
            external_uid,
        )
        .with_identity(identity_id)
    }

    /// Detect orphan discrepancy (account exists, no identity).
    #[must_use] 
    pub fn detect_orphan(&self, external_uid: String) -> DiscrepancyInfo {
        DiscrepancyInfo::new(
            self.run_id,
            self.tenant_id,
            DiscrepancyType::Orphan,
            external_uid,
        )
    }

    /// Detect mismatch discrepancy (linked but attributes differ).
    #[must_use] 
    pub fn detect_mismatch(
        &self,
        identity_id: Uuid,
        external_uid: String,
        mismatches: MismatchedAttributes,
    ) -> DiscrepancyInfo {
        DiscrepancyInfo::new(
            self.run_id,
            self.tenant_id,
            DiscrepancyType::Mismatch,
            external_uid,
        )
        .with_identity(identity_id)
        .with_mismatches(mismatches)
    }

    /// Detect collision discrepancy (multiple identities match one account).
    #[must_use] 
    pub fn detect_collision(
        &self,
        external_uid: String,
        matches: Vec<CorrelationMatch>,
    ) -> DiscrepancyInfo {
        // For collision, we don't set a single identity_id since multiple match
        let mut discrepancy = DiscrepancyInfo::new(
            self.run_id,
            self.tenant_id,
            DiscrepancyType::Collision,
            external_uid,
        );

        // Store collision details in mismatched_attributes as JSON
        if !matches.is_empty() {
            let mut attrs = MismatchedAttributes::new();
            for (i, m) in matches.iter().enumerate() {
                attrs.add(
                    format!("collision_match_{i}"),
                    Some(m.identity_id.to_string()),
                    Some(format!("confidence: {:.2}", m.confidence)),
                );
            }
            discrepancy = discrepancy.with_mismatches(attrs);
        }

        discrepancy
    }

    /// Detect unlinked discrepancy (account exists, owner found, no shadow).
    #[must_use] 
    pub fn detect_unlinked(&self, identity_id: Uuid, external_uid: String) -> DiscrepancyInfo {
        DiscrepancyInfo::new(
            self.run_id,
            self.tenant_id,
            DiscrepancyType::Unlinked,
            external_uid,
        )
        .with_identity(identity_id)
    }

    /// Detect deleted discrepancy (shadow exists, account removed).
    #[must_use] 
    pub fn detect_deleted(&self, identity_id: Uuid, external_uid: String) -> DiscrepancyInfo {
        DiscrepancyInfo::new(
            self.run_id,
            self.tenant_id,
            DiscrepancyType::Deleted,
            external_uid,
        )
        .with_identity(identity_id)
    }
}

/// Filter for querying discrepancies.
#[derive(Debug, Clone, Default)]
pub struct DiscrepancyFilter {
    /// Filter by run ID.
    pub run_id: Option<Uuid>,
    /// Filter by discrepancy type.
    pub discrepancy_type: Option<DiscrepancyType>,
    /// Filter by resolution status.
    pub resolution_status: Option<ResolutionStatus>,
    /// Filter by identity ID.
    pub identity_id: Option<Uuid>,
    /// Filter by external UID (partial match).
    pub external_uid: Option<String>,
}

impl DiscrepancyFilter {
    /// Create a new filter.
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Filter by run.
    #[must_use] 
    pub fn for_run(mut self, run_id: Uuid) -> Self {
        self.run_id = Some(run_id);
        self
    }

    /// Filter by type.
    #[must_use] 
    pub fn with_type(mut self, discrepancy_type: DiscrepancyType) -> Self {
        self.discrepancy_type = Some(discrepancy_type);
        self
    }

    /// Filter by status.
    #[must_use] 
    pub fn with_status(mut self, status: ResolutionStatus) -> Self {
        self.resolution_status = Some(status);
        self
    }

    /// Filter pending only.
    #[must_use] 
    pub fn pending_only(self) -> Self {
        self.with_status(ResolutionStatus::Pending)
    }

    /// Filter by identity.
    #[must_use] 
    pub fn for_identity(mut self, identity_id: Uuid) -> Self {
        self.identity_id = Some(identity_id);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discrepancy_info_new() {
        let run_id = Uuid::new_v4();
        let tenant_id = Uuid::new_v4();
        let info = DiscrepancyInfo::new(
            run_id,
            tenant_id,
            DiscrepancyType::Orphan,
            "uid=test".to_string(),
        );

        assert_eq!(info.run_id, run_id);
        assert_eq!(info.tenant_id, tenant_id);
        assert_eq!(info.discrepancy_type, DiscrepancyType::Orphan);
        assert_eq!(info.external_uid, "uid=test");
        assert!(info.identity_id.is_none());
        assert!(info.is_pending());
        assert!(!info.suggested_actions.is_empty());
    }

    #[test]
    fn test_discrepancy_info_with_identity() {
        let identity_id = Uuid::new_v4();
        let info = DiscrepancyInfo::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            DiscrepancyType::Missing,
            "uid=test".to_string(),
        )
        .with_identity(identity_id)
        .with_identity_name("John Doe".to_string());

        assert_eq!(info.identity_id, Some(identity_id));
        assert_eq!(info.identity_display_name, Some("John Doe".to_string()));
    }

    #[test]
    fn test_discrepancy_info_mark_resolved() {
        let mut info = DiscrepancyInfo::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            DiscrepancyType::Missing,
            "uid=test".to_string(),
        );
        let resolver = Uuid::new_v4();

        assert!(info.is_pending());
        info.mark_resolved(ActionType::Create, resolver);

        assert!(info.is_resolved());
        assert!(!info.is_pending());
        assert_eq!(info.resolved_action, Some(ActionType::Create));
        assert_eq!(info.resolved_by, Some(resolver));
        assert!(info.resolved_at.is_some());
    }

    #[test]
    fn test_discrepancy_info_mark_ignored() {
        let mut info = DiscrepancyInfo::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            DiscrepancyType::Orphan,
            "uid=test".to_string(),
        );
        let ignorer = Uuid::new_v4();

        info.mark_ignored(ignorer);

        assert!(info.is_ignored());
        assert!(!info.is_pending());
        assert!(info.resolved_action.is_none());
        assert_eq!(info.resolved_by, Some(ignorer));
    }

    #[test]
    fn test_discrepancy_detector_missing() {
        let tenant_id = Uuid::new_v4();
        let run_id = Uuid::new_v4();
        let identity_id = Uuid::new_v4();
        let detector = DiscrepancyDetector::new(tenant_id, run_id);

        let discrepancy = detector.detect_missing(identity_id, "uid=test".to_string());

        assert_eq!(discrepancy.discrepancy_type, DiscrepancyType::Missing);
        assert_eq!(discrepancy.identity_id, Some(identity_id));
        assert_eq!(discrepancy.tenant_id, tenant_id);
        assert_eq!(discrepancy.run_id, run_id);
    }

    #[test]
    fn test_discrepancy_detector_orphan() {
        let detector = DiscrepancyDetector::new(Uuid::new_v4(), Uuid::new_v4());
        let discrepancy = detector.detect_orphan("uid=orphan".to_string());

        assert_eq!(discrepancy.discrepancy_type, DiscrepancyType::Orphan);
        assert!(discrepancy.identity_id.is_none());
    }

    #[test]
    fn test_discrepancy_detector_mismatch() {
        let detector = DiscrepancyDetector::new(Uuid::new_v4(), Uuid::new_v4());
        let identity_id = Uuid::new_v4();
        let mut mismatches = MismatchedAttributes::new();
        mismatches.add(
            "email".to_string(),
            Some("john@company.com".to_string()),
            Some("jdoe@company.com".to_string()),
        );

        let discrepancy = detector.detect_mismatch(identity_id, "uid=test".to_string(), mismatches);

        assert_eq!(discrepancy.discrepancy_type, DiscrepancyType::Mismatch);
        assert_eq!(discrepancy.identity_id, Some(identity_id));
        assert!(discrepancy.mismatched_attributes.is_some());
    }

    #[test]
    fn test_discrepancy_detector_collision() {
        let detector = DiscrepancyDetector::new(Uuid::new_v4(), Uuid::new_v4());
        let matches = vec![
            CorrelationMatch {
                identity_id: Uuid::new_v4(),
                confidence: 0.9,
                matched_rules: vec!["email".to_string()],
            },
            CorrelationMatch {
                identity_id: Uuid::new_v4(),
                confidence: 0.85,
                matched_rules: vec!["email".to_string()],
            },
        ];

        let discrepancy = detector.detect_collision("uid=collision".to_string(), matches);

        assert_eq!(discrepancy.discrepancy_type, DiscrepancyType::Collision);
        assert!(discrepancy.identity_id.is_none()); // No single identity for collision
        assert!(discrepancy.mismatched_attributes.is_some()); // Contains collision info
    }

    #[test]
    fn test_discrepancy_filter() {
        let run_id = Uuid::new_v4();
        let filter = DiscrepancyFilter::new()
            .for_run(run_id)
            .with_type(DiscrepancyType::Orphan)
            .pending_only();

        assert_eq!(filter.run_id, Some(run_id));
        assert_eq!(filter.discrepancy_type, Some(DiscrepancyType::Orphan));
        assert_eq!(filter.resolution_status, Some(ResolutionStatus::Pending));
    }
}
