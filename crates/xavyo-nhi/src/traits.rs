//! Core trait for Non-Human Identity abstraction.

use crate::types::{NhiStatus, NhiType};
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Common trait for all non-human identities.
///
/// This trait defines the unified interface for governance operations
/// across different NHI types (service accounts, AI agents, etc.).
///
/// # Implementing Types
///
/// - `GovServiceAccount` - Traditional service accounts (F061)
/// - `AiAgent` - AI/ML agents (F089-F094)
///
/// # Example
///
/// ```ignore
/// use xavyo_nhi::{NonHumanIdentity, NhiType, NhiStatus};
///
/// fn audit_nhi<T: NonHumanIdentity>(nhi: &T) {
///     println!(
///         "NHI {} ({}) owned by {} has risk score {}",
///         nhi.name(),
///         nhi.nhi_type(),
///         nhi.owner_id(),
///         nhi.risk_score()
///     );
/// }
/// ```
pub trait NonHumanIdentity: Send + Sync {
    // --- Core Identity ---

    /// Unique identifier for this NHI.
    fn id(&self) -> Uuid;

    /// Tenant this identity belongs to.
    fn tenant_id(&self) -> Uuid;

    /// Display name for this NHI.
    fn name(&self) -> &str;

    /// Optional description or purpose statement.
    fn description(&self) -> Option<&str>;

    /// Type discriminator for this NHI.
    fn nhi_type(&self) -> NhiType;

    // --- Ownership ---

    /// Primary owner responsible for this NHI.
    fn owner_id(&self) -> Uuid;

    /// Backup owner for succession planning.
    ///
    /// If the primary owner becomes unavailable, the backup owner
    /// can be promoted to maintain governance continuity.
    fn backup_owner_id(&self) -> Option<Uuid>;

    // --- Lifecycle ---

    /// Current status of this NHI.
    fn status(&self) -> NhiStatus;

    /// When this NHI was created.
    fn created_at(&self) -> DateTime<Utc>;

    /// When this NHI expires, if set.
    ///
    /// After expiration, the NHI should be suspended and require
    /// re-certification or extension.
    fn expires_at(&self) -> Option<DateTime<Utc>>;

    /// Last time this NHI was used/accessed.
    ///
    /// Used for staleness detection and inactivity-based suspension.
    fn last_activity_at(&self) -> Option<DateTime<Utc>>;

    // --- Governance ---

    /// Unified risk score (0-100).
    ///
    /// Higher scores indicate higher risk. Scores are normalized
    /// from type-specific algorithms:
    /// - Service accounts: staleness (40) + credential age (30) + scope (30)
    /// - AI agents: mapped from risk_level enum or computed score
    fn risk_score(&self) -> u32;

    /// When the next certification is due.
    fn next_certification_at(&self) -> Option<DateTime<Utc>>;

    /// When this NHI was last certified.
    fn last_certified_at(&self) -> Option<DateTime<Utc>>;

    // --- Derived Methods ---

    /// Returns true if this NHI is currently active and usable.
    fn is_active(&self) -> bool {
        self.status().is_usable()
    }

    /// Returns true if this NHI is expired.
    fn is_expired(&self) -> bool {
        if let Some(expires) = self.expires_at() {
            expires < Utc::now()
        } else {
            false
        }
    }

    /// Returns true if this NHI requires certification review.
    fn needs_certification(&self) -> bool {
        if let Some(due) = self.next_certification_at() {
            due <= Utc::now()
        } else {
            false
        }
    }

    /// Returns true if this NHI is considered stale (no activity in threshold days).
    fn is_stale(&self, threshold_days: i64) -> bool {
        if let Some(last_activity) = self.last_activity_at() {
            let threshold = Utc::now() - chrono::Duration::days(threshold_days);
            last_activity < threshold
        } else {
            // No activity recorded = considered stale
            true
        }
    }

    /// Returns the risk level based on the risk score.
    fn risk_level(&self) -> crate::types::NhiRiskLevel {
        crate::types::NhiRiskLevel::from(self.risk_score())
    }
}

/// Extension trait for boxed NHI objects.
///
/// Allows calling trait methods on `Box<dyn NonHumanIdentity>`.
impl NonHumanIdentity for Box<dyn NonHumanIdentity> {
    fn id(&self) -> Uuid {
        (**self).id()
    }

    fn tenant_id(&self) -> Uuid {
        (**self).tenant_id()
    }

    fn name(&self) -> &str {
        (**self).name()
    }

    fn description(&self) -> Option<&str> {
        (**self).description()
    }

    fn nhi_type(&self) -> NhiType {
        (**self).nhi_type()
    }

    fn owner_id(&self) -> Uuid {
        (**self).owner_id()
    }

    fn backup_owner_id(&self) -> Option<Uuid> {
        (**self).backup_owner_id()
    }

    fn status(&self) -> NhiStatus {
        (**self).status()
    }

    fn created_at(&self) -> DateTime<Utc> {
        (**self).created_at()
    }

    fn expires_at(&self) -> Option<DateTime<Utc>> {
        (**self).expires_at()
    }

    fn last_activity_at(&self) -> Option<DateTime<Utc>> {
        (**self).last_activity_at()
    }

    fn risk_score(&self) -> u32 {
        (**self).risk_score()
    }

    fn next_certification_at(&self) -> Option<DateTime<Utc>> {
        (**self).next_certification_at()
    }

    fn last_certified_at(&self) -> Option<DateTime<Utc>> {
        (**self).last_certified_at()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test implementation of NonHumanIdentity for unit tests.
    struct MockNhi {
        id: Uuid,
        tenant_id: Uuid,
        name: String,
        description: Option<String>,
        nhi_type: NhiType,
        owner_id: Uuid,
        backup_owner_id: Option<Uuid>,
        status: NhiStatus,
        created_at: DateTime<Utc>,
        expires_at: Option<DateTime<Utc>>,
        last_activity_at: Option<DateTime<Utc>>,
        risk_score: u32,
        next_certification_at: Option<DateTime<Utc>>,
        last_certified_at: Option<DateTime<Utc>>,
    }

    impl Default for MockNhi {
        fn default() -> Self {
            Self {
                id: Uuid::new_v4(),
                tenant_id: Uuid::new_v4(),
                name: "test-nhi".to_string(),
                description: None,
                nhi_type: NhiType::ServiceAccount,
                owner_id: Uuid::new_v4(),
                backup_owner_id: None,
                status: NhiStatus::Active,
                created_at: Utc::now(),
                expires_at: None,
                last_activity_at: Some(Utc::now()),
                risk_score: 25,
                next_certification_at: None,
                last_certified_at: None,
            }
        }
    }

    impl NonHumanIdentity for MockNhi {
        fn id(&self) -> Uuid {
            self.id
        }
        fn tenant_id(&self) -> Uuid {
            self.tenant_id
        }
        fn name(&self) -> &str {
            &self.name
        }
        fn description(&self) -> Option<&str> {
            self.description.as_deref()
        }
        fn nhi_type(&self) -> NhiType {
            self.nhi_type
        }
        fn owner_id(&self) -> Uuid {
            self.owner_id
        }
        fn backup_owner_id(&self) -> Option<Uuid> {
            self.backup_owner_id
        }
        fn status(&self) -> NhiStatus {
            self.status
        }
        fn created_at(&self) -> DateTime<Utc> {
            self.created_at
        }
        fn expires_at(&self) -> Option<DateTime<Utc>> {
            self.expires_at
        }
        fn last_activity_at(&self) -> Option<DateTime<Utc>> {
            self.last_activity_at
        }
        fn risk_score(&self) -> u32 {
            self.risk_score
        }
        fn next_certification_at(&self) -> Option<DateTime<Utc>> {
            self.next_certification_at
        }
        fn last_certified_at(&self) -> Option<DateTime<Utc>> {
            self.last_certified_at
        }
    }

    #[test]
    fn test_is_active() {
        let active = MockNhi {
            status: NhiStatus::Active,
            ..Default::default()
        };
        assert!(active.is_active());

        let suspended = MockNhi {
            status: NhiStatus::Suspended,
            ..Default::default()
        };
        assert!(!suspended.is_active());
    }

    #[test]
    fn test_is_expired() {
        let not_expired = MockNhi {
            expires_at: Some(Utc::now() + chrono::Duration::days(30)),
            ..Default::default()
        };
        assert!(!not_expired.is_expired());

        let expired = MockNhi {
            expires_at: Some(Utc::now() - chrono::Duration::days(1)),
            ..Default::default()
        };
        assert!(expired.is_expired());

        let no_expiry = MockNhi {
            expires_at: None,
            ..Default::default()
        };
        assert!(!no_expiry.is_expired());
    }

    #[test]
    fn test_is_stale() {
        let recent = MockNhi {
            last_activity_at: Some(Utc::now() - chrono::Duration::days(10)),
            ..Default::default()
        };
        assert!(!recent.is_stale(30));
        assert!(recent.is_stale(5));

        let no_activity = MockNhi {
            last_activity_at: None,
            ..Default::default()
        };
        assert!(no_activity.is_stale(30));
    }

    #[test]
    fn test_needs_certification() {
        let due = MockNhi {
            next_certification_at: Some(Utc::now() - chrono::Duration::days(1)),
            ..Default::default()
        };
        assert!(due.needs_certification());

        let not_due = MockNhi {
            next_certification_at: Some(Utc::now() + chrono::Duration::days(30)),
            ..Default::default()
        };
        assert!(!not_due.needs_certification());
    }

    #[test]
    fn test_risk_level() {
        let low_risk = MockNhi {
            risk_score: 20,
            ..Default::default()
        };
        assert_eq!(low_risk.risk_level(), crate::types::NhiRiskLevel::Low);

        let high_risk = MockNhi {
            risk_score: 70,
            ..Default::default()
        };
        assert_eq!(high_risk.risk_level(), crate::types::NhiRiskLevel::High);
    }
}
