//! Core trait for Non-Human Identity abstraction.
//!
//! This module defines the [`NonHumanIdentity`] trait that provides a unified
//! interface for governance operations across different NHI types.

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
/// # Multi-Tenant Isolation
///
/// **CRITICAL**: The [`tenant_id()`](Self::tenant_id) method returns the tenant UUID.
/// All database queries and operations MUST filter by this tenant ID to prevent
/// cross-tenant data leakage. Never query NHIs without a tenant filter.
///
/// # Example
///
/// ```rust
/// use xavyo_nhi::{NonHumanIdentity, NhiType, NhiStatus, NhiRiskLevel};
/// use uuid::Uuid;
/// use chrono::{DateTime, Utc};
///
/// // Define your custom NHI type
/// struct MyServiceAccount {
///     id: Uuid,
///     tenant_id: Uuid,
///     name: String,
///     owner_id: Uuid,
///     status: NhiStatus,
///     created_at: DateTime<Utc>,
///     risk_score: u32,
/// }
///
/// // Implement the trait
/// impl NonHumanIdentity for MyServiceAccount {
///     fn id(&self) -> Uuid { self.id }
///     fn tenant_id(&self) -> Uuid { self.tenant_id }
///     fn name(&self) -> &str { &self.name }
///     fn description(&self) -> Option<&str> { None }
///     fn nhi_type(&self) -> NhiType { NhiType::ServiceAccount }
///     fn owner_id(&self) -> Uuid { self.owner_id }
///     fn backup_owner_id(&self) -> Option<Uuid> { None }
///     fn status(&self) -> NhiStatus { self.status }
///     fn created_at(&self) -> DateTime<Utc> { self.created_at }
///     fn expires_at(&self) -> Option<DateTime<Utc>> { None }
///     fn last_activity_at(&self) -> Option<DateTime<Utc>> { None }
///     fn risk_score(&self) -> u32 { self.risk_score }
///     fn next_certification_at(&self) -> Option<DateTime<Utc>> { None }
///     fn last_certified_at(&self) -> Option<DateTime<Utc>> { None }
/// }
///
/// // Use derived methods
/// let account = MyServiceAccount {
///     id: Uuid::new_v4(),
///     tenant_id: Uuid::new_v4(),
///     name: "my-service".to_string(),
///     owner_id: Uuid::new_v4(),
///     status: NhiStatus::Active,
///     created_at: Utc::now(),
///     risk_score: 25,
/// };
///
/// assert!(account.is_active());
/// assert!(!account.is_expired());
/// assert_eq!(account.risk_level(), NhiRiskLevel::Low);
/// ```
pub trait NonHumanIdentity: Send + Sync {
    // --- Core Identity ---

    /// Returns the unique identifier for this NHI.
    ///
    /// This UUID is globally unique and immutable once assigned.
    fn id(&self) -> Uuid;

    /// Returns the tenant UUID this identity belongs to.
    ///
    /// # Multi-Tenant Isolation
    ///
    /// **CRITICAL**: This value MUST be used to filter all database queries.
    /// Never access NHI data without filtering by tenant ID.
    ///
    /// # Example
    ///
    /// ```text
    /// // CORRECT: Filter by tenant
    /// SELECT * FROM nhis WHERE tenant_id = $1 AND id = $2
    ///
    /// // WRONG: Missing tenant filter - security violation!
    /// SELECT * FROM nhis WHERE id = $1
    /// ```
    fn tenant_id(&self) -> Uuid;

    /// Returns the display name for this NHI.
    ///
    /// This is a human-readable identifier used in UIs and logs.
    /// It should be unique within the tenant scope.
    fn name(&self) -> &str;

    /// Returns an optional description or purpose statement.
    ///
    /// This provides context about why this NHI exists and what it's used for.
    fn description(&self) -> Option<&str>;

    /// Returns the type discriminator for this NHI.
    ///
    /// See [`NhiType`] for the available categories.
    fn nhi_type(&self) -> NhiType;

    // --- Ownership ---

    /// Returns the UUID of the primary owner responsible for this NHI.
    ///
    /// The owner is accountable for:
    /// - Certifying the NHI during governance campaigns
    /// - Approving permission changes
    /// - Responding to security alerts
    fn owner_id(&self) -> Uuid;

    /// Returns the optional backup owner UUID for succession planning.
    ///
    /// If the primary owner becomes unavailable, the backup owner
    /// can be promoted to maintain governance continuity.
    fn backup_owner_id(&self) -> Option<Uuid>;

    // --- Lifecycle ---

    /// Returns the current lifecycle status of this NHI.
    ///
    /// See [`NhiStatus`] for possible values and their meanings.
    fn status(&self) -> NhiStatus;

    /// Returns when this NHI was created.
    fn created_at(&self) -> DateTime<Utc>;

    /// Returns when this NHI expires, if an expiration is set.
    ///
    /// After expiration, the NHI should be suspended and require
    /// re-certification or extension before it can be used again.
    fn expires_at(&self) -> Option<DateTime<Utc>>;

    /// Returns the last time this NHI was used or accessed.
    ///
    /// Used for staleness detection and inactivity-based suspension.
    /// Returns `None` if no activity has been recorded.
    fn last_activity_at(&self) -> Option<DateTime<Utc>>;

    // --- Governance ---

    /// Returns the unified risk score (0-100).
    ///
    /// Higher scores indicate higher risk. Scores are normalized
    /// from type-specific algorithms:
    /// - **Service accounts**: staleness (40) + credential age (30) + scope (30)
    /// - **AI agents**: mapped from `risk_level` enum or computed score
    ///
    /// See [`crate::risk::calculate_risk_score`] for the algorithm.
    fn risk_score(&self) -> u32;

    /// Returns when the next certification is due, if scheduled.
    ///
    /// When this date passes, [`needs_certification()`](Self::needs_certification)
    /// will return `true`.
    fn next_certification_at(&self) -> Option<DateTime<Utc>>;

    /// Returns when this NHI was last certified by its owner.
    fn last_certified_at(&self) -> Option<DateTime<Utc>>;

    // --- Derived Methods ---

    /// Returns `true` if this NHI is currently active and usable.
    ///
    /// An NHI is active if its status is [`NhiStatus::Active`].
    ///
    /// # Example
    ///
    /// ```text
    /// if !nhi.is_active() {
    ///     return Err("NHI is not active");
    /// }
    /// ```
    fn is_active(&self) -> bool {
        self.status().is_usable()
    }

    /// Returns `true` if this NHI has passed its expiration date.
    ///
    /// Returns `false` if no expiration is set.
    ///
    /// # Note
    ///
    /// An NHI that is expired should typically also have its status
    /// set to [`NhiStatus::Expired`]. This method checks the timestamp
    /// directly for cases where status hasn't been updated yet.
    fn is_expired(&self) -> bool {
        if let Some(expires) = self.expires_at() {
            expires < Utc::now()
        } else {
            false
        }
    }

    /// Returns `true` if this NHI requires certification review.
    ///
    /// An NHI needs certification if its `next_certification_at` date
    /// has passed (is less than or equal to now).
    fn needs_certification(&self) -> bool {
        if let Some(due) = self.next_certification_at() {
            due <= Utc::now()
        } else {
            false
        }
    }

    /// Returns `true` if this NHI is considered stale.
    ///
    /// An NHI is stale if it hasn't been used for longer than `threshold_days`.
    /// If no activity has ever been recorded, the NHI is considered stale.
    ///
    /// # Arguments
    ///
    /// * `threshold_days` - Number of days of inactivity that constitutes staleness
    ///
    /// # Example
    ///
    /// ```text
    /// // Check if NHI has been inactive for 30+ days
    /// if nhi.is_stale(30) {
    ///     trigger_staleness_alert(nhi);
    /// }
    /// ```
    fn is_stale(&self, threshold_days: i64) -> bool {
        if let Some(last_activity) = self.last_activity_at() {
            let threshold = Utc::now() - chrono::Duration::days(threshold_days);
            last_activity < threshold
        } else {
            // No activity recorded = considered stale
            true
        }
    }

    /// Returns the risk level category based on the risk score.
    ///
    /// Maps the numeric [`risk_score()`](Self::risk_score) to a
    /// [`NhiRiskLevel`](crate::types::NhiRiskLevel) category.
    ///
    /// | Score Range | Level |
    /// |-------------|-------|
    /// | 0-25 | Low |
    /// | 26-50 | Medium |
    /// | 51-75 | High |
    /// | 76-100 | Critical |
    fn risk_level(&self) -> crate::types::NhiRiskLevel {
        crate::types::NhiRiskLevel::from(self.risk_score())
    }
}

/// Extension trait for boxed NHI objects.
///
/// Allows calling trait methods on `Box<dyn NonHumanIdentity>`.
/// This enables storing heterogeneous NHI types in collections.
///
/// # Example
///
/// ```text
/// let nhis: Vec<Box<dyn NonHumanIdentity>> = vec![
///     Box::new(service_account),
///     Box::new(ai_agent),
/// ];
///
/// for nhi in &nhis {
///     println!("{}: {}", nhi.name(), nhi.risk_score());
/// }
/// ```
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

    /// Test implementation of `NonHumanIdentity` for unit tests.
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

    #[test]
    fn test_boxed_trait_object() {
        let nhi = MockNhi::default();
        let boxed: Box<dyn NonHumanIdentity> = Box::new(nhi);

        // Verify all methods work through the box
        let _ = boxed.id();
        let _ = boxed.tenant_id();
        assert_eq!(boxed.name(), "test-nhi");
        assert!(boxed.description().is_none());
        assert_eq!(boxed.nhi_type(), NhiType::ServiceAccount);
        let _ = boxed.owner_id();
        assert!(boxed.backup_owner_id().is_none());
        assert_eq!(boxed.status(), NhiStatus::Active);
        let _ = boxed.created_at();
        assert!(boxed.expires_at().is_none());
        assert!(boxed.last_activity_at().is_some());
        assert_eq!(boxed.risk_score(), 25);
        assert!(boxed.next_certification_at().is_none());
        assert!(boxed.last_certified_at().is_none());

        // Verify derived methods
        assert!(boxed.is_active());
        assert!(!boxed.is_expired());
        assert!(!boxed.needs_certification());
        assert_eq!(boxed.risk_level(), crate::types::NhiRiskLevel::Low);
    }
}
