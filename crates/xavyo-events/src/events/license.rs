//! License management events for F065 License Management.
//!
//! Events for license governance operations:
//! - License assignment and reclamation
//! - License pool expiration and expiring warnings
//! - Bulk license operations
//! - License capacity warnings

use crate::event::Event;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// =============================================================================
// License Assignment Events
// =============================================================================

/// Published when a license is assigned to a user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseAssigned {
    /// The license pool ID.
    pub pool_id: Uuid,
    /// The license pool name.
    pub pool_name: String,
    /// The assignment ID.
    pub assignment_id: Uuid,
    /// The user who received the license.
    pub user_id: Uuid,
    /// Source of the assignment (manual/entitlement/bulk).
    pub source: String,
    /// When the license was assigned.
    pub assigned_at: DateTime<Utc>,
}

impl Event for LicenseAssigned {
    const TOPIC: &'static str = "xavyo.governance.license.assigned";
    const EVENT_TYPE: &'static str = "xavyo.governance.license.assigned";
}

/// Published when a license is reclaimed from a user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseReclaimed {
    /// The license pool ID.
    pub pool_id: Uuid,
    /// The license pool name.
    pub pool_name: String,
    /// The assignment ID.
    pub assignment_id: Uuid,
    /// The user from whom the license was reclaimed.
    pub user_id: Uuid,
    /// Trigger for reclamation (inactivity/lifecycle/manual).
    pub trigger: String,
    /// When the license was reclaimed.
    pub reclaimed_at: DateTime<Utc>,
}

impl Event for LicenseReclaimed {
    const TOPIC: &'static str = "xavyo.governance.license.reclaimed";
    const EVENT_TYPE: &'static str = "xavyo.governance.license.reclaimed";
}

// =============================================================================
// License Pool Expiration Events
// =============================================================================

/// Published when a license pool expires.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicensePoolExpired {
    /// The license pool ID.
    pub pool_id: Uuid,
    /// The license pool name.
    pub pool_name: String,
    /// The vendor name.
    pub vendor: String,
    /// The expiration policy applied (`block_new/revoke_all/warn_only`).
    pub expiration_policy: String,
    /// Number of assignments revoked as a result.
    pub assignments_revoked: i64,
    /// When the pool expired.
    pub expired_at: DateTime<Utc>,
}

impl Event for LicensePoolExpired {
    const TOPIC: &'static str = "xavyo.governance.license.pool_expired";
    const EVENT_TYPE: &'static str = "xavyo.governance.license.pool_expired";
}

/// Published when a license pool is approaching expiration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicensePoolExpiringWarning {
    /// The license pool ID.
    pub pool_id: Uuid,
    /// The license pool name.
    pub pool_name: String,
    /// The vendor name.
    pub vendor: String,
    /// When the pool expires.
    pub expiration_date: DateTime<Utc>,
    /// Days until the pool expires.
    pub days_until_expiration: i64,
    /// Number of currently allocated licenses.
    pub allocated_count: i32,
    /// Total license capacity in the pool.
    pub total_capacity: i32,
}

impl Event for LicensePoolExpiringWarning {
    const TOPIC: &'static str = "xavyo.governance.license.pool_expiring";
    const EVENT_TYPE: &'static str = "xavyo.governance.license.pool_expiring";
}

// =============================================================================
// Bulk Operation Events
// =============================================================================

/// Published when a bulk license operation completes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseBulkOperation {
    /// The license pool ID.
    pub pool_id: Uuid,
    /// The license pool name.
    pub pool_name: String,
    /// The operation type (`bulk_assign/bulk_reclaim`).
    pub operation: String,
    /// Number of licenses affected.
    pub count: i64,
    /// When the operation completed.
    pub completed_at: DateTime<Utc>,
}

impl Event for LicenseBulkOperation {
    const TOPIC: &'static str = "xavyo.governance.license.bulk_operation";
    const EVENT_TYPE: &'static str = "xavyo.governance.license.bulk_operation";
}

// =============================================================================
// Capacity Warning Events
// =============================================================================

/// Published when a license pool exceeds a utilization threshold.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseCapacityWarning {
    /// The license pool ID.
    pub pool_id: Uuid,
    /// The license pool name.
    pub pool_name: String,
    /// Number of currently allocated licenses.
    pub allocated_count: i32,
    /// Total license capacity in the pool.
    pub total_capacity: i32,
    /// Current utilization percentage (0.0 - 100.0).
    pub utilization_percent: f64,
}

impl Event for LicenseCapacityWarning {
    const TOPIC: &'static str = "xavyo.governance.license.capacity_warning";
    const EVENT_TYPE: &'static str = "xavyo.governance.license.capacity_warning";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_license_assigned_serialization() {
        let event = LicenseAssigned {
            pool_id: Uuid::new_v4(),
            pool_name: "Microsoft 365 E5".to_string(),
            assignment_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            source: "manual".to_string(),
            assigned_at: Utc::now(),
        };

        let json = serde_json::to_string(&event).unwrap();
        let restored: LicenseAssigned = serde_json::from_str(&json).unwrap();
        assert_eq!(event.pool_id, restored.pool_id);
        assert_eq!(event.pool_name, restored.pool_name);
        assert_eq!(event.assignment_id, restored.assignment_id);
        assert_eq!(event.user_id, restored.user_id);
        assert_eq!(event.source, restored.source);
    }

    #[test]
    fn test_license_reclaimed_serialization() {
        let event = LicenseReclaimed {
            pool_id: Uuid::new_v4(),
            pool_name: "Adobe Creative Cloud".to_string(),
            assignment_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            trigger: "inactivity".to_string(),
            reclaimed_at: Utc::now(),
        };

        let json = serde_json::to_string(&event).unwrap();
        let restored: LicenseReclaimed = serde_json::from_str(&json).unwrap();
        assert_eq!(event.pool_id, restored.pool_id);
        assert_eq!(event.pool_name, restored.pool_name);
        assert_eq!(event.trigger, restored.trigger);
    }

    #[test]
    fn test_license_pool_expired_serialization() {
        let event = LicensePoolExpired {
            pool_id: Uuid::new_v4(),
            pool_name: "Jira Software".to_string(),
            vendor: "Atlassian".to_string(),
            expiration_policy: "revoke_all".to_string(),
            assignments_revoked: 42,
            expired_at: Utc::now(),
        };

        let json = serde_json::to_string(&event).unwrap();
        let restored: LicensePoolExpired = serde_json::from_str(&json).unwrap();
        assert_eq!(event.pool_id, restored.pool_id);
        assert_eq!(event.vendor, restored.vendor);
        assert_eq!(event.expiration_policy, restored.expiration_policy);
        assert_eq!(event.assignments_revoked, restored.assignments_revoked);
    }

    #[test]
    fn test_license_pool_expiring_warning_serialization() {
        let event = LicensePoolExpiringWarning {
            pool_id: Uuid::new_v4(),
            pool_name: "Slack Enterprise".to_string(),
            vendor: "Salesforce".to_string(),
            expiration_date: Utc::now(),
            days_until_expiration: 30,
            allocated_count: 150,
            total_capacity: 200,
        };

        let json = serde_json::to_string(&event).unwrap();
        let restored: LicensePoolExpiringWarning = serde_json::from_str(&json).unwrap();
        assert_eq!(event.pool_id, restored.pool_id);
        assert_eq!(event.vendor, restored.vendor);
        assert_eq!(event.days_until_expiration, restored.days_until_expiration);
        assert_eq!(event.allocated_count, restored.allocated_count);
        assert_eq!(event.total_capacity, restored.total_capacity);
    }

    #[test]
    fn test_license_bulk_operation_serialization() {
        let event = LicenseBulkOperation {
            pool_id: Uuid::new_v4(),
            pool_name: "GitHub Enterprise".to_string(),
            operation: "bulk_assign".to_string(),
            count: 25,
            completed_at: Utc::now(),
        };

        let json = serde_json::to_string(&event).unwrap();
        let restored: LicenseBulkOperation = serde_json::from_str(&json).unwrap();
        assert_eq!(event.pool_id, restored.pool_id);
        assert_eq!(event.operation, restored.operation);
        assert_eq!(event.count, restored.count);
    }

    #[test]
    fn test_license_capacity_warning_serialization() {
        let event = LicenseCapacityWarning {
            pool_id: Uuid::new_v4(),
            pool_name: "Zoom Business".to_string(),
            allocated_count: 95,
            total_capacity: 100,
            utilization_percent: 95.0,
        };

        let json = serde_json::to_string(&event).unwrap();
        let restored: LicenseCapacityWarning = serde_json::from_str(&json).unwrap();
        assert_eq!(event.pool_id, restored.pool_id);
        assert_eq!(event.pool_name, restored.pool_name);
        assert_eq!(event.allocated_count, restored.allocated_count);
        assert_eq!(event.total_capacity, restored.total_capacity);
        assert!((event.utilization_percent - restored.utilization_percent).abs() < f64::EPSILON);
    }

    #[test]
    fn test_license_event_topics() {
        assert_eq!(LicenseAssigned::TOPIC, "xavyo.governance.license.assigned");
        assert_eq!(
            LicenseReclaimed::TOPIC,
            "xavyo.governance.license.reclaimed"
        );
        assert_eq!(
            LicensePoolExpired::TOPIC,
            "xavyo.governance.license.pool_expired"
        );
        assert_eq!(
            LicensePoolExpiringWarning::TOPIC,
            "xavyo.governance.license.pool_expiring"
        );
        assert_eq!(
            LicenseBulkOperation::TOPIC,
            "xavyo.governance.license.bulk_operation"
        );
        assert_eq!(
            LicenseCapacityWarning::TOPIC,
            "xavyo.governance.license.capacity_warning"
        );
    }

    #[test]
    fn test_license_event_type_matches_topic() {
        assert_eq!(LicenseAssigned::EVENT_TYPE, LicenseAssigned::TOPIC);
        assert_eq!(LicenseReclaimed::EVENT_TYPE, LicenseReclaimed::TOPIC);
        assert_eq!(LicensePoolExpired::EVENT_TYPE, LicensePoolExpired::TOPIC);
        assert_eq!(
            LicensePoolExpiringWarning::EVENT_TYPE,
            LicensePoolExpiringWarning::TOPIC
        );
        assert_eq!(
            LicenseBulkOperation::EVENT_TYPE,
            LicenseBulkOperation::TOPIC
        );
        assert_eq!(
            LicenseCapacityWarning::EVENT_TYPE,
            LicenseCapacityWarning::TOPIC
        );
    }

    #[test]
    fn test_all_license_topics_follow_convention() {
        assert!(LicenseAssigned::TOPIC.starts_with("xavyo."));
        assert!(LicenseReclaimed::TOPIC.starts_with("xavyo."));
        assert!(LicensePoolExpired::TOPIC.starts_with("xavyo."));
        assert!(LicensePoolExpiringWarning::TOPIC.starts_with("xavyo."));
        assert!(LicenseBulkOperation::TOPIC.starts_with("xavyo."));
        assert!(LicenseCapacityWarning::TOPIC.starts_with("xavyo."));
    }

    #[test]
    fn test_all_license_topics_are_non_empty() {
        assert!(!LicenseAssigned::TOPIC.is_empty());
        assert!(!LicenseReclaimed::TOPIC.is_empty());
        assert!(!LicensePoolExpired::TOPIC.is_empty());
        assert!(!LicensePoolExpiringWarning::TOPIC.is_empty());
        assert!(!LicenseBulkOperation::TOPIC.is_empty());
        assert!(!LicenseCapacityWarning::TOPIC.is_empty());
    }

    #[test]
    fn test_all_license_topics_consistent_naming() {
        // All license topics should follow the xavyo.governance.license.* convention
        assert!(LicenseAssigned::TOPIC.starts_with("xavyo.governance.license."));
        assert!(LicenseReclaimed::TOPIC.starts_with("xavyo.governance.license."));
        assert!(LicensePoolExpired::TOPIC.starts_with("xavyo.governance.license."));
        assert!(LicensePoolExpiringWarning::TOPIC.starts_with("xavyo.governance.license."));
        assert!(LicenseBulkOperation::TOPIC.starts_with("xavyo.governance.license."));
        assert!(LicenseCapacityWarning::TOPIC.starts_with("xavyo.governance.license."));
    }
}
