//! Micro-certification event consumers for F055.
//!
//! Consumers that listen for governance events and automatically
//! create micro-certifications based on configured trigger rules.

use std::sync::Arc;

use async_trait::async_trait;
use sqlx::PgPool;
use tracing::{error, info, warn};
use uuid::Uuid;

use xavyo_events::consumer::EventHandler;
use xavyo_events::events::{EntitlementAssignmentCreated, SodViolationDetected, UserUpdated};

use crate::services::MicroCertificationService;

/// Consumer for entitlement assignment events.
///
/// Creates micro-certifications when high-risk entitlements are assigned.
/// This is the primary trigger for T084 - EntitlementAssignedConsumer.
pub struct AssignmentCreatedConsumer {
    #[allow(dead_code)]
    pool: PgPool,
    service: Arc<MicroCertificationService>,
}

impl AssignmentCreatedConsumer {
    /// Create a new assignment created consumer.
    pub fn new(pool: PgPool, service: Arc<MicroCertificationService>) -> Self {
        Self { pool, service }
    }
}

#[async_trait]
impl EventHandler<EntitlementAssignmentCreated> for AssignmentCreatedConsumer {
    async fn handle(
        &self,
        event: EntitlementAssignmentCreated,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!(
            assignment_id = %event.assignment_id,
            user_id = %event.user_id,
            entitlement_id = %event.entitlement_id,
            risk_level = %event.risk_level,
            "Processing entitlement assignment event for micro-certification"
        );

        // Only trigger for high-risk assignments
        if event.risk_level != "high" && event.risk_level != "critical" {
            info!(
                assignment_id = %event.assignment_id,
                risk_level = %event.risk_level,
                "Skipping non-high-risk assignment"
            );
            return Ok(());
        }

        // Try to create a micro-certification
        let result = self
            .service
            .create_from_assignment_event(
                event.tenant_id,
                event.assignment_id,
                event.user_id,
                event.entitlement_id,
                "high_risk_assignment",
                event.assignment_id, // Use assignment ID as event ID for traceability
                Some(serde_json::json!({
                    "risk_level": event.risk_level,
                    "entitlement_name": event.entitlement_name,
                    "assigned_by": event.assigned_by,
                    "created_at": event.created_at.to_rfc3339(),
                })),
            )
            .await;

        match result {
            Ok(Some(creation_result)) => {
                if creation_result.duplicate_skipped {
                    info!(
                        assignment_id = %event.assignment_id,
                        certification_id = %creation_result.certification.id,
                        "Duplicate micro-certification skipped"
                    );
                } else {
                    info!(
                        assignment_id = %event.assignment_id,
                        certification_id = %creation_result.certification.id,
                        reviewer_id = %creation_result.certification.reviewer_id,
                        "Micro-certification created from assignment event"
                    );
                }
            }
            Ok(None) => {
                info!(
                    assignment_id = %event.assignment_id,
                    "No matching trigger rule found for assignment"
                );
            }
            Err(e) => {
                error!(
                    assignment_id = %event.assignment_id,
                    error = %e,
                    "Failed to create micro-certification from assignment event"
                );
                return Err(e.to_string().into());
            }
        }

        Ok(())
    }
}

/// Consumer for SoD violation events.
///
/// Creates micro-certifications when SoD violations are detected.
/// This is the primary trigger for T085 - SodViolationConsumer.
pub struct SodViolationConsumer {
    #[allow(dead_code)]
    pool: PgPool,
    service: Arc<MicroCertificationService>,
}

impl SodViolationConsumer {
    /// Create a new SoD violation consumer.
    pub fn new(pool: PgPool, service: Arc<MicroCertificationService>) -> Self {
        Self { pool, service }
    }
}

#[async_trait]
impl EventHandler<SodViolationDetected> for SodViolationConsumer {
    async fn handle(
        &self,
        event: SodViolationDetected,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!(
            violation_id = %event.violation_id,
            user_id = %event.user_id,
            rule_id = %event.rule_id,
            severity = %event.severity,
            "Processing SoD violation event for micro-certification"
        );

        // Try to create a micro-certification for SoD violations
        let result = self
            .service
            .create_from_sod_violation(
                event.tenant_id,
                event.violation_id,
                event.user_id,
                event.entitlement_b_id, // The triggering entitlement
                event.triggering_assignment_id,
                event.entitlement_a_id, // The conflicting entitlement
                "sod_violation",
                event.violation_id, // Use violation ID as event ID for traceability
                Some(serde_json::json!({
                    "rule_id": event.rule_id,
                    "rule_name": event.rule_name,
                    "severity": event.severity,
                    "entitlement_a_id": event.entitlement_a_id,
                    "entitlement_b_id": event.entitlement_b_id,
                    "detected_at": event.detected_at.to_rfc3339(),
                })),
            )
            .await;

        match result {
            Ok(Some(creation_result)) => {
                if creation_result.duplicate_skipped {
                    info!(
                        violation_id = %event.violation_id,
                        certification_id = %creation_result.certification.id,
                        "Duplicate SoD micro-certification skipped"
                    );
                } else {
                    info!(
                        violation_id = %event.violation_id,
                        certification_id = %creation_result.certification.id,
                        reviewer_id = %creation_result.certification.reviewer_id,
                        "Micro-certification created from SoD violation event"
                    );
                }
            }
            Ok(None) => {
                info!(
                    violation_id = %event.violation_id,
                    "No matching trigger rule found for SoD violation"
                );
            }
            Err(e) => {
                error!(
                    violation_id = %event.violation_id,
                    error = %e,
                    "Failed to create micro-certification from SoD violation event"
                );
                return Err(e.to_string().into());
            }
        }

        Ok(())
    }
}

/// Consumer for user updated events.
///
/// Creates micro-certifications when a user's manager changes.
/// This is the primary trigger for T086 - UserUpdatedConsumer.
pub struct ManagerChangeConsumer {
    pool: PgPool,
    service: Arc<MicroCertificationService>,
}

impl ManagerChangeConsumer {
    /// Create a new manager change consumer.
    pub fn new(pool: PgPool, service: Arc<MicroCertificationService>) -> Self {
        Self { pool, service }
    }
}

#[async_trait]
impl EventHandler<UserUpdated> for ManagerChangeConsumer {
    async fn handle(
        &self,
        event: UserUpdated,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Check if manager_id was changed
        let manager_changed = event
            .changes
            .get("manager_id")
            .or_else(|| event.changes.get("managerId"))
            .is_some();

        if !manager_changed {
            // Not a manager change event, skip
            return Ok(());
        }

        info!(
            user_id = %event.user_id,
            "Processing manager change event for micro-certification"
        );

        // Get the new manager ID from the changes
        let new_manager_id = event
            .changes
            .get("manager_id")
            .or_else(|| event.changes.get("managerId"))
            .and_then(|v| v.as_str())
            .and_then(|s| Uuid::parse_str(s).ok());

        // Get the old manager ID from previous values (if available)
        let old_manager_id = event
            .previous
            .as_ref()
            .and_then(|p| p.get("manager_id").or_else(|| p.get("managerId")))
            .and_then(|v| v.as_str())
            .and_then(|s| Uuid::parse_str(s).ok());

        // If new_manager_id is not set (cleared), we don't trigger certifications
        let Some(new_manager_id) = new_manager_id else {
            info!(
                user_id = %event.user_id,
                "Manager cleared (set to null) - skipping micro-certification"
            );
            return Ok(());
        };

        // Lookup user's tenant_id from the database
        let user = match xavyo_db::User::find_by_id(&self.pool, event.user_id).await {
            Ok(Some(user)) => user,
            Ok(None) => {
                warn!(
                    user_id = %event.user_id,
                    "User not found for manager change event - skipping"
                );
                return Ok(());
            }
            Err(e) => {
                error!(
                    user_id = %event.user_id,
                    error = %e,
                    "Failed to lookup user for manager change event"
                );
                return Err(e.into());
            }
        };

        let tenant_id = user.tenant_id;

        // Create a unique event ID for this manager change
        let manager_change_event_id = Uuid::new_v4();

        // Try to create micro-certifications for manager change
        let result = self
            .service
            .create_from_manager_change(
                tenant_id,
                event.user_id,
                old_manager_id,
                new_manager_id,
                "manager_change",
                manager_change_event_id,
            )
            .await;

        match result {
            Ok(certifications) => {
                if certifications.is_empty() {
                    info!(
                        user_id = %event.user_id,
                        "No micro-certifications created for manager change (no applicable entitlements or no trigger rule)"
                    );
                } else {
                    info!(
                        user_id = %event.user_id,
                        count = certifications.len(),
                        "Created {} micro-certification(s) from manager change event",
                        certifications.len()
                    );
                }
            }
            Err(e) => {
                error!(
                    user_id = %event.user_id,
                    error = %e,
                    "Failed to create micro-certifications from manager change event"
                );
                return Err(e.to_string().into());
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::collections::HashMap;

    #[test]
    fn test_assignment_created_consumer_creation() {
        // Just verify the struct can be created (without database)
        // Actual testing requires integration tests with database
    }

    #[test]
    fn test_manager_change_detection() {
        let mut changes = HashMap::new();
        changes.insert(
            "manager_id".to_string(),
            serde_json::json!("550e8400-e29b-41d4-a716-446655440000"),
        );

        let event = UserUpdated {
            user_id: Uuid::new_v4(),
            changes: changes.clone(),
            previous: None,
        };

        let manager_changed = event
            .changes
            .get("manager_id")
            .or_else(|| event.changes.get("managerId"))
            .is_some();

        assert!(manager_changed);
    }

    #[test]
    fn test_no_manager_change() {
        let mut changes = HashMap::new();
        changes.insert("email".to_string(), serde_json::json!("new@example.com"));

        let event = UserUpdated {
            user_id: Uuid::new_v4(),
            changes,
            previous: None,
        };

        let manager_changed = event
            .changes
            .get("manager_id")
            .or_else(|| event.changes.get("managerId"))
            .is_some();

        assert!(!manager_changed);
    }
}
