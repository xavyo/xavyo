//! Test fixtures factory for integration tests.
//!
//! This module provides factory functions for creating test data
//! with predictable identifiers for easier debugging.

use std::collections::HashMap;

use chrono::{Duration, Utc};
use uuid::Uuid;
use xavyo_governance::services::assignment::AssignEntitlementInput;
use xavyo_governance::services::entitlement::CreateEntitlementInput;
use xavyo_governance::services::sod::CreateSodRuleInput;
use xavyo_governance::services::sod_exemption::CreateSodExemptionInput;
use xavyo_governance::types::{RiskLevel, SodConflictType, SodRuleId, SodSeverity};

use super::TestContext;

/// Result of fixture setup with created entity IDs.
#[derive(Debug, Default)]
pub struct TestFixtures {
    /// Created entitlements by name.
    pub entitlements: HashMap<String, Uuid>,
    /// Created assignments by key "user:entitlement".
    pub assignments: HashMap<String, Uuid>,
    /// Created SoD rules by name.
    pub sod_rules: HashMap<String, SodRuleId>,
    /// Created users by name.
    pub users: HashMap<String, Uuid>,
}

impl TestFixtures {
    /// Create a new empty fixtures container.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get entitlement ID by name, panics if not found.
    pub fn entitlement(&self, name: &str) -> Uuid {
        *self.entitlements.get(name).unwrap_or_else(|| {
            panic!("Entitlement '{}' not found in fixtures", name);
        })
    }

    /// Get assignment ID by key, panics if not found.
    pub fn assignment(&self, user: &str, entitlement: &str) -> Uuid {
        let key = format!("{}:{}", user, entitlement);
        *self.assignments.get(&key).unwrap_or_else(|| {
            panic!("Assignment '{}' not found in fixtures", key);
        })
    }

    /// Get SoD rule ID by name, panics if not found.
    pub fn sod_rule(&self, name: &str) -> SodRuleId {
        *self.sod_rules.get(name).unwrap_or_else(|| {
            panic!("SoD rule '{}' not found in fixtures", name);
        })
    }

    /// Get user ID by name, panics if not found.
    pub fn user(&self, name: &str) -> Uuid {
        *self.users.get(name).unwrap_or_else(|| {
            panic!("User '{}' not found in fixtures", name);
        })
    }
}

/// Factory for creating test entitlements.
pub struct EntitlementFactory {
    app_id: Uuid,
}

impl EntitlementFactory {
    /// Create a new entitlement factory.
    pub fn new(app_id: Uuid) -> Self {
        Self { app_id }
    }

    /// Create input for a low-risk entitlement.
    pub fn low_risk(&self, name: &str) -> CreateEntitlementInput {
        CreateEntitlementInput {
            application_id: self.app_id,
            name: name.to_string(),
            description: Some(format!("{} (Low Risk)", name)),
            risk_level: RiskLevel::Low,
            owner_id: None,
            external_id: None,
            metadata: None,
            is_delegable: true,
        }
    }

    /// Create input for a medium-risk entitlement.
    pub fn medium_risk(&self, name: &str) -> CreateEntitlementInput {
        CreateEntitlementInput {
            application_id: self.app_id,
            name: name.to_string(),
            description: Some(format!("{} (Medium Risk)", name)),
            risk_level: RiskLevel::Medium,
            owner_id: None,
            external_id: None,
            metadata: None,
            is_delegable: true,
        }
    }

    /// Create input for a high-risk entitlement.
    pub fn high_risk(&self, name: &str) -> CreateEntitlementInput {
        CreateEntitlementInput {
            application_id: self.app_id,
            name: name.to_string(),
            description: Some(format!("{} (High Risk)", name)),
            risk_level: RiskLevel::High,
            owner_id: None,
            external_id: None,
            metadata: None,
            is_delegable: true,
        }
    }

    /// Create input for a critical-risk entitlement.
    pub fn critical_risk(&self, name: &str) -> CreateEntitlementInput {
        CreateEntitlementInput {
            application_id: self.app_id,
            name: name.to_string(),
            description: Some(format!("{} (Critical Risk)", name)),
            risk_level: RiskLevel::Critical,
            owner_id: None,
            external_id: None,
            metadata: None,
            is_delegable: false,
        }
    }
}

/// Factory for creating test SoD rules.
pub struct SodRuleFactory;

impl SodRuleFactory {
    /// Create an exclusive SoD rule.
    pub fn exclusive(
        name: &str,
        entitlement_ids: Vec<Uuid>,
        created_by: Uuid,
    ) -> CreateSodRuleInput {
        CreateSodRuleInput {
            name: name.to_string(),
            description: Some(format!("Exclusive rule: {}", name)),
            conflict_type: SodConflictType::Exclusive,
            entitlement_ids,
            max_count: None,
            severity: SodSeverity::High,
            created_by,
        }
    }

    /// Create a cardinality SoD rule.
    pub fn cardinality(
        name: &str,
        entitlement_ids: Vec<Uuid>,
        max_count: u32,
        created_by: Uuid,
    ) -> CreateSodRuleInput {
        CreateSodRuleInput {
            name: name.to_string(),
            description: Some(format!("Cardinality rule: {} (max {})", name, max_count)),
            conflict_type: SodConflictType::Cardinality,
            entitlement_ids,
            max_count: Some(max_count),
            severity: SodSeverity::Medium,
            created_by,
        }
    }

    /// Create an inclusive SoD rule.
    pub fn inclusive(
        name: &str,
        entitlement_ids: Vec<Uuid>,
        created_by: Uuid,
    ) -> CreateSodRuleInput {
        CreateSodRuleInput {
            name: name.to_string(),
            description: Some(format!("Inclusive rule: {}", name)),
            conflict_type: SodConflictType::Inclusive,
            entitlement_ids,
            max_count: None,
            severity: SodSeverity::Low,
            created_by,
        }
    }
}

/// Factory for creating test assignments.
pub struct AssignmentFactory;

impl AssignmentFactory {
    /// Create an assignment input.
    pub fn create(
        entitlement_id: Uuid,
        user_id: Uuid,
        assigned_by: Uuid,
    ) -> AssignEntitlementInput {
        AssignEntitlementInput {
            entitlement_id,
            user_id,
            assigned_by,
            expires_at: None,
            justification: Some("Test assignment".to_string()),
        }
    }

    /// Create an assignment input with expiration.
    pub fn create_with_expiry(
        entitlement_id: Uuid,
        user_id: Uuid,
        assigned_by: Uuid,
        days_until_expiry: i64,
    ) -> AssignEntitlementInput {
        AssignEntitlementInput {
            entitlement_id,
            user_id,
            assigned_by,
            expires_at: Some(Utc::now() + Duration::days(days_until_expiry)),
            justification: Some("Test assignment with expiry".to_string()),
        }
    }
}

/// Factory for creating test exemptions.
pub struct ExemptionFactory;

impl ExemptionFactory {
    /// Create an exemption input.
    pub fn create(
        rule_id: SodRuleId,
        user_id: Uuid,
        granted_by: Uuid,
    ) -> CreateSodExemptionInput {
        CreateSodExemptionInput {
            rule_id,
            user_id,
            justification: "Test exemption with sufficient justification for validation".to_string(),
            expires_at: Some(Utc::now() + Duration::days(30)),
            granted_by,
        }
    }

    /// Create an exemption that expires soon.
    pub fn create_expiring_soon(
        rule_id: SodRuleId,
        user_id: Uuid,
        granted_by: Uuid,
        hours_until_expiry: i64,
    ) -> CreateSodExemptionInput {
        CreateSodExemptionInput {
            rule_id,
            user_id,
            justification: "Test exemption expiring soon for edge case testing".to_string(),
            expires_at: Some(Utc::now() + Duration::hours(hours_until_expiry)),
            granted_by,
        }
    }
}

/// Set up basic test fixtures for a single tenant.
pub async fn setup_basic_fixtures(
    ctx: &TestContext,
    tenant_id: Uuid,
) -> xavyo_governance::Result<TestFixtures> {
    let mut fixtures = TestFixtures::new();
    let app_id = Uuid::new_v4();
    let factory = EntitlementFactory::new(app_id);

    // Create users
    fixtures.users.insert("admin".to_string(), Uuid::new_v4());
    fixtures.users.insert("regular".to_string(), Uuid::new_v4());
    fixtures.users.insert("auditor".to_string(), Uuid::new_v4());

    // Create entitlements with different risk levels
    let entitlements = [
        ("View Reports", factory.low_risk("View Reports")),
        ("Edit Users", factory.medium_risk("Edit Users")),
        ("Delete Records", factory.high_risk("Delete Records")),
        ("System Admin", factory.critical_risk("System Admin")),
    ];

    for (name, input) in entitlements {
        let entitlement = ctx
            .services
            .entitlement
            .create(tenant_id, input, ctx.actor_id)
            .await?;
        fixtures
            .entitlements
            .insert(name.to_string(), entitlement.id.into_inner());
    }

    Ok(fixtures)
}

/// Set up SoD rules for testing.
pub async fn setup_sod_rules(
    ctx: &TestContext,
    tenant_id: Uuid,
    fixtures: &TestFixtures,
) -> xavyo_governance::Result<TestFixtures> {
    let mut result = TestFixtures::new();
    result.entitlements = fixtures.entitlements.clone();
    result.users = fixtures.users.clone();

    // Exclusive rule: Cannot have both Edit and Delete
    let exclusive_rule = ctx
        .services
        .sod
        .create_rule(
            tenant_id,
            SodRuleFactory::exclusive(
                "No Edit+Delete",
                vec![
                    fixtures.entitlement("Edit Users"),
                    fixtures.entitlement("Delete Records"),
                ],
                ctx.actor_id,
            ),
        )
        .await?;
    result
        .sod_rules
        .insert("No Edit+Delete".to_string(), exclusive_rule.id);

    // Cardinality rule: Max 2 of 4 entitlements
    let cardinality_rule = ctx
        .services
        .sod
        .create_rule(
            tenant_id,
            SodRuleFactory::cardinality(
                "Max 2 Permissions",
                vec![
                    fixtures.entitlement("View Reports"),
                    fixtures.entitlement("Edit Users"),
                    fixtures.entitlement("Delete Records"),
                    fixtures.entitlement("System Admin"),
                ],
                2,
                ctx.actor_id,
            ),
        )
        .await?;
    result
        .sod_rules
        .insert("Max 2 Permissions".to_string(), cardinality_rule.id);

    Ok(result)
}

/// Create many entitlements for performance testing.
pub async fn setup_many_entitlements(
    ctx: &TestContext,
    tenant_id: Uuid,
    count: usize,
) -> xavyo_governance::Result<Vec<Uuid>> {
    let app_id = Uuid::new_v4();
    let factory = EntitlementFactory::new(app_id);
    let mut ids = Vec::with_capacity(count);

    for i in 0..count {
        let risk = match i % 4 {
            0 => RiskLevel::Low,
            1 => RiskLevel::Medium,
            2 => RiskLevel::High,
            _ => RiskLevel::Critical,
        };

        let input = CreateEntitlementInput {
            application_id: app_id,
            name: format!("Entitlement {:05}", i),
            description: Some(format!("Performance test entitlement {}", i)),
            risk_level: risk,
            owner_id: None,
            external_id: None,
            metadata: None,
            is_delegable: true,
        };

        let entitlement = ctx
            .services
            .entitlement
            .create(tenant_id, input, ctx.actor_id)
            .await?;
        ids.push(entitlement.id.into_inner());
    }

    Ok(ids)
}
