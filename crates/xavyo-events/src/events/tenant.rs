//! Tenant lifecycle events.

use crate::event::Event;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Subscription plan for a tenant.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionPlan {
    Free,
    Starter,
    Professional,
    Enterprise,
}

/// Published when a new tenant is provisioned.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantCreated {
    /// The new tenant's ID.
    pub tenant_id: Uuid,
    /// Tenant display name.
    pub name: String,
    /// Unique URL-safe identifier.
    pub slug: String,
    /// Subscription plan (optional).
    pub plan: Option<SubscriptionPlan>,
    /// Initial admin user ID (optional).
    pub admin_user_id: Option<Uuid>,
}

impl Event for TenantCreated {
    const TOPIC: &'static str = "xavyo.idp.tenant.created";
    const EVENT_TYPE: &'static str = "xavyo.idp.tenant.created";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tenant_created_serialization() {
        let event = TenantCreated {
            tenant_id: Uuid::new_v4(),
            name: "Acme Corp".to_string(),
            slug: "acme-corp".to_string(),
            plan: Some(SubscriptionPlan::Professional),
            admin_user_id: Some(Uuid::new_v4()),
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("professional"));

        let restored: TenantCreated = serde_json::from_str(&json).unwrap();
        assert_eq!(event.name, restored.name);
        assert_eq!(event.slug, restored.slug);
        assert_eq!(event.plan, restored.plan);
    }

    #[test]
    fn test_tenant_created_minimal() {
        let json = r#"{
            "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
            "name": "Test Tenant",
            "slug": "test-tenant"
        }"#;

        let event: TenantCreated = serde_json::from_str(json).unwrap();
        assert!(event.plan.is_none());
        assert!(event.admin_user_id.is_none());
    }

    #[test]
    fn test_tenant_created_topic() {
        assert_eq!(TenantCreated::TOPIC, "xavyo.idp.tenant.created");
        assert_eq!(TenantCreated::EVENT_TYPE, "xavyo.idp.tenant.created");
    }

    #[test]
    fn test_subscription_plan_serialization() {
        assert_eq!(
            serde_json::to_string(&SubscriptionPlan::Free).unwrap(),
            "\"free\""
        );
        assert_eq!(
            serde_json::to_string(&SubscriptionPlan::Enterprise).unwrap(),
            "\"enterprise\""
        );
    }
}
