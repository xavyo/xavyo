//! Common test utilities for xavyo-api-agents integration tests.

use sqlx::PgPool;
use uuid::Uuid;

/// Test tenant ID for isolation.
pub const TEST_TENANT_ID: &str = "00000000-0000-0000-0000-000000000001";

/// Creates a test tenant ID.
pub fn test_tenant_id() -> Uuid {
    Uuid::parse_str(TEST_TENANT_ID).unwrap()
}

/// Creates a test user ID.
pub fn test_user_id() -> Uuid {
    Uuid::new_v4()
}

/// Sets up the tenant context in the database connection.
pub async fn setup_tenant_context(pool: &PgPool, tenant_id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query(&format!("SET LOCAL app.current_tenant = '{tenant_id}'"))
        .execute(pool)
        .await?;
    Ok(())
}

/// Creates test agent data for testing.
pub struct TestAgentData {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub agent_type: String,
    pub owner_id: Uuid,
}

impl Default for TestAgentData {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4(),
            tenant_id: test_tenant_id(),
            name: format!("test-agent-{}", Uuid::new_v4()),
            agent_type: "autonomous".to_string(),
            owner_id: test_user_id(),
        }
    }
}

/// Creates test tool data for testing.
pub struct TestToolData {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub risk_level: String,
}

impl Default for TestToolData {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4(),
            tenant_id: test_tenant_id(),
            name: format!("test-tool-{}", Uuid::new_v4()),
            risk_level: "low".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tenant_id_parses() {
        let id = test_tenant_id();
        assert_eq!(id.to_string(), TEST_TENANT_ID);
    }

    #[test]
    fn test_agent_data_default() {
        let data = TestAgentData::default();
        assert_eq!(data.agent_type, "autonomous");
        assert!(data.name.starts_with("test-agent-"));
    }

    #[test]
    fn test_tool_data_default() {
        let data = TestToolData::default();
        assert_eq!(data.risk_level, "low");
        assert!(data.name.starts_with("test-tool-"));
    }
}
