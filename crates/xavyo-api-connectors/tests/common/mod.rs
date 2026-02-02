//! Common test utilities for connector API tests.
//!
//! These tests use mock services to avoid requiring a database connection.

use std::sync::Arc;
use uuid::Uuid;

/// Test context containing tenant and authentication info.
#[derive(Clone)]
pub struct TestContext {
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub jwt_token: String,
}

impl TestContext {
    /// Create a new test context with a fresh tenant.
    pub fn new() -> Self {
        let tenant_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let jwt_token = generate_test_jwt(tenant_id, user_id);

        Self {
            tenant_id,
            user_id,
            jwt_token,
        }
    }
}

impl Default for TestContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Generate a test JWT token for the given tenant and user.
fn generate_test_jwt(tenant_id: Uuid, user_id: Uuid) -> String {
    format!(
        "test_token_{}_{}",
        tenant_id, user_id
    )
}
