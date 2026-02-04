//! Integration tests for Dynamic Secrets Provisioning (F120).
//!
//! Tests the credential request endpoint with real database connectivity.

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::sync::{Arc, Once};
use std::time::Duration as StdDuration;
use uuid::Uuid;
use xavyo_api_agents::services::encryption::EncryptionService;

static INIT: Once = Once::new();

/// Initialize logging for tests (once).
fn init_test_logging() {
    INIT.call_once(|| {
        if std::env::var("RUST_LOG").is_ok() {
            tracing_subscriber::fmt()
                .with_test_writer()
                .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
                .try_init()
                .ok();
        }
    });
}

/// Get the database URL for the app user (non-superuser, RLS enforced).
fn get_app_database_url() -> String {
    std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgres://xavyo_app:xavyo_app_password@localhost:5434/xavyo_test".to_string()
    })
}

/// Get the database URL for the superuser (RLS bypassed, for setup operations).
fn get_superuser_database_url() -> String {
    std::env::var("DATABASE_URL_SUPERUSER").unwrap_or_else(|_| {
        "postgres://xavyo:xavyo_test_password@localhost:5434/xavyo_test".to_string()
    })
}

/// Test context for credential integration tests.
struct CredentialTestContext {
    /// App user pool - RLS is enforced
    pub pool: PgPool,
    /// Admin/superuser pool - bypasses RLS, used for test setup
    pub admin_pool: PgPool,
    /// Test tenant ID
    pub tenant_id: Uuid,
}

impl CredentialTestContext {
    /// Create a new test context with both app and admin database connections.
    async fn new() -> Option<Self> {
        init_test_logging();

        // Try to connect - skip test if database not available
        let pool = match PgPoolOptions::new()
            .max_connections(5)
            .acquire_timeout(StdDuration::from_secs(5))
            .connect(&get_app_database_url())
            .await
        {
            Ok(p) => p,
            Err(_) => return None, // Database not available
        };

        let admin_pool = match PgPoolOptions::new()
            .max_connections(5)
            .acquire_timeout(StdDuration::from_secs(5))
            .connect(&get_superuser_database_url())
            .await
        {
            Ok(p) => p,
            Err(_) => return None, // Database not available
        };

        // Create a unique test tenant
        let tenant_id = Uuid::new_v4();
        let slug = format!("test-{}", &tenant_id.to_string()[..8]);
        if sqlx::query("INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)")
            .bind(tenant_id)
            .bind(format!("Test Tenant {}", &tenant_id.to_string()[..8]))
            .bind(&slug)
            .execute(&admin_pool)
            .await
            .is_err()
        {
            return None;
        }

        Some(Self {
            pool,
            admin_pool,
            tenant_id,
        })
    }

    /// Create a test user for the tenant.
    async fn create_user(&self) -> Result<Uuid, sqlx::Error> {
        let user_id = Uuid::new_v4();
        let email = format!("test-{}@test.local", &user_id.to_string()[..8]);
        sqlx::query(
            "INSERT INTO users (id, tenant_id, email, password_hash, is_active, email_verified)
             VALUES ($1, $2, $3, $4, true, true)",
        )
        .bind(user_id)
        .bind(self.tenant_id)
        .bind(&email)
        .bind("$argon2id$v=19$m=65536,t=3,p=4$dGVzdHNhbHQ$testhash")
        .execute(&self.admin_pool)
        .await?;

        Ok(user_id)
    }

    /// Create a test AI agent.
    async fn create_agent(&self, owner_id: Uuid) -> Result<Uuid, sqlx::Error> {
        let agent_id = Uuid::new_v4();
        let name = format!("test-agent-{}", &agent_id.to_string()[..8]);
        sqlx::query(
            "INSERT INTO ai_agents (id, tenant_id, name, agent_type, owner_id, status, risk_level)
             VALUES ($1, $2, $3, 'autonomous', $4, 'active', 'low')",
        )
        .bind(agent_id)
        .bind(self.tenant_id)
        .bind(&name)
        .bind(owner_id)
        .execute(&self.admin_pool)
        .await?;

        Ok(agent_id)
    }

    /// Create a secret type configuration.
    async fn create_secret_type(
        &self,
        type_name: &str,
        rate_limit: i32,
    ) -> Result<Uuid, sqlx::Error> {
        let config_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO secret_type_configurations
             (id, tenant_id, type_name, default_ttl_seconds, max_ttl_seconds, provider_type, rate_limit_per_hour, enabled)
             VALUES ($1, $2, $3, 300, 3600, 'internal', $4, true)",
        )
        .bind(config_id)
        .bind(self.tenant_id)
        .bind(type_name)
        .bind(rate_limit)
        .execute(&self.admin_pool)
        .await?;

        Ok(config_id)
    }

    /// Grant permission to an agent for a secret type.
    async fn grant_permission(
        &self,
        agent_id: Uuid,
        secret_type: &str,
        granted_by: Uuid,
    ) -> Result<Uuid, sqlx::Error> {
        let perm_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO agent_secret_permissions
             (id, tenant_id, agent_id, secret_type, granted_by)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(perm_id)
        .bind(self.tenant_id)
        .bind(agent_id)
        .bind(secret_type)
        .bind(granted_by)
        .execute(&self.admin_pool)
        .await?;

        Ok(perm_id)
    }

    /// Clean up test data.
    async fn cleanup(&self) {
        // Delete in reverse dependency order
        let _ = sqlx::query("DELETE FROM credential_request_audit WHERE tenant_id = $1")
            .bind(self.tenant_id)
            .execute(&self.admin_pool)
            .await;
        let _ = sqlx::query("DELETE FROM dynamic_credentials WHERE tenant_id = $1")
            .bind(self.tenant_id)
            .execute(&self.admin_pool)
            .await;
        let _ = sqlx::query("DELETE FROM agent_secret_permissions WHERE tenant_id = $1")
            .bind(self.tenant_id)
            .execute(&self.admin_pool)
            .await;
        let _ = sqlx::query("DELETE FROM secret_type_configurations WHERE tenant_id = $1")
            .bind(self.tenant_id)
            .execute(&self.admin_pool)
            .await;
        let _ = sqlx::query("DELETE FROM ai_agents WHERE tenant_id = $1")
            .bind(self.tenant_id)
            .execute(&self.admin_pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE tenant_id = $1")
            .bind(self.tenant_id)
            .execute(&self.admin_pool)
            .await;
        let _ = sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(self.tenant_id)
            .execute(&self.admin_pool)
            .await;
    }
}

// ============================================================================
// Rate Limiting Tests (US2)
// ============================================================================

#[tokio::test]
#[cfg_attr(not(feature = "integration"), ignore)]
async fn test_rate_limit_enforcement() {
    let ctx = if let Some(c) = CredentialTestContext::new().await { c } else {
        eprintln!("Skipping test: database not available");
        return;
    };

    // Setup test data
    let user_id = ctx.create_user().await.expect("Failed to create user");
    let agent_id = ctx
        .create_agent(user_id)
        .await
        .expect("Failed to create agent");
    let _config_id = ctx
        .create_secret_type("test-rate-limit", 5) // Low limit for testing
        .await
        .expect("Failed to create secret type");
    ctx.grant_permission(agent_id, "test-rate-limit", user_id)
        .await
        .expect("Failed to grant permission");

    // Create credential service
    let encryption = Arc::new(EncryptionService::from_env_or_generate().expect("encryption"));
    let service =
        xavyo_api_agents::services::DynamicCredentialService::new(ctx.pool.clone(), encryption);

    // Make requests up to the limit
    for i in 0..5 {
        let request = xavyo_api_agents::models::CredentialRequest {
            secret_type: "test-rate-limit".to_string(),
            ttl_seconds: Some(60),
            context: Default::default(),
        };

        let result = service
            .request_credential(ctx.tenant_id, agent_id, request, None)
            .await;

        assert!(
            result.is_ok(),
            "Request {} should succeed, got: {:?}",
            i + 1,
            result.err()
        );
    }

    // 6th request should be rate limited
    let request = xavyo_api_agents::models::CredentialRequest {
        secret_type: "test-rate-limit".to_string(),
        ttl_seconds: Some(60),
        context: Default::default(),
    };

    let result = service
        .request_credential(ctx.tenant_id, agent_id, request, None)
        .await;

    assert!(result.is_err(), "6th request should be rate limited");
    let err = result.unwrap_err();
    assert!(
        matches!(
            err,
            xavyo_api_agents::error::ApiAgentsError::CredentialRateLimitExceeded(_, _)
        ),
        "Error should be CredentialRateLimitExceeded, got: {err:?}"
    );

    // Cleanup
    ctx.cleanup().await;
}

// ============================================================================
// Permission Tests (US5)
// ============================================================================

#[tokio::test]
#[cfg_attr(not(feature = "integration"), ignore)]
async fn test_permission_denied_without_grant() {
    let ctx = if let Some(c) = CredentialTestContext::new().await { c } else {
        eprintln!("Skipping test: database not available");
        return;
    };

    // Setup test data - agent without permission
    let user_id = ctx.create_user().await.expect("Failed to create user");
    let agent_id = ctx
        .create_agent(user_id)
        .await
        .expect("Failed to create agent");
    let _config_id = ctx
        .create_secret_type("test-no-permission", 100)
        .await
        .expect("Failed to create secret type");
    // Note: NOT granting permission

    // Create credential service
    let encryption = Arc::new(EncryptionService::from_env_or_generate().expect("encryption"));
    let service =
        xavyo_api_agents::services::DynamicCredentialService::new(ctx.pool.clone(), encryption);

    // Request should be denied
    let request = xavyo_api_agents::models::CredentialRequest {
        secret_type: "test-no-permission".to_string(),
        ttl_seconds: Some(60),
        context: Default::default(),
    };

    let result = service
        .request_credential(ctx.tenant_id, agent_id, request, None)
        .await;

    assert!(result.is_err(), "Request without permission should fail");
    let err = result.unwrap_err();
    assert!(
        matches!(
            err,
            xavyo_api_agents::error::ApiAgentsError::SecretPermissionDenied(_)
        ),
        "Error should be SecretPermissionDenied, got: {err:?}"
    );

    // Cleanup
    ctx.cleanup().await;
}

#[tokio::test]
#[cfg_attr(not(feature = "integration"), ignore)]
async fn test_suspended_agent_denied() {
    let ctx = if let Some(c) = CredentialTestContext::new().await { c } else {
        eprintln!("Skipping test: database not available");
        return;
    };

    // Setup test data
    let user_id = ctx.create_user().await.expect("Failed to create user");
    let agent_id = ctx
        .create_agent(user_id)
        .await
        .expect("Failed to create agent");
    let _config_id = ctx
        .create_secret_type("test-suspended", 100)
        .await
        .expect("Failed to create secret type");
    ctx.grant_permission(agent_id, "test-suspended", user_id)
        .await
        .expect("Failed to grant permission");

    // Suspend the agent
    sqlx::query("UPDATE ai_agents SET status = 'suspended' WHERE id = $1")
        .bind(agent_id)
        .execute(&ctx.admin_pool)
        .await
        .expect("Failed to suspend agent");

    // Create credential service
    let encryption = Arc::new(EncryptionService::from_env_or_generate().expect("encryption"));
    let service =
        xavyo_api_agents::services::DynamicCredentialService::new(ctx.pool.clone(), encryption);

    // Request should be denied
    let request = xavyo_api_agents::models::CredentialRequest {
        secret_type: "test-suspended".to_string(),
        ttl_seconds: Some(60),
        context: Default::default(),
    };

    let result = service
        .request_credential(ctx.tenant_id, agent_id, request, None)
        .await;

    assert!(result.is_err(), "Request from suspended agent should fail");
    let err = result.unwrap_err();
    assert!(
        matches!(err, xavyo_api_agents::error::ApiAgentsError::AgentNotActive),
        "Error should be AgentNotActive, got: {err:?}"
    );

    // Cleanup
    ctx.cleanup().await;
}

// ============================================================================
// Secret Type Tests (US3)
// ============================================================================

#[tokio::test]
#[cfg_attr(not(feature = "integration"), ignore)]
async fn test_secret_type_not_found() {
    let ctx = if let Some(c) = CredentialTestContext::new().await { c } else {
        eprintln!("Skipping test: database not available");
        return;
    };

    // Setup test data - no secret type created
    let user_id = ctx.create_user().await.expect("Failed to create user");
    let agent_id = ctx
        .create_agent(user_id)
        .await
        .expect("Failed to create agent");

    // Create credential service
    let encryption = Arc::new(EncryptionService::from_env_or_generate().expect("encryption"));
    let service =
        xavyo_api_agents::services::DynamicCredentialService::new(ctx.pool.clone(), encryption);

    // Request for non-existent secret type
    let request = xavyo_api_agents::models::CredentialRequest {
        secret_type: "nonexistent-type".to_string(),
        ttl_seconds: Some(60),
        context: Default::default(),
    };

    let result = service
        .request_credential(ctx.tenant_id, agent_id, request, None)
        .await;

    assert!(result.is_err(), "Request for non-existent type should fail");
    let err = result.unwrap_err();
    assert!(
        matches!(
            err,
            xavyo_api_agents::error::ApiAgentsError::SecretTypeNotFound(_)
        ),
        "Error should be SecretTypeNotFound, got: {err:?}"
    );

    // Cleanup
    ctx.cleanup().await;
}

#[tokio::test]
#[cfg_attr(not(feature = "integration"), ignore)]
async fn test_disabled_secret_type_denied() {
    let ctx = if let Some(c) = CredentialTestContext::new().await { c } else {
        eprintln!("Skipping test: database not available");
        return;
    };

    // Setup test data
    let user_id = ctx.create_user().await.expect("Failed to create user");
    let agent_id = ctx
        .create_agent(user_id)
        .await
        .expect("Failed to create agent");

    // Create and disable secret type
    let config_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO secret_type_configurations
         (id, tenant_id, type_name, default_ttl_seconds, max_ttl_seconds, provider_type, rate_limit_per_hour, enabled)
         VALUES ($1, $2, 'test-disabled', 300, 3600, 'internal', 100, false)", // enabled = false
    )
    .bind(config_id)
    .bind(ctx.tenant_id)
    .execute(&ctx.admin_pool)
    .await
    .expect("Failed to create secret type");

    ctx.grant_permission(agent_id, "test-disabled", user_id)
        .await
        .expect("Failed to grant permission");

    // Create credential service
    let encryption = Arc::new(EncryptionService::from_env_or_generate().expect("encryption"));
    let service =
        xavyo_api_agents::services::DynamicCredentialService::new(ctx.pool.clone(), encryption);

    // Request should be denied
    let request = xavyo_api_agents::models::CredentialRequest {
        secret_type: "test-disabled".to_string(),
        ttl_seconds: Some(60),
        context: Default::default(),
    };

    let result = service
        .request_credential(ctx.tenant_id, agent_id, request, None)
        .await;

    assert!(result.is_err(), "Request for disabled type should fail");
    let err = result.unwrap_err();
    assert!(
        matches!(
            err,
            xavyo_api_agents::error::ApiAgentsError::SecretTypeDisabled(_)
        ),
        "Error should be SecretTypeDisabled, got: {err:?}"
    );

    // Cleanup
    ctx.cleanup().await;
}

// ============================================================================
// Successful Credential Request Test (US1)
// ============================================================================

#[tokio::test]
#[cfg_attr(not(feature = "integration"), ignore)]
async fn test_successful_credential_request() {
    let ctx = if let Some(c) = CredentialTestContext::new().await { c } else {
        eprintln!("Skipping test: database not available");
        return;
    };

    // Setup test data
    let user_id = ctx.create_user().await.expect("Failed to create user");
    let agent_id = ctx
        .create_agent(user_id)
        .await
        .expect("Failed to create agent");
    let _config_id = ctx
        .create_secret_type("test-success", 100)
        .await
        .expect("Failed to create secret type");
    ctx.grant_permission(agent_id, "test-success", user_id)
        .await
        .expect("Failed to grant permission");

    // Create credential service
    let encryption = Arc::new(EncryptionService::from_env_or_generate().expect("encryption"));
    let service =
        xavyo_api_agents::services::DynamicCredentialService::new(ctx.pool.clone(), encryption);

    // Make successful request
    let request = xavyo_api_agents::models::CredentialRequest {
        secret_type: "test-success".to_string(),
        ttl_seconds: Some(120),
        context: xavyo_api_agents::models::CredentialRequestContext {
            conversation_id: Some(Uuid::new_v4()),
            session_id: Some(Uuid::new_v4()),
            user_instruction: Some("Test credential request".to_string()),
        },
    };

    let result = service
        .request_credential(ctx.tenant_id, agent_id, request, Some("127.0.0.1"))
        .await;

    assert!(
        result.is_ok(),
        "Request should succeed, got: {:?}",
        result.err()
    );

    let (response, rate_info) = result.unwrap();

    // Verify response
    assert!(!response.credential_id.is_nil());
    assert_eq!(response.ttl_seconds, 120);
    assert_eq!(response.provider, "internal");
    assert!(response.credentials.get("username").is_some());
    assert!(response.credentials.get("password").is_some());
    assert!(response.expires_at > response.issued_at);

    // Verify rate limit info
    assert!(rate_info.remaining >= 0);
    assert!(rate_info.reset_at > chrono::Utc::now());

    // Verify audit log was created
    let audit_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM credential_request_audit WHERE tenant_id = $1 AND agent_id = $2",
    )
    .bind(ctx.tenant_id)
    .bind(agent_id)
    .fetch_one(&ctx.admin_pool)
    .await
    .expect("Failed to count audit records");

    assert_eq!(audit_count, 1, "Should have 1 audit record");

    // Verify credential was stored
    let cred_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM dynamic_credentials WHERE tenant_id = $1 AND agent_id = $2",
    )
    .bind(ctx.tenant_id)
    .bind(agent_id)
    .fetch_one(&ctx.admin_pool)
    .await
    .expect("Failed to count credentials");

    assert_eq!(cred_count, 1, "Should have 1 stored credential");

    // Cleanup
    ctx.cleanup().await;
}
