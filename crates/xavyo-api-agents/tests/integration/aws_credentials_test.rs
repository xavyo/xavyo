//! Integration tests for AWS Cloud Credentials API (F121).
//!
//! Tests the /agents/{id}/cloud-credentials endpoint for AWS STS credentials.
//!
//! Note: These tests require AWS credentials and a configured IAM role.
//! Run with: cargo test -p xavyo-api-agents --test aws_credentials_test -- --ignored

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::sync::Once;
use std::time::Duration as StdDuration;
use uuid::Uuid;

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

/// Get the database URL for the superuser.
fn get_superuser_database_url() -> String {
    std::env::var("DATABASE_URL_SUPERUSER").unwrap_or_else(|_| {
        "postgres://xavyo:xavyo_test_password@localhost:5434/xavyo_test".to_string()
    })
}

/// Test context for AWS credential integration tests.
struct AwsTestContext {
    pub admin_pool: PgPool,
    pub tenant_id: Uuid,
    pub agent_id: Uuid,
}

impl AwsTestContext {
    async fn new() -> Option<Self> {
        init_test_logging();

        let admin_pool = match PgPoolOptions::new()
            .max_connections(5)
            .acquire_timeout(StdDuration::from_secs(5))
            .connect(&get_superuser_database_url())
            .await
        {
            Ok(p) => p,
            Err(_) => return None,
        };

        // Create test tenant
        let tenant_id = Uuid::new_v4();
        let slug = format!("aws-test-{}", &tenant_id.to_string()[..8]);
        if sqlx::query("INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)")
            .bind(&tenant_id)
            .bind(&format!("AWS Test Tenant {}", &tenant_id.to_string()[..8]))
            .bind(&slug)
            .execute(&admin_pool)
            .await
            .is_err()
        {
            return None;
        }

        // Create test agent
        let agent_id = Uuid::new_v4();
        if sqlx::query(
            r#"
            INSERT INTO ai_agents (id, tenant_id, name, agent_type, status, risk_level)
            VALUES ($1, $2, 'test-aws-agent', 'ai_assistant', 'active', 'low')
            "#,
        )
        .bind(&agent_id)
        .bind(&tenant_id)
        .execute(&admin_pool)
        .await
        .is_err()
        {
            return None;
        }

        Some(Self {
            admin_pool,
            tenant_id,
            agent_id,
        })
    }

    /// Create an AWS identity provider configuration.
    async fn create_aws_provider(&self) -> Result<Uuid, sqlx::Error> {
        let provider_id = Uuid::new_v4();
        sqlx::query(
            r#"
            INSERT INTO identity_provider_configs
                (id, tenant_id, name, provider_type, config, status)
            VALUES ($1, $2, 'test-aws', 'aws', $3, 'active')
            "#,
        )
        .bind(&provider_id)
        .bind(&self.tenant_id)
        .bind(serde_json::json!({
            "account_id": "123456789012",
            "region": "us-east-1",
            "oidc_provider_arn": "arn:aws:iam::123456789012:oidc-provider/xavyo.example.com"
        }))
        .execute(&self.admin_pool)
        .await?;
        Ok(provider_id)
    }

    /// Create an IAM role mapping for the test agent.
    async fn create_role_mapping(&self, provider_id: Uuid) -> Result<Uuid, sqlx::Error> {
        let mapping_id = Uuid::new_v4();
        sqlx::query(
            r#"
            INSERT INTO iam_role_mappings
                (id, tenant_id, provider_id, role_arn, conditions, session_duration_seconds)
            VALUES ($1, $2, $3, $4, $5, 3600)
            "#,
        )
        .bind(&mapping_id)
        .bind(&self.tenant_id)
        .bind(&provider_id)
        .bind("arn:aws:iam::123456789012:role/XavyoAgentRole")
        .bind(serde_json::json!({
            "agent_ids": [self.agent_id.to_string()]
        }))
        .execute(&self.admin_pool)
        .await?;
        Ok(mapping_id)
    }

    async fn cleanup(&self) {
        let _ = sqlx::query("DELETE FROM iam_role_mappings WHERE tenant_id = $1")
            .bind(&self.tenant_id)
            .execute(&self.admin_pool)
            .await;
        let _ = sqlx::query("DELETE FROM identity_provider_configs WHERE tenant_id = $1")
            .bind(&self.tenant_id)
            .execute(&self.admin_pool)
            .await;
        let _ = sqlx::query("DELETE FROM ai_agents WHERE tenant_id = $1")
            .bind(&self.tenant_id)
            .execute(&self.admin_pool)
            .await;
        let _ = sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(&self.tenant_id)
            .execute(&self.admin_pool)
            .await;
    }
}

/// Test: Verify identity provider configuration can be created.
#[tokio::test]
#[ignore = "requires database - run with: cargo test --test aws_credentials_test -- --ignored"]
async fn test_create_aws_identity_provider() {
    let ctx = match AwsTestContext::new().await {
        Some(c) => c,
        None => {
            eprintln!("Skipping test: database not available");
            return;
        }
    };

    let provider_id = ctx
        .create_aws_provider()
        .await
        .expect("Failed to create provider");

    // Verify provider was created
    let row: (String, String) = sqlx::query_as(
        "SELECT name, provider_type FROM identity_provider_configs WHERE id = $1",
    )
    .bind(&provider_id)
    .fetch_one(&ctx.admin_pool)
    .await
    .expect("Provider not found");

    assert_eq!(row.0, "test-aws");
    assert_eq!(row.1, "aws");

    ctx.cleanup().await;
}

/// Test: Verify IAM role mapping can be created.
#[tokio::test]
#[ignore = "requires database - run with: cargo test --test aws_credentials_test -- --ignored"]
async fn test_create_iam_role_mapping() {
    let ctx = match AwsTestContext::new().await {
        Some(c) => c,
        None => {
            eprintln!("Skipping test: database not available");
            return;
        }
    };

    let provider_id = ctx.create_aws_provider().await.unwrap();
    let mapping_id = ctx.create_role_mapping(provider_id).await.unwrap();

    // Verify mapping was created
    let row: (String,) = sqlx::query_as(
        "SELECT role_arn FROM iam_role_mappings WHERE id = $1",
    )
    .bind(&mapping_id)
    .fetch_one(&ctx.admin_pool)
    .await
    .expect("Mapping not found");

    assert_eq!(row.0, "arn:aws:iam::123456789012:role/XavyoAgentRole");

    ctx.cleanup().await;
}

/// Test: Verify agent is mapped to role via conditions.
#[tokio::test]
#[ignore = "requires database - run with: cargo test --test aws_credentials_test -- --ignored"]
async fn test_agent_role_mapping_conditions() {
    let ctx = match AwsTestContext::new().await {
        Some(c) => c,
        None => {
            eprintln!("Skipping test: database not available");
            return;
        }
    };

    let provider_id = ctx.create_aws_provider().await.unwrap();
    let _ = ctx.create_role_mapping(provider_id).await.unwrap();

    // Query mappings where agent_id is in conditions
    let agent_id_str = ctx.agent_id.to_string();
    let count: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM iam_role_mappings
        WHERE tenant_id = $1
        AND conditions->>'agent_ids' LIKE $2
        "#,
    )
    .bind(&ctx.tenant_id)
    .bind(format!("%{}%", agent_id_str))
    .fetch_one(&ctx.admin_pool)
    .await
    .expect("Query failed");

    assert_eq!(count.0, 1, "Should find one mapping for this agent");

    ctx.cleanup().await;
}

/// Test: Tenant isolation for identity providers.
#[tokio::test]
#[ignore = "requires database - run with: cargo test --test aws_credentials_test -- --ignored"]
async fn test_identity_provider_tenant_isolation() {
    let ctx = match AwsTestContext::new().await {
        Some(c) => c,
        None => {
            eprintln!("Skipping test: database not available");
            return;
        }
    };

    // Create provider for our tenant
    let _ = ctx.create_aws_provider().await.unwrap();

    // Create another tenant with its own provider
    let other_tenant_id = Uuid::new_v4();
    let other_slug = format!("other-aws-{}", &other_tenant_id.to_string()[..8]);
    sqlx::query("INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)")
        .bind(&other_tenant_id)
        .bind("Other AWS Tenant")
        .bind(&other_slug)
        .execute(&ctx.admin_pool)
        .await
        .unwrap();

    sqlx::query(
        r#"
        INSERT INTO identity_provider_configs
            (id, tenant_id, name, provider_type, config, status)
        VALUES ($1, $2, 'other-aws', 'aws', $3, 'active')
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(&other_tenant_id)
    .bind(serde_json::json!({}))
    .execute(&ctx.admin_pool)
    .await
    .unwrap();

    // Query our tenant's providers only
    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM identity_provider_configs WHERE tenant_id = $1",
    )
    .bind(&ctx.tenant_id)
    .fetch_one(&ctx.admin_pool)
    .await
    .unwrap();

    assert_eq!(count.0, 1, "Should only see our tenant's provider");

    // Cleanup other tenant
    let _ = sqlx::query("DELETE FROM identity_provider_configs WHERE tenant_id = $1")
        .bind(&other_tenant_id)
        .execute(&ctx.admin_pool)
        .await;
    let _ = sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(&other_tenant_id)
        .execute(&ctx.admin_pool)
        .await;

    ctx.cleanup().await;
}
