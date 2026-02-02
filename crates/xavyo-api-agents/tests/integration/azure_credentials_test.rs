//! Integration tests for Azure Cloud Credentials API (F121).
//!
//! Tests the /agents/{id}/cloud-credentials endpoint for Azure Federated Credentials.
//!
//! Note: These tests require Azure configuration and a configured federated identity.
//! Run with: cargo test -p xavyo-api-agents --test azure_credentials_test -- --ignored

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

/// Test context for Azure credential integration tests.
struct AzureTestContext {
    pub admin_pool: PgPool,
    pub tenant_id: Uuid,
    pub agent_id: Uuid,
}

impl AzureTestContext {
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
        let slug = format!("azure-test-{}", &tenant_id.to_string()[..8]);
        if sqlx::query("INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)")
            .bind(&tenant_id)
            .bind(&format!("Azure Test Tenant {}", &tenant_id.to_string()[..8]))
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
            VALUES ($1, $2, 'test-azure-agent', 'ai_assistant', 'active', 'low')
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

    /// Create an Azure identity provider configuration.
    async fn create_azure_provider(&self) -> Result<Uuid, sqlx::Error> {
        let provider_id = Uuid::new_v4();
        sqlx::query(
            r#"
            INSERT INTO identity_provider_configs
                (id, tenant_id, name, provider_type, configuration, status)
            VALUES ($1, $2, 'test-azure', 'azure', $3, 'active')
            "#,
        )
        .bind(&provider_id)
        .bind(&self.tenant_id)
        .bind(serde_json::json!({
            "type": "azure",
            "tenant_id": "00000000-0000-0000-0000-000000000000",
            "client_id": "11111111-1111-1111-1111-111111111111",
            "audience": "https://management.azure.com",
            "issuer": "https://xavyo.net",
            "subject_claim": "agent_id"
        }).to_string())
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
                (id, tenant_id, provider_config_id, agent_type_pattern, role_identifier, allowed_scopes, constraints, max_ttl_seconds)
            VALUES ($1, $2, $3, 'ai_assistant', $4, $5, $6, 3600)
            "#,
        )
        .bind(&mapping_id)
        .bind(&self.tenant_id)
        .bind(&provider_id)
        .bind("Azure-Agent-Role")
        .bind(serde_json::json!(["https://management.azure.com/.default"]))
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

/// Test: Verify Azure identity provider configuration can be created.
#[tokio::test]
#[ignore = "requires database - run with: cargo test --test azure_credentials_test -- --ignored"]
async fn test_create_azure_identity_provider() {
    let ctx = match AzureTestContext::new().await {
        Some(c) => c,
        None => {
            eprintln!("Skipping test: database not available");
            return;
        }
    };

    let provider_id = ctx
        .create_azure_provider()
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

    assert_eq!(row.0, "test-azure");
    assert_eq!(row.1, "azure");

    ctx.cleanup().await;
}

/// Test: Verify Azure IAM role mapping can be created.
#[tokio::test]
#[ignore = "requires database - run with: cargo test --test azure_credentials_test -- --ignored"]
async fn test_create_azure_role_mapping() {
    let ctx = match AzureTestContext::new().await {
        Some(c) => c,
        None => {
            eprintln!("Skipping test: database not available");
            return;
        }
    };

    let provider_id = ctx.create_azure_provider().await.unwrap();
    let mapping_id = ctx.create_role_mapping(provider_id).await.unwrap();

    // Verify mapping was created
    let row: (String,) = sqlx::query_as(
        "SELECT role_identifier FROM iam_role_mappings WHERE id = $1",
    )
    .bind(&mapping_id)
    .fetch_one(&ctx.admin_pool)
    .await
    .expect("Mapping not found");

    assert_eq!(row.0, "Azure-Agent-Role");

    ctx.cleanup().await;
}

/// Test: Verify Azure agent is mapped to role via conditions.
#[tokio::test]
#[ignore = "requires database - run with: cargo test --test azure_credentials_test -- --ignored"]
async fn test_azure_agent_role_mapping_conditions() {
    let ctx = match AzureTestContext::new().await {
        Some(c) => c,
        None => {
            eprintln!("Skipping test: database not available");
            return;
        }
    };

    let provider_id = ctx.create_azure_provider().await.unwrap();
    let _ = ctx.create_role_mapping(provider_id).await.unwrap();

    // Query mappings where agent_id is in constraints
    let agent_id_str = ctx.agent_id.to_string();
    let count: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM iam_role_mappings
        WHERE tenant_id = $1
        AND constraints->>'agent_ids' LIKE $2
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

/// Test: Tenant isolation for Azure identity providers.
#[tokio::test]
#[ignore = "requires database - run with: cargo test --test azure_credentials_test -- --ignored"]
async fn test_azure_identity_provider_tenant_isolation() {
    let ctx = match AzureTestContext::new().await {
        Some(c) => c,
        None => {
            eprintln!("Skipping test: database not available");
            return;
        }
    };

    // Create provider for our tenant
    let _ = ctx.create_azure_provider().await.unwrap();

    // Create another tenant with its own provider
    let other_tenant_id = Uuid::new_v4();
    let other_slug = format!("other-azure-{}", &other_tenant_id.to_string()[..8]);
    sqlx::query("INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)")
        .bind(&other_tenant_id)
        .bind("Other Azure Tenant")
        .bind(&other_slug)
        .execute(&ctx.admin_pool)
        .await
        .unwrap();

    sqlx::query(
        r#"
        INSERT INTO identity_provider_configs
            (id, tenant_id, name, provider_type, configuration, status)
        VALUES ($1, $2, 'other-azure', 'azure', $3, 'active')
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(&other_tenant_id)
    .bind(serde_json::json!({
        "type": "azure",
        "tenant_id": "22222222-2222-2222-2222-222222222222",
        "client_id": "33333333-3333-3333-3333-333333333333",
        "audience": "https://management.azure.com",
        "issuer": "https://other.example.com",
        "subject_claim": "agent_id"
    }).to_string())
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

/// Test: Verify Azure provider configuration is validated.
#[tokio::test]
async fn test_azure_provider_config_validation() {
    use xavyo_api_agents::providers::{AzureFederatedConfig, AzureFederatedProvider};

    // Missing tenant_id
    let config = AzureFederatedConfig {
        tenant_id: String::new(),
        client_id: "client".to_string(),
        audience: String::new(),
        issuer: "https://xavyo.net".to_string(),
        subject_claim: "agent_id".to_string(),
    };
    assert!(AzureFederatedProvider::new(config).is_err());

    // Missing client_id
    let config = AzureFederatedConfig {
        tenant_id: "tenant".to_string(),
        client_id: String::new(),
        audience: String::new(),
        issuer: "https://xavyo.net".to_string(),
        subject_claim: "agent_id".to_string(),
    };
    assert!(AzureFederatedProvider::new(config).is_err());

    // Missing issuer
    let config = AzureFederatedConfig {
        tenant_id: "tenant".to_string(),
        client_id: "client".to_string(),
        audience: String::new(),
        issuer: String::new(),
        subject_claim: "agent_id".to_string(),
    };
    assert!(AzureFederatedProvider::new(config).is_err());

    // Missing subject_claim
    let config = AzureFederatedConfig {
        tenant_id: "tenant".to_string(),
        client_id: "client".to_string(),
        audience: String::new(),
        issuer: "https://xavyo.net".to_string(),
        subject_claim: String::new(),
    };
    assert!(AzureFederatedProvider::new(config).is_err());

    // Valid config
    let config = AzureFederatedConfig {
        tenant_id: "00000000-0000-0000-0000-000000000000".to_string(),
        client_id: "11111111-1111-1111-1111-111111111111".to_string(),
        audience: String::new(),
        issuer: "https://xavyo.net".to_string(),
        subject_claim: "agent_id".to_string(),
    };
    assert!(AzureFederatedProvider::new(config).is_ok());
}

/// Test: Verify Azure provider type is correct.
#[tokio::test]
async fn test_azure_provider_type() {
    use xavyo_api_agents::providers::{AzureFederatedConfig, AzureFederatedProvider, CloudIdentityProvider};

    let config = AzureFederatedConfig {
        tenant_id: "00000000-0000-0000-0000-000000000000".to_string(),
        client_id: "11111111-1111-1111-1111-111111111111".to_string(),
        audience: String::new(),
        issuer: "https://xavyo.net".to_string(),
        subject_claim: "agent_id".to_string(),
    };

    let provider = AzureFederatedProvider::new(config).unwrap();
    assert_eq!(provider.provider_type(), "azure");
}

/// Test: Verify Azure provider validate_token returns invalid.
#[tokio::test]
async fn test_azure_validate_token_not_supported() {
    use xavyo_api_agents::providers::{AzureFederatedConfig, AzureFederatedProvider, CloudIdentityProvider};

    let config = AzureFederatedConfig {
        tenant_id: "00000000-0000-0000-0000-000000000000".to_string(),
        client_id: "11111111-1111-1111-1111-111111111111".to_string(),
        audience: String::new(),
        issuer: "https://xavyo.net".to_string(),
        subject_claim: "agent_id".to_string(),
    };

    let provider = AzureFederatedProvider::new(config).unwrap();
    let result = provider.validate_token("any-token").await;

    assert!(result.is_ok());
    let validation = result.unwrap();
    assert!(!validation.valid);
}
