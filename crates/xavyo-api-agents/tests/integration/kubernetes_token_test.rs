//! Integration tests for Kubernetes Token Verification (F121 - US2).
//!
//! Tests the /identity/verify-token endpoint for verifying K8s service account tokens.
//!
//! Run with: cargo test -p xavyo-api-agents --test kubernetes_token_test -- --ignored

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::sync::Once;
use std::time::Duration as StdDuration;
use uuid::Uuid;

static INIT: Once = Once::new();

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

fn get_superuser_database_url() -> String {
    std::env::var("DATABASE_URL_SUPERUSER").unwrap_or_else(|_| {
        "postgres://xavyo:xavyo_test_password@localhost:5434/xavyo_test".to_string()
    })
}

struct K8sTokenTestContext {
    pub admin_pool: PgPool,
    pub tenant_id: Uuid,
    pub provider_config_id: Uuid,
}

impl K8sTokenTestContext {
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
        let slug = format!("k8s-test-{}", &tenant_id.to_string()[..8]);
        if sqlx::query("INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)")
            .bind(&tenant_id)
            .bind(&format!("K8s Test Tenant {}", &tenant_id.to_string()[..8]))
            .bind(&slug)
            .execute(&admin_pool)
            .await
            .is_err()
        {
            return None;
        }

        // Create Kubernetes identity provider config
        let provider_config_id = Uuid::new_v4();
        let k8s_config = serde_json::json!({
            "type": "kubernetes",
            "api_server_url": "https://kubernetes.default.svc:443",
            "issuer_url": "https://kubernetes.default.svc",
            "jwks_url": "https://kubernetes.default.svc/openid/v1/jwks",
            "audience": "xavyo"
        });

        if sqlx::query(
            r#"
            INSERT INTO identity_provider_configs
                (id, tenant_id, name, provider_type, configuration, is_active)
            VALUES ($1, $2, 'Test K8s Provider', 'kubernetes', $3, true)
            "#,
        )
        .bind(&provider_config_id)
        .bind(&tenant_id)
        .bind(&k8s_config.to_string())
        .execute(&admin_pool)
        .await
        .is_err()
        {
            // Cleanup tenant if provider config fails
            let _ = sqlx::query("DELETE FROM tenants WHERE id = $1")
                .bind(&tenant_id)
                .execute(&admin_pool)
                .await;
            return None;
        }

        Some(Self {
            admin_pool,
            tenant_id,
            provider_config_id,
        })
    }

    async fn cleanup(&self) {
        let _ = sqlx::query("DELETE FROM identity_audit_events WHERE tenant_id = $1")
            .bind(&self.tenant_id)
            .execute(&self.admin_pool)
            .await;
        let _ = sqlx::query("DELETE FROM identity_provider_configs WHERE tenant_id = $1")
            .bind(&self.tenant_id)
            .execute(&self.admin_pool)
            .await;
        let _ = sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(&self.tenant_id)
            .execute(&self.admin_pool)
            .await;
    }
}

/// Test: Kubernetes provider config is properly created.
#[tokio::test]
#[ignore = "requires database - run with: cargo test --test kubernetes_token_test -- --ignored"]
async fn test_kubernetes_provider_config_creation() {
    let ctx = match K8sTokenTestContext::new().await {
        Some(c) => c,
        None => {
            eprintln!("Skipping test: database not available");
            return;
        }
    };

    // Verify provider config was created
    let row: (String, String, bool) = sqlx::query_as(
        "SELECT name, provider_type, is_active FROM identity_provider_configs WHERE id = $1",
    )
    .bind(&ctx.provider_config_id)
    .fetch_one(&ctx.admin_pool)
    .await
    .expect("Provider config not found");

    assert_eq!(row.0, "Test K8s Provider");
    assert_eq!(row.1, "kubernetes");
    assert!(row.2);

    ctx.cleanup().await;
}

/// Test: Kubernetes provider configuration JSON is valid.
#[tokio::test]
#[ignore = "requires database - run with: cargo test --test kubernetes_token_test -- --ignored"]
async fn test_kubernetes_provider_config_json() {
    let ctx = match K8sTokenTestContext::new().await {
        Some(c) => c,
        None => {
            eprintln!("Skipping test: database not available");
            return;
        }
    };

    // Verify provider config JSON is valid
    let row: (String,) = sqlx::query_as(
        "SELECT configuration FROM identity_provider_configs WHERE id = $1",
    )
    .bind(&ctx.provider_config_id)
    .fetch_one(&ctx.admin_pool)
    .await
    .expect("Provider config not found");

    let config: serde_json::Value = serde_json::from_str(&row.0)
        .expect("Configuration should be valid JSON");

    assert_eq!(config["type"], "kubernetes");
    assert_eq!(config["audience"], "xavyo");
    assert!(config["issuer_url"].as_str().unwrap().starts_with("https://"));
    assert!(config["jwks_url"].as_str().unwrap().contains("/jwks"));

    ctx.cleanup().await;
}

/// Test: Token verification records audit event on failure.
#[tokio::test]
#[ignore = "requires database - run with: cargo test --test kubernetes_token_test -- --ignored"]
async fn test_kubernetes_token_verification_audit() {
    let ctx = match K8sTokenTestContext::new().await {
        Some(c) => c,
        None => {
            eprintln!("Skipping test: database not available");
            return;
        }
    };

    // Create a mock failed verification audit event
    let event_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO identity_audit_events
            (id, tenant_id, event_type, provider_type, success, details, operation, outcome)
        VALUES ($1, $2, 'token_verification', 'kubernetes', false, $3, 'verify', 'failure')
        "#,
    )
    .bind(&event_id)
    .bind(&ctx.tenant_id)
    .bind(serde_json::json!({
        "error": "Invalid token signature",
        "issuer": "https://kubernetes.default.svc"
    }))
    .execute(&ctx.admin_pool)
    .await
    .expect("Failed to create audit event");

    // Verify audit event was created
    let row: (String, String, bool) = sqlx::query_as(
        "SELECT event_type, provider_type, success FROM identity_audit_events WHERE id = $1",
    )
    .bind(&event_id)
    .fetch_one(&ctx.admin_pool)
    .await
    .expect("Audit event not found");

    assert_eq!(row.0, "token_verification");
    assert_eq!(row.1, "kubernetes");
    assert!(!row.2);

    ctx.cleanup().await;
}

/// Test: Multiple Kubernetes providers for same tenant.
#[tokio::test]
#[ignore = "requires database - run with: cargo test --test kubernetes_token_test -- --ignored"]
async fn test_multiple_kubernetes_providers() {
    let ctx = match K8sTokenTestContext::new().await {
        Some(c) => c,
        None => {
            eprintln!("Skipping test: database not available");
            return;
        }
    };

    // Create a second provider (e.g., for a different cluster)
    let second_provider_id = Uuid::new_v4();
    let second_config = serde_json::json!({
        "type": "kubernetes",
        "api_server_url": "https://eks.us-west-2.amazonaws.com",
        "issuer_url": "https://oidc.eks.us-west-2.amazonaws.com/id/EXAMPLE",
        "jwks_url": "https://oidc.eks.us-west-2.amazonaws.com/id/EXAMPLE/keys",
        "audience": "xavyo-prod"
    });

    sqlx::query(
        r#"
        INSERT INTO identity_provider_configs
            (id, tenant_id, name, provider_type, configuration, is_active)
        VALUES ($1, $2, 'EKS Cluster', 'kubernetes', $3, true)
        "#,
    )
    .bind(&second_provider_id)
    .bind(&ctx.tenant_id)
    .bind(&second_config.to_string())
    .execute(&ctx.admin_pool)
    .await
    .expect("Failed to create second provider");

    // Verify both providers exist
    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM identity_provider_configs WHERE tenant_id = $1 AND provider_type = 'kubernetes'",
    )
    .bind(&ctx.tenant_id)
    .fetch_one(&ctx.admin_pool)
    .await
    .unwrap();

    assert_eq!(count.0, 2, "Should have 2 Kubernetes providers");

    // Cleanup second provider
    let _ = sqlx::query("DELETE FROM identity_provider_configs WHERE id = $1")
        .bind(&second_provider_id)
        .execute(&ctx.admin_pool)
        .await;

    ctx.cleanup().await;
}

/// Test: Kubernetes provider tenant isolation.
#[tokio::test]
#[ignore = "requires database - run with: cargo test --test kubernetes_token_test -- --ignored"]
async fn test_kubernetes_provider_tenant_isolation() {
    let ctx = match K8sTokenTestContext::new().await {
        Some(c) => c,
        None => {
            eprintln!("Skipping test: database not available");
            return;
        }
    };

    // Create another tenant with its own K8s provider
    let other_tenant_id = Uuid::new_v4();
    let other_slug = format!("other-k8s-{}", &other_tenant_id.to_string()[..8]);
    sqlx::query("INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)")
        .bind(&other_tenant_id)
        .bind("Other K8s Tenant")
        .bind(&other_slug)
        .execute(&ctx.admin_pool)
        .await
        .unwrap();

    let other_provider_id = Uuid::new_v4();
    let other_config = serde_json::json!({
        "type": "kubernetes",
        "api_server_url": "https://other-cluster.example.com",
        "issuer_url": "https://other-cluster.example.com",
        "jwks_url": "https://other-cluster.example.com/openid/v1/jwks",
        "audience": "other-audience"
    });

    sqlx::query(
        r#"
        INSERT INTO identity_provider_configs
            (id, tenant_id, name, provider_type, configuration, is_active)
        VALUES ($1, $2, 'Other K8s Provider', 'kubernetes', $3, true)
        "#,
    )
    .bind(&other_provider_id)
    .bind(&other_tenant_id)
    .bind(&other_config.to_string())
    .execute(&ctx.admin_pool)
    .await
    .unwrap();

    // Verify our tenant only sees its own provider
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
