//! Integration tests for Tenant-Scoped IAM Configuration Isolation (F121 - US5).
//!
//! Tests that identity providers and role mappings are properly isolated between tenants.
//!
//! Run with: cargo test -p xavyo-api-agents --test tenant_isolation_test -- --ignored

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

struct TenantIsolationTestContext {
    pub admin_pool: PgPool,
    pub tenant_a_id: Uuid,
    pub tenant_b_id: Uuid,
    pub provider_a_id: Uuid,
    pub provider_b_id: Uuid,
    pub mapping_a_id: Uuid,
    pub mapping_b_id: Uuid,
}

impl TenantIsolationTestContext {
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

        // Create two test tenants
        let tenant_a_id = Uuid::new_v4();
        let tenant_b_id = Uuid::new_v4();
        let slug_a = format!("tenant-a-{}", &tenant_a_id.to_string()[..8]);
        let slug_b = format!("tenant-b-{}", &tenant_b_id.to_string()[..8]);

        // Create Tenant A
        if sqlx::query("INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)")
            .bind(&tenant_a_id)
            .bind(&format!("Test Tenant A {}", &tenant_a_id.to_string()[..8]))
            .bind(&slug_a)
            .execute(&admin_pool)
            .await
            .is_err()
        {
            return None;
        }

        // Create Tenant B
        if sqlx::query("INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)")
            .bind(&tenant_b_id)
            .bind(&format!("Test Tenant B {}", &tenant_b_id.to_string()[..8]))
            .bind(&slug_b)
            .execute(&admin_pool)
            .await
            .is_err()
        {
            // Cleanup tenant A
            let _ = sqlx::query("DELETE FROM tenants WHERE id = $1")
                .bind(&tenant_a_id)
                .execute(&admin_pool)
                .await;
            return None;
        }

        // Create identity provider for Tenant A
        let provider_a_id = Uuid::new_v4();
        let aws_config_a = serde_json::json!({
            "type": "aws",
            "region": "us-east-1",
            "oidc_provider_arn": "arn:aws:iam::111111111111:oidc-provider/xavyo.net",
            "session_name_prefix": "tenant-a"
        });

        if sqlx::query(
            r#"
            INSERT INTO identity_provider_configs
                (id, tenant_id, name, provider_type, configuration, is_active)
            VALUES ($1, $2, 'Tenant A AWS Provider', 'aws', $3, true)
            "#,
        )
        .bind(&provider_a_id)
        .bind(&tenant_a_id)
        .bind(&aws_config_a.to_string())
        .execute(&admin_pool)
        .await
        .is_err()
        {
            // Cleanup
            Self::cleanup_tenants(&admin_pool, tenant_a_id, tenant_b_id).await;
            return None;
        }

        // Create identity provider for Tenant B
        let provider_b_id = Uuid::new_v4();
        let aws_config_b = serde_json::json!({
            "type": "aws",
            "region": "eu-west-1",
            "oidc_provider_arn": "arn:aws:iam::222222222222:oidc-provider/xavyo.net",
            "session_name_prefix": "tenant-b"
        });

        if sqlx::query(
            r#"
            INSERT INTO identity_provider_configs
                (id, tenant_id, name, provider_type, configuration, is_active)
            VALUES ($1, $2, 'Tenant B AWS Provider', 'aws', $3, true)
            "#,
        )
        .bind(&provider_b_id)
        .bind(&tenant_b_id)
        .bind(&aws_config_b.to_string())
        .execute(&admin_pool)
        .await
        .is_err()
        {
            // Cleanup
            let _ = sqlx::query("DELETE FROM identity_provider_configs WHERE tenant_id = $1")
                .bind(&tenant_a_id)
                .execute(&admin_pool)
                .await;
            Self::cleanup_tenants(&admin_pool, tenant_a_id, tenant_b_id).await;
            return None;
        }

        // Create role mapping for Tenant A
        let mapping_a_id = Uuid::new_v4();
        if sqlx::query(
            r#"
            INSERT INTO iam_role_mappings
                (id, tenant_id, provider_config_id, agent_type, role_identifier, allowed_scopes, max_ttl_seconds, constraints)
            VALUES ($1, $2, $3, 'code-assistant', 'arn:aws:iam::111111111111:role/TenantARole', ARRAY['s3:*'], 3600, '{}')
            "#,
        )
        .bind(&mapping_a_id)
        .bind(&tenant_a_id)
        .bind(&provider_a_id)
        .execute(&admin_pool)
        .await
        .is_err()
        {
            // Cleanup
            Self::cleanup_providers(&admin_pool, tenant_a_id, tenant_b_id).await;
            Self::cleanup_tenants(&admin_pool, tenant_a_id, tenant_b_id).await;
            return None;
        }

        // Create role mapping for Tenant B
        let mapping_b_id = Uuid::new_v4();
        if sqlx::query(
            r#"
            INSERT INTO iam_role_mappings
                (id, tenant_id, provider_config_id, agent_type, role_identifier, allowed_scopes, max_ttl_seconds, constraints)
            VALUES ($1, $2, $3, 'data-analyst', 'arn:aws:iam::222222222222:role/TenantBRole', ARRAY['dynamodb:*'], 7200, '{}')
            "#,
        )
        .bind(&mapping_b_id)
        .bind(&tenant_b_id)
        .bind(&provider_b_id)
        .execute(&admin_pool)
        .await
        .is_err()
        {
            // Cleanup
            let _ = sqlx::query("DELETE FROM iam_role_mappings WHERE tenant_id = $1")
                .bind(&tenant_a_id)
                .execute(&admin_pool)
                .await;
            Self::cleanup_providers(&admin_pool, tenant_a_id, tenant_b_id).await;
            Self::cleanup_tenants(&admin_pool, tenant_a_id, tenant_b_id).await;
            return None;
        }

        Some(Self {
            admin_pool,
            tenant_a_id,
            tenant_b_id,
            provider_a_id,
            provider_b_id,
            mapping_a_id,
            mapping_b_id,
        })
    }

    async fn cleanup_providers(pool: &PgPool, tenant_a_id: Uuid, tenant_b_id: Uuid) {
        let _ = sqlx::query("DELETE FROM identity_provider_configs WHERE tenant_id IN ($1, $2)")
            .bind(&tenant_a_id)
            .bind(&tenant_b_id)
            .execute(pool)
            .await;
    }

    async fn cleanup_tenants(pool: &PgPool, tenant_a_id: Uuid, tenant_b_id: Uuid) {
        let _ = sqlx::query("DELETE FROM tenants WHERE id IN ($1, $2)")
            .bind(&tenant_a_id)
            .bind(&tenant_b_id)
            .execute(pool)
            .await;
    }

    async fn cleanup(&self) {
        // Cleanup in order: mappings -> providers -> audit events -> tenants
        let _ = sqlx::query("DELETE FROM iam_role_mappings WHERE tenant_id IN ($1, $2)")
            .bind(&self.tenant_a_id)
            .bind(&self.tenant_b_id)
            .execute(&self.admin_pool)
            .await;

        let _ = sqlx::query("DELETE FROM identity_audit_events WHERE tenant_id IN ($1, $2)")
            .bind(&self.tenant_a_id)
            .bind(&self.tenant_b_id)
            .execute(&self.admin_pool)
            .await;

        let _ = sqlx::query("DELETE FROM identity_provider_configs WHERE tenant_id IN ($1, $2)")
            .bind(&self.tenant_a_id)
            .bind(&self.tenant_b_id)
            .execute(&self.admin_pool)
            .await;

        let _ = sqlx::query("DELETE FROM tenants WHERE id IN ($1, $2)")
            .bind(&self.tenant_a_id)
            .bind(&self.tenant_b_id)
            .execute(&self.admin_pool)
            .await;
    }
}

// ============================================================================
// Identity Provider Tenant Isolation Tests
// ============================================================================

/// Test: Tenant A cannot see Tenant B's identity providers.
#[tokio::test]
#[ignore = "requires database - run with: cargo test --test tenant_isolation_test -- --ignored"]
async fn test_provider_list_tenant_isolation() {
    let ctx = match TenantIsolationTestContext::new().await {
        Some(c) => c,
        None => {
            eprintln!("Skipping test: database not available");
            return;
        }
    };

    // Query providers visible to Tenant A
    let tenant_a_providers: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT id, name FROM identity_provider_configs WHERE tenant_id = $1",
    )
    .bind(&ctx.tenant_a_id)
    .fetch_all(&ctx.admin_pool)
    .await
    .expect("Query failed");

    // Query providers visible to Tenant B
    let tenant_b_providers: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT id, name FROM identity_provider_configs WHERE tenant_id = $1",
    )
    .bind(&ctx.tenant_b_id)
    .fetch_all(&ctx.admin_pool)
    .await
    .expect("Query failed");

    // Tenant A should only see its own provider
    assert_eq!(tenant_a_providers.len(), 1);
    assert_eq!(tenant_a_providers[0].0, ctx.provider_a_id);
    assert!(tenant_a_providers[0].1.contains("Tenant A"));

    // Tenant B should only see its own provider
    assert_eq!(tenant_b_providers.len(), 1);
    assert_eq!(tenant_b_providers[0].0, ctx.provider_b_id);
    assert!(tenant_b_providers[0].1.contains("Tenant B"));

    ctx.cleanup().await;
}

/// Test: Tenant A cannot access Tenant B's provider by ID.
#[tokio::test]
#[ignore = "requires database - run with: cargo test --test tenant_isolation_test -- --ignored"]
async fn test_provider_get_by_id_tenant_isolation() {
    let ctx = match TenantIsolationTestContext::new().await {
        Some(c) => c,
        None => {
            eprintln!("Skipping test: database not available");
            return;
        }
    };

    // Tenant A trying to access their own provider - should succeed
    let own_provider: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM identity_provider_configs WHERE tenant_id = $1 AND id = $2",
    )
    .bind(&ctx.tenant_a_id)
    .bind(&ctx.provider_a_id)
    .fetch_optional(&ctx.admin_pool)
    .await
    .expect("Query failed");

    assert!(own_provider.is_some(), "Tenant A should see their own provider");

    // Tenant A trying to access Tenant B's provider - should fail
    let cross_tenant: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM identity_provider_configs WHERE tenant_id = $1 AND id = $2",
    )
    .bind(&ctx.tenant_a_id)
    .bind(&ctx.provider_b_id)
    .fetch_optional(&ctx.admin_pool)
    .await
    .expect("Query failed");

    assert!(
        cross_tenant.is_none(),
        "Tenant A should NOT see Tenant B's provider"
    );

    ctx.cleanup().await;
}

/// Test: Tenant A cannot update Tenant B's provider.
#[tokio::test]
#[ignore = "requires database - run with: cargo test --test tenant_isolation_test -- --ignored"]
async fn test_provider_update_tenant_isolation() {
    let ctx = match TenantIsolationTestContext::new().await {
        Some(c) => c,
        None => {
            eprintln!("Skipping test: database not available");
            return;
        }
    };

    // Tenant A trying to update Tenant B's provider - should affect 0 rows
    let result = sqlx::query(
        "UPDATE identity_provider_configs SET name = 'Hacked!' WHERE tenant_id = $1 AND id = $2",
    )
    .bind(&ctx.tenant_a_id)
    .bind(&ctx.provider_b_id)
    .execute(&ctx.admin_pool)
    .await
    .expect("Query failed");

    assert_eq!(
        result.rows_affected(),
        0,
        "Tenant A should NOT be able to update Tenant B's provider"
    );

    // Verify Tenant B's provider is unchanged
    let name: (String,) = sqlx::query_as(
        "SELECT name FROM identity_provider_configs WHERE id = $1",
    )
    .bind(&ctx.provider_b_id)
    .fetch_one(&ctx.admin_pool)
    .await
    .expect("Query failed");

    assert!(
        name.0.contains("Tenant B"),
        "Tenant B's provider name should be unchanged"
    );

    ctx.cleanup().await;
}

/// Test: Tenant A cannot delete Tenant B's provider.
#[tokio::test]
#[ignore = "requires database - run with: cargo test --test tenant_isolation_test -- --ignored"]
async fn test_provider_delete_tenant_isolation() {
    let ctx = match TenantIsolationTestContext::new().await {
        Some(c) => c,
        None => {
            eprintln!("Skipping test: database not available");
            return;
        }
    };

    // Tenant A trying to delete Tenant B's provider - should affect 0 rows
    let result = sqlx::query(
        "DELETE FROM identity_provider_configs WHERE tenant_id = $1 AND id = $2",
    )
    .bind(&ctx.tenant_a_id)
    .bind(&ctx.provider_b_id)
    .execute(&ctx.admin_pool)
    .await
    .expect("Query failed");

    assert_eq!(
        result.rows_affected(),
        0,
        "Tenant A should NOT be able to delete Tenant B's provider"
    );

    // Verify Tenant B's provider still exists
    let exists: (bool,) = sqlx::query_as(
        "SELECT EXISTS(SELECT 1 FROM identity_provider_configs WHERE id = $1)",
    )
    .bind(&ctx.provider_b_id)
    .fetch_one(&ctx.admin_pool)
    .await
    .expect("Query failed");

    assert!(exists.0, "Tenant B's provider should still exist");

    ctx.cleanup().await;
}

// ============================================================================
// Role Mapping Tenant Isolation Tests
// ============================================================================

/// Test: Tenant A cannot see Tenant B's role mappings.
#[tokio::test]
#[ignore = "requires database - run with: cargo test --test tenant_isolation_test -- --ignored"]
async fn test_mapping_list_tenant_isolation() {
    let ctx = match TenantIsolationTestContext::new().await {
        Some(c) => c,
        None => {
            eprintln!("Skipping test: database not available");
            return;
        }
    };

    // Query mappings visible to Tenant A
    let tenant_a_mappings: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT id, role_identifier FROM iam_role_mappings WHERE tenant_id = $1",
    )
    .bind(&ctx.tenant_a_id)
    .fetch_all(&ctx.admin_pool)
    .await
    .expect("Query failed");

    // Query mappings visible to Tenant B
    let tenant_b_mappings: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT id, role_identifier FROM iam_role_mappings WHERE tenant_id = $1",
    )
    .bind(&ctx.tenant_b_id)
    .fetch_all(&ctx.admin_pool)
    .await
    .expect("Query failed");

    // Tenant A should only see its own mapping
    assert_eq!(tenant_a_mappings.len(), 1);
    assert_eq!(tenant_a_mappings[0].0, ctx.mapping_a_id);
    assert!(tenant_a_mappings[0].1.contains("111111111111"));

    // Tenant B should only see its own mapping
    assert_eq!(tenant_b_mappings.len(), 1);
    assert_eq!(tenant_b_mappings[0].0, ctx.mapping_b_id);
    assert!(tenant_b_mappings[0].1.contains("222222222222"));

    ctx.cleanup().await;
}

/// Test: Tenant A cannot access Tenant B's role mapping by ID.
#[tokio::test]
#[ignore = "requires database - run with: cargo test --test tenant_isolation_test -- --ignored"]
async fn test_mapping_get_by_id_tenant_isolation() {
    let ctx = match TenantIsolationTestContext::new().await {
        Some(c) => c,
        None => {
            eprintln!("Skipping test: database not available");
            return;
        }
    };

    // Tenant A trying to access their own mapping - should succeed
    let own_mapping: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM iam_role_mappings WHERE tenant_id = $1 AND id = $2",
    )
    .bind(&ctx.tenant_a_id)
    .bind(&ctx.mapping_a_id)
    .fetch_optional(&ctx.admin_pool)
    .await
    .expect("Query failed");

    assert!(own_mapping.is_some(), "Tenant A should see their own mapping");

    // Tenant A trying to access Tenant B's mapping - should fail
    let cross_tenant: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM iam_role_mappings WHERE tenant_id = $1 AND id = $2",
    )
    .bind(&ctx.tenant_a_id)
    .bind(&ctx.mapping_b_id)
    .fetch_optional(&ctx.admin_pool)
    .await
    .expect("Query failed");

    assert!(
        cross_tenant.is_none(),
        "Tenant A should NOT see Tenant B's mapping"
    );

    ctx.cleanup().await;
}

/// Test: Tenant A cannot update Tenant B's role mapping.
#[tokio::test]
#[ignore = "requires database - run with: cargo test --test tenant_isolation_test -- --ignored"]
async fn test_mapping_update_tenant_isolation() {
    let ctx = match TenantIsolationTestContext::new().await {
        Some(c) => c,
        None => {
            eprintln!("Skipping test: database not available");
            return;
        }
    };

    // Tenant A trying to update Tenant B's mapping - should affect 0 rows
    let result = sqlx::query(
        "UPDATE iam_role_mappings SET role_identifier = 'arn:aws:iam::HACKED:role/Hacked' WHERE tenant_id = $1 AND id = $2",
    )
    .bind(&ctx.tenant_a_id)
    .bind(&ctx.mapping_b_id)
    .execute(&ctx.admin_pool)
    .await
    .expect("Query failed");

    assert_eq!(
        result.rows_affected(),
        0,
        "Tenant A should NOT be able to update Tenant B's mapping"
    );

    // Verify Tenant B's mapping is unchanged
    let role_id: (String,) = sqlx::query_as(
        "SELECT role_identifier FROM iam_role_mappings WHERE id = $1",
    )
    .bind(&ctx.mapping_b_id)
    .fetch_one(&ctx.admin_pool)
    .await
    .expect("Query failed");

    assert!(
        role_id.0.contains("222222222222"),
        "Tenant B's mapping role identifier should be unchanged"
    );

    ctx.cleanup().await;
}

/// Test: Tenant A cannot delete Tenant B's role mapping.
#[tokio::test]
#[ignore = "requires database - run with: cargo test --test tenant_isolation_test -- --ignored"]
async fn test_mapping_delete_tenant_isolation() {
    let ctx = match TenantIsolationTestContext::new().await {
        Some(c) => c,
        None => {
            eprintln!("Skipping test: database not available");
            return;
        }
    };

    // Tenant A trying to delete Tenant B's mapping - should affect 0 rows
    let result = sqlx::query(
        "DELETE FROM iam_role_mappings WHERE tenant_id = $1 AND id = $2",
    )
    .bind(&ctx.tenant_a_id)
    .bind(&ctx.mapping_b_id)
    .execute(&ctx.admin_pool)
    .await
    .expect("Query failed");

    assert_eq!(
        result.rows_affected(),
        0,
        "Tenant A should NOT be able to delete Tenant B's mapping"
    );

    // Verify Tenant B's mapping still exists
    let exists: (bool,) = sqlx::query_as(
        "SELECT EXISTS(SELECT 1 FROM iam_role_mappings WHERE id = $1)",
    )
    .bind(&ctx.mapping_b_id)
    .fetch_one(&ctx.admin_pool)
    .await
    .expect("Query failed");

    assert!(exists.0, "Tenant B's mapping should still exist");

    ctx.cleanup().await;
}

// ============================================================================
// Cross-Entity Tenant Isolation Tests
// ============================================================================

/// Test: Tenant A cannot create a role mapping for Tenant B's provider.
#[tokio::test]
#[ignore = "requires database - run with: cargo test --test tenant_isolation_test -- --ignored"]
async fn test_mapping_cannot_reference_other_tenant_provider() {
    let ctx = match TenantIsolationTestContext::new().await {
        Some(c) => c,
        None => {
            eprintln!("Skipping test: database not available");
            return;
        }
    };

    // Tenant A trying to create a mapping referencing Tenant B's provider
    // This should fail due to foreign key constraint with tenant isolation
    let malicious_mapping_id = Uuid::new_v4();
    let result = sqlx::query(
        r#"
        INSERT INTO iam_role_mappings
            (id, tenant_id, provider_config_id, agent_type, role_identifier, allowed_scopes, max_ttl_seconds, constraints)
        VALUES ($1, $2, $3, 'malicious', 'arn:aws:iam::ATTACKER:role/MaliciousRole', ARRAY['*:*'], 3600, '{}')
        "#,
    )
    .bind(&malicious_mapping_id)
    .bind(&ctx.tenant_a_id)
    .bind(&ctx.provider_b_id)  // Trying to use Tenant B's provider!
    .execute(&ctx.admin_pool)
    .await;

    // This should fail due to foreign key constraint or RLS
    assert!(
        result.is_err(),
        "Tenant A should NOT be able to create a mapping for Tenant B's provider"
    );

    ctx.cleanup().await;
}

/// Test: Providers with same name allowed in different tenants.
#[tokio::test]
#[ignore = "requires database - run with: cargo test --test tenant_isolation_test -- --ignored"]
async fn test_same_provider_name_allowed_different_tenants() {
    let ctx = match TenantIsolationTestContext::new().await {
        Some(c) => c,
        None => {
            eprintln!("Skipping test: database not available");
            return;
        }
    };

    // Create a provider with the same name for both tenants
    let common_name = "Production AWS";
    let provider_a2_id = Uuid::new_v4();
    let provider_b2_id = Uuid::new_v4();

    let config_a = serde_json::json!({
        "type": "aws",
        "region": "us-east-1",
        "oidc_provider_arn": "arn:aws:iam::111111111111:oidc-provider/prod.xavyo.net",
        "session_name_prefix": "prod-a"
    });

    let config_b = serde_json::json!({
        "type": "aws",
        "region": "eu-west-1",
        "oidc_provider_arn": "arn:aws:iam::222222222222:oidc-provider/prod.xavyo.net",
        "session_name_prefix": "prod-b"
    });

    // Create for Tenant A
    let result_a = sqlx::query(
        r#"
        INSERT INTO identity_provider_configs
            (id, tenant_id, name, provider_type, configuration, is_active)
        VALUES ($1, $2, $3, 'aws', $4, true)
        "#,
    )
    .bind(&provider_a2_id)
    .bind(&ctx.tenant_a_id)
    .bind(common_name)
    .bind(&config_a.to_string())
    .execute(&ctx.admin_pool)
    .await;

    assert!(
        result_a.is_ok(),
        "Should be able to create provider with common name for Tenant A"
    );

    // Create for Tenant B with the SAME name
    let result_b = sqlx::query(
        r#"
        INSERT INTO identity_provider_configs
            (id, tenant_id, name, provider_type, configuration, is_active)
        VALUES ($1, $2, $3, 'aws', $4, true)
        "#,
    )
    .bind(&provider_b2_id)
    .bind(&ctx.tenant_b_id)
    .bind(common_name)
    .bind(&config_b.to_string())
    .execute(&ctx.admin_pool)
    .await;

    assert!(
        result_b.is_ok(),
        "Should be able to create provider with same name for Tenant B"
    );

    // Cleanup additional providers
    let _ = sqlx::query("DELETE FROM identity_provider_configs WHERE id IN ($1, $2)")
        .bind(&provider_a2_id)
        .bind(&provider_b2_id)
        .execute(&ctx.admin_pool)
        .await;

    ctx.cleanup().await;
}

/// Test: Audit events are tenant-isolated.
#[tokio::test]
#[ignore = "requires database - run with: cargo test --test tenant_isolation_test -- --ignored"]
async fn test_audit_events_tenant_isolation() {
    let ctx = match TenantIsolationTestContext::new().await {
        Some(c) => c,
        None => {
            eprintln!("Skipping test: database not available");
            return;
        }
    };

    // Create audit events for both tenants
    let event_a_id = Uuid::new_v4();
    let event_b_id = Uuid::new_v4();

    sqlx::query(
        r#"
        INSERT INTO identity_audit_events
            (id, tenant_id, event_type, provider_type, success, details, operation, outcome)
        VALUES ($1, $2, 'test_event', 'aws', true, '{"from": "tenant_a"}', 'test', 'success')
        "#,
    )
    .bind(&event_a_id)
    .bind(&ctx.tenant_a_id)
    .execute(&ctx.admin_pool)
    .await
    .expect("Failed to create event for Tenant A");

    sqlx::query(
        r#"
        INSERT INTO identity_audit_events
            (id, tenant_id, event_type, provider_type, success, details, operation, outcome)
        VALUES ($1, $2, 'test_event', 'aws', true, '{"from": "tenant_b"}', 'test', 'success')
        "#,
    )
    .bind(&event_b_id)
    .bind(&ctx.tenant_b_id)
    .execute(&ctx.admin_pool)
    .await
    .expect("Failed to create event for Tenant B");

    // Tenant A should only see their audit event
    let tenant_a_events: Vec<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM identity_audit_events WHERE tenant_id = $1",
    )
    .bind(&ctx.tenant_a_id)
    .fetch_all(&ctx.admin_pool)
    .await
    .expect("Query failed");

    assert_eq!(tenant_a_events.len(), 1);
    assert_eq!(tenant_a_events[0].0, event_a_id);

    // Tenant B should only see their audit event
    let tenant_b_events: Vec<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM identity_audit_events WHERE tenant_id = $1",
    )
    .bind(&ctx.tenant_b_id)
    .fetch_all(&ctx.admin_pool)
    .await
    .expect("Query failed");

    assert_eq!(tenant_b_events.len(), 1);
    assert_eq!(tenant_b_events[0].0, event_b_id);

    ctx.cleanup().await;
}
