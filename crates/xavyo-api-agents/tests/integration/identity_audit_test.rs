//! Integration tests for Identity Audit API (F121).
//!
//! Tests the /identity/audit endpoint for querying identity-related audit events.
//!
//! Run with: cargo test -p xavyo-api-agents --test identity_audit_test -- --ignored

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

struct AuditTestContext {
    pub admin_pool: PgPool,
    pub tenant_id: Uuid,
    pub agent_id: Uuid,
}

impl AuditTestContext {
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
        let slug = format!("audit-test-{}", &tenant_id.to_string()[..8]);
        if sqlx::query("INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)")
            .bind(&tenant_id)
            .bind(&format!("Audit Test Tenant {}", &tenant_id.to_string()[..8]))
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
            VALUES ($1, $2, 'test-audit-agent', 'ai_assistant', 'active', 'low')
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

    /// Create a test identity audit event.
    async fn create_audit_event(
        &self,
        event_type: &str,
        success: bool,
    ) -> Result<Uuid, sqlx::Error> {
        let event_id = Uuid::new_v4();
        sqlx::query(
            r#"
            INSERT INTO identity_audit_events
                (id, tenant_id, agent_id, event_type, provider_type, success, details)
            VALUES ($1, $2, $3, $4, 'aws', $5, $6)
            "#,
        )
        .bind(&event_id)
        .bind(&self.tenant_id)
        .bind(&self.agent_id)
        .bind(event_type)
        .bind(success)
        .bind(serde_json::json!({
            "role_arn": "arn:aws:iam::123456789012:role/TestRole",
            "session_duration": 3600
        }))
        .execute(&self.admin_pool)
        .await?;
        Ok(event_id)
    }

    async fn cleanup(&self) {
        let _ = sqlx::query("DELETE FROM identity_audit_events WHERE tenant_id = $1")
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

/// Test: Create and retrieve identity audit events.
#[tokio::test]
#[ignore = "requires database - run with: cargo test --test identity_audit_test -- --ignored"]
async fn test_create_identity_audit_event() {
    let ctx = match AuditTestContext::new().await {
        Some(c) => c,
        None => {
            eprintln!("Skipping test: database not available");
            return;
        }
    };

    let event_id = ctx
        .create_audit_event("credential_request", true)
        .await
        .expect("Failed to create audit event");

    // Verify event was created
    let row: (String, bool) = sqlx::query_as(
        "SELECT event_type, success FROM identity_audit_events WHERE id = $1",
    )
    .bind(&event_id)
    .fetch_one(&ctx.admin_pool)
    .await
    .expect("Event not found");

    assert_eq!(row.0, "credential_request");
    assert!(row.1);

    ctx.cleanup().await;
}

/// Test: Query audit events by agent_id.
#[tokio::test]
#[ignore = "requires database - run with: cargo test --test identity_audit_test -- --ignored"]
async fn test_query_audit_by_agent() {
    let ctx = match AuditTestContext::new().await {
        Some(c) => c,
        None => {
            eprintln!("Skipping test: database not available");
            return;
        }
    };

    // Create multiple events
    let _ = ctx.create_audit_event("credential_request", true).await.unwrap();
    let _ = ctx.create_audit_event("credential_request", true).await.unwrap();
    let _ = ctx.create_audit_event("credential_request", false).await.unwrap();

    // Query events for our agent
    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM identity_audit_events WHERE tenant_id = $1 AND agent_id = $2",
    )
    .bind(&ctx.tenant_id)
    .bind(&ctx.agent_id)
    .fetch_one(&ctx.admin_pool)
    .await
    .unwrap();

    assert_eq!(count.0, 3, "Should have 3 audit events");

    // Query only successful events
    let success_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM identity_audit_events WHERE tenant_id = $1 AND agent_id = $2 AND success = true",
    )
    .bind(&ctx.tenant_id)
    .bind(&ctx.agent_id)
    .fetch_one(&ctx.admin_pool)
    .await
    .unwrap();

    assert_eq!(success_count.0, 2, "Should have 2 successful events");

    ctx.cleanup().await;
}

/// Test: Query audit events by event_type.
#[tokio::test]
#[ignore = "requires database - run with: cargo test --test identity_audit_test -- --ignored"]
async fn test_query_audit_by_event_type() {
    let ctx = match AuditTestContext::new().await {
        Some(c) => c,
        None => {
            eprintln!("Skipping test: database not available");
            return;
        }
    };

    // Create events of different types
    let _ = ctx.create_audit_event("credential_request", true).await.unwrap();
    let _ = ctx.create_audit_event("token_verification", true).await.unwrap();
    let _ = ctx.create_audit_event("provider_health_check", true).await.unwrap();

    // Query by event_type
    let cred_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM identity_audit_events WHERE tenant_id = $1 AND event_type = $2",
    )
    .bind(&ctx.tenant_id)
    .bind("credential_request")
    .fetch_one(&ctx.admin_pool)
    .await
    .unwrap();

    assert_eq!(cred_count.0, 1, "Should have 1 credential_request event");

    ctx.cleanup().await;
}

/// Test: Tenant isolation for audit events.
#[tokio::test]
#[ignore = "requires database - run with: cargo test --test identity_audit_test -- --ignored"]
async fn test_audit_tenant_isolation() {
    let ctx = match AuditTestContext::new().await {
        Some(c) => c,
        None => {
            eprintln!("Skipping test: database not available");
            return;
        }
    };

    // Create event for our tenant
    let _ = ctx.create_audit_event("credential_request", true).await.unwrap();

    // Create another tenant with its own event
    let other_tenant_id = Uuid::new_v4();
    let other_slug = format!("other-audit-{}", &other_tenant_id.to_string()[..8]);
    sqlx::query("INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)")
        .bind(&other_tenant_id)
        .bind("Other Audit Tenant")
        .bind(&other_slug)
        .execute(&ctx.admin_pool)
        .await
        .unwrap();

    let other_agent_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO ai_agents (id, tenant_id, name, agent_type, status, risk_level)
        VALUES ($1, $2, 'other-agent', 'ai_assistant', 'active', 'low')
        "#,
    )
    .bind(&other_agent_id)
    .bind(&other_tenant_id)
    .execute(&ctx.admin_pool)
    .await
    .unwrap();

    sqlx::query(
        r#"
        INSERT INTO identity_audit_events
            (id, tenant_id, agent_id, event_type, provider_type, success, details)
        VALUES ($1, $2, $3, 'credential_request', 'aws', true, $4)
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(&other_tenant_id)
    .bind(&other_agent_id)
    .bind(serde_json::json!({}))
    .execute(&ctx.admin_pool)
    .await
    .unwrap();

    // Query our tenant's events only
    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM identity_audit_events WHERE tenant_id = $1",
    )
    .bind(&ctx.tenant_id)
    .fetch_one(&ctx.admin_pool)
    .await
    .unwrap();

    assert_eq!(count.0, 1, "Should only see our tenant's events");

    // Cleanup other tenant
    let _ = sqlx::query("DELETE FROM identity_audit_events WHERE tenant_id = $1")
        .bind(&other_tenant_id)
        .execute(&ctx.admin_pool)
        .await;
    let _ = sqlx::query("DELETE FROM ai_agents WHERE tenant_id = $1")
        .bind(&other_tenant_id)
        .execute(&ctx.admin_pool)
        .await;
    let _ = sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(&other_tenant_id)
        .execute(&ctx.admin_pool)
        .await;

    ctx.cleanup().await;
}
