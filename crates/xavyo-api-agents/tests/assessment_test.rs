//! Integration tests for Security Assessment API (F093).
//!
//! Tests the AssessmentService with real database connectivity to verify
//! the 14-point vulnerability framework assessment works end-to-end.

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::sync::Once;
use std::time::Duration as StdDuration;
use uuid::Uuid;
use xavyo_api_agents::models::{CheckName, Status};

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

/// Test context for assessment integration tests.
struct AssessmentTestContext {
    /// App user pool - RLS is enforced
    pub pool: PgPool,
    /// Admin/superuser pool - bypasses RLS, used for test setup
    pub admin_pool: PgPool,
    /// Test tenant ID
    pub tenant_id: Uuid,
}

impl AssessmentTestContext {
    /// Create a new test context with both app and admin database connections.
    async fn new() -> Self {
        init_test_logging();

        let pool = PgPoolOptions::new()
            .max_connections(5)
            .acquire_timeout(StdDuration::from_secs(5))
            .connect(&get_app_database_url())
            .await
            .expect("Failed to connect as app user. Is PostgreSQL running?");

        let admin_pool = PgPoolOptions::new()
            .max_connections(5)
            .acquire_timeout(StdDuration::from_secs(5))
            .connect(&get_superuser_database_url())
            .await
            .expect("Failed to connect as superuser");

        // Create a unique test tenant
        let tenant_id = Uuid::new_v4();
        let slug = format!("test-{}", &tenant_id.to_string()[..8]);
        sqlx::query("INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)")
            .bind(&tenant_id)
            .bind(&format!("Test Tenant {}", &tenant_id.to_string()[..8]))
            .bind(&slug)
            .execute(&admin_pool)
            .await
            .expect("Failed to create test tenant");

        Self {
            pool,
            admin_pool,
            tenant_id,
        }
    }

    /// Create a test user for the tenant.
    async fn create_user(&self) -> Uuid {
        let user_id = Uuid::new_v4();
        let email = format!("test-{}@test.local", &user_id.to_string()[..8]);
        sqlx::query(
            "INSERT INTO users (id, tenant_id, email, password_hash, is_active, email_verified)
             VALUES ($1, $2, $3, $4, true, true)",
        )
        .bind(&user_id)
        .bind(&self.tenant_id)
        .bind(&email)
        .bind("$argon2id$v=19$m=65536,t=3,p=4$dGVzdHNhbHQ$testhash")
        .execute(&self.admin_pool)
        .await
        .expect("Failed to create test user");
        user_id
    }

    /// Create a test AI agent.
    async fn create_agent(
        &self,
        owner_id: Uuid,
        max_token_lifetime_secs: Option<i32>,
        requires_human_approval: bool,
    ) -> Uuid {
        let agent_id = Uuid::new_v4();
        let name = format!("test-agent-{}", &agent_id.to_string()[..8]);
        sqlx::query(
            r#"INSERT INTO ai_agents
               (id, tenant_id, name, description, agent_type, owner_id,
                max_token_lifetime_secs, requires_human_approval, status, risk_level)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'active', 'medium')"#,
        )
        .bind(&agent_id)
        .bind(&self.tenant_id)
        .bind(&name)
        .bind("Test agent for integration tests")
        .bind("autonomous")
        .bind(&owner_id)
        .bind(max_token_lifetime_secs.unwrap_or(900))
        .bind(requires_human_approval)
        .execute(&self.admin_pool)
        .await
        .expect("Failed to create test agent");
        agent_id
    }

    /// Create a test AI tool.
    async fn create_tool(
        &self,
        risk_level: &str,
        requires_approval: bool,
        max_calls_per_hour: Option<i32>,
    ) -> Uuid {
        let tool_id = Uuid::new_v4();
        let name = format!("test-tool-{}", &tool_id.to_string()[..8]);
        sqlx::query(
            r#"INSERT INTO ai_tools
               (id, tenant_id, name, description, category, input_schema,
                risk_level, requires_approval, max_calls_per_hour, status)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'active')"#,
        )
        .bind(&tool_id)
        .bind(&self.tenant_id)
        .bind(&name)
        .bind("Test tool for integration tests")
        .bind("data")
        .bind(serde_json::json!({"type": "object"}))
        .bind(risk_level)
        .bind(requires_approval)
        .bind(max_calls_per_hour)
        .execute(&self.admin_pool)
        .await
        .expect("Failed to create test tool");
        tool_id
    }

    /// Grant a tool permission to an agent.
    async fn grant_permission(&self, agent_id: Uuid, tool_id: Uuid, granted_by: Uuid) -> Uuid {
        let permission_id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO ai_agent_tool_permissions
               (id, tenant_id, agent_id, tool_id, granted_by, granted_at)
               VALUES ($1, $2, $3, $4, $5, NOW())"#,
        )
        .bind(&permission_id)
        .bind(&self.tenant_id)
        .bind(&agent_id)
        .bind(&tool_id)
        .bind(&granted_by)
        .execute(&self.admin_pool)
        .await
        .expect("Failed to grant permission");
        permission_id
    }

    /// Create an audit event for an agent.
    async fn create_audit_event(
        &self,
        agent_id: Uuid,
        event_type: &str,
        tool_id: Option<Uuid>,
        session_id: Option<&str>,
    ) {
        let event_id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO ai_agent_audit_events
               (id, tenant_id, agent_id, event_type, tool_id, session_id, decision, timestamp)
               VALUES ($1, $2, $3, $4, $5, $6, 'allowed', NOW())"#,
        )
        .bind(&event_id)
        .bind(&self.tenant_id)
        .bind(&agent_id)
        .bind(event_type)
        .bind(tool_id)
        .bind(session_id)
        .execute(&self.admin_pool)
        .await
        .expect("Failed to create audit event");
    }

    /// Clean up test data.
    async fn cleanup(&self) {
        // Clean up in reverse order of dependencies
        let _ = sqlx::query("DELETE FROM ai_agent_audit_events WHERE tenant_id = $1")
            .bind(&self.tenant_id)
            .execute(&self.admin_pool)
            .await;
        let _ = sqlx::query("DELETE FROM ai_agent_tool_permissions WHERE tenant_id = $1")
            .bind(&self.tenant_id)
            .execute(&self.admin_pool)
            .await;
        let _ = sqlx::query("DELETE FROM ai_agents WHERE tenant_id = $1")
            .bind(&self.tenant_id)
            .execute(&self.admin_pool)
            .await;
        let _ = sqlx::query("DELETE FROM ai_tools WHERE tenant_id = $1")
            .bind(&self.tenant_id)
            .execute(&self.admin_pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE tenant_id = $1")
            .bind(&self.tenant_id)
            .execute(&self.admin_pool)
            .await;
        let _ = sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(&self.tenant_id)
            .execute(&self.admin_pool)
            .await;
    }
}

/// Integration test: Assess an agent with good security configuration.
#[tokio::test]
#[ignore = "requires database"]
async fn test_assess_agent_with_good_security() {
    use xavyo_api_agents::services::AssessmentService;

    let ctx = AssessmentTestContext::new().await;

    // Create test data
    let owner_id = ctx.create_user().await;
    let agent_id = ctx.create_agent(owner_id, Some(600), true).await; // 10 min token, requires approval

    // Create a low-risk tool with rate limiting
    let tool_id = ctx.create_tool("low", true, Some(100)).await;
    ctx.grant_permission(agent_id, tool_id, owner_id).await;

    // Create some normal audit events (single session)
    for _ in 0..5 {
        ctx.create_audit_event(
            agent_id,
            "tool_invocation",
            Some(tool_id),
            Some("session-1"),
        )
        .await;
    }

    // Run assessment
    let service = AssessmentService::new(ctx.pool.clone());

    // Set tenant context for RLS
    sqlx::query(&format!(
        "SET LOCAL app.current_tenant = '{}'",
        ctx.tenant_id
    ))
    .execute(&ctx.pool)
    .await
    .expect("Failed to set tenant context");

    let assessment = service.assess_agent(ctx.tenant_id, agent_id).await;

    // Clean up
    ctx.cleanup().await;

    // Verify assessment
    let assessment = assessment.expect("Assessment should succeed");
    assert_eq!(assessment.agent_id, agent_id);
    assert!(
        assessment.overall_score >= 50,
        "Score should be decent: {}",
        assessment.overall_score
    );
    assert_eq!(
        assessment.vulnerabilities.len(),
        14,
        "Should have all 14 checks"
    );

    // Check that token_lifetime passes (600 <= 900)
    let token_check = assessment
        .vulnerabilities
        .iter()
        .find(|v| v.name == CheckName::TokenLifetime)
        .expect("Should have token_lifetime check");
    assert_eq!(
        token_check.status,
        Status::Pass,
        "Token lifetime should pass"
    );
}

/// Integration test: Assess an agent with poor security configuration.
#[tokio::test]
#[ignore = "requires database"]
async fn test_assess_agent_with_poor_security() {
    use xavyo_api_agents::services::AssessmentService;

    let ctx = AssessmentTestContext::new().await;

    // Create test data
    let owner_id = ctx.create_user().await;
    let agent_id = ctx.create_agent(owner_id, Some(7200), false).await; // 2 hour token, no approval

    // Create many high-risk tools
    for _ in 0..15 {
        let tool_id = ctx.create_tool("critical", false, None).await;
        ctx.grant_permission(agent_id, tool_id, owner_id).await;
    }

    // Run assessment
    let service = AssessmentService::new(ctx.pool.clone());

    // Set tenant context for RLS
    sqlx::query(&format!(
        "SET LOCAL app.current_tenant = '{}'",
        ctx.tenant_id
    ))
    .execute(&ctx.pool)
    .await
    .expect("Failed to set tenant context");

    let assessment = service.assess_agent(ctx.tenant_id, agent_id).await;

    // Clean up
    ctx.cleanup().await;

    // Verify assessment
    let assessment = assessment.expect("Assessment should succeed");
    assert!(
        assessment.overall_score < 50,
        "Score should be low: {}",
        assessment.overall_score
    );

    // Check that token_lifetime fails (7200 > 900)
    let token_check = assessment
        .vulnerabilities
        .iter()
        .find(|v| v.name == CheckName::TokenLifetime)
        .expect("Should have token_lifetime check");
    assert_eq!(
        token_check.status,
        Status::Fail,
        "Token lifetime should fail"
    );

    // Check that granular_scopes fails (15 permissions, all high-risk)
    let scopes_check = assessment
        .vulnerabilities
        .iter()
        .find(|v| v.name == CheckName::GranularScopes)
        .expect("Should have granular_scopes check");
    assert_ne!(
        scopes_check.status,
        Status::Pass,
        "Granular scopes should not pass"
    );

    // Should have recommendations
    assert!(
        !assessment.recommendations.is_empty(),
        "Should have recommendations"
    );
}

/// Integration test: Assess non-existent agent returns error.
#[tokio::test]
#[ignore = "requires database"]
async fn test_assess_nonexistent_agent() {
    use xavyo_api_agents::services::AssessmentService;

    let ctx = AssessmentTestContext::new().await;

    let service = AssessmentService::new(ctx.pool.clone());

    // Set tenant context for RLS
    sqlx::query(&format!(
        "SET LOCAL app.current_tenant = '{}'",
        ctx.tenant_id
    ))
    .execute(&ctx.pool)
    .await
    .expect("Failed to set tenant context");

    let result = service.assess_agent(ctx.tenant_id, Uuid::new_v4()).await;

    // Clean up
    ctx.cleanup().await;

    // Should return AgentNotFound error
    assert!(
        result.is_err(),
        "Should return error for non-existent agent"
    );
}

/// Integration test: Verify tenant isolation in assessments.
#[tokio::test]
#[ignore = "requires database"]
async fn test_assess_agent_tenant_isolation() {
    use xavyo_api_agents::services::AssessmentService;

    let ctx = AssessmentTestContext::new().await;

    // Create agent in test tenant
    let owner_id = ctx.create_user().await;
    let agent_id = ctx.create_agent(owner_id, Some(600), true).await;

    // Try to assess with different tenant ID
    let other_tenant_id = Uuid::new_v4();
    let service = AssessmentService::new(ctx.pool.clone());

    // Set different tenant context
    sqlx::query(&format!(
        "SET LOCAL app.current_tenant = '{}'",
        other_tenant_id
    ))
    .execute(&ctx.pool)
    .await
    .expect("Failed to set tenant context");

    let result = service.assess_agent(other_tenant_id, agent_id).await;

    // Clean up
    ctx.cleanup().await;

    // Should not find agent in other tenant
    assert!(result.is_err(), "Should not find agent in different tenant");
}

/// Integration test: Verify all 14 vulnerability checks are present.
#[tokio::test]
#[ignore = "requires database"]
async fn test_all_14_vulnerability_checks_present() {
    use xavyo_api_agents::services::AssessmentService;

    let ctx = AssessmentTestContext::new().await;

    let owner_id = ctx.create_user().await;
    let agent_id = ctx.create_agent(owner_id, Some(900), false).await;

    let service = AssessmentService::new(ctx.pool.clone());

    // Set tenant context
    sqlx::query(&format!(
        "SET LOCAL app.current_tenant = '{}'",
        ctx.tenant_id
    ))
    .execute(&ctx.pool)
    .await
    .expect("Failed to set tenant context");

    let assessment = service.assess_agent(ctx.tenant_id, agent_id).await;

    ctx.cleanup().await;

    let assessment = assessment.expect("Assessment should succeed");

    // Verify all 14 checks are present
    let expected_checks = vec![
        CheckName::TokenLifetime,
        CheckName::GranularScopes,
        CheckName::MessageIntegrity,
        CheckName::RateLimiting,
        CheckName::InputValidation,
        CheckName::OutputFiltering,
        CheckName::AuditLogging,
        CheckName::ConsentTracking,
        CheckName::SessionIsolation,
        CheckName::CredentialRotation,
        CheckName::AnomalyDetection,
        CheckName::PrivilegeEscalation,
        CheckName::DataLeakage,
        CheckName::SupplyChain,
    ];

    assert_eq!(
        assessment.vulnerabilities.len(),
        14,
        "Should have exactly 14 vulnerability checks"
    );

    for check_name in expected_checks {
        assert!(
            assessment
                .vulnerabilities
                .iter()
                .any(|v| v.name == check_name),
            "Should have {:?} check",
            check_name
        );
    }
}

/// Integration test: Verify compliance calculation.
#[tokio::test]
#[ignore = "requires database"]
async fn test_compliance_calculation() {
    use xavyo_api_agents::services::AssessmentService;

    let ctx = AssessmentTestContext::new().await;

    let owner_id = ctx.create_user().await;
    // Agent with MCP-compliant token lifetime (<=900s)
    let agent_id = ctx.create_agent(owner_id, Some(600), true).await;

    let service = AssessmentService::new(ctx.pool.clone());

    sqlx::query(&format!(
        "SET LOCAL app.current_tenant = '{}'",
        ctx.tenant_id
    ))
    .execute(&ctx.pool)
    .await
    .expect("Failed to set tenant context");

    let assessment = service.assess_agent(ctx.tenant_id, agent_id).await;

    ctx.cleanup().await;

    let assessment = assessment.expect("Assessment should succeed");

    // Check compliance section exists and has valid values
    // OWASP Agentic compliance should have 8 total controls
    assert_eq!(
        assessment.compliance.owasp_agentic.total_controls, 8,
        "OWASP Agentic should have 8 controls"
    );
    assert!(
        assessment.compliance.owasp_agentic.controls_satisfied <= 8,
        "Controls satisfied should not exceed total"
    );

    // MCP OAuth and A2A Protocol are booleans
    // With 600s token (<=900s), MCP OAuth should pass
    assert!(
        assessment.compliance.mcp_oauth,
        "MCP OAuth should pass with 600s token"
    );
}
