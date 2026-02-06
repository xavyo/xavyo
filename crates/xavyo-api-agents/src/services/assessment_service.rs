//! Security Assessment service for the AI Agent Security API (F093).
//!
//! Implements the arXiv:2511.03841 14-point vulnerability framework to evaluate
//! AI agent security posture in real-time.

use chrono::{Duration, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::ApiAgentsError;
use crate::models::assessment_models::{
    CheckName, ComplianceStatus, OwaspAgenticCompliance, Priority, Recommendation, RiskLevel,
    SecurityAssessment, Status, VulnerabilityCheck,
};
use xavyo_db::models::ai_agent::AiAgent;
use xavyo_db::models::ai_agent_audit_event::AiAgentAuditEvent;
use xavyo_db::models::ai_agent_tool_permission::AiAgentToolPermission;
use xavyo_db::models::ai_tool::AiTool;
use xavyo_db::models::{AnomalyBaseline, DetectedAnomaly, DetectedAnomalyFilter};

/// Maximum recommended token lifetime in seconds (15 minutes).
const MAX_TOKEN_LIFETIME_SECS: i32 = 900;

/// Maximum recommended tool permissions count.
const MAX_TOOL_PERMISSIONS: usize = 10;

/// Maximum age in days before credential rotation is recommended.
const MAX_CREDENTIAL_AGE_DAYS: i64 = 90;

/// Service for computing security assessments.
#[derive(Clone)]
pub struct AssessmentService {
    pool: PgPool,
}

/// Context data collected for assessment computation.
#[derive(Debug)]
pub struct AssessmentContext {
    pub agent: AiAgent,
    pub permissions: Vec<PermissionWithTool>,
    pub tools: Vec<AiTool>,
    pub recent_events: Vec<AiAgentAuditEvent>,
    pub recent_event_count: i64,
    pub distinct_session_count: i64,
    /// Detected anomalies from F094 (last 24 hours).
    pub detected_anomalies: Vec<DetectedAnomaly>,
    /// Whether the agent has an active baseline.
    pub has_active_baseline: bool,
}

/// Permission with associated tool data.
#[derive(Debug, Clone)]
pub struct PermissionWithTool {
    pub permission: AiAgentToolPermission,
    pub tool: AiTool,
}

impl AssessmentService {
    /// Create a new `AssessmentService`.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Perform a complete security assessment for an agent.
    pub async fn assess_agent(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
    ) -> Result<SecurityAssessment, ApiAgentsError> {
        // Fetch agent
        let agent = AiAgent::find_by_id(&self.pool, tenant_id, agent_id)
            .await?
            .ok_or(ApiAgentsError::AgentNotFound)?;

        // Collect context data
        let context = self.collect_context(tenant_id, &agent).await?;

        // Run all vulnerability checks
        let vulnerabilities = self.run_all_checks(&context);

        // Calculate overall score
        let overall_score = Self::calculate_score(&vulnerabilities);

        // Determine risk level
        let risk_level = RiskLevel::from_score(overall_score);

        // Calculate compliance status
        let compliance = Self::calculate_compliance(&vulnerabilities, &context.agent);

        // Generate recommendations
        let recommendations = Self::generate_recommendations(&vulnerabilities);

        Ok(SecurityAssessment {
            agent_id,
            assessment_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            overall_score,
            risk_level,
            vulnerabilities,
            compliance,
            recommendations,
        })
    }

    /// Collect all data needed for assessment.
    async fn collect_context(
        &self,
        tenant_id: Uuid,
        agent: &AiAgent,
    ) -> Result<AssessmentContext, ApiAgentsError> {
        // Get agent's tool permissions
        let permissions =
            AiAgentToolPermission::list_by_agent(&self.pool, tenant_id, agent.id).await?;

        // Get tool details for each permission
        let tool_ids: Vec<Uuid> = permissions.iter().map(|p| p.tool_id).collect();
        let tools = if tool_ids.is_empty() {
            vec![]
        } else {
            AiTool::find_by_ids(&self.pool, tenant_id, &tool_ids).await?
        };

        // Build permission-tool pairs
        let permissions_with_tools: Vec<PermissionWithTool> = permissions
            .into_iter()
            .filter_map(|p| {
                tools
                    .iter()
                    .find(|t| t.id == p.tool_id)
                    .map(|t| PermissionWithTool {
                        permission: p,
                        tool: t.clone(),
                    })
            })
            .collect();

        // Get recent audit events (last 24 hours)
        let since = Utc::now() - Duration::hours(24);
        let recent_events = AiAgentAuditEvent::list_by_agent(
            &self.pool,
            tenant_id,
            agent.id,
            Some(since),
            None,
            1000,
        )
        .await?;

        // Count recent events
        let recent_event_count =
            AiAgentAuditEvent::count_by_agent(&self.pool, tenant_id, agent.id, Some(since)).await?;

        // Count distinct sessions
        let distinct_session_count = AiAgentAuditEvent::count_distinct_sessions(
            &self.pool,
            tenant_id,
            agent.id,
            Some(since),
        )
        .await
        .unwrap_or(0);

        // F094 Integration: Fetch detected anomalies from last 24 hours
        let anomaly_filter = DetectedAnomalyFilter {
            since: Some(since),
            anomaly_type: None,
            severity: None,
        };
        let detected_anomalies = DetectedAnomaly::list_by_agent(
            &self.pool,
            tenant_id,
            agent.id,
            &anomaly_filter,
            100,
            0,
        )
        .await
        .unwrap_or_default();

        // Check if agent has an active baseline
        let baselines = AnomalyBaseline::get_by_agent(&self.pool, tenant_id, agent.id)
            .await
            .unwrap_or_default();
        let has_active_baseline = baselines.iter().any(|b| b.sample_count >= 24);

        Ok(AssessmentContext {
            agent: agent.clone(),
            permissions: permissions_with_tools,
            tools,
            recent_events,
            recent_event_count,
            distinct_session_count,
            detected_anomalies,
            has_active_baseline,
        })
    }

    /// Run all 14 vulnerability checks.
    fn run_all_checks(&self, ctx: &AssessmentContext) -> Vec<VulnerabilityCheck> {
        vec![
            self.check_token_lifetime(ctx),
            self.check_granular_scopes(ctx),
            self.check_message_integrity(ctx),
            self.check_rate_limiting(ctx),
            self.check_input_validation(ctx),
            self.check_output_filtering(ctx),
            self.check_audit_logging(ctx),
            self.check_consent_tracking(ctx),
            self.check_session_isolation(ctx),
            self.check_credential_rotation(ctx),
            self.check_anomaly_detection(ctx),
            self.check_privilege_escalation(ctx),
            self.check_data_leakage(ctx),
            self.check_supply_chain(ctx),
        ]
    }

    // ========================================================================
    // Vulnerability Checks
    // ========================================================================

    /// Check 1: Token lifetime validation.
    fn check_token_lifetime(&self, ctx: &AssessmentContext) -> VulnerabilityCheck {
        let lifetime = ctx.agent.max_token_lifetime_secs;

        if lifetime <= MAX_TOKEN_LIFETIME_SECS {
            VulnerabilityCheck::pass(
                CheckName::TokenLifetime,
                format!(
                    "Token lifetime is {lifetime} seconds (≤{MAX_TOKEN_LIFETIME_SECS} recommended)"
                ),
            )
        } else if lifetime <= MAX_TOKEN_LIFETIME_SECS * 2 {
            VulnerabilityCheck::warning(
                CheckName::TokenLifetime,
                format!(
                    "Token lifetime is {lifetime} seconds (>{MAX_TOKEN_LIFETIME_SECS} not recommended)"
                ),
            )
        } else {
            VulnerabilityCheck::fail(
                CheckName::TokenLifetime,
                format!(
                    "Token lifetime is {lifetime} seconds (>{MAX_TOKEN_LIFETIME_SECS} is a security risk)"
                ),
            )
        }
    }

    /// Check 2: Granular scopes/permission verification.
    fn check_granular_scopes(&self, ctx: &AssessmentContext) -> VulnerabilityCheck {
        let count = ctx.permissions.len();

        if count == 0 {
            VulnerabilityCheck::warning(
                CheckName::GranularScopes,
                "Agent has no tool permissions assigned - configure required tools",
            )
        } else if count <= MAX_TOOL_PERMISSIONS {
            VulnerabilityCheck::pass(
                CheckName::GranularScopes,
                format!("Agent has {count} tool permissions (<{MAX_TOOL_PERMISSIONS} recommended)"),
            )
        } else {
            VulnerabilityCheck::warning(
                CheckName::GranularScopes,
                format!(
                    "Agent has {count} tool permissions (>{MAX_TOOL_PERMISSIONS} may be excessive)"
                ),
            )
        }
    }

    /// Check 3: Message/AgentCard signature integrity.
    fn check_message_integrity(&self, ctx: &AssessmentContext) -> VulnerabilityCheck {
        if ctx.agent.agent_card_signature.is_some() {
            VulnerabilityCheck::pass(
                CheckName::MessageIntegrity,
                "AgentCard signature is configured for message integrity",
            )
        } else if ctx.agent.agent_card_url.is_some() {
            VulnerabilityCheck::warning(
                CheckName::MessageIntegrity,
                "AgentCard URL is set but signature is not configured",
            )
        } else {
            VulnerabilityCheck::fail(
                CheckName::MessageIntegrity,
                "AgentCard signature is not configured - A2A message integrity at risk",
            )
        }
    }

    /// Check 4: Rate limiting configuration.
    fn check_rate_limiting(&self, ctx: &AssessmentContext) -> VulnerabilityCheck {
        if ctx.permissions.is_empty() {
            return VulnerabilityCheck::pass(
                CheckName::RateLimiting,
                "No permissions to rate limit",
            );
        }

        let with_limits = ctx
            .permissions
            .iter()
            .filter(|p| {
                p.permission.max_calls_per_hour.is_some() || p.tool.max_calls_per_hour.is_some()
            })
            .count();

        let ratio = with_limits as f64 / ctx.permissions.len() as f64;

        if ratio >= 1.0 {
            VulnerabilityCheck::pass(
                CheckName::RateLimiting,
                "All tool permissions have rate limits configured",
            )
        } else if ratio >= 0.5 {
            VulnerabilityCheck::warning(
                CheckName::RateLimiting,
                format!(
                    "{}/{} tool permissions have rate limits (some missing)",
                    with_limits,
                    ctx.permissions.len()
                ),
            )
        } else {
            VulnerabilityCheck::fail(
                CheckName::RateLimiting,
                format!(
                    "Only {}/{} tool permissions have rate limits",
                    with_limits,
                    ctx.permissions.len()
                ),
            )
        }
    }

    /// Check 5: Input parameter validation.
    fn check_input_validation(&self, ctx: &AssessmentContext) -> VulnerabilityCheck {
        if ctx.permissions.is_empty() {
            return VulnerabilityCheck::pass(CheckName::InputValidation, "No tools to validate");
        }

        let with_schema = ctx
            .permissions
            .iter()
            .filter(|p| {
                // Check if input_schema is non-empty object/array
                !p.tool.input_schema.is_null() && p.tool.input_schema != serde_json::json!({})
            })
            .count();

        let ratio = with_schema as f64 / ctx.permissions.len() as f64;

        if ratio >= 1.0 {
            VulnerabilityCheck::pass(
                CheckName::InputValidation,
                "All permitted tools have input schemas defined",
            )
        } else if ratio >= 0.7 {
            VulnerabilityCheck::warning(
                CheckName::InputValidation,
                format!(
                    "{}/{} permitted tools have input schemas",
                    with_schema,
                    ctx.permissions.len()
                ),
            )
        } else {
            VulnerabilityCheck::fail(
                CheckName::InputValidation,
                format!(
                    "Only {}/{} permitted tools have input schemas - validation incomplete",
                    with_schema,
                    ctx.permissions.len()
                ),
            )
        }
    }

    /// Check 6: Output filtering/sanitization.
    fn check_output_filtering(&self, ctx: &AssessmentContext) -> VulnerabilityCheck {
        if ctx.permissions.is_empty() {
            return VulnerabilityCheck::pass(CheckName::OutputFiltering, "No tools to filter");
        }

        let with_schema = ctx
            .permissions
            .iter()
            .filter(|p| p.tool.output_schema.is_some())
            .count();

        let ratio = with_schema as f64 / ctx.permissions.len() as f64;

        if ratio >= 0.8 {
            VulnerabilityCheck::pass(
                CheckName::OutputFiltering,
                format!(
                    "{}/{} permitted tools have output schemas",
                    with_schema,
                    ctx.permissions.len()
                ),
            )
        } else if ratio >= 0.5 {
            VulnerabilityCheck::warning(
                CheckName::OutputFiltering,
                format!(
                    "{}/{} permitted tools have output schemas (some missing)",
                    with_schema,
                    ctx.permissions.len()
                ),
            )
        } else {
            VulnerabilityCheck::fail(
                CheckName::OutputFiltering,
                format!(
                    "Only {}/{} permitted tools have output schemas",
                    with_schema,
                    ctx.permissions.len()
                ),
            )
        }
    }

    /// Check 7: Audit logging presence.
    fn check_audit_logging(&self, ctx: &AssessmentContext) -> VulnerabilityCheck {
        let agent_age = Utc::now() - ctx.agent.created_at;
        let is_new = agent_age < Duration::hours(24);

        if ctx.recent_event_count > 0 {
            VulnerabilityCheck::pass(
                CheckName::AuditLogging,
                format!(
                    "{} audit events recorded in the last 24 hours",
                    ctx.recent_event_count
                ),
            )
        } else if is_new {
            VulnerabilityCheck::pass(
                CheckName::AuditLogging,
                "Agent is new (<24h) - no activity expected yet",
            )
        } else {
            VulnerabilityCheck::fail(
                CheckName::AuditLogging,
                "No audit events recorded in the last 24 hours - logging may be disabled",
            )
        }
    }

    /// Check 8: Human-in-the-loop consent tracking.
    fn check_consent_tracking(&self, ctx: &AssessmentContext) -> VulnerabilityCheck {
        let high_risk_tools: Vec<_> = ctx
            .permissions
            .iter()
            .filter(|p| p.tool.risk_level == "high" || p.tool.risk_level == "critical")
            .collect();

        if high_risk_tools.is_empty() {
            return VulnerabilityCheck::pass(
                CheckName::ConsentTracking,
                "No high-risk tools permitted - consent tracking not required",
            );
        }

        // Check if agent or permissions require approval for high-risk tools
        let with_approval = high_risk_tools
            .iter()
            .filter(|p| {
                ctx.agent.requires_human_approval
                    || p.permission.requires_approval.unwrap_or(false)
                    || p.tool.requires_approval
            })
            .count();

        if with_approval == high_risk_tools.len() {
            VulnerabilityCheck::pass(
                CheckName::ConsentTracking,
                format!(
                    "All {} high-risk tools require human approval",
                    high_risk_tools.len()
                ),
            )
        } else if ctx.agent.requires_human_approval {
            VulnerabilityCheck::pass(
                CheckName::ConsentTracking,
                "Agent requires human approval for all operations",
            )
        } else {
            VulnerabilityCheck::fail(
                CheckName::ConsentTracking,
                format!(
                    "{}/{} high-risk tools require approval - some unprotected",
                    with_approval,
                    high_risk_tools.len()
                ),
            )
        }
    }

    /// Check 9: Session/conversation isolation.
    fn check_session_isolation(&self, ctx: &AssessmentContext) -> VulnerabilityCheck {
        if ctx.recent_events.is_empty() {
            return VulnerabilityCheck::pass(
                CheckName::SessionIsolation,
                "No recent activity to analyze for session isolation",
            );
        }

        // Check if events have session_id set
        let with_session = ctx
            .recent_events
            .iter()
            .filter(|e| e.session_id.is_some())
            .count();

        let ratio = with_session as f64 / ctx.recent_events.len() as f64;

        if ratio >= 0.9 {
            VulnerabilityCheck::pass(
                CheckName::SessionIsolation,
                format!(
                    "{}% of events have session_id - isolation maintained",
                    (ratio * 100.0) as u8
                ),
            )
        } else if ratio >= 0.5 {
            VulnerabilityCheck::warning(
                CheckName::SessionIsolation,
                format!(
                    "Only {}% of events have session_id - partial isolation",
                    (ratio * 100.0) as u8
                ),
            )
        } else {
            VulnerabilityCheck::fail(
                CheckName::SessionIsolation,
                format!(
                    "Only {}% of events have session_id - isolation at risk",
                    (ratio * 100.0) as u8
                ),
            )
        }
    }

    /// Check 10: Credential rotation policy.
    fn check_credential_rotation(&self, ctx: &AssessmentContext) -> VulnerabilityCheck {
        let last_update = ctx.agent.updated_at;
        let age = Utc::now() - last_update;
        let age_days = age.num_days();

        if age_days <= MAX_CREDENTIAL_AGE_DAYS {
            VulnerabilityCheck::pass(
                CheckName::CredentialRotation,
                format!(
                    "Agent configuration updated {age_days} days ago (≤{MAX_CREDENTIAL_AGE_DAYS} recommended)"
                ),
            )
        } else if age_days <= MAX_CREDENTIAL_AGE_DAYS * 2 {
            VulnerabilityCheck::warning(
                CheckName::CredentialRotation,
                format!(
                    "Agent configuration is {age_days} days old (>{MAX_CREDENTIAL_AGE_DAYS} may indicate stale credentials)"
                ),
            )
        } else {
            VulnerabilityCheck::fail(
                CheckName::CredentialRotation,
                format!(
                    "Agent configuration is {age_days} days old - credential rotation recommended"
                ),
            )
        }
    }

    /// Check 11: Behavioral anomaly detection (F094 integration).
    fn check_anomaly_detection(&self, ctx: &AssessmentContext) -> VulnerabilityCheck {
        // Check if baseline is active
        if !ctx.has_active_baseline {
            return VulnerabilityCheck::warning(
                CheckName::AnomalyDetection,
                "Behavioral baseline not yet established - anomaly detection limited",
            );
        }

        // Check for detected anomalies from F094
        if ctx.detected_anomalies.is_empty() {
            if ctx.recent_events.is_empty() {
                return VulnerabilityCheck::pass(
                    CheckName::AnomalyDetection,
                    "No recent activity - no anomalies detected",
                );
            }
            return VulnerabilityCheck::pass(
                CheckName::AnomalyDetection,
                format!(
                    "No anomalies detected: {} events within normal baseline",
                    ctx.recent_event_count
                ),
            );
        }

        // Count anomalies by severity
        let critical = ctx
            .detected_anomalies
            .iter()
            .filter(|a| a.severity == "critical")
            .count();
        let high = ctx
            .detected_anomalies
            .iter()
            .filter(|a| a.severity == "high")
            .count();
        let medium = ctx
            .detected_anomalies
            .iter()
            .filter(|a| a.severity == "medium")
            .count();

        if critical > 0 {
            return VulnerabilityCheck::fail(
                CheckName::AnomalyDetection,
                format!(
                    "{critical} critical anomalies detected in last 24h ({high} high, {medium} medium)"
                ),
            );
        }

        if high > 0 {
            return VulnerabilityCheck::fail(
                CheckName::AnomalyDetection,
                format!("{high} high-severity anomalies detected in last 24h ({medium} medium)"),
            );
        }

        if medium > 0 {
            return VulnerabilityCheck::warning(
                CheckName::AnomalyDetection,
                format!("{medium} medium-severity anomalies detected in last 24h"),
            );
        }

        // Low severity anomalies - still pass but note them
        VulnerabilityCheck::pass(
            CheckName::AnomalyDetection,
            format!(
                "{} low-severity anomalies detected - within acceptable range",
                ctx.detected_anomalies.len()
            ),
        )
    }

    /// Check 12: Privilege escalation prevention.
    fn check_privilege_escalation(&self, ctx: &AssessmentContext) -> VulnerabilityCheck {
        let critical_tools: Vec<_> = ctx
            .permissions
            .iter()
            .filter(|p| p.tool.risk_level == "critical")
            .collect();

        if critical_tools.is_empty() {
            return VulnerabilityCheck::pass(
                CheckName::PrivilegeEscalation,
                "No critical-risk tools permitted",
            );
        }

        // Check if critical tools have approval requirement
        let protected = critical_tools
            .iter()
            .filter(|p| {
                ctx.agent.requires_human_approval
                    || p.permission.requires_approval.unwrap_or(false)
                    || p.tool.requires_approval
            })
            .count();

        if protected == critical_tools.len() {
            VulnerabilityCheck::pass(
                CheckName::PrivilegeEscalation,
                format!(
                    "All {} critical-risk tools require approval",
                    critical_tools.len()
                ),
            )
        } else {
            VulnerabilityCheck::fail(
                CheckName::PrivilegeEscalation,
                format!(
                    "{}/{} critical-risk tools lack approval requirement - escalation risk",
                    critical_tools.len() - protected,
                    critical_tools.len()
                ),
            )
        }
    }

    /// Check 13: Data leakage prevention.
    fn check_data_leakage(&self, ctx: &AssessmentContext) -> VulnerabilityCheck {
        if ctx.permissions.is_empty() {
            return VulnerabilityCheck::pass(
                CheckName::DataLeakage,
                "No tool permissions - no data leakage risk",
            );
        }

        let high_risk = ctx
            .permissions
            .iter()
            .filter(|p| p.tool.risk_level == "high" || p.tool.risk_level == "critical")
            .count();

        let ratio = high_risk as f64 / ctx.permissions.len() as f64;

        if ratio < 0.3 {
            VulnerabilityCheck::pass(
                CheckName::DataLeakage,
                format!(
                    "{}% of permitted tools are high/critical risk (<30% threshold)",
                    (ratio * 100.0) as u8
                ),
            )
        } else if ratio < 0.5 {
            VulnerabilityCheck::warning(
                CheckName::DataLeakage,
                format!(
                    "{}% of permitted tools are high/critical risk (30-50% range)",
                    (ratio * 100.0) as u8
                ),
            )
        } else {
            VulnerabilityCheck::fail(
                CheckName::DataLeakage,
                format!(
                    "{}% of permitted tools are high/critical risk - data leakage concern",
                    (ratio * 100.0) as u8
                ),
            )
        }
    }

    /// Check 14: Supply chain security.
    fn check_supply_chain(&self, ctx: &AssessmentContext) -> VulnerabilityCheck {
        if ctx.permissions.is_empty() {
            return VulnerabilityCheck::pass(
                CheckName::SupplyChain,
                "No tool permissions - no supply chain risk",
            );
        }

        let verified = ctx
            .permissions
            .iter()
            .filter(|p| p.tool.provider_verified)
            .count();

        let ratio = verified as f64 / ctx.permissions.len() as f64;

        if ratio >= 1.0 {
            VulnerabilityCheck::pass(
                CheckName::SupplyChain,
                "All permitted tools have verified providers",
            )
        } else if ratio >= 0.8 {
            VulnerabilityCheck::warning(
                CheckName::SupplyChain,
                format!(
                    "{}/{} permitted tools have verified providers",
                    verified,
                    ctx.permissions.len()
                ),
            )
        } else {
            VulnerabilityCheck::fail(
                CheckName::SupplyChain,
                format!(
                    "Only {}/{} permitted tools have verified providers - supply chain risk",
                    verified,
                    ctx.permissions.len()
                ),
            )
        }
    }

    // ========================================================================
    // Scoring and Compliance
    // ========================================================================

    /// Calculate overall security score from check results.
    fn calculate_score(checks: &[VulnerabilityCheck]) -> u8 {
        let mut score: i16 = 100;

        for check in checks {
            let deduction = match check.status {
                Status::Pass => 0,
                Status::Warning => i16::from(check.severity.warning_deduction()),
                Status::Fail => i16::from(check.severity.fail_deduction()),
            };
            score -= deduction;
        }

        score.clamp(0, 100) as u8
    }

    /// Calculate compliance status for security standards.
    fn calculate_compliance(checks: &[VulnerabilityCheck], agent: &AiAgent) -> ComplianceStatus {
        // OWASP Agentic: checks 1, 2, 3, 4, 5, 6, 8, 12
        let owasp_passing = OwaspAgenticCompliance::CONTROL_CHECK_IDS
            .iter()
            .filter(|&&id| {
                checks
                    .iter()
                    .find(|c| c.id == id)
                    .is_some_and(|c| c.status == Status::Pass)
            })
            .count() as u8;

        // A2A Protocol: check 3 (message_integrity) passes
        let a2a_protocol = checks
            .iter()
            .find(|c| c.id == 3)
            .is_some_and(|c| c.status == Status::Pass);

        // MCP OAuth: check 1 (token_lifetime) passes AND lifetime <= 900s
        let mcp_oauth = checks
            .iter()
            .find(|c| c.id == 1)
            .is_some_and(|c| c.status == Status::Pass)
            && agent.max_token_lifetime_secs <= MAX_TOKEN_LIFETIME_SECS;

        ComplianceStatus {
            owasp_agentic: OwaspAgenticCompliance::from_passing_count(owasp_passing),
            a2a_protocol,
            mcp_oauth,
        }
    }

    /// Generate recommendations based on failed/warning checks.
    fn generate_recommendations(checks: &[VulnerabilityCheck]) -> Vec<Recommendation> {
        checks
            .iter()
            .filter(|c| c.status != Status::Pass)
            .map(|c| {
                let (title, action) = Self::recommendation_for_check(c.name);
                Recommendation::new(c.id, Priority::from(c.severity), title, action)
            })
            .collect()
    }

    /// Get recommendation text for a check.
    fn recommendation_for_check(name: CheckName) -> (&'static str, &'static str) {
        match name {
            CheckName::TokenLifetime => (
                "Reduce token lifetime",
                "Update max_token_lifetime_secs to 900 or less",
            ),
            CheckName::GranularScopes => (
                "Review tool permissions",
                "Audit and remove unnecessary tool permissions following least-privilege principle",
            ),
            CheckName::MessageIntegrity => (
                "Enable AgentCard signing",
                "Configure agent_card_signature for A2A message integrity verification",
            ),
            CheckName::RateLimiting => (
                "Configure rate limits",
                "Set max_calls_per_hour on tool permissions to prevent abuse",
            ),
            CheckName::InputValidation => (
                "Add input schemas",
                "Define JSON Schema for tool input parameters to enable validation",
            ),
            CheckName::OutputFiltering => (
                "Add output schemas",
                "Define JSON Schema for tool outputs to enable filtering and validation",
            ),
            CheckName::AuditLogging => (
                "Enable audit logging",
                "Verify audit events are being recorded for agent activities",
            ),
            CheckName::ConsentTracking => (
                "Enable human approval",
                "Set requires_human_approval to true for agent or high-risk tool permissions",
            ),
            CheckName::SessionIsolation => (
                "Improve session tracking",
                "Ensure all agent requests include session_id for proper isolation",
            ),
            CheckName::CredentialRotation => (
                "Rotate credentials",
                "Update agent configuration to trigger credential refresh",
            ),
            CheckName::AnomalyDetection => (
                "Review unusual activity",
                "Investigate high activity levels and verify they are expected",
            ),
            CheckName::PrivilegeEscalation => (
                "Protect critical tools",
                "Enable requires_approval for permissions to critical-risk tools",
            ),
            CheckName::DataLeakage => (
                "Reduce high-risk tool access",
                "Review and limit permissions to high/critical risk tools",
            ),
            CheckName::SupplyChain => (
                "Verify tool providers",
                "Only use tools from verified providers or mark internal tools as verified",
            ),
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_score_all_pass() {
        let checks: Vec<VulnerabilityCheck> = CheckName::all()
            .iter()
            .map(|&name| VulnerabilityCheck::pass(name, "Test"))
            .collect();

        assert_eq!(AssessmentService::calculate_score(&checks), 100);
    }

    #[test]
    fn test_calculate_score_one_critical_fail() {
        let mut checks: Vec<VulnerabilityCheck> = CheckName::all()
            .iter()
            .map(|&name| VulnerabilityCheck::pass(name, "Test"))
            .collect();

        // Fail a critical check (audit_logging = 25 point deduction)
        checks[6] = VulnerabilityCheck::fail(CheckName::AuditLogging, "Test");

        assert_eq!(AssessmentService::calculate_score(&checks), 75);
    }

    #[test]
    fn test_calculate_score_mixed() {
        let checks = vec![
            VulnerabilityCheck::pass(CheckName::TokenLifetime, "Test"),
            VulnerabilityCheck::warning(CheckName::GranularScopes, "Test"), // Medium warning: -5
            VulnerabilityCheck::fail(CheckName::MessageIntegrity, "Test"),  // High fail: -15
            VulnerabilityCheck::pass(CheckName::RateLimiting, "Test"),
            VulnerabilityCheck::pass(CheckName::InputValidation, "Test"),
            VulnerabilityCheck::pass(CheckName::OutputFiltering, "Test"),
            VulnerabilityCheck::pass(CheckName::AuditLogging, "Test"),
            VulnerabilityCheck::pass(CheckName::ConsentTracking, "Test"),
            VulnerabilityCheck::pass(CheckName::SessionIsolation, "Test"),
            VulnerabilityCheck::pass(CheckName::CredentialRotation, "Test"),
            VulnerabilityCheck::pass(CheckName::AnomalyDetection, "Test"),
            VulnerabilityCheck::pass(CheckName::PrivilegeEscalation, "Test"),
            VulnerabilityCheck::pass(CheckName::DataLeakage, "Test"),
            VulnerabilityCheck::pass(CheckName::SupplyChain, "Test"),
        ];

        // 100 - 5 (warning medium) - 15 (fail high) = 80
        assert_eq!(AssessmentService::calculate_score(&checks), 80);
    }

    #[test]
    fn test_calculate_score_minimum_zero() {
        // All critical/high checks fail
        let checks: Vec<VulnerabilityCheck> = CheckName::all()
            .iter()
            .map(|&name| VulnerabilityCheck::fail(name, "Test"))
            .collect();

        // Score should clamp to 0, not go negative
        assert_eq!(AssessmentService::calculate_score(&checks), 0);
    }

    #[test]
    fn test_generate_recommendations_only_for_non_pass() {
        let checks = vec![
            VulnerabilityCheck::pass(CheckName::TokenLifetime, "Test"),
            VulnerabilityCheck::warning(CheckName::GranularScopes, "Test"),
            VulnerabilityCheck::fail(CheckName::MessageIntegrity, "Test"),
        ];

        let recommendations = AssessmentService::generate_recommendations(&checks);

        assert_eq!(recommendations.len(), 2);
        assert_eq!(recommendations[0].check_id, 2); // GranularScopes
        assert_eq!(recommendations[1].check_id, 3); // MessageIntegrity
    }

    #[test]
    fn test_recommendation_priorities() {
        let checks = vec![
            VulnerabilityCheck::fail(CheckName::AuditLogging, "Test"), // Critical
            VulnerabilityCheck::fail(CheckName::TokenLifetime, "Test"), // High
            VulnerabilityCheck::fail(CheckName::GranularScopes, "Test"), // Medium
            VulnerabilityCheck::fail(CheckName::AnomalyDetection, "Test"), // Low
        ];

        let recommendations = AssessmentService::generate_recommendations(&checks);

        assert_eq!(recommendations.len(), 4);
        assert_eq!(recommendations[0].priority, Priority::High); // Critical -> High priority
        assert_eq!(recommendations[1].priority, Priority::High); // High -> High priority
        assert_eq!(recommendations[2].priority, Priority::Medium);
        assert_eq!(recommendations[3].priority, Priority::Low);
    }

    #[test]
    fn test_owasp_compliance_calculation() {
        // All checks pass
        let checks: Vec<VulnerabilityCheck> = CheckName::all()
            .iter()
            .map(|&name| VulnerabilityCheck::pass(name, "Test"))
            .collect();

        let agent = create_test_agent();
        let compliance = AssessmentService::calculate_compliance(&checks, &agent);

        assert_eq!(compliance.owasp_agentic.controls_satisfied, 8);
        assert!(compliance.owasp_agentic.compliant);
    }

    #[test]
    fn test_owasp_compliance_partial() {
        // Fail some OWASP checks (1, 2, 3)
        let mut checks: Vec<VulnerabilityCheck> = CheckName::all()
            .iter()
            .map(|&name| VulnerabilityCheck::pass(name, "Test"))
            .collect();

        checks[0] = VulnerabilityCheck::fail(CheckName::TokenLifetime, "Test");
        checks[1] = VulnerabilityCheck::fail(CheckName::GranularScopes, "Test");
        checks[2] = VulnerabilityCheck::fail(CheckName::MessageIntegrity, "Test");

        let agent = create_test_agent();
        let compliance = AssessmentService::calculate_compliance(&checks, &agent);

        assert_eq!(compliance.owasp_agentic.controls_satisfied, 5);
        assert!(!compliance.owasp_agentic.compliant); // < 6 controls
    }

    #[test]
    fn test_a2a_compliance() {
        let mut checks: Vec<VulnerabilityCheck> = CheckName::all()
            .iter()
            .map(|&name| VulnerabilityCheck::pass(name, "Test"))
            .collect();

        let agent = create_test_agent();

        // A2A requires check 3 (message_integrity) to pass
        let compliance = AssessmentService::calculate_compliance(&checks, &agent);
        assert!(compliance.a2a_protocol);

        // Fail check 3
        checks[2] = VulnerabilityCheck::fail(CheckName::MessageIntegrity, "Test");
        let compliance = AssessmentService::calculate_compliance(&checks, &agent);
        assert!(!compliance.a2a_protocol);
    }

    #[test]
    fn test_mcp_oauth_compliance() {
        let checks: Vec<VulnerabilityCheck> = CheckName::all()
            .iter()
            .map(|&name| VulnerabilityCheck::pass(name, "Test"))
            .collect();

        // Agent with token lifetime <= 900
        let mut agent = create_test_agent();
        agent.max_token_lifetime_secs = 900;

        let compliance = AssessmentService::calculate_compliance(&checks, &agent);
        assert!(compliance.mcp_oauth);

        // Agent with token lifetime > 900 (even if check passes due to warning threshold)
        agent.max_token_lifetime_secs = 1800;
        let compliance = AssessmentService::calculate_compliance(&checks, &agent);
        assert!(!compliance.mcp_oauth);
    }

    fn create_test_agent() -> AiAgent {
        AiAgent {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "test-agent".to_string(),
            description: None,
            agent_type: "copilot".to_string(),
            owner_id: None,
            team_id: None,
            backup_owner_id: None,
            model_provider: None,
            model_name: None,
            model_version: None,
            agent_card_url: None,
            agent_card_signature: Some("sig".to_string()),
            status: "active".to_string(),
            risk_level: "medium".to_string(),
            max_token_lifetime_secs: 900,
            requires_human_approval: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_activity_at: None,
            expires_at: None,
            // F108 governance fields
            inactivity_threshold_days: Some(90),
            grace_period_ends_at: None,
            suspension_reason: None,
            rotation_interval_days: None,
            last_rotation_at: None,
            risk_score: None,
            next_certification_at: None,
            last_certified_at: None,
            last_certified_by: None,
        }
    }
}
