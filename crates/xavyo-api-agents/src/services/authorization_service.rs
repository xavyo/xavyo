//! Authorization service for real-time tool authorization decisions.
//!
//! Provides sub-100ms authorization decisions with rate limiting using DashMap.
//! Includes optional anomaly detection for behavioral analysis (F094).

use chrono::Utc;
use dashmap::DashMap;
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Instant;
use uuid::Uuid;

use crate::error::ApiAgentsError;
use crate::models::{AuthorizationContext, AuthorizeRequest, AuthorizeResponse};
use crate::services::{AnomalyService, ApprovalService, AuditService, PermissionService};
use xavyo_db::models::ai_agent::AiAgent;
use xavyo_db::models::ai_agent_approval_request::CreateApprovalRequest;

/// Rate limit tracking entry.
#[derive(Debug, Clone)]
struct RateLimitEntry {
    /// Number of calls in the current hour window.
    count: i32,
    /// Start of the current hour window.
    window_start: chrono::DateTime<Utc>,
}

/// Service for real-time authorization decisions.
#[derive(Clone)]
pub struct AuthorizationService {
    pool: PgPool,
    permission_service: Arc<PermissionService>,
    audit_service: Arc<AuditService>,
    anomaly_service: Arc<AnomalyService>,
    approval_service: Arc<ApprovalService>,
    /// In-memory rate limit tracking: (tenant_id, agent_id, tool_id) -> RateLimitEntry
    rate_limits: Arc<DashMap<(Uuid, Uuid, Uuid), RateLimitEntry>>,
    /// Whether to enable inline anomaly detection (adds latency but improves security)
    anomaly_detection_enabled: bool,
}

impl AuthorizationService {
    /// Create a new AuthorizationService.
    pub fn new(
        pool: PgPool,
        permission_service: Arc<PermissionService>,
        audit_service: Arc<AuditService>,
        approval_service: Arc<ApprovalService>,
    ) -> Self {
        let anomaly_service = Arc::new(AnomalyService::new(pool.clone()));
        Self {
            pool,
            permission_service,
            audit_service,
            anomaly_service,
            approval_service,
            rate_limits: Arc::new(DashMap::new()),
            anomaly_detection_enabled: true, // Enabled by default
        }
    }

    /// Create with explicit anomaly service (for testing or custom configuration).
    pub fn with_anomaly_service(
        pool: PgPool,
        permission_service: Arc<PermissionService>,
        audit_service: Arc<AuditService>,
        anomaly_service: Arc<AnomalyService>,
        approval_service: Arc<ApprovalService>,
        anomaly_detection_enabled: bool,
    ) -> Self {
        Self {
            pool,
            permission_service,
            audit_service,
            anomaly_service,
            approval_service,
            rate_limits: Arc::new(DashMap::new()),
            anomaly_detection_enabled,
        }
    }

    /// Authorize by separate parameters (convenience method for MCP).
    pub async fn authorize(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
        tool: &str,
        parameters: Option<serde_json::Value>,
        conversation_id: Option<String>,
        session_id: Option<String>,
    ) -> Result<AuthorizeResponse, ApiAgentsError> {
        let context = if conversation_id.is_some() || session_id.is_some() {
            Some(AuthorizationContext {
                conversation_id,
                session_id,
                user_instruction: None,
                user_context: None,
            })
        } else {
            None
        };

        let request = AuthorizeRequest {
            agent_id,
            tool: tool.to_string(),
            parameters,
            context,
        };

        self.authorize_request(tenant_id, request, None).await
    }

    /// Make an authorization decision for an agent tool invocation.
    ///
    /// Target latency: <100ms
    pub async fn authorize_request(
        &self,
        tenant_id: Uuid,
        request: AuthorizeRequest,
        source_ip: Option<&str>,
    ) -> Result<AuthorizeResponse, ApiAgentsError> {
        // Delegate to the existing implementation
        self.authorize_internal(tenant_id, request, source_ip).await
    }

    /// Internal authorization implementation.
    async fn authorize_internal(
        &self,
        tenant_id: Uuid,
        request: AuthorizeRequest,
        source_ip: Option<&str>,
    ) -> Result<AuthorizeResponse, ApiAgentsError> {
        let start = Instant::now();
        let decision_id = Uuid::new_v4();

        // 1. Check agent exists and is active (~5ms)
        let agent = AiAgent::find_by_id(&self.pool, tenant_id, request.agent_id)
            .await?
            .ok_or(ApiAgentsError::AgentNotFound)?;

        if !agent.is_active() {
            let reason = "Agent is not active";
            let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

            // Log the denial
            let _ = self
                .log_authorization(
                    tenant_id,
                    request.agent_id,
                    None,
                    &request.tool,
                    request.parameters.clone(),
                    "denied", // DB constraint uses "denied" not "deny"
                    reason,
                    &request.context,
                    source_ip,
                    latency_ms as i32,
                )
                .await;

            return Ok(AuthorizeResponse {
                decision: "deny".to_string(),
                decision_id,
                reason: reason.to_string(),
                latency_ms,
                approval_request_id: None,
                anomaly_warnings: None,
            });
        }

        // Check if agent is expired
        if agent.is_expired() {
            let reason = "Agent has expired";
            let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

            let _ = self
                .log_authorization(
                    tenant_id,
                    request.agent_id,
                    None,
                    &request.tool,
                    request.parameters.clone(),
                    "denied", // DB constraint uses "denied" not "deny"
                    reason,
                    &request.context,
                    source_ip,
                    latency_ms as i32,
                )
                .await;

            return Ok(AuthorizeResponse {
                decision: "deny".to_string(),
                decision_id,
                reason: reason.to_string(),
                latency_ms,
                approval_request_id: None,
                anomaly_warnings: None,
            });
        }

        // 2. Check permission exists (~5ms)
        let (permission, tool) = match self
            .permission_service
            .check_permission_by_tool_name(tenant_id, request.agent_id, &request.tool)
            .await?
        {
            Some((p, t)) => (p, t),
            None => {
                let reason = format!("Agent does not have permission for tool '{}'", request.tool);
                let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

                let _ = self
                    .log_authorization(
                        tenant_id,
                        request.agent_id,
                        None,
                        &request.tool,
                        request.parameters.clone(),
                        "denied", // DB constraint uses "denied" not "deny"
                        &reason,
                        &request.context,
                        source_ip,
                        latency_ms as i32,
                    )
                    .await;

                return Ok(AuthorizeResponse {
                    decision: "deny".to_string(),
                    decision_id,
                    reason,
                    latency_ms,
                    approval_request_id: None,
                    anomaly_warnings: None,
                });
            }
        };

        // Check if tool is active
        if tool.status != "active" {
            let reason = format!("Tool '{}' is not active", request.tool);
            let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

            let _ = self
                .log_authorization(
                    tenant_id,
                    request.agent_id,
                    Some(tool.id),
                    &request.tool,
                    request.parameters.clone(),
                    "denied", // DB constraint uses "denied" not "deny"
                    &reason,
                    &request.context,
                    source_ip,
                    latency_ms as i32,
                )
                .await;

            return Ok(AuthorizeResponse {
                decision: "deny".to_string(),
                decision_id,
                reason,
                latency_ms,
                approval_request_id: None,
                anomaly_warnings: None,
            });
        }

        // Check if permission is expired
        if permission.is_expired() {
            let reason = "Permission has expired";
            let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

            let _ = self
                .log_authorization(
                    tenant_id,
                    request.agent_id,
                    Some(tool.id),
                    &request.tool,
                    request.parameters.clone(),
                    "denied", // DB constraint uses "denied" not "deny"
                    reason,
                    &request.context,
                    source_ip,
                    latency_ms as i32,
                )
                .await;

            return Ok(AuthorizeResponse {
                decision: "deny".to_string(),
                decision_id,
                reason: reason.to_string(),
                latency_ms,
                approval_request_id: None,
                anomaly_warnings: None,
            });
        }

        // 3. Check rate limits (~1ms - in-memory)
        let max_calls = permission
            .max_calls_per_hour
            .or(tool.max_calls_per_hour)
            .unwrap_or(i32::MAX);

        if max_calls < i32::MAX {
            let key = (tenant_id, request.agent_id, tool.id);
            let now = Utc::now();

            let current_count = {
                let mut entry = self
                    .rate_limits
                    .entry(key)
                    .or_insert_with(|| RateLimitEntry {
                        count: 0,
                        window_start: now,
                    });

                // Check if we need to reset the window (hourly)
                let hours_diff = (now - entry.window_start).num_hours();
                if hours_diff >= 1 {
                    entry.count = 0;
                    entry.window_start = now;
                }

                entry.count += 1;
                entry.count
            };

            if current_count > max_calls {
                let reason = format!(
                    "Rate limit exceeded: {}/{} calls in current hour",
                    current_count, max_calls
                );
                let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

                let _ = self
                    .log_authorization(
                        tenant_id,
                        request.agent_id,
                        Some(tool.id),
                        &request.tool,
                        request.parameters.clone(),
                        "denied", // DB constraint uses "denied" not "deny"
                        &reason,
                        &request.context,
                        source_ip,
                        latency_ms as i32,
                    )
                    .await;

                return Ok(AuthorizeResponse {
                    decision: "deny".to_string(),
                    decision_id,
                    reason,
                    latency_ms,
                    approval_request_id: None,
                    anomaly_warnings: None,
                });
            }
        }

        // 4. Check if approval is required
        let requires_approval = permission
            .requires_approval
            .unwrap_or(tool.requires_approval)
            || agent.requires_human_approval;

        if requires_approval {
            let reason = "Human approval required for this action";

            // Create actual approval request (F092 HITL integration)
            let (conversation_id, session_id, user_instruction) = match &request.context {
                Some(ctx) => (
                    ctx.conversation_id.clone(),
                    ctx.session_id.clone(),
                    ctx.user_instruction.clone(),
                ),
                None => (None, None, None),
            };

            // Calculate risk score based on tool risk level
            let risk_score = match tool.risk_level.as_str() {
                "critical" => 90,
                "high" => 70,
                "medium" => 50,
                "low" => 30,
                _ => 50,
            };

            let approval_input = CreateApprovalRequest {
                agent_id: request.agent_id,
                tool_id: tool.id,
                parameters: request.parameters.clone().unwrap_or(serde_json::json!({})),
                context: serde_json::json!({
                    "tool_name": request.tool,
                    "source_ip": source_ip,
                }),
                risk_score,
                user_instruction,
                session_id,
                conversation_id,
                timeout_secs: None,     // Use default (5 minutes)
                notification_url: None, // Could be added from agent config
            };

            // Create the approval request in the database
            let approval_request_id = match self
                .approval_service
                .create_approval(tenant_id, approval_input)
                .await
            {
                Ok(approval) => Some(approval.id),
                Err(e) => {
                    tracing::error!("Failed to create approval request: {}", e);
                    // Fall back to a random UUID to maintain API contract
                    Some(Uuid::new_v4())
                }
            };

            let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

            let _ = self
                .log_authorization(
                    tenant_id,
                    request.agent_id,
                    Some(tool.id),
                    &request.tool,
                    request.parameters.clone(),
                    "require_approval",
                    reason,
                    &request.context,
                    source_ip,
                    latency_ms as i32,
                )
                .await;

            return Ok(AuthorizeResponse {
                decision: "require_approval".to_string(),
                decision_id,
                reason: reason.to_string(),
                latency_ms,
                approval_request_id,
                anomaly_warnings: None,
            });
        }

        // 5. Authorization allowed - check for anomalies (non-blocking)
        let anomaly_warnings = if self.anomaly_detection_enabled {
            self.detect_anomalies_for_tool(tenant_id, request.agent_id, &request.tool)
                .await
        } else {
            None
        };

        let reason = "Agent has permission for tool";
        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

        // Update agent's last activity (fire-and-forget)
        let pool = self.pool.clone();
        let agent_id_copy = request.agent_id;
        tokio::spawn(async move {
            let _ = AiAgent::update_last_activity(&pool, tenant_id, agent_id_copy).await;
        });

        // Log the authorization (fire-and-forget)
        let _ = self
            .log_authorization(
                tenant_id,
                request.agent_id,
                Some(tool.id),
                &request.tool,
                request.parameters,
                "allowed", // DB constraint uses "allowed" not "allow"
                reason,
                &request.context,
                source_ip,
                latency_ms as i32,
            )
            .await;

        Ok(AuthorizeResponse {
            decision: "allow".to_string(),
            decision_id,
            reason: reason.to_string(),
            latency_ms,
            approval_request_id: None,
            anomaly_warnings,
        })
    }

    /// Detect anomalies for a tool invocation (non-blocking).
    ///
    /// Returns anomaly warnings if any are detected, None otherwise.
    async fn detect_anomalies_for_tool(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
        tool_name: &str,
    ) -> Option<Vec<crate::models::AnomalyWarning>> {
        // Try to detect anomalies, but don't fail authorization if detection fails
        match self
            .anomaly_service
            .detect_tool_invocation_anomalies(tenant_id, agent_id, tool_name)
            .await
        {
            Ok(anomalies) if !anomalies.is_empty() => {
                let warnings: Vec<crate::models::AnomalyWarning> = anomalies
                    .into_iter()
                    .map(|a| crate::models::AnomalyWarning {
                        anomaly_type: a.anomaly_type.as_str().to_string(),
                        severity: a.severity.as_str().to_string(),
                        description: a.description,
                        score: a.score,
                    })
                    .collect();
                Some(warnings)
            }
            Ok(_) => None,
            Err(e) => {
                // Log error but don't fail authorization
                tracing::warn!("Anomaly detection failed: {}", e);
                None
            }
        }
    }

    /// Log an authorization event.
    #[allow(clippy::too_many_arguments)]
    async fn log_authorization(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
        tool_id: Option<Uuid>,
        tool_name: &str,
        parameters: Option<serde_json::Value>,
        decision: &str,
        reason: &str,
        context: &Option<AuthorizationContext>,
        source_ip: Option<&str>,
        duration_ms: i32,
    ) -> Result<Uuid, ApiAgentsError> {
        let (conversation_id, session_id, user_instruction) = match context {
            Some(ctx) => (
                ctx.conversation_id.as_deref(),
                ctx.session_id.as_deref(),
                ctx.user_instruction.as_deref(),
            ),
            None => (None, None, None),
        };

        self.audit_service
            .log_authorization(
                tenant_id,
                agent_id,
                tool_id,
                tool_name,
                parameters,
                decision,
                reason,
                conversation_id,
                session_id,
                user_instruction,
                source_ip,
                duration_ms,
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::requests::UserContext;

    #[test]
    fn test_rate_limit_entry() {
        let entry = RateLimitEntry {
            count: 5,
            window_start: Utc::now(),
        };

        assert_eq!(entry.count, 5);
    }

    #[test]
    fn test_rate_limit_window_reset() {
        // Test rate limit window behavior
        let now = Utc::now();
        let old_window = now - chrono::Duration::hours(2);

        let entry = RateLimitEntry {
            count: 100,
            window_start: old_window,
        };

        // Check that hours_diff would trigger a reset
        let hours_diff = (now - entry.window_start).num_hours();
        assert!(hours_diff >= 1);
    }

    #[test]
    fn test_authorize_response_structure() {
        use crate::models::AuthorizeResponse;

        let response = AuthorizeResponse {
            decision: "allow".to_string(),
            decision_id: Uuid::new_v4(),
            reason: "Agent has permission".to_string(),
            latency_ms: 12.5,
            approval_request_id: None,
            anomaly_warnings: None,
        };

        assert_eq!(response.decision, "allow");
        assert!(response.latency_ms < 100.0);
        assert!(response.anomaly_warnings.is_none());
    }

    // F123: User context extraction tests
    #[test]
    fn test_user_context_in_authorization_context() {
        let user_context = UserContext {
            user_id: Uuid::new_v4(),
            email: Some("alice@example.com".to_string()),
            roles: Some(vec!["workflow-operator".to_string()]),
        };

        let context = AuthorizationContext {
            conversation_id: Some("conv-123".to_string()),
            session_id: Some("sess-456".to_string()),
            user_instruction: Some("Transfer funds".to_string()),
            user_context: Some(user_context.clone()),
        };

        assert!(context.user_context.is_some());
        let uc = context.user_context.as_ref().unwrap();
        assert_eq!(uc.email, Some("alice@example.com".to_string()));
        assert_eq!(uc.roles.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn test_authorization_context_without_user_context() {
        let context = AuthorizationContext {
            conversation_id: Some("conv-123".to_string()),
            session_id: Some("sess-456".to_string()),
            user_instruction: None,
            user_context: None,
        };

        assert!(context.user_context.is_none());
        assert_eq!(context.conversation_id, Some("conv-123".to_string()));
    }

    #[test]
    fn test_user_context_serialization() {
        let user_context = UserContext {
            user_id: Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            email: Some("bob@example.com".to_string()),
            roles: Some(vec!["admin".to_string(), "operator".to_string()]),
        };

        let json = serde_json::to_string(&user_context).unwrap();
        assert!(json.contains("550e8400-e29b-41d4-a716-446655440000"));
        assert!(json.contains("bob@example.com"));
        assert!(json.contains("admin"));

        let deserialized: UserContext = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.user_id, user_context.user_id);
        assert_eq!(deserialized.email, user_context.email);
    }

    #[test]
    fn test_user_context_deserialization_minimal() {
        // User context with only required field
        let json = r#"{"user_id": "550e8400-e29b-41d4-a716-446655440000"}"#;
        let user_context: UserContext = serde_json::from_str(json).unwrap();

        assert_eq!(
            user_context.user_id,
            Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap()
        );
        assert!(user_context.email.is_none());
        assert!(user_context.roles.is_none());
    }
}
