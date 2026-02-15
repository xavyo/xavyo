use std::sync::Arc;

use sqlx::PgPool;
use tonic::{Request, Response, Status};
use uuid::Uuid;
use xavyo_core::TenantId;

use xavyo_authorization::cache::{MappingCache, PolicyCache};
use xavyo_authorization::pdp::PolicyDecisionPoint;
use xavyo_authorization::types::AuthorizationRequest;
use xavyo_db::models::NhiToolPermission;
use xavyo_nhi::{NhiRiskLevel, NhiType};

use crate::activity::ActivityTracker;
use crate::config::ExtAuthzConfig;
use crate::error::ExtAuthzError;
use crate::nhi_cache::NhiCache;
use crate::proto;
use crate::proto::authorization_server::Authorization;
use crate::request::{parse_check_request, AuthzContext};
use crate::response::{
    build_allow_response, build_deny_response, build_fail_open_response, AllowMetadata,
};

/// The ext_authz gRPC service implementation.
pub struct ExtAuthzService {
    pool: Arc<PgPool>,
    pdp: Arc<PolicyDecisionPoint>,
    nhi_cache: Arc<NhiCache>,
    activity_tracker: Arc<ActivityTracker>,
    fail_open: bool,
    risk_score_deny_threshold: i32,
    require_metadata_context: bool,
}

impl ExtAuthzService {
    /// Create a new service instance.
    pub fn new(
        pool: Arc<PgPool>,
        config: &ExtAuthzConfig,
        policy_cache: Arc<PolicyCache>,
        mapping_cache: Arc<MappingCache>,
    ) -> Self {
        let pdp = Arc::new(PolicyDecisionPoint::new(policy_cache, mapping_cache));
        let nhi_cache = Arc::new(NhiCache::new(config.nhi_cache_ttl_secs));
        let activity_tracker = Arc::new(ActivityTracker::new(
            Arc::clone(&pool),
            config.activity_flush_interval_secs,
        ));

        Self {
            pool,
            pdp,
            nhi_cache,
            activity_tracker,
            fail_open: config.fail_open,
            risk_score_deny_threshold: config.risk_score_deny_threshold,
            require_metadata_context: config.require_metadata_context,
        }
    }

    /// Core authorization check logic.
    ///
    /// Returns `Err((error, Option<AuthzContext>))` — the context is `Some` when
    /// JWT parsing succeeded but a later step (DB, PDP, risk) failed. This allows
    /// the caller to include tenant context in fail-open responses.
    async fn do_check(
        &self,
        request: &proto::CheckRequest,
    ) -> Result<proto::CheckResponse, (ExtAuthzError, Option<AuthzContext>)> {
        // Step 1-2: Extract and parse JWT claims
        let ctx = parse_check_request(request).map_err(|e| (e, None))?;

        // Enforce metadata_context requirement if configured
        if self.require_metadata_context && !ctx.from_metadata_context {
            return Err((
                ExtAuthzError::JwtExtraction(
                    "metadata_context required but JWT extracted from Authorization header fallback"
                        .into(),
                ),
                Some(ctx),
            ));
        }

        tracing::debug!(
            subject_id = %ctx.subject_id,
            tenant_id = %ctx.tenant_id,
            method = %ctx.method,
            path = %ctx.path,
            action = %ctx.action,
            resource_type = %ctx.resource_type,
            "processing ext_authz check"
        );

        let tenant_uuid = *ctx.tenant_id.as_uuid();

        // Helper: wrap errors with the parsed context for fail-open support
        let ctx_err =
            |e: ExtAuthzError| -> (ExtAuthzError, Option<AuthzContext>) { (e, Some(ctx.clone())) };

        // Step 3: Lookup NHI identity (with cache)
        let cached = self
            .nhi_cache
            .get_or_load(&self.pool, ctx.tenant_id, ctx.subject_id)
            .await
            .map_err(|e| ctx_err(e.into()))?
            .ok_or_else(|| ctx_err(ExtAuthzError::NhiNotFound(ctx.subject_id)))?;

        let identity = &cached.identity;

        // Step 4: Verify lifecycle state
        if !identity.lifecycle_state.is_usable() {
            return Err(ctx_err(ExtAuthzError::NhiNotUsable(
                identity.lifecycle_state.as_str().to_string(),
            )));
        }

        // Step 5: Check risk score against threshold
        let (risk_score, risk_level) = if let Some(ref rs) = cached.risk_score {
            let level = NhiRiskLevel::from(rs.total_score);
            if rs.total_score > self.risk_score_deny_threshold {
                return Err(ctx_err(ExtAuthzError::RiskScoreExceeded {
                    score: rs.total_score,
                    threshold: self.risk_score_deny_threshold,
                }));
            }
            (rs.total_score, level)
        } else {
            // No risk score on file: assume low risk
            (0, NhiRiskLevel::Low)
        };

        // Step 6: PDP evaluation
        let authz_request = AuthorizationRequest {
            subject_id: ctx.subject_id,
            tenant_id: tenant_uuid,
            action: ctx.action.clone(),
            resource_type: ctx.resource_type.clone(),
            resource_id: None,
        };

        let decision = self
            .pdp
            .evaluate(&self.pool, authz_request, &ctx.roles, None)
            .await;

        if !decision.allowed {
            return Err(ctx_err(ExtAuthzError::AuthorizationDenied(decision.reason)));
        }

        // Step 7: Load tool permissions for agents
        let allowed_tools = if identity.nhi_type == NhiType::Agent {
            self.resolve_tool_names(ctx.tenant_id, ctx.subject_id)
                .await
                .map_err(ctx_err)?
        } else {
            vec![]
        };

        // Step 8: Build ALLOW response with dynamic_metadata
        let (agent_type, model_provider, requires_human_approval) =
            if let Some(ref agent) = cached.agent {
                (
                    Some(agent.agent_type.clone()),
                    agent.model_provider.clone(),
                    Some(agent.requires_human_approval),
                )
            } else {
                (None, None, None)
            };

        let metadata = AllowMetadata {
            nhi_id: identity.id,
            nhi_type: identity.nhi_type.as_str().to_string(),
            nhi_name: identity.name.clone(),
            lifecycle_state: identity.lifecycle_state.as_str().to_string(),
            tenant_id: ctx.tenant_id,
            risk_score,
            risk_level: risk_level.as_str().to_string(),
            allowed_tools,
            agent_type,
            model_provider,
            requires_human_approval,
            decision_id: decision.decision_id,
        };

        // Step 9: Record activity (async, non-blocking)
        self.activity_tracker.record(ctx.tenant_id, ctx.subject_id);

        tracing::info!(
            subject_id = %ctx.subject_id,
            tenant_id = %ctx.tenant_id,
            decision_id = %decision.decision_id,
            nhi_type = %identity.nhi_type,
            risk_level = %risk_level,
            "ext_authz ALLOW"
        );

        Ok(build_allow_response(&metadata))
    }

    /// Resolve tool names for an agent via a single JOIN query.
    async fn resolve_tool_names(
        &self,
        tenant_id: TenantId,
        agent_nhi_id: Uuid,
    ) -> Result<Vec<String>, ExtAuthzError> {
        let tenant_uuid = *tenant_id.as_uuid();
        let names =
            NhiToolPermission::tool_names_by_agent(&self.pool, tenant_uuid, agent_nhi_id).await?;
        Ok(names)
    }
}

#[tonic::async_trait]
impl Authorization for ExtAuthzService {
    async fn check(
        &self,
        request: Request<proto::CheckRequest>,
    ) -> Result<Response<proto::CheckResponse>, Status> {
        let check_request = request.into_inner();

        match self.do_check(&check_request).await {
            Ok(response) => Ok(Response::new(response)),
            Err((err, ctx)) => {
                // Log the denial with full operational detail (server-side only)
                if let Some(ref ctx) = ctx {
                    tracing::warn!(
                        error = %err,
                        tenant_id = %ctx.tenant_id,
                        subject_id = %ctx.subject_id,
                        "ext_authz DENY"
                    );
                } else {
                    tracing::warn!(error = %err, "ext_authz DENY (pre-parse)");
                }

                // If fail_open and it's an internal error, allow with minimal metadata
                if self.fail_open
                    && matches!(err, ExtAuthzError::Database(_) | ExtAuthzError::Internal(_))
                {
                    if let Some(ref ctx) = ctx {
                        tracing::warn!(
                            tenant_id = %ctx.tenant_id,
                            subject_id = %ctx.subject_id,
                            "fail_open: allowing with minimal metadata"
                        );
                        return Ok(Response::new(build_fail_open_response(ctx)));
                    }
                    // No context available (parse failed) — cannot fail-open safely
                    tracing::warn!("fail_open: no tenant context available, denying");
                }

                Ok(Response::new(build_deny_response(&err)))
            }
        }
    }
}
