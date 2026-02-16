//! Handler for the NHI authorization explain endpoint.
//!
//! Runs the full ext-authz authorization pipeline (NHI lookup, lifecycle,
//! risk score, delegation, PDP) for a given NHI and returns step-by-step
//! results. Unlike ext-authz which short-circuits on first failure, this
//! runs ALL checks so operators can diagnose multi-cause denials.

use axum::{
    extract::{Query, State},
    Extension, Json,
};
use xavyo_auth::JwtClaims;
use xavyo_authorization::AuthorizationRequest;
use xavyo_db::models::{GovNhiRiskScore, NhiAgent, NhiDelegationGrant, NhiIdentity};
use xavyo_nhi::NhiRiskLevel;

use crate::error::{ApiAuthorizationError, ApiResult};
use crate::models::explain::{
    ExplainCheckStep, ExplainNhiQuery, ExplainNhiResponse, ExplainStep,
};
use crate::router::AuthorizationState;

/// Explain NHI authorization — admin-only dry-run of the full authz pipeline.
///
/// Runs every check the real ext-authz service would run and returns all
/// results. Steps are marked **decisive** (affect `would_allow`) or
/// **informational** (context only). PDP evaluation uses empty roles because
/// NHI permissions come from entitlements, not JWT roles — the same pattern
/// as `admin_check_handler`.
#[utoipa::path(
    get,
    path = "/admin/authorization/explain-nhi",
    tag = "Authorization - Explain",
    params(ExplainNhiQuery),
    responses(
        (status = 200, description = "Step-by-step authorization evaluation", body = ExplainNhiResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden — admin role required"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn explain_nhi_handler(
    State(state): State<AuthorizationState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ExplainNhiQuery>,
) -> ApiResult<Json<ExplainNhiResponse>> {
    // Admin gate (same pattern as admin_check_handler)
    if !claims.has_role("admin") {
        return Err(ApiAuthorizationError::Forbidden);
    }

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiAuthorizationError::Unauthorized)?
        .as_uuid();

    let nhi_id = query.nhi_id;
    let mut checks = Vec::with_capacity(6);

    // -----------------------------------------------------------------------
    // Step 1: NHI identity lookup (decisive)
    // -----------------------------------------------------------------------
    let identity = match NhiIdentity::find_by_id(&state.pool, tenant_id, nhi_id).await {
        Ok(Some(id)) => {
            checks.push(ExplainCheckStep {
                step: ExplainStep::NhiIdentity,
                pass: true,
                detail: format!("'{}' (type: {})", id.name, id.nhi_type),
            });
            Some(id)
        }
        Ok(None) => {
            checks.push(ExplainCheckStep {
                step: ExplainStep::NhiIdentity,
                pass: false,
                detail: "NHI identity not found".to_string(),
            });
            None
        }
        Err(e) => {
            checks.push(ExplainCheckStep {
                step: ExplainStep::NhiIdentity,
                pass: false,
                detail: format!("database error: {e}"),
            });
            None
        }
    };

    // -----------------------------------------------------------------------
    // Step 2: Lifecycle state (decisive — no DB call, just struct check)
    // -----------------------------------------------------------------------
    if let Some(ref id) = identity {
        let usable = id.lifecycle_state.is_usable();
        checks.push(ExplainCheckStep {
            step: ExplainStep::LifecycleState,
            pass: usable,
            detail: format!(
                "state: {} ({})",
                id.lifecycle_state,
                if usable { "usable" } else { "not usable" }
            ),
        });
    } else {
        checks.push(ExplainCheckStep {
            step: ExplainStep::LifecycleState,
            pass: false,
            detail: "skipped — identity not found".to_string(),
        });
    }

    // -----------------------------------------------------------------------
    // Steps 3, 4, 5: Independent DB queries — run in parallel
    // -----------------------------------------------------------------------
    let is_agent = identity
        .as_ref()
        .map_or(false, |id| id.nhi_type == xavyo_nhi::NhiType::Agent);

    let (agent_result, risk_result, delegation_result) = tokio::join!(
        // Step 3: Agent details (informational)
        async {
            if is_agent {
                Some(NhiAgent::find_by_nhi_id(&state.pool, tenant_id, nhi_id).await)
            } else {
                None // Not an agent — skip entirely
            }
        },
        // Step 4: Risk score (decisive)
        GovNhiRiskScore::find_by_nhi(&state.pool, tenant_id, nhi_id),
        // Step 5: Delegation grants (informational)
        NhiDelegationGrant::list_by_actor(&state.pool, tenant_id, nhi_id, 100, 0),
    );

    // --- Process step 3: Agent details (informational — never affects would_allow) ---
    if let Some(result) = agent_result {
        match result {
            Ok(Some(agent)) => {
                checks.push(ExplainCheckStep {
                    step: ExplainStep::AgentDetails,
                    pass: true,
                    detail: format!(
                        "agent_type: {}, requires_human_approval: {}",
                        agent.agent_type, agent.requires_human_approval
                    ),
                });
            }
            Ok(None) => {
                // Missing agent extension row does NOT deny in real ext-authz.
                // The pipeline just sets agent_type/model_provider to None.
                checks.push(ExplainCheckStep {
                    step: ExplainStep::AgentDetails,
                    pass: true,
                    detail: "agent extension row not found (non-blocking)".to_string(),
                });
            }
            Err(e) => {
                checks.push(ExplainCheckStep {
                    step: ExplainStep::AgentDetails,
                    pass: true, // informational — DB errors here don't deny
                    detail: format!("could not load agent details: {e}"),
                });
            }
        }
    }

    // --- Process step 4: Risk score (decisive) ---
    // Mirror ext-authz: `rs.total_score > threshold` → deny.
    // So pass = `score <= threshold`.
    match risk_result {
        Ok(Some(rs)) => {
            let level = NhiRiskLevel::from(rs.total_score);
            let pass = rs.total_score <= state.risk_score_deny_threshold;
            checks.push(ExplainCheckStep {
                step: ExplainStep::RiskScore,
                pass,
                detail: format!(
                    "score: {}, threshold: {}, level: {}",
                    rs.total_score,
                    state.risk_score_deny_threshold,
                    level.as_str()
                ),
            });
        }
        Ok(None) => {
            // No risk score on file → ext-authz assumes (0, Low) → always passes
            checks.push(ExplainCheckStep {
                step: ExplainStep::RiskScore,
                pass: true,
                detail: format!(
                    "no score on file (assumed 0), threshold: {}",
                    state.risk_score_deny_threshold
                ),
            });
        }
        Err(e) => {
            checks.push(ExplainCheckStep {
                step: ExplainStep::RiskScore,
                pass: false,
                detail: format!("database error: {e}"),
            });
        }
    }

    // --- Process step 5: Delegation grants (informational) ---
    // In real ext-authz, delegation is only checked when the token has an `act`
    // claim. This dry-run just lists active grants for visibility.
    match delegation_result {
        Ok(grants) => {
            let active: Vec<_> = grants.iter().filter(|g| g.is_active()).collect();
            let detail = if active.is_empty() {
                "no active delegation grants".to_string()
            } else {
                let summaries: Vec<String> = active
                    .iter()
                    .map(|g| {
                        format!(
                            "grant_id={} (principal: {} {}, max_depth: {})",
                            g.id, g.principal_type, g.principal_id, g.max_delegation_depth
                        )
                    })
                    .collect();
                format!("{} active grant(s): {}", active.len(), summaries.join("; "))
            };
            checks.push(ExplainCheckStep {
                step: ExplainStep::DelegationGrants,
                pass: true,
                detail,
            });
        }
        Err(e) => {
            checks.push(ExplainCheckStep {
                step: ExplainStep::DelegationGrants,
                pass: false, // signal the error honestly in `pass`…
                detail: format!("could not load grants: {e}"),
                // …but DelegationGrants is informational, so this doesn't
                // affect `would_allow` via `compute_would_allow()`.
            });
        }
    }

    // -----------------------------------------------------------------------
    // Step 6: PDP evaluation (decisive)
    //
    // Uses empty roles — NHI permissions come from entitlements, not JWT
    // roles. This matches `admin_check_handler` behavior.
    // -----------------------------------------------------------------------
    if identity.is_some() {
        let authz_request = AuthorizationRequest {
            subject_id: nhi_id,
            tenant_id,
            action: query.action,
            resource_type: query.resource_type,
            resource_id: None,
            delegation: None,
        };

        let decision = state
            .pdp
            .evaluate(&state.pool, authz_request, &[], None)
            .await;

        checks.push(ExplainCheckStep {
            step: ExplainStep::PdpEvaluation,
            pass: decision.allowed,
            detail: format!(
                "{} (source: {}, reason: {})",
                if decision.allowed {
                    "allowed"
                } else {
                    "denied"
                },
                decision.source,
                decision.reason
            ),
        });
    } else {
        checks.push(ExplainCheckStep {
            step: ExplainStep::PdpEvaluation,
            pass: false,
            detail: "skipped — identity not found".to_string(),
        });
    }

    // -----------------------------------------------------------------------
    // Assemble response
    // -----------------------------------------------------------------------
    let would_allow = ExplainNhiResponse::compute_would_allow(&checks);

    Ok(Json(ExplainNhiResponse {
        nhi_id,
        tenant_id,
        would_allow,
        checks,
    }))
}
