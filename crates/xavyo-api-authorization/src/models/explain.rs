//! DTOs for the NHI authorization explain endpoint.

use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

/// Query parameters for the explain-nhi endpoint.
#[derive(Debug, Deserialize, IntoParams)]
pub struct ExplainNhiQuery {
    /// The NHI identity to evaluate.
    pub nhi_id: Uuid,

    /// The action to check (defaults to "create").
    #[serde(default = "default_action")]
    pub action: String,

    /// The resource type to check (defaults to "mcp").
    #[serde(default = "default_resource_type")]
    pub resource_type: String,
}

fn default_action() -> String {
    "create".to_string()
}

fn default_resource_type() -> String {
    "mcp".to_string()
}

/// The authorization check steps, matching the ext-authz pipeline order.
///
/// Steps are either **decisive** (affect `would_allow`) or **informational**
/// (provide context but never fail the overall result).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExplainStep {
    /// NHI identity lookup. **Decisive.**
    NhiIdentity,
    /// Lifecycle state check. **Decisive.**
    LifecycleState,
    /// Agent extension details. **Informational** — missing agent row does
    /// not cause a deny in the real ext-authz pipeline.
    AgentDetails,
    /// Risk score vs deny threshold. **Decisive.**
    RiskScore,
    /// Active delegation grants. **Informational** — the real ext-authz only
    /// evaluates delegation when the token carries an `act` claim.
    DelegationGrants,
    /// PDP policy evaluation. **Decisive.** Uses empty roles (NHI permissions
    /// come from entitlements, not JWT roles — same as `admin_check_handler`).
    PdpEvaluation,
}

impl ExplainStep {
    /// Whether this step's `pass` value affects the `would_allow` outcome.
    /// Informational steps are always excluded from the allow/deny decision.
    pub fn is_decisive(self) -> bool {
        matches!(
            self,
            Self::NhiIdentity | Self::LifecycleState | Self::RiskScore | Self::PdpEvaluation
        )
    }
}

/// A single step in the authorization evaluation.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ExplainCheckStep {
    /// Which pipeline step this result is for.
    pub step: ExplainStep,

    /// Whether the check passed.
    pub pass: bool,

    /// Human-readable detail about the result.
    pub detail: String,
}

/// Response for the explain-nhi endpoint.
#[derive(Debug, Serialize, ToSchema)]
pub struct ExplainNhiResponse {
    /// The NHI identity that was evaluated.
    pub nhi_id: Uuid,

    /// The tenant scope.
    pub tenant_id: Uuid,

    /// Whether the request would be allowed. Computed from **decisive** steps
    /// only (`nhi_identity`, `lifecycle_state`, `risk_score`, `pdp_evaluation`).
    /// Informational steps (`agent_details`, `delegation_grants`) never affect
    /// this value.
    pub would_allow: bool,

    /// Step-by-step check results.
    pub checks: Vec<ExplainCheckStep>,
}

impl ExplainNhiResponse {
    /// Compute `would_allow` from the decisive steps.
    pub fn compute_would_allow(checks: &[ExplainCheckStep]) -> bool {
        checks
            .iter()
            .filter(|c| c.step.is_decisive())
            .all(|c| c.pass)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_explain_step_serde_round_trip() {
        let all = [
            ExplainStep::NhiIdentity,
            ExplainStep::LifecycleState,
            ExplainStep::AgentDetails,
            ExplainStep::RiskScore,
            ExplainStep::DelegationGrants,
            ExplainStep::PdpEvaluation,
        ];
        for step in &all {
            let json = serde_json::to_string(step).unwrap();
            let deserialized: ExplainStep = serde_json::from_str(&json).unwrap();
            assert_eq!(*step, deserialized);
        }
    }

    #[test]
    fn test_explain_step_snake_case_names() {
        assert_eq!(
            serde_json::to_string(&ExplainStep::NhiIdentity).unwrap(),
            "\"nhi_identity\""
        );
        assert_eq!(
            serde_json::to_string(&ExplainStep::LifecycleState).unwrap(),
            "\"lifecycle_state\""
        );
        assert_eq!(
            serde_json::to_string(&ExplainStep::AgentDetails).unwrap(),
            "\"agent_details\""
        );
        assert_eq!(
            serde_json::to_string(&ExplainStep::RiskScore).unwrap(),
            "\"risk_score\""
        );
        assert_eq!(
            serde_json::to_string(&ExplainStep::DelegationGrants).unwrap(),
            "\"delegation_grants\""
        );
        assert_eq!(
            serde_json::to_string(&ExplainStep::PdpEvaluation).unwrap(),
            "\"pdp_evaluation\""
        );
    }

    #[test]
    fn test_decisive_vs_informational() {
        assert!(ExplainStep::NhiIdentity.is_decisive());
        assert!(ExplainStep::LifecycleState.is_decisive());
        assert!(!ExplainStep::AgentDetails.is_decisive());
        assert!(ExplainStep::RiskScore.is_decisive());
        assert!(!ExplainStep::DelegationGrants.is_decisive());
        assert!(ExplainStep::PdpEvaluation.is_decisive());
    }

    #[test]
    fn test_would_allow_ignores_informational_steps() {
        // All decisive steps pass, but an informational step fails.
        let checks = vec![
            ExplainCheckStep {
                step: ExplainStep::NhiIdentity,
                pass: true,
                detail: String::new(),
            },
            ExplainCheckStep {
                step: ExplainStep::LifecycleState,
                pass: true,
                detail: String::new(),
            },
            ExplainCheckStep {
                step: ExplainStep::AgentDetails,
                pass: false, // informational — should not affect result
                detail: "agent extension row not found".to_string(),
            },
            ExplainCheckStep {
                step: ExplainStep::RiskScore,
                pass: true,
                detail: String::new(),
            },
            ExplainCheckStep {
                step: ExplainStep::DelegationGrants,
                pass: false, // informational — should not affect result
                detail: "database error".to_string(),
            },
            ExplainCheckStep {
                step: ExplainStep::PdpEvaluation,
                pass: true,
                detail: String::new(),
            },
        ];
        assert!(ExplainNhiResponse::compute_would_allow(&checks));
    }

    #[test]
    fn test_would_allow_false_on_decisive_failure() {
        let checks = vec![
            ExplainCheckStep {
                step: ExplainStep::NhiIdentity,
                pass: true,
                detail: String::new(),
            },
            ExplainCheckStep {
                step: ExplainStep::LifecycleState,
                pass: false, // decisive — should fail result
                detail: "state: suspended (not usable)".to_string(),
            },
            ExplainCheckStep {
                step: ExplainStep::RiskScore,
                pass: true,
                detail: String::new(),
            },
            ExplainCheckStep {
                step: ExplainStep::PdpEvaluation,
                pass: true,
                detail: String::new(),
            },
        ];
        assert!(!ExplainNhiResponse::compute_would_allow(&checks));
    }

    #[test]
    fn test_query_defaults() {
        let q: ExplainNhiQuery =
            serde_json::from_str(&format!(r#"{{"nhi_id": "{}"}}"#, Uuid::nil())).unwrap();
        assert_eq!(q.action, "create");
        assert_eq!(q.resource_type, "mcp");
    }

    #[test]
    fn test_query_explicit_values() {
        let q: ExplainNhiQuery = serde_json::from_str(&format!(
            r#"{{"nhi_id": "{}", "action": "read", "resource_type": "tools"}}"#,
            Uuid::nil()
        ))
        .unwrap();
        assert_eq!(q.action, "read");
        assert_eq!(q.resource_type, "tools");
    }

    #[test]
    fn test_response_serialization() {
        let resp = ExplainNhiResponse {
            nhi_id: Uuid::nil(),
            tenant_id: Uuid::nil(),
            would_allow: false,
            checks: vec![ExplainCheckStep {
                step: ExplainStep::NhiIdentity,
                pass: false,
                detail: "NHI identity not found".to_string(),
            }],
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["would_allow"], false);
        assert_eq!(json["checks"][0]["step"], "nhi_identity");
        assert_eq!(json["checks"][0]["pass"], false);
    }
}
