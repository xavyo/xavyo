//! Unified NHI data models for the CLI

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// --- Unified NHI Identity ---

/// Unified NHI identity response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NhiIdentityResponse {
    pub id: Uuid,
    #[serde(default)]
    pub tenant_id: Option<Uuid>,
    pub nhi_type: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub lifecycle_state: String,
    #[serde(default)]
    pub owner_id: Option<Uuid>,
    #[serde(default)]
    pub backup_owner_id: Option<Uuid>,
    #[serde(default)]
    pub risk_level: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Paginated list response for unified NHI identities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NhiListResponse {
    pub data: Vec<NhiIdentityResponse>,
    pub total: i64,
    pub limit: i32,
    pub offset: i32,
}

// --- Lifecycle ---

/// Request to suspend an NHI identity
#[derive(Debug, Clone, Serialize)]
pub struct SuspendRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Generic lifecycle action response (reused across actions)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleActionResponse {
    pub id: Uuid,
    pub name: String,
    pub lifecycle_state: String,
    #[serde(default)]
    pub nhi_type: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
}

// --- Permissions ---

/// Request to grant a tool permission to an agent
#[derive(Debug, Clone, Serialize)]
pub struct GrantPermissionRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

/// Tool permission response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionResponse {
    pub id: Uuid,
    pub agent_identity_id: Uuid,
    pub tool_identity_id: Uuid,
    #[serde(default)]
    pub granted_by: Option<Uuid>,
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Paginated permission list
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionListResponse {
    pub data: Vec<PermissionResponse>,
    pub total: i64,
}

/// Revoke permission response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokePermissionResponse {
    #[serde(default)]
    pub revoked: bool,
    #[serde(default)]
    pub message: Option<String>,
}

// --- Risk ---

/// Risk assessment for a single NHI identity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskResponse {
    pub nhi_identity_id: Uuid,
    #[serde(default)]
    pub overall_risk: Option<String>,
    #[serde(default)]
    pub risk_score: Option<f64>,
    #[serde(default)]
    pub factors: Vec<RiskFactor>,
}

/// Individual risk factor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactor {
    pub name: String,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}

/// Tenant-wide risk summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskSummaryResponse {
    #[serde(default)]
    pub total_identities: i64,
    #[serde(default)]
    pub high_risk_count: i64,
    #[serde(default)]
    pub medium_risk_count: i64,
    #[serde(default)]
    pub low_risk_count: i64,
    #[serde(default)]
    pub critical_risk_count: i64,
    #[serde(default)]
    pub risk_breakdown: Vec<serde_json::Value>,
}

// --- Certifications ---

/// Request to create a certification campaign
#[derive(Debug, Clone, Serialize)]
pub struct CreateCampaignRequest {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub due_date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_filter: Option<serde_json::Value>,
}

/// Campaign response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignResponse {
    pub id: Uuid,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub due_date: Option<String>,
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub updated_at: Option<DateTime<Utc>>,
}

/// Paginated campaign list
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignListResponse {
    pub data: Vec<CampaignResponse>,
    pub total: i64,
}

/// Certify response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertifyResponse {
    pub nhi_id: Uuid,
    #[serde(default)]
    pub certified_by: Option<Uuid>,
    #[serde(default)]
    pub certified_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub next_certification_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub message: Option<String>,
}

/// Revoke certification response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeCertResponse {
    pub nhi_id: Uuid,
    #[serde(default)]
    pub revoked: bool,
    #[serde(default)]
    pub new_state: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
}

// --- SoD (Separation of Duties) ---

/// Request to create a SoD rule
#[derive(Debug, Clone, Serialize)]
pub struct CreateSodRuleRequest {
    pub tool_id_a: Uuid,
    pub tool_id_b: Uuid,
    pub enforcement: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// SoD rule response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SodRuleResponse {
    pub id: Uuid,
    pub tool_id_a: Uuid,
    pub tool_id_b: Uuid,
    pub enforcement: String,
    #[serde(default)]
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Paginated SoD rule list
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SodRuleListResponse {
    pub data: Vec<SodRuleResponse>,
    pub total: i64,
}

/// SoD check request
#[derive(Debug, Clone, Serialize)]
pub struct SodCheckRequest {
    pub agent_id: Uuid,
    pub tool_id: Uuid,
}

/// SoD check response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SodCheckResponse {
    #[serde(default)]
    pub violations: Vec<SodViolation>,
    #[serde(default)]
    pub is_allowed: bool,
}

/// SoD violation detail
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SodViolation {
    pub rule_id: Uuid,
    #[serde(default)]
    pub conflicting_tool_id: Option<Uuid>,
    pub enforcement: String,
    #[serde(default)]
    pub description: Option<String>,
}

// --- Inactivity ---

/// Inactive NHI entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InactiveEntity {
    pub id: Uuid,
    pub name: String,
    pub nhi_type: String,
    pub lifecycle_state: String,
    #[serde(default)]
    pub last_activity_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub inactive_days: Option<i64>,
}

/// Inactive detection response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InactiveDetectResponse {
    pub data: Vec<InactiveEntity>,
    pub total: i64,
}

/// Grace period request
#[derive(Debug, Clone, Serialize)]
pub struct GracePeriodRequest {
    pub grace_days: i32,
}

/// Grace period response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GracePeriodResponse {
    pub id: Uuid,
    #[serde(default)]
    pub grace_until: Option<DateTime<Utc>>,
    #[serde(default)]
    pub message: Option<String>,
}

/// Auto-suspend response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoSuspendResponse {
    #[serde(default)]
    pub suspended_count: i64,
    #[serde(default)]
    pub suspended_ids: Vec<Uuid>,
    #[serde(default)]
    pub message: Option<String>,
}

/// Orphan entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrphanEntity {
    pub id: Uuid,
    pub name: String,
    pub nhi_type: String,
    pub lifecycle_state: String,
    #[serde(default)]
    pub owner_id: Option<Uuid>,
}

/// Orphan detection response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrphanDetectResponse {
    pub data: Vec<OrphanEntity>,
    pub total: i64,
}

// --- Tool Update ---

/// Request to update a tool via PATCH
#[derive(Debug, Clone, Serialize)]
pub struct UpdateToolRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requires_approval: Option<bool>,
}

impl UpdateToolRequest {
    pub fn has_changes(&self) -> bool {
        self.name.is_some()
            || self.description.is_some()
            || self.category.is_some()
            || self.requires_approval.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nhi_identity_response_deserialization() {
        let json = r#"{
            "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "nhi_type": "agent",
            "name": "test-agent",
            "lifecycle_state": "active",
            "created_at": "2026-02-01T10:00:00Z",
            "updated_at": "2026-02-01T10:00:00Z"
        }"#;

        let identity: NhiIdentityResponse = serde_json::from_str(json).unwrap();
        assert_eq!(identity.name, "test-agent");
        assert_eq!(identity.nhi_type, "agent");
        assert_eq!(identity.lifecycle_state, "active");
        assert!(identity.description.is_none());
    }

    #[test]
    fn test_nhi_list_response_deserialization() {
        let json = r#"{
            "data": [],
            "total": 0,
            "limit": 50,
            "offset": 0
        }"#;

        let list: NhiListResponse = serde_json::from_str(json).unwrap();
        assert_eq!(list.data.len(), 0);
        assert_eq!(list.total, 0);
    }

    #[test]
    fn test_suspend_request_serialization() {
        let req = SuspendRequest {
            reason: Some("maintenance".to_string()),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["reason"], "maintenance");

        let req_none = SuspendRequest { reason: None };
        let json_none = serde_json::to_value(&req_none).unwrap();
        assert!(json_none.get("reason").is_none());
    }

    #[test]
    fn test_create_sod_rule_request_serialization() {
        let req = CreateSodRuleRequest {
            tool_id_a: Uuid::nil(),
            tool_id_b: Uuid::nil(),
            enforcement: "prevent".to_string(),
            description: Some("Test rule".to_string()),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["enforcement"], "prevent");
        assert_eq!(json["description"], "Test rule");
    }

    #[test]
    fn test_sod_check_response_deserialization() {
        let json = r#"{
            "violations": [],
            "is_allowed": true
        }"#;

        let resp: SodCheckResponse = serde_json::from_str(json).unwrap();
        assert!(resp.is_allowed);
        assert!(resp.violations.is_empty());
    }

    #[test]
    fn test_update_tool_request_has_changes() {
        let empty = UpdateToolRequest {
            name: None,
            description: None,
            category: None,
            requires_approval: None,
        };
        assert!(!empty.has_changes());

        let with_name = UpdateToolRequest {
            name: Some("new-name".to_string()),
            description: None,
            category: None,
            requires_approval: None,
        };
        assert!(with_name.has_changes());
    }

    #[test]
    fn test_risk_summary_response_deserialization() {
        let json = r#"{
            "total_identities": 42,
            "high_risk_count": 5,
            "medium_risk_count": 10,
            "low_risk_count": 25,
            "critical_risk_count": 2,
            "risk_breakdown": []
        }"#;

        let resp: RiskSummaryResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.total_identities, 42);
        assert_eq!(resp.critical_risk_count, 2);
    }

    #[test]
    fn test_campaign_response_deserialization() {
        let json = r#"{
            "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "name": "Q1 Review",
            "status": "active",
            "created_at": "2026-02-01T10:00:00Z"
        }"#;

        let resp: CampaignResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.name, "Q1 Review");
        assert_eq!(resp.status, Some("active".to_string()));
    }
}
