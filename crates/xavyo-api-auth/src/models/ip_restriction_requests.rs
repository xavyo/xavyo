//! Request and response DTOs for IP restriction endpoints (F028).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;
use xavyo_db::models::{IpEnforcementMode, IpRestrictionRule, IpRuleType, TenantIpSettings};

// ============================================================================
// Settings Endpoints
// ============================================================================

/// Response for GET /admin/ip-restrictions/settings.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct IpSettingsResponse {
    /// The tenant ID.
    pub tenant_id: Uuid,

    /// IP restriction enforcement mode.
    pub enforcement_mode: IpEnforcementMode,

    /// Whether super admins bypass IP restrictions.
    pub bypass_for_super_admin: bool,

    /// When the settings were last updated.
    pub updated_at: DateTime<Utc>,

    /// User who last updated the settings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<Uuid>,
}

impl From<TenantIpSettings> for IpSettingsResponse {
    fn from(settings: TenantIpSettings) -> Self {
        Self {
            tenant_id: settings.tenant_id,
            enforcement_mode: settings.enforcement_mode,
            bypass_for_super_admin: settings.bypass_for_super_admin,
            updated_at: settings.updated_at,
            updated_by: settings.updated_by,
        }
    }
}

/// Request for PUT /admin/ip-restrictions/settings.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UpdateIpSettingsRequest {
    /// New enforcement mode (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enforcement_mode: Option<IpEnforcementMode>,

    /// New bypass setting for super admins (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bypass_for_super_admin: Option<bool>,
}

// ============================================================================
// Rules Endpoints
// ============================================================================

/// Response for an IP restriction rule.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct IpRuleResponse {
    /// Rule ID.
    pub id: Uuid,

    /// Tenant ID.
    pub tenant_id: Uuid,

    /// Rule type: whitelist or blacklist.
    pub rule_type: IpRuleType,

    /// Target scope: all, admin, or role:name.
    pub scope: String,

    /// IP address or range in CIDR notation.
    pub ip_cidr: String,

    /// Human-readable rule name.
    pub name: String,

    /// Optional description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Whether the rule is active.
    pub is_active: bool,

    /// User who created the rule.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_by: Option<Uuid>,

    /// When the rule was created.
    pub created_at: DateTime<Utc>,

    /// When the rule was last updated.
    pub updated_at: DateTime<Utc>,
}

impl From<IpRestrictionRule> for IpRuleResponse {
    fn from(rule: IpRestrictionRule) -> Self {
        Self {
            id: rule.id,
            tenant_id: rule.tenant_id,
            rule_type: rule.rule_type,
            scope: rule.scope,
            ip_cidr: rule.ip_cidr,
            name: rule.name,
            description: rule.description,
            is_active: rule.is_active,
            created_by: rule.created_by,
            created_at: rule.created_at,
            updated_at: rule.updated_at,
        }
    }
}

/// Response for GET /admin/ip-restrictions/rules.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ListRulesResponse {
    /// List of IP restriction rules.
    pub rules: Vec<IpRuleResponse>,
}

/// Request for POST /admin/ip-restrictions/rules.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateIpRuleRequest {
    /// Rule type: whitelist or blacklist.
    pub rule_type: IpRuleType,

    /// Target scope: all, admin, or role:name.
    #[serde(default = "default_scope")]
    #[validate(custom(function = "validate_scope"))]
    pub scope: String,

    /// IP address or range in CIDR notation.
    #[validate(length(min = 1, max = 50, message = "CIDR must be 1-50 characters"))]
    pub ip_cidr: String,

    /// Human-readable rule name.
    #[validate(length(min = 1, max = 100, message = "Name must be 1-100 characters"))]
    pub name: String,

    /// Optional description.
    #[validate(length(max = 500, message = "Description must be at most 500 characters"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Whether the rule is active.
    #[serde(default = "default_active")]
    pub is_active: bool,
}

fn default_scope() -> String {
    "all".to_string()
}

fn default_active() -> bool {
    true
}

fn validate_scope(scope: &str) -> Result<(), validator::ValidationError> {
    if scope == "all" || scope == "admin" || scope.starts_with("role:") {
        Ok(())
    } else {
        let mut err = validator::ValidationError::new("invalid_scope");
        err.message = Some("Scope must be 'all', 'admin', or 'role:<name>'".into());
        Err(err)
    }
}

/// Request for PUT /admin/ip-restrictions/rules/:id.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UpdateIpRuleRequest {
    /// New rule type (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_type: Option<IpRuleType>,

    /// New target scope (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    /// New IP CIDR (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_cidr: Option<String>,

    /// New name (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// New description (optional, use null to clear).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// New active status (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_active: Option<bool>,
}

impl Validate for UpdateIpRuleRequest {
    fn validate(&self) -> Result<(), validator::ValidationErrors> {
        let mut errors = validator::ValidationErrors::new();

        // Validate scope if present
        if let Some(ref s) = self.scope {
            if let Err(e) = validate_scope(s) {
                errors.add("scope", e);
            }
        }

        // Validate ip_cidr length if present
        if let Some(ref cidr) = self.ip_cidr {
            if cidr.is_empty() || cidr.len() > 50 {
                let mut err = validator::ValidationError::new("length");
                err.message = Some("CIDR must be 1-50 characters".into());
                errors.add("ip_cidr", err);
            }
        }

        // Validate name length if present
        if let Some(ref name) = self.name {
            if name.is_empty() || name.len() > 100 {
                let mut err = validator::ValidationError::new("length");
                err.message = Some("Name must be 1-100 characters".into());
                errors.add("name", err);
            }
        }

        // Validate description length if present
        if let Some(ref desc) = self.description {
            if desc.len() > 500 {
                let mut err = validator::ValidationError::new("length");
                err.message = Some("Description must be at most 500 characters".into());
                errors.add("description", err);
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

// ============================================================================
// Validate Endpoint
// ============================================================================

/// Request for POST /admin/ip-restrictions/validate.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct ValidateIpRequest {
    /// IP address to validate.
    #[validate(length(min = 1, max = 45, message = "IP address must be 1-45 characters"))]
    pub ip_address: String,

    /// Optional role to check scope rules against.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
}

/// Matching rule info for validate response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MatchingRuleInfo {
    /// Rule ID.
    pub id: Uuid,

    /// Rule name.
    pub name: String,

    /// IP CIDR that matched.
    pub ip_cidr: String,
}

/// Response for POST /admin/ip-restrictions/validate.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ValidateIpResponse {
    /// The IP address that was validated.
    pub ip_address: String,

    /// Validation status: allowed, blocked, or disabled.
    pub status: String,

    /// Current enforcement mode.
    pub enforcement_mode: IpEnforcementMode,

    /// Rules that matched the IP address.
    pub matching_rules: Vec<MatchingRuleInfo>,

    /// Human-readable reason for the result.
    pub reason: String,
}

// ============================================================================
// Query Parameters
// ============================================================================

/// Query parameters for GET /admin/ip-restrictions/rules.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListRulesQuery {
    /// Filter by active status.
    pub is_active: Option<bool>,

    /// Filter by rule type.
    pub rule_type: Option<IpRuleType>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_rule_request_validation() {
        let valid = CreateIpRuleRequest {
            rule_type: IpRuleType::Whitelist,
            scope: "all".to_string(),
            ip_cidr: "192.168.1.0/24".to_string(),
            name: "Corporate Network".to_string(),
            description: Some("Allow corporate network access".to_string()),
            is_active: true,
        };
        assert!(valid.validate().is_ok());

        // Invalid scope
        let invalid_scope = CreateIpRuleRequest {
            rule_type: IpRuleType::Whitelist,
            scope: "invalid".to_string(),
            ip_cidr: "192.168.1.0/24".to_string(),
            name: "Test".to_string(),
            description: None,
            is_active: true,
        };
        assert!(invalid_scope.validate().is_err());

        // Empty name
        let empty_name = CreateIpRuleRequest {
            rule_type: IpRuleType::Whitelist,
            scope: "all".to_string(),
            ip_cidr: "192.168.1.0/24".to_string(),
            name: "".to_string(),
            description: None,
            is_active: true,
        };
        assert!(empty_name.validate().is_err());
    }

    #[test]
    fn test_scope_validation() {
        assert!(validate_scope("all").is_ok());
        assert!(validate_scope("admin").is_ok());
        assert!(validate_scope("role:manager").is_ok());
        assert!(validate_scope("role:admin").is_ok());
        assert!(validate_scope("invalid").is_err());
        assert!(validate_scope("role").is_err());
    }

    #[test]
    fn test_validate_ip_request() {
        let valid = ValidateIpRequest {
            ip_address: "192.168.1.100".to_string(),
            role: Some("admin".to_string()),
        };
        assert!(valid.validate().is_ok());

        let empty_ip = ValidateIpRequest {
            ip_address: "".to_string(),
            role: None,
        };
        assert!(empty_ip.validate().is_err());
    }
}
