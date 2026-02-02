//! Security Assessment models for the AI Agent Security API (F093).
//!
//! Implements the arXiv:2511.03841 14-point vulnerability framework.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ============================================================================
// Enumerations
// ============================================================================

/// Risk level derived from overall security score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    /// Score >= 75: Agent is well-configured with proper security controls.
    Low,
    /// Score >= 50 && < 75: Agent has some security gaps.
    Medium,
    /// Score >= 25 && < 50: Agent has significant security issues.
    High,
    /// Score < 25: Agent has severe security vulnerabilities.
    Critical,
}

impl RiskLevel {
    /// Determine risk level from overall score.
    pub fn from_score(score: u8) -> Self {
        match score {
            75..=100 => RiskLevel::Low,
            50..=74 => RiskLevel::Medium,
            25..=49 => RiskLevel::High,
            _ => RiskLevel::Critical,
        }
    }
}

/// Vulnerability check category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum Category {
    /// Identity and credential security.
    Authentication,
    /// Access control and permissions.
    Authorization,
    /// Data handling and validation.
    DataIntegrity,
    /// Observability and oversight.
    Monitoring,
}

/// Vulnerability check status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// Check passed - no issues found.
    Pass,
    /// Check passed with warnings - minor issues.
    Warning,
    /// Check failed - security issue detected.
    Fail,
}

/// Vulnerability check severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Low severity: 5 point deduction on fail, 2.5 on warning.
    Low,
    /// Medium severity: 10 point deduction on fail, 5 on warning.
    Medium,
    /// High severity: 15 point deduction on fail, 7.5 on warning.
    High,
    /// Critical severity: 25 point deduction on fail, 12.5 on warning.
    Critical,
}

impl Severity {
    /// Get the score deduction for a failure.
    pub fn fail_deduction(&self) -> u8 {
        match self {
            Severity::Low => 5,
            Severity::Medium => 10,
            Severity::High => 15,
            Severity::Critical => 25,
        }
    }

    /// Get the score deduction for a warning.
    pub fn warning_deduction(&self) -> u8 {
        self.fail_deduction() / 2
    }
}

/// Recommendation priority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "lowercase")]
pub enum Priority {
    /// Low priority - address when convenient.
    Low,
    /// Medium priority - address soon.
    Medium,
    /// High priority - address immediately.
    High,
}

impl From<Severity> for Priority {
    fn from(severity: Severity) -> Self {
        match severity {
            Severity::Critical | Severity::High => Priority::High,
            Severity::Medium => Priority::Medium,
            Severity::Low => Priority::Low,
        }
    }
}

// ============================================================================
// Check Name Enum
// ============================================================================

/// Vulnerability check name identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum CheckName {
    /// Check 1: Token lifetime validation.
    TokenLifetime,
    /// Check 2: Granular scope/permission verification.
    GranularScopes,
    /// Check 3: Message/AgentCard signature integrity.
    MessageIntegrity,
    /// Check 4: Rate limiting configuration.
    RateLimiting,
    /// Check 5: Input parameter validation.
    InputValidation,
    /// Check 6: Output filtering/sanitization.
    OutputFiltering,
    /// Check 7: Audit logging presence.
    AuditLogging,
    /// Check 8: Human-in-the-loop consent tracking.
    ConsentTracking,
    /// Check 9: Session/conversation isolation.
    SessionIsolation,
    /// Check 10: Credential rotation policy.
    CredentialRotation,
    /// Check 11: Behavioral anomaly detection.
    AnomalyDetection,
    /// Check 12: Privilege escalation prevention.
    PrivilegeEscalation,
    /// Check 13: Data leakage prevention.
    DataLeakage,
    /// Check 14: Supply chain security.
    SupplyChain,
}

impl CheckName {
    /// Get check ID (1-14).
    pub fn id(&self) -> u8 {
        match self {
            CheckName::TokenLifetime => 1,
            CheckName::GranularScopes => 2,
            CheckName::MessageIntegrity => 3,
            CheckName::RateLimiting => 4,
            CheckName::InputValidation => 5,
            CheckName::OutputFiltering => 6,
            CheckName::AuditLogging => 7,
            CheckName::ConsentTracking => 8,
            CheckName::SessionIsolation => 9,
            CheckName::CredentialRotation => 10,
            CheckName::AnomalyDetection => 11,
            CheckName::PrivilegeEscalation => 12,
            CheckName::DataLeakage => 13,
            CheckName::SupplyChain => 14,
        }
    }

    /// Get check category.
    pub fn category(&self) -> Category {
        match self {
            CheckName::TokenLifetime | CheckName::CredentialRotation => Category::Authentication,
            CheckName::GranularScopes
            | CheckName::RateLimiting
            | CheckName::SessionIsolation
            | CheckName::PrivilegeEscalation => Category::Authorization,
            CheckName::MessageIntegrity
            | CheckName::InputValidation
            | CheckName::OutputFiltering
            | CheckName::DataLeakage
            | CheckName::SupplyChain => Category::DataIntegrity,
            CheckName::AuditLogging | CheckName::ConsentTracking | CheckName::AnomalyDetection => {
                Category::Monitoring
            }
        }
    }

    /// Get check severity.
    pub fn severity(&self) -> Severity {
        match self {
            CheckName::AuditLogging | CheckName::PrivilegeEscalation => Severity::Critical,
            CheckName::TokenLifetime
            | CheckName::MessageIntegrity
            | CheckName::InputValidation
            | CheckName::ConsentTracking
            | CheckName::DataLeakage => Severity::High,
            CheckName::GranularScopes
            | CheckName::RateLimiting
            | CheckName::OutputFiltering
            | CheckName::SessionIsolation
            | CheckName::CredentialRotation
            | CheckName::SupplyChain => Severity::Medium,
            CheckName::AnomalyDetection => Severity::Low,
        }
    }

    /// Get all check names in order.
    pub fn all() -> [CheckName; 14] {
        [
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
        ]
    }
}

// ============================================================================
// Response Structs
// ============================================================================

/// Individual vulnerability check result.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct VulnerabilityCheck {
    /// Check identifier (1-14).
    pub id: u8,

    /// Check name.
    pub name: CheckName,

    /// Check category.
    pub category: Category,

    /// Check result status.
    pub status: Status,

    /// Check severity level.
    pub severity: Severity,

    /// Human-readable explanation of the check result.
    pub details: String,
}

impl VulnerabilityCheck {
    /// Create a new vulnerability check result.
    pub fn new(name: CheckName, status: Status, details: impl Into<String>) -> Self {
        Self {
            id: name.id(),
            name,
            category: name.category(),
            status,
            severity: name.severity(),
            details: details.into(),
        }
    }

    /// Create a passing check.
    pub fn pass(name: CheckName, details: impl Into<String>) -> Self {
        Self::new(name, Status::Pass, details)
    }

    /// Create a warning check.
    pub fn warning(name: CheckName, details: impl Into<String>) -> Self {
        Self::new(name, Status::Warning, details)
    }

    /// Create a failing check.
    pub fn fail(name: CheckName, details: impl Into<String>) -> Self {
        Self::new(name, Status::Fail, details)
    }
}

/// OWASP Agentic compliance status.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct OwaspAgenticCompliance {
    /// Number of OWASP Agentic controls passing (0-8).
    pub controls_satisfied: u8,

    /// Total number of OWASP Agentic controls (always 8).
    pub total_controls: u8,

    /// True if controls_satisfied >= 6.
    pub compliant: bool,
}

impl OwaspAgenticCompliance {
    /// OWASP Agentic control check IDs.
    pub const CONTROL_CHECK_IDS: [u8; 8] = [1, 2, 3, 4, 5, 6, 8, 12];

    /// Create compliance status from passing check count.
    pub fn from_passing_count(controls_satisfied: u8) -> Self {
        Self {
            controls_satisfied,
            total_controls: 8,
            compliant: controls_satisfied >= 6,
        }
    }
}

/// Compliance status for security standards.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ComplianceStatus {
    /// OWASP Agentic Top 10 compliance.
    pub owasp_agentic: OwaspAgenticCompliance,

    /// A2A Protocol compliance (check 3 passes).
    pub a2a_protocol: bool,

    /// MCP OAuth 2.1 compliance (check 1 passes with <= 900s).
    pub mcp_oauth: bool,
}

/// Actionable recommendation based on check results.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Recommendation {
    /// Related vulnerability check ID (1-14).
    pub check_id: u8,

    /// Recommendation priority.
    pub priority: Priority,

    /// Short description of the issue.
    pub title: String,

    /// Actionable remediation step.
    pub action: String,
}

impl Recommendation {
    /// Create a new recommendation.
    pub fn new(
        check_id: u8,
        priority: Priority,
        title: impl Into<String>,
        action: impl Into<String>,
    ) -> Self {
        Self {
            check_id,
            priority,
            title: title.into(),
            action: action.into(),
        }
    }
}

/// Complete security assessment response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SecurityAssessment {
    /// The assessed agent's ID.
    pub agent_id: Uuid,

    /// Unique ID for this assessment instance.
    pub assessment_id: Uuid,

    /// When the assessment was performed.
    pub timestamp: DateTime<Utc>,

    /// Computed security score (0-100).
    pub overall_score: u8,

    /// Risk level derived from score.
    pub risk_level: RiskLevel,

    /// All 14 vulnerability check results.
    pub vulnerabilities: Vec<VulnerabilityCheck>,

    /// Compliance status for security standards.
    pub compliance: ComplianceStatus,

    /// Actionable improvement suggestions.
    pub recommendations: Vec<Recommendation>,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_risk_level_from_score() {
        assert_eq!(RiskLevel::from_score(100), RiskLevel::Low);
        assert_eq!(RiskLevel::from_score(75), RiskLevel::Low);
        assert_eq!(RiskLevel::from_score(74), RiskLevel::Medium);
        assert_eq!(RiskLevel::from_score(50), RiskLevel::Medium);
        assert_eq!(RiskLevel::from_score(49), RiskLevel::High);
        assert_eq!(RiskLevel::from_score(25), RiskLevel::High);
        assert_eq!(RiskLevel::from_score(24), RiskLevel::Critical);
        assert_eq!(RiskLevel::from_score(0), RiskLevel::Critical);
    }

    #[test]
    fn test_severity_deductions() {
        assert_eq!(Severity::Low.fail_deduction(), 5);
        assert_eq!(Severity::Low.warning_deduction(), 2);
        assert_eq!(Severity::Medium.fail_deduction(), 10);
        assert_eq!(Severity::Medium.warning_deduction(), 5);
        assert_eq!(Severity::High.fail_deduction(), 15);
        assert_eq!(Severity::High.warning_deduction(), 7);
        assert_eq!(Severity::Critical.fail_deduction(), 25);
        assert_eq!(Severity::Critical.warning_deduction(), 12);
    }

    #[test]
    fn test_check_name_id_mapping() {
        assert_eq!(CheckName::TokenLifetime.id(), 1);
        assert_eq!(CheckName::GranularScopes.id(), 2);
        assert_eq!(CheckName::SupplyChain.id(), 14);

        // Verify all IDs are unique and 1-14
        let checks = CheckName::all();
        for (i, check) in checks.iter().enumerate() {
            assert_eq!(check.id(), (i + 1) as u8);
        }
    }

    #[test]
    fn test_check_name_categories() {
        assert_eq!(
            CheckName::TokenLifetime.category(),
            Category::Authentication
        );
        assert_eq!(
            CheckName::GranularScopes.category(),
            Category::Authorization
        );
        assert_eq!(
            CheckName::MessageIntegrity.category(),
            Category::DataIntegrity
        );
        assert_eq!(CheckName::AuditLogging.category(), Category::Monitoring);
    }

    #[test]
    fn test_check_name_severities() {
        assert_eq!(CheckName::AuditLogging.severity(), Severity::Critical);
        assert_eq!(
            CheckName::PrivilegeEscalation.severity(),
            Severity::Critical
        );
        assert_eq!(CheckName::TokenLifetime.severity(), Severity::High);
        assert_eq!(CheckName::GranularScopes.severity(), Severity::Medium);
        assert_eq!(CheckName::AnomalyDetection.severity(), Severity::Low);
    }

    #[test]
    fn test_vulnerability_check_creation() {
        let check =
            VulnerabilityCheck::pass(CheckName::TokenLifetime, "Token lifetime is 900 seconds");

        assert_eq!(check.id, 1);
        assert_eq!(check.name, CheckName::TokenLifetime);
        assert_eq!(check.category, Category::Authentication);
        assert_eq!(check.status, Status::Pass);
        assert_eq!(check.severity, Severity::High);
    }

    #[test]
    fn test_owasp_compliance() {
        let compliant = OwaspAgenticCompliance::from_passing_count(6);
        assert!(compliant.compliant);
        assert_eq!(compliant.controls_satisfied, 6);
        assert_eq!(compliant.total_controls, 8);

        let not_compliant = OwaspAgenticCompliance::from_passing_count(5);
        assert!(!not_compliant.compliant);
    }

    #[test]
    fn test_priority_from_severity() {
        assert_eq!(Priority::from(Severity::Critical), Priority::High);
        assert_eq!(Priority::from(Severity::High), Priority::High);
        assert_eq!(Priority::from(Severity::Medium), Priority::Medium);
        assert_eq!(Priority::from(Severity::Low), Priority::Low);
    }

    #[test]
    fn test_security_assessment_serialization() {
        let assessment = SecurityAssessment {
            agent_id: Uuid::new_v4(),
            assessment_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            overall_score: 85,
            risk_level: RiskLevel::Low,
            vulnerabilities: vec![VulnerabilityCheck::pass(
                CheckName::TokenLifetime,
                "Token lifetime OK",
            )],
            compliance: ComplianceStatus {
                owasp_agentic: OwaspAgenticCompliance::from_passing_count(7),
                a2a_protocol: true,
                mcp_oauth: true,
            },
            recommendations: vec![],
        };

        let json = serde_json::to_string(&assessment).unwrap();
        assert!(json.contains("\"overall_score\":85"));
        assert!(json.contains("\"risk_level\":\"low\""));
        assert!(json.contains("\"a2a_protocol\":true"));
    }

    #[test]
    fn test_category_serialization() {
        let json = serde_json::to_string(&Category::DataIntegrity).unwrap();
        assert_eq!(json, "\"data_integrity\"");
    }

    #[test]
    fn test_check_name_serialization() {
        let json = serde_json::to_string(&CheckName::TokenLifetime).unwrap();
        assert_eq!(json, "\"token_lifetime\"");

        let json = serde_json::to_string(&CheckName::AnomalyDetection).unwrap();
        assert_eq!(json, "\"anomaly_detection\"");
    }

    #[test]
    fn test_recommendation_creation() {
        let rec = Recommendation::new(
            1,
            Priority::High,
            "Reduce token lifetime",
            "Update max_token_lifetime_secs to 900 or less",
        );

        assert_eq!(rec.check_id, 1);
        assert_eq!(rec.priority, Priority::High);
        assert!(rec.title.contains("token"));
    }
}
