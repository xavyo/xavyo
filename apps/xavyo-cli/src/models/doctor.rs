//! Doctor diagnostic models for xavyo CLI

use serde::{Deserialize, Serialize};

/// Status of a diagnostic check
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticStatus {
    /// Check passed successfully
    Pass,
    /// Check failed with an issue
    Fail,
    /// Check passed with warnings
    Warn,
    /// Check was skipped (dependency not met)
    Skip,
}

impl DiagnosticStatus {
    /// Returns the display symbol for this status
    pub fn symbol(&self) -> &'static str {
        match self {
            DiagnosticStatus::Pass => "✓",
            DiagnosticStatus::Fail => "✗",
            DiagnosticStatus::Warn => "!",
            DiagnosticStatus::Skip => "-",
        }
    }

    /// Returns the display name for this status
    pub fn display(&self) -> &'static str {
        match self {
            DiagnosticStatus::Pass => "Pass",
            DiagnosticStatus::Fail => "Fail",
            DiagnosticStatus::Warn => "Warn",
            DiagnosticStatus::Skip => "Skip",
        }
    }

    /// Returns the ANSI color code for this status
    pub fn color(&self) -> &'static str {
        match self {
            DiagnosticStatus::Pass => "\x1b[32m", // Green
            DiagnosticStatus::Fail => "\x1b[31m", // Red
            DiagnosticStatus::Warn => "\x1b[33m", // Yellow
            DiagnosticStatus::Skip => "\x1b[90m", // Gray
        }
    }

    /// Returns true if this status indicates success (pass or warn)
    pub fn is_ok(&self) -> bool {
        matches!(self, DiagnosticStatus::Pass | DiagnosticStatus::Warn)
    }
}

/// Individual diagnostic check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticCheck {
    /// Check identifier (e.g., "configuration", "credentials")
    pub name: String,
    /// Human-readable name (e.g., "Configuration", "Credentials")
    pub display_name: String,
    /// Result of the check
    pub status: DiagnosticStatus,
    /// Description of the result
    pub message: String,
    /// Remediation suggestion if failed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggestion: Option<String>,
}

impl DiagnosticCheck {
    /// Create a new passing check
    pub fn pass(name: &str, display_name: &str, message: &str) -> Self {
        Self {
            name: name.to_string(),
            display_name: display_name.to_string(),
            status: DiagnosticStatus::Pass,
            message: message.to_string(),
            suggestion: None,
        }
    }

    /// Create a new failing check
    pub fn fail(name: &str, display_name: &str, message: &str, suggestion: &str) -> Self {
        Self {
            name: name.to_string(),
            display_name: display_name.to_string(),
            status: DiagnosticStatus::Fail,
            message: message.to_string(),
            suggestion: Some(suggestion.to_string()),
        }
    }

    /// Create a new warning check
    pub fn warn(name: &str, display_name: &str, message: &str, suggestion: Option<&str>) -> Self {
        Self {
            name: name.to_string(),
            display_name: display_name.to_string(),
            status: DiagnosticStatus::Warn,
            message: message.to_string(),
            suggestion: suggestion.map(std::string::ToString::to_string),
        }
    }

    /// Create a new skipped check
    pub fn skip(name: &str, display_name: &str, message: &str) -> Self {
        Self {
            name: name.to_string(),
            display_name: display_name.to_string(),
            status: DiagnosticStatus::Skip,
            message: message.to_string(),
            suggestion: None,
        }
    }
}

/// Complete diagnostic report containing all checks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticReport {
    /// Aggregate status (Pass if all pass, Fail if any fail)
    pub overall_status: DiagnosticStatus,
    /// List of all diagnostic checks
    pub checks: Vec<DiagnosticCheck>,
    /// CLI version for debugging
    pub cli_version: String,
    /// ISO 8601 timestamp of when checks ran
    pub timestamp: String,
}

impl DiagnosticReport {
    /// Create a new diagnostic report from a list of checks
    pub fn new(checks: Vec<DiagnosticCheck>) -> Self {
        let overall_status = Self::calculate_overall_status(&checks);
        let cli_version = env!("CARGO_PKG_VERSION").to_string();
        let timestamp = chrono::Utc::now().to_rfc3339();

        Self {
            overall_status,
            checks,
            cli_version,
            timestamp,
        }
    }

    /// Calculate overall status from checks
    fn calculate_overall_status(checks: &[DiagnosticCheck]) -> DiagnosticStatus {
        let has_fail = checks.iter().any(|c| c.status == DiagnosticStatus::Fail);
        let has_warn = checks.iter().any(|c| c.status == DiagnosticStatus::Warn);

        if has_fail {
            DiagnosticStatus::Fail
        } else if has_warn {
            DiagnosticStatus::Warn
        } else {
            DiagnosticStatus::Pass
        }
    }

    /// Count failed checks
    pub fn fail_count(&self) -> usize {
        self.checks
            .iter()
            .filter(|c| c.status == DiagnosticStatus::Fail)
            .count()
    }

    /// Count passed checks
    #[allow(dead_code)]
    pub fn pass_count(&self) -> usize {
        self.checks
            .iter()
            .filter(|c| c.status == DiagnosticStatus::Pass)
            .count()
    }

    /// Returns true if all checks passed
    pub fn all_passed(&self) -> bool {
        self.overall_status == DiagnosticStatus::Pass
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diagnostic_status_symbol() {
        assert_eq!(DiagnosticStatus::Pass.symbol(), "✓");
        assert_eq!(DiagnosticStatus::Fail.symbol(), "✗");
        assert_eq!(DiagnosticStatus::Warn.symbol(), "!");
        assert_eq!(DiagnosticStatus::Skip.symbol(), "-");
    }

    #[test]
    fn test_diagnostic_status_display() {
        assert_eq!(DiagnosticStatus::Pass.display(), "Pass");
        assert_eq!(DiagnosticStatus::Fail.display(), "Fail");
        assert_eq!(DiagnosticStatus::Warn.display(), "Warn");
        assert_eq!(DiagnosticStatus::Skip.display(), "Skip");
    }

    #[test]
    fn test_diagnostic_status_is_ok() {
        assert!(DiagnosticStatus::Pass.is_ok());
        assert!(DiagnosticStatus::Warn.is_ok());
        assert!(!DiagnosticStatus::Fail.is_ok());
        assert!(!DiagnosticStatus::Skip.is_ok());
    }

    #[test]
    fn test_diagnostic_check_pass() {
        let check = DiagnosticCheck::pass("config", "Configuration", "Config file found");
        assert_eq!(check.name, "config");
        assert_eq!(check.display_name, "Configuration");
        assert_eq!(check.status, DiagnosticStatus::Pass);
        assert_eq!(check.message, "Config file found");
        assert!(check.suggestion.is_none());
    }

    #[test]
    fn test_diagnostic_check_fail() {
        let check = DiagnosticCheck::fail(
            "credentials",
            "Credentials",
            "No credentials found",
            "Run `xavyo login`",
        );
        assert_eq!(check.name, "credentials");
        assert_eq!(check.status, DiagnosticStatus::Fail);
        assert_eq!(check.suggestion, Some("Run `xavyo login`".to_string()));
    }

    #[test]
    fn test_diagnostic_check_skip() {
        let check = DiagnosticCheck::skip("api", "API Connectivity", "Skipped - requires config");
        assert_eq!(check.status, DiagnosticStatus::Skip);
        assert!(check.suggestion.is_none());
    }

    #[test]
    fn test_diagnostic_check_serialization() {
        let check = DiagnosticCheck::pass("config", "Configuration", "Config found");
        let json = serde_json::to_string(&check).unwrap();
        assert!(json.contains("\"name\":\"config\""));
        assert!(json.contains("\"status\":\"pass\""));
        assert!(json.contains("\"message\":\"Config found\""));
        // suggestion should not appear since it's None
        assert!(!json.contains("suggestion"));
    }

    #[test]
    fn test_diagnostic_check_with_suggestion_serialization() {
        let check = DiagnosticCheck::fail("creds", "Credentials", "Not found", "Run `xavyo login`");
        let json = serde_json::to_string(&check).unwrap();
        assert!(json.contains("\"suggestion\":\"Run `xavyo login`\""));
    }

    #[test]
    fn test_diagnostic_report_all_pass() {
        let checks = vec![
            DiagnosticCheck::pass("config", "Configuration", "Found"),
            DiagnosticCheck::pass("creds", "Credentials", "Loaded"),
        ];
        let report = DiagnosticReport::new(checks);
        assert_eq!(report.overall_status, DiagnosticStatus::Pass);
        assert!(report.all_passed());
        assert_eq!(report.pass_count(), 2);
        assert_eq!(report.fail_count(), 0);
    }

    #[test]
    fn test_diagnostic_report_with_failure() {
        let checks = vec![
            DiagnosticCheck::pass("config", "Configuration", "Found"),
            DiagnosticCheck::fail("creds", "Credentials", "Not found", "Run login"),
        ];
        let report = DiagnosticReport::new(checks);
        assert_eq!(report.overall_status, DiagnosticStatus::Fail);
        assert!(!report.all_passed());
        assert_eq!(report.pass_count(), 1);
        assert_eq!(report.fail_count(), 1);
    }

    #[test]
    fn test_diagnostic_report_with_warning() {
        let checks = vec![
            DiagnosticCheck::pass("config", "Configuration", "Found"),
            DiagnosticCheck::warn("token", "Token", "Expires soon", Some("Refresh soon")),
        ];
        let report = DiagnosticReport::new(checks);
        assert_eq!(report.overall_status, DiagnosticStatus::Warn);
    }

    #[test]
    fn test_diagnostic_report_serialization() {
        let checks = vec![DiagnosticCheck::pass("config", "Configuration", "Found")];
        let report = DiagnosticReport::new(checks);
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"overall_status\":\"pass\""));
        assert!(json.contains("\"cli_version\""));
        assert!(json.contains("\"timestamp\""));
    }

    #[test]
    fn test_diagnostic_report_deserialization() {
        let json = r#"{
            "overall_status": "pass",
            "checks": [
                {
                    "name": "config",
                    "display_name": "Configuration",
                    "status": "pass",
                    "message": "Found"
                }
            ],
            "cli_version": "0.1.0",
            "timestamp": "2026-01-29T10:30:45Z"
        }"#;
        let report: DiagnosticReport = serde_json::from_str(json).unwrap();
        assert_eq!(report.overall_status, DiagnosticStatus::Pass);
        assert_eq!(report.checks.len(), 1);
        assert_eq!(report.cli_version, "0.1.0");
    }
}
