//! `IdP` quirk definitions and documentation.

/// Severity level for a quirk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Minor inconvenience, easy workaround.
    Low,
    /// Moderate impact, requires specific handling.
    Medium,
    /// Significant impact, may affect core functionality.
    High,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Low => write!(f, "Low"),
            Severity::Medium => write!(f, "Medium"),
            Severity::High => write!(f, "High"),
        }
    }
}

/// Definition of an IdP-specific quirk (deviation from SCIM spec).
#[derive(Debug, Clone)]
pub struct QuirkDefinition {
    /// Unique identifier (e.g., "OKTA-001").
    pub id: String,
    /// Identity provider name.
    pub idp: String,
    /// Description of the quirk.
    pub description: String,
    /// Severity of the quirk.
    pub severity: Severity,
    /// Impact on our SCIM server.
    pub impact: String,
    /// Recommended workaround.
    pub workaround: String,
}

impl QuirkDefinition {
    /// Create a new quirk definition.
    pub fn new(
        id: impl Into<String>,
        idp: impl Into<String>,
        description: impl Into<String>,
        severity: Severity,
        impact: impl Into<String>,
        workaround: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            idp: idp.into(),
            description: description.into(),
            severity,
            impact: impact.into(),
            workaround: workaround.into(),
        }
    }
}

/// Okta quirk definitions.
pub fn okta_quirks() -> Vec<QuirkDefinition> {
    vec![
        QuirkDefinition::new(
            "OKTA-001",
            "Okta",
            "Sends empty string for optional attributes instead of omitting",
            Severity::Low,
            "Empty strings may be stored instead of null",
            "Treat empty strings as null during parsing",
        ),
        QuirkDefinition::new(
            "OKTA-002",
            "Okta",
            "PATCH operations use value array even for single values",
            Severity::Medium,
            "Parser may fail if expecting scalar value",
            "Accept both array and scalar in PATCH value field",
        ),
        QuirkDefinition::new(
            "OKTA-003",
            "Okta",
            "Expects id in response to be string, not UUID format",
            Severity::High,
            "Client may fail to parse UUID-formatted IDs",
            "Always return IDs as strings without UUID formatting",
        ),
        QuirkDefinition::new(
            "OKTA-004",
            "Okta",
            "Retries on 5xx with exponential backoff (up to 5 times)",
            Severity::Low,
            "Server may receive duplicate requests",
            "Return consistent errors, use idempotency",
        ),
        QuirkDefinition::new(
            "OKTA-005",
            "Okta",
            "Sends active: false for deactivation, not DELETE",
            Severity::High,
            "Users may not be properly deactivated if expecting DELETE",
            "Support soft-delete via PATCH active=false",
        ),
    ]
}

/// Azure AD quirk definitions.
pub fn azure_ad_quirks() -> Vec<QuirkDefinition> {
    vec![
        QuirkDefinition::new(
            "AAD-001",
            "Azure AD",
            "Sends requests without schemas in payload (sometimes)",
            Severity::High,
            "Request may be rejected for missing required field",
            "Make schemas field optional in parser",
        ),
        QuirkDefinition::new(
            "AAD-002",
            "Azure AD",
            "Uses non-standard urn:scim:schemas:extension:enterprise:1.0 sometimes",
            Severity::Medium,
            "Enterprise extension may not be recognized",
            "Accept both 1.0 and 2.0 schema URIs",
        ),
        QuirkDefinition::new(
            "AAD-003",
            "Azure AD",
            "PATCH replace operations may include full resource",
            Severity::Medium,
            "Parser may fail expecting partial update",
            "Accept full resource in PATCH replace",
        ),
        QuirkDefinition::new(
            "AAD-004",
            "Azure AD",
            "Expects exact schema match in ServiceProviderConfig",
            Severity::High,
            "Config endpoint may fail Azure AD validation",
            "Match Azure's expected format exactly",
        ),
        QuirkDefinition::new(
            "AAD-005",
            "Azure AD",
            "Sends filter with spaces around operators",
            Severity::Low,
            "Filter parsing may fail on whitespace",
            "Trim filter tokens during parsing",
        ),
        QuirkDefinition::new(
            "AAD-006",
            "Azure AD",
            "May send duplicate requests on timeout (no idempotency key)",
            Severity::High,
            "Duplicate users may be created",
            "Use externalId for deduplication",
        ),
    ]
}

/// `OneLogin` quirk definitions.
pub fn onelogin_quirks() -> Vec<QuirkDefinition> {
    vec![
        QuirkDefinition::new(
            "OL-001",
            "OneLogin",
            "Sends null explicitly for optional fields",
            Severity::Low,
            "Null handling may differ from field omission",
            "Accept explicit nulls same as omitted fields",
        ),
        QuirkDefinition::new(
            "OL-002",
            "OneLogin",
            "PATCH path syntax uses array notation for single values",
            Severity::Medium,
            "Path parsing may fail on members[value eq \"x\"] syntax",
            "Parse array notation in PATCH paths",
        ),
        QuirkDefinition::new(
            "OL-003",
            "OneLogin",
            "May omit meta from resource responses",
            Severity::Low,
            "Client may expect meta field presence",
            "Make meta optional in response parsing",
        ),
        QuirkDefinition::new(
            "OL-004",
            "OneLogin",
            "Uses different date format (ISO 8601 with timezone)",
            Severity::Medium,
            "Date parsing may fail",
            "Accept multiple date formats",
        ),
        QuirkDefinition::new(
            "OL-005",
            "OneLogin",
            "Filter and/or operators must be lowercase",
            Severity::Low,
            "Case-sensitive filter parsing may fail",
            "Normalize filter operators to lowercase",
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_okta_quirks_count() {
        let quirks = okta_quirks();
        assert_eq!(quirks.len(), 5);
        assert!(quirks.iter().all(|q| q.idp == "Okta"));
    }

    #[test]
    fn test_azure_ad_quirks_count() {
        let quirks = azure_ad_quirks();
        assert_eq!(quirks.len(), 6);
        assert!(quirks.iter().all(|q| q.idp == "Azure AD"));
    }

    #[test]
    fn test_onelogin_quirks_count() {
        let quirks = onelogin_quirks();
        assert_eq!(quirks.len(), 5);
        assert!(quirks.iter().all(|q| q.idp == "OneLogin"));
    }

    #[test]
    fn test_quirk_id_format() {
        let all_quirks: Vec<_> = okta_quirks()
            .into_iter()
            .chain(azure_ad_quirks())
            .chain(onelogin_quirks())
            .collect();

        for quirk in all_quirks {
            // ID should match pattern: PREFIX-NNN
            assert!(
                quirk.id.contains('-'),
                "Quirk ID '{}' should contain a hyphen",
                quirk.id
            );
        }
    }
}
