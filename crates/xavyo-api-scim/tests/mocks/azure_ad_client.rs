//! Azure AD SCIM client mock implementation.
//!
//! Simulates Azure AD's SCIM provisioning behavior including known quirks.

use serde_json::{json, Value};

use super::base_client::{MockClientConfig, MockScimClient};
use super::quirks::{azure_ad_quirks, QuirkDefinition};

/// Mock Azure AD SCIM client that simulates Azure AD's provisioning behavior.
#[derive(Debug)]
pub struct AzureAdClient {
    config: MockClientConfig,
}

impl AzureAdClient {
    /// Create a new Azure AD mock client with default configuration.
    pub fn new() -> Self {
        let quirk_ids = azure_ad_quirks().into_iter().map(|q| q.id).collect();
        Self {
            config: MockClientConfig::with_all_quirks(quirk_ids),
        }
    }

    /// Create with custom configuration.
    pub fn with_config(config: MockClientConfig) -> Self {
        Self { config }
    }
}

impl Default for AzureAdClient {
    fn default() -> Self {
        Self::new()
    }
}

impl MockScimClient for AzureAdClient {
    fn idp_name(&self) -> &'static str {
        "Azure AD"
    }

    fn user_agent(&self) -> &'static str {
        "Azure Active Directory SCIM Client"
    }

    fn get_quirks(&self) -> Vec<QuirkDefinition> {
        azure_ad_quirks()
    }

    fn config(&self) -> &MockClientConfig {
        &self.config
    }

    fn build_create_user_payload(&self, email: &str, external_id: &str) -> Value {
        let mut payload = json!({
            "userName": email,
            "externalId": external_id,
            "name": {
                "givenName": "Test",
                "familyName": "User"
            },
            "emails": [{
                "primary": true,
                "value": email,
                "type": "work"
            }],
            "active": true,
            "displayName": "Test User"
        });

        // AAD-001: Azure AD sometimes omits schemas
        if !self.config.quirk_enabled("AAD-001") {
            payload["schemas"] = json!(["urn:ietf:params:scim:schemas:core:2.0:User"]);
        }

        // AAD-002: Azure AD may use legacy schema URIs
        if self.config.quirk_enabled("AAD-002") {
            // Add enterprise extension with legacy 1.0 URI
            payload["urn:scim:schemas:extension:enterprise:1.0"] = json!({
                "department": "Engineering"
            });
        }

        payload
    }

    fn build_patch_user_payload(&self, operations: Vec<Value>) -> Value {
        let ops: Vec<Value> = operations
            .into_iter()
            .map(|op| {
                // AAD-003: Azure AD may include full resource in PATCH replace
                // This is handled at a higher level, not in individual operations
                op
            })
            .collect();

        json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": ops
        })
    }

    fn build_filter(&self, attribute: &str, operator: &str, value: &str) -> String {
        // AAD-005: Azure AD sends filters with extra whitespace
        if self.config.quirk_enabled("AAD-005") {
            format!("{}  {}  \"{}\"", attribute, operator, value)
        } else {
            format!("{} {} \"{}\"", attribute, operator, value)
        }
    }

    fn build_headers(&self) -> Vec<(&'static str, String)> {
        vec![
            ("User-Agent", self.user_agent().to_string()),
            ("client-request-id", uuid::Uuid::new_v4().to_string()),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_azure_ad_client_default() {
        let client = AzureAdClient::new();
        assert_eq!(client.idp_name(), "Azure AD");
        assert_eq!(client.get_quirks().len(), 6);
    }

    #[test]
    fn test_azure_ad_user_agent() {
        let client = AzureAdClient::new();
        assert!(client.user_agent().contains("Azure"));
    }

    #[test]
    fn test_azure_ad_create_payload_omits_schemas() {
        let client = AzureAdClient::new();
        let payload = client.build_create_user_payload("test@example.com", "ext-123");

        // AAD-001: schemas field should be omitted by default
        assert!(payload.get("schemas").is_none());
    }

    #[test]
    fn test_azure_ad_create_payload_with_legacy_schema() {
        let client = AzureAdClient::new();
        let payload = client.build_create_user_payload("test@example.com", "ext-123");

        // AAD-002: Should include legacy 1.0 enterprise extension
        assert!(payload
            .get("urn:scim:schemas:extension:enterprise:1.0")
            .is_some());
    }

    #[test]
    fn test_azure_ad_filter_with_extra_whitespace() {
        let client = AzureAdClient::new();
        let filter = client.build_filter("userName", "eq", "test@example.com");

        // AAD-005: Should have extra whitespace around operator
        assert!(filter.contains("  eq  "));
    }

    #[test]
    fn test_azure_ad_headers_include_request_id() {
        let client = AzureAdClient::new();
        let headers = client.build_headers();

        let has_request_id = headers.iter().any(|(k, _)| *k == "client-request-id");
        assert!(has_request_id);
    }

    #[test]
    fn test_azure_ad_client_without_quirks() {
        let config = MockClientConfig::default();
        let client = AzureAdClient::with_config(config);
        let payload = client.build_create_user_payload("test@example.com", "ext-123");

        // Without AAD-001, schemas should be present
        assert!(payload.get("schemas").is_some());
    }
}
