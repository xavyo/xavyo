//! Okta SCIM client mock implementation.
//!
//! Simulates Okta's SCIM provisioning behavior including known quirks.

use serde_json::{json, Value};

use super::base_client::{MockClientConfig, MockScimClient};
use super::quirks::{okta_quirks, QuirkDefinition};

/// Mock Okta SCIM client that simulates Okta's provisioning behavior.
#[derive(Debug)]
pub struct OktaClient {
    config: MockClientConfig,
}

impl OktaClient {
    /// Create a new Okta mock client with default configuration.
    pub fn new() -> Self {
        let quirk_ids = okta_quirks().into_iter().map(|q| q.id).collect();
        Self {
            config: MockClientConfig::with_all_quirks(quirk_ids),
        }
    }

    /// Create with custom configuration.
    pub fn with_config(config: MockClientConfig) -> Self {
        Self { config }
    }
}

impl Default for OktaClient {
    fn default() -> Self {
        Self::new()
    }
}

impl MockScimClient for OktaClient {
    fn idp_name(&self) -> &'static str {
        "Okta"
    }

    fn user_agent(&self) -> &'static str {
        "Okta SCIM Client/2.0"
    }

    fn get_quirks(&self) -> Vec<QuirkDefinition> {
        okta_quirks()
    }

    fn config(&self) -> &MockClientConfig {
        &self.config
    }

    fn build_create_user_payload(&self, email: &str, external_id: &str) -> Value {
        let mut payload = json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
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
            "active": true
        });

        // OKTA-001: Okta sends empty strings for optional attributes
        if self.config.quirk_enabled("OKTA-001") {
            payload["displayName"] = json!("");
            payload["nickName"] = json!("");
            payload["title"] = json!("");
        }

        payload
    }

    fn build_patch_user_payload(&self, operations: Vec<Value>) -> Value {
        let ops: Vec<Value> = operations
            .into_iter()
            .map(|mut op| {
                // OKTA-002: Okta uses value array even for single values
                if self.config.quirk_enabled("OKTA-002") {
                    if let Some(value) = op.get("value") {
                        if !value.is_array() {
                            op["value"] = json!([value.clone()]);
                        }
                    }
                }
                op
            })
            .collect();

        json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": ops
        })
    }

    fn build_filter(&self, attribute: &str, operator: &str, value: &str) -> String {
        // Okta uses standard filter syntax
        format!("{attribute} {operator} \"{value}\"")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_okta_client_default() {
        let client = OktaClient::new();
        assert_eq!(client.idp_name(), "Okta");
        assert_eq!(client.get_quirks().len(), 5);
    }

    #[test]
    fn test_okta_user_agent() {
        let client = OktaClient::new();
        assert!(client.user_agent().contains("Okta"));
    }

    #[test]
    fn test_okta_create_payload_with_empty_strings() {
        let client = OktaClient::new();
        let payload = client.build_create_user_payload("test@example.com", "ext-123");

        // OKTA-001: Should include empty strings for optional attributes
        assert_eq!(payload["displayName"], "");
        assert_eq!(payload["nickName"], "");
        assert_eq!(payload["title"], "");
    }

    #[test]
    fn test_okta_patch_payload_wraps_single_values() {
        let client = OktaClient::new();
        let ops = vec![json!({
            "op": "replace",
            "path": "active",
            "value": false
        })];
        let payload = client.build_patch_user_payload(ops);

        // OKTA-002: Single values should be wrapped in arrays
        let value = &payload["Operations"][0]["value"];
        assert!(value.is_array());
        assert_eq!(value[0], false);
    }

    #[test]
    fn test_okta_filter_format() {
        let client = OktaClient::new();
        let filter = client.build_filter("userName", "eq", "test@example.com");
        assert_eq!(filter, "userName eq \"test@example.com\"");
    }

    #[test]
    fn test_okta_client_without_quirks() {
        let config = MockClientConfig::default();
        let client = OktaClient::with_config(config);
        let payload = client.build_create_user_payload("test@example.com", "ext-123");

        // Without OKTA-001, displayName should not be present
        assert!(payload.get("displayName").is_none());
    }
}
