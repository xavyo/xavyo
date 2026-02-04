//! `OneLogin` SCIM client mock implementation.
//!
//! Simulates `OneLogin`'s SCIM provisioning behavior including known quirks.

use serde_json::{json, Value};

use super::base_client::{MockClientConfig, MockScimClient};
use super::quirks::{onelogin_quirks, QuirkDefinition};

/// Mock `OneLogin` SCIM client that simulates `OneLogin`'s provisioning behavior.
#[derive(Debug)]
pub struct OneLoginClient {
    config: MockClientConfig,
}

impl OneLoginClient {
    /// Create a new `OneLogin` mock client with default configuration.
    pub fn new() -> Self {
        let quirk_ids = onelogin_quirks().into_iter().map(|q| q.id).collect();
        Self {
            config: MockClientConfig::with_all_quirks(quirk_ids),
        }
    }

    /// Create with custom configuration.
    pub fn with_config(config: MockClientConfig) -> Self {
        Self { config }
    }
}

impl Default for OneLoginClient {
    fn default() -> Self {
        Self::new()
    }
}

impl MockScimClient for OneLoginClient {
    fn idp_name(&self) -> &'static str {
        "OneLogin"
    }

    fn user_agent(&self) -> &'static str {
        "OneLogin SCIM Provisioner/2.0"
    }

    fn get_quirks(&self) -> Vec<QuirkDefinition> {
        onelogin_quirks()
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
            "active": true,
            "displayName": "Test User"
        });

        // OL-001: OneLogin sends explicit nulls for optional fields
        if self.config.quirk_enabled("OL-001") {
            payload["nickName"] = Value::Null;
            payload["title"] = Value::Null;
            payload["profileUrl"] = Value::Null;
        }

        payload
    }

    fn build_patch_user_payload(&self, operations: Vec<Value>) -> Value {
        let ops: Vec<Value> = operations
            .into_iter()
            .map(|mut op| {
                // OL-002: OneLogin uses array notation for member paths
                if self.config.quirk_enabled("OL-002") {
                    if let Some(path) = op.get("path").and_then(|p| p.as_str()) {
                        if path == "members" {
                            if let Some(value) = op.get("value") {
                                // Transform to array notation syntax
                                if let Some(member_value) = value.as_str() {
                                    op["path"] =
                                        json!(format!("members[value eq \"{}\"]", member_value));
                                }
                            }
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
        // OL-005: OneLogin requires lowercase operators
        let op = if self.config.quirk_enabled("OL-005") {
            operator.to_lowercase()
        } else {
            operator.to_string()
        };
        format!("{attribute} {op} \"{value}\"")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_onelogin_client_default() {
        let client = OneLoginClient::new();
        assert_eq!(client.idp_name(), "OneLogin");
        assert_eq!(client.get_quirks().len(), 5);
    }

    #[test]
    fn test_onelogin_user_agent() {
        let client = OneLoginClient::new();
        assert!(client.user_agent().contains("OneLogin"));
    }

    #[test]
    fn test_onelogin_create_payload_with_explicit_nulls() {
        let client = OneLoginClient::new();
        let payload = client.build_create_user_payload("test@example.com", "ext-123");

        // OL-001: Should include explicit nulls for optional fields
        assert_eq!(payload["nickName"], Value::Null);
        assert_eq!(payload["title"], Value::Null);
        assert_eq!(payload["profileUrl"], Value::Null);
    }

    #[test]
    fn test_onelogin_patch_payload_array_notation() {
        let client = OneLoginClient::new();
        let ops = vec![json!({
            "op": "add",
            "path": "members",
            "value": "user-123"
        })];
        let payload = client.build_patch_user_payload(ops);

        // OL-002: Path should use array notation
        let path = payload["Operations"][0]["path"].as_str().unwrap();
        assert!(path.contains("members[value eq"));
    }

    #[test]
    fn test_onelogin_filter_lowercase_operators() {
        let client = OneLoginClient::new();
        let filter = client.build_filter("userName", "EQ", "test@example.com");

        // OL-005: Operator should be lowercase
        assert!(filter.contains(" eq "));
        assert!(!filter.contains(" EQ "));
    }

    #[test]
    fn test_onelogin_client_without_quirks() {
        let config = MockClientConfig::default();
        let client = OneLoginClient::with_config(config);
        let payload = client.build_create_user_payload("test@example.com", "ext-123");

        // Without OL-001, nulls should not be present
        assert!(payload.get("nickName").is_none());
    }
}
