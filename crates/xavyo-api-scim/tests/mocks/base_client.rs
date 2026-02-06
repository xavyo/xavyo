//! Base mock SCIM client trait and shared functionality.

use axum::http::Method;
use serde_json::Value;
use std::time::Duration;

use super::quirks::QuirkDefinition;
use crate::common::TestApp;

/// Configuration for mock client behavior.
#[derive(Debug, Clone, Default)]
pub struct MockClientConfig {
    /// Simulated network delay.
    pub delay: Option<Duration>,
    /// Which quirks to simulate.
    pub enabled_quirks: Vec<String>,
}

impl MockClientConfig {
    /// Create config with all quirks enabled.
    pub fn with_all_quirks(quirk_ids: Vec<String>) -> Self {
        Self {
            delay: None,
            enabled_quirks: quirk_ids,
        }
    }

    /// Add a simulated delay.
    pub fn with_delay(mut self, delay: Duration) -> Self {
        self.delay = Some(delay);
        self
    }

    /// Check if a specific quirk is enabled.
    pub fn quirk_enabled(&self, quirk_id: &str) -> bool {
        self.enabled_quirks.contains(&quirk_id.to_string())
    }
}

/// Trait for mock SCIM clients that simulate `IdP` behavior.
#[allow(async_fn_in_trait)]
pub trait MockScimClient {
    /// Get the `IdP` name (e.g., "Okta", "Azure AD", "`OneLogin`").
    fn idp_name(&self) -> &'static str;

    /// Get the User-Agent header value for this `IdP`.
    fn user_agent(&self) -> &'static str;

    /// Get all quirks defined for this `IdP`.
    fn get_quirks(&self) -> Vec<QuirkDefinition>;

    /// Get the client configuration.
    fn config(&self) -> &MockClientConfig;

    /// Build a user creation payload with IdP-specific formatting.
    fn build_create_user_payload(&self, email: &str, external_id: &str) -> Value;

    /// Build a user update (PATCH) payload with IdP-specific formatting.
    fn build_patch_user_payload(&self, operations: Vec<Value>) -> Value;

    /// Build a filter query string with IdP-specific syntax.
    fn build_filter(&self, attribute: &str, operator: &str, value: &str) -> String;

    /// Build IdP-specific headers for requests.
    fn build_headers(&self) -> Vec<(&'static str, String)> {
        vec![("User-Agent", self.user_agent().to_string())]
    }

    /// Create a user via the SCIM API.
    async fn create_user(
        &self,
        app: &TestApp,
        email: &str,
        external_id: &str,
    ) -> crate::common::TestResponse {
        let payload = self.build_create_user_payload(email, external_id);
        self.apply_delay().await;
        app.request_with_headers(
            Method::POST,
            "/scim/v2/Users",
            Some(payload),
            self.build_headers()
                .iter()
                .map(|(k, v)| (*k, v.as_str()))
                .collect(),
        )
        .await
    }

    /// Get a user by ID via the SCIM API.
    async fn get_user(&self, app: &TestApp, user_id: &str) -> crate::common::TestResponse {
        self.apply_delay().await;
        app.request_with_headers(
            Method::GET,
            &format!("/scim/v2/Users/{user_id}"),
            None,
            self.build_headers()
                .iter()
                .map(|(k, v)| (*k, v.as_str()))
                .collect(),
        )
        .await
    }

    /// List users with optional filter.
    async fn list_users(
        &self,
        app: &TestApp,
        filter: Option<&str>,
        start_index: Option<i64>,
        count: Option<i64>,
    ) -> crate::common::TestResponse {
        let mut path = "/scim/v2/Users".to_string();
        let mut params = vec![];

        if let Some(f) = filter {
            // Simple URL encoding for filter parameter
            let encoded: String = f
                .chars()
                .map(|c| match c {
                    ' ' => "%20".to_string(),
                    '"' => "%22".to_string(),
                    _ => c.to_string(),
                })
                .collect();
            params.push(format!("filter={encoded}"));
        }
        if let Some(idx) = start_index {
            params.push(format!("startIndex={idx}"));
        }
        if let Some(c) = count {
            params.push(format!("count={c}"));
        }

        if !params.is_empty() {
            path = format!("{}?{}", path, params.join("&"));
        }

        self.apply_delay().await;
        app.request_with_headers(
            Method::GET,
            &path,
            None,
            self.build_headers()
                .iter()
                .map(|(k, v)| (*k, v.as_str()))
                .collect(),
        )
        .await
    }

    /// Update a user via PATCH.
    async fn patch_user(
        &self,
        app: &TestApp,
        user_id: &str,
        operations: Vec<Value>,
    ) -> crate::common::TestResponse {
        let payload = self.build_patch_user_payload(operations);
        self.apply_delay().await;
        app.request_with_headers(
            Method::PATCH,
            &format!("/scim/v2/Users/{user_id}"),
            Some(payload),
            self.build_headers()
                .iter()
                .map(|(k, v)| (*k, v.as_str()))
                .collect(),
        )
        .await
    }

    /// Delete a user.
    async fn delete_user(&self, app: &TestApp, user_id: &str) -> crate::common::TestResponse {
        self.apply_delay().await;
        app.request_with_headers(
            Method::DELETE,
            &format!("/scim/v2/Users/{user_id}"),
            None,
            self.build_headers()
                .iter()
                .map(|(k, v)| (*k, v.as_str()))
                .collect(),
        )
        .await
    }

    /// Deactivate a user (IdP-specific method).
    async fn deactivate_user(&self, app: &TestApp, user_id: &str) -> crate::common::TestResponse {
        // Default: PATCH with active=false
        let ops = vec![serde_json::json!({
            "op": "replace",
            "path": "active",
            "value": false
        })];
        self.patch_user(app, user_id, ops).await
    }

    /// Get schema discovery endpoint.
    async fn get_schemas(&self, app: &TestApp) -> crate::common::TestResponse {
        self.apply_delay().await;
        app.request_with_headers(
            Method::GET,
            "/scim/v2/Schemas",
            None,
            self.build_headers()
                .iter()
                .map(|(k, v)| (*k, v.as_str()))
                .collect(),
        )
        .await
    }

    /// Get service provider config.
    async fn get_service_provider_config(&self, app: &TestApp) -> crate::common::TestResponse {
        self.apply_delay().await;
        app.request_with_headers(
            Method::GET,
            "/scim/v2/ServiceProviderConfig",
            None,
            self.build_headers()
                .iter()
                .map(|(k, v)| (*k, v.as_str()))
                .collect(),
        )
        .await
    }

    /// Create a group.
    async fn create_group(
        &self,
        app: &TestApp,
        display_name: &str,
        external_id: &str,
    ) -> crate::common::TestResponse {
        let payload = serde_json::json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "displayName": display_name,
            "externalId": external_id,
            "members": []
        });
        self.apply_delay().await;
        app.request_with_headers(
            Method::POST,
            "/scim/v2/Groups",
            Some(payload),
            self.build_headers()
                .iter()
                .map(|(k, v)| (*k, v.as_str()))
                .collect(),
        )
        .await
    }

    /// Apply configured delay if set.
    async fn apply_delay(&self) {
        if let Some(delay) = self.config().delay {
            tokio::time::sleep(delay).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_client_config_defaults() {
        let config = MockClientConfig::default();
        assert!(config.delay.is_none());
        assert!(config.enabled_quirks.is_empty());
    }

    #[test]
    fn test_mock_client_config_with_quirks() {
        let config = MockClientConfig::with_all_quirks(vec!["OKTA-001".to_string()]);
        assert!(config.quirk_enabled("OKTA-001"));
        assert!(!config.quirk_enabled("OKTA-002"));
    }

    #[test]
    fn test_mock_client_config_with_delay() {
        let config = MockClientConfig::default().with_delay(Duration::from_millis(100));
        assert_eq!(config.delay, Some(Duration::from_millis(100)));
    }
}
