//! Common test utilities for xavyo-cli integration tests
//!
//! This module provides:
//! - TestContext for isolated test environments
//! - MockServer helpers for API mocking
//! - Fixture generators for test data
//! - Credential file helpers for test isolation

use chrono::{Duration, Utc};
use serde_json::{json, Value};
use std::path::PathBuf;
use tempfile::TempDir;
use uuid::Uuid;
use wiremock::matchers::{body_string_contains, header, method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Test context providing isolated environment for each test
pub struct TestContext {
    /// Mock API server
    pub server: MockServer,
    /// Temporary directory for credentials
    pub credentials_dir: TempDir,
    /// Temporary directory for config
    pub config_dir: TempDir,
}

impl TestContext {
    /// Create a new test context with fresh mock server and temp directories
    pub async fn new() -> Self {
        let server = MockServer::start().await;
        let credentials_dir = TempDir::new().expect("Failed to create temp dir for credentials");
        let config_dir = TempDir::new().expect("Failed to create temp dir for config");

        Self {
            server,
            credentials_dir,
            config_dir,
        }
    }

    /// Get the mock server base URL
    pub fn base_url(&self) -> String {
        self.server.uri()
    }

    /// Get the credentials directory path
    pub fn credentials_path(&self) -> PathBuf {
        self.credentials_dir.path().to_path_buf()
    }

    /// Get the config directory path
    pub fn config_path(&self) -> PathBuf {
        self.config_dir.path().to_path_buf()
    }

    // =========================================================================
    // Device Code Flow Mocks (T004)
    // =========================================================================

    /// Mock successful device code request
    pub async fn mock_device_code_success(&self) {
        Mock::given(method("POST"))
            .and(path("/oauth/device/code"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "device_code": "test-device-code-12345",
                "user_code": "ABCD-1234",
                "verification_uri": format!("{}/device", self.base_url()),
                "verification_uri_complete": format!("{}/device?user_code=ABCD-1234", self.base_url()),
                "expires_in": 1800,
                "interval": 5
            })))
            .mount(&self.server)
            .await;
    }

    /// Mock device code request failure
    pub async fn mock_device_code_failure(&self, status: u16, error: &str) {
        Mock::given(method("POST"))
            .and(path("/oauth/device/code"))
            .respond_with(ResponseTemplate::new(status).set_body_json(json!({
                "error": error,
                "error_description": format!("Device code request failed: {}", error)
            })))
            .mount(&self.server)
            .await;
    }

    // =========================================================================
    // Token Endpoint Mocks (T005)
    // =========================================================================

    /// Mock successful token exchange
    pub async fn mock_token_success(&self) {
        let expires_at = Utc::now() + Duration::hours(1);
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "test-access-token-xyz",
                "refresh_token": "test-refresh-token-abc",
                "token_type": "Bearer",
                "expires_in": 3600,
                "scope": "openid profile email"
            })))
            .mount(&self.server)
            .await;
    }

    /// Mock token polling - authorization pending
    pub async fn mock_token_pending(&self) {
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({
                "error": "authorization_pending",
                "error_description": "The authorization request is still pending"
            })))
            .mount(&self.server)
            .await;
    }

    /// Mock token polling - expired device code
    pub async fn mock_token_expired(&self) {
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({
                "error": "expired_token",
                "error_description": "The device code has expired"
            })))
            .mount(&self.server)
            .await;
    }

    /// Mock token polling - access denied
    pub async fn mock_token_denied(&self) {
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({
                "error": "access_denied",
                "error_description": "The user denied the authorization request"
            })))
            .mount(&self.server)
            .await;
    }

    /// Mock token refresh success
    pub async fn mock_token_refresh_success(&self) {
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .and(body_string_contains("grant_type=refresh_token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "refreshed-access-token-xyz",
                "refresh_token": "refreshed-refresh-token-abc",
                "token_type": "Bearer",
                "expires_in": 3600
            })))
            .mount(&self.server)
            .await;
    }

    // =========================================================================
    // Error Response Mocks (T006)
    // =========================================================================

    /// Mock 401 Unauthorized response
    pub async fn mock_unauthorized(&self, endpoint: &str) {
        Mock::given(method("GET"))
            .and(path(endpoint))
            .respond_with(ResponseTemplate::new(401).set_body_json(json!({
                "error": "unauthorized",
                "message": "Authentication required"
            })))
            .mount(&self.server)
            .await;
    }

    /// Mock 404 Not Found response
    pub async fn mock_not_found(&self, endpoint: &str) {
        Mock::given(method("GET"))
            .and(path(endpoint))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({
                "error": "not_found",
                "message": "Resource not found"
            })))
            .mount(&self.server)
            .await;
    }

    /// Mock 500 Internal Server Error
    pub async fn mock_server_error(&self, endpoint: &str) {
        Mock::given(method("GET"))
            .and(path(endpoint))
            .respond_with(ResponseTemplate::new(500).set_body_json(json!({
                "error": "internal_server_error",
                "message": "An unexpected error occurred"
            })))
            .mount(&self.server)
            .await;
    }

    /// Mock 429 Rate Limited
    pub async fn mock_rate_limited(&self, endpoint: &str) {
        Mock::given(method("GET"))
            .and(path(endpoint))
            .respond_with(
                ResponseTemplate::new(429)
                    .set_body_json(json!({
                        "error": "rate_limited",
                        "message": "Too many requests, please retry later",
                        "retry_after": 60
                    }))
                    .insert_header("Retry-After", "60"),
            )
            .mount(&self.server)
            .await;
    }

    /// Mock network timeout (using delay)
    pub async fn mock_timeout(&self, endpoint: &str) {
        Mock::given(method("GET"))
            .and(path(endpoint))
            .respond_with(ResponseTemplate::new(200).set_delay(std::time::Duration::from_secs(120)))
            .mount(&self.server)
            .await;
    }

    // =========================================================================
    // Agent Mocks
    // =========================================================================

    /// Mock agents list endpoint
    pub async fn mock_agents_list(&self, agents: Vec<Value>) {
        Mock::given(method("GET"))
            .and(path_regex(r"/nhi/agents.*"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "agents": agents,
                "total": agents.len(),
                "limit": 100,
                "offset": 0
            })))
            .mount(&self.server)
            .await;
    }

    /// Mock single agent get endpoint
    pub async fn mock_agent_get(&self, agent: Value) {
        let agent_id = agent["id"].as_str().unwrap_or("test-id");
        Mock::given(method("GET"))
            .and(path(format!("/nhi/agents/{}", agent_id)))
            .respond_with(ResponseTemplate::new(200).set_body_json(agent))
            .mount(&self.server)
            .await;
    }

    /// Mock agent create endpoint
    pub async fn mock_agent_create(&self, response: Value) {
        Mock::given(method("POST"))
            .and(path("/nhi/agents"))
            .respond_with(ResponseTemplate::new(201).set_body_json(response))
            .mount(&self.server)
            .await;
    }

    /// Mock agent delete endpoint
    pub async fn mock_agent_delete(&self, agent_id: &str) {
        Mock::given(method("DELETE"))
            .and(path(format!("/nhi/agents/{}", agent_id)))
            .respond_with(ResponseTemplate::new(204))
            .mount(&self.server)
            .await;
    }

    // =========================================================================
    // Tool Mocks
    // =========================================================================

    /// Mock tools list endpoint
    pub async fn mock_tools_list(&self, tools: Vec<Value>) {
        Mock::given(method("GET"))
            .and(path_regex(r"/nhi/tools.*"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "tools": tools,
                "total": tools.len(),
                "limit": 100,
                "offset": 0
            })))
            .mount(&self.server)
            .await;
    }

    /// Mock single tool get endpoint
    pub async fn mock_tool_get(&self, tool: Value) {
        let tool_id = tool["id"].as_str().unwrap_or("test-id");
        Mock::given(method("GET"))
            .and(path(format!("/nhi/tools/{}", tool_id)))
            .respond_with(ResponseTemplate::new(200).set_body_json(tool))
            .mount(&self.server)
            .await;
    }

    /// Mock tool create endpoint
    pub async fn mock_tool_create(&self, response: Value) {
        Mock::given(method("POST"))
            .and(path("/nhi/tools"))
            .respond_with(ResponseTemplate::new(201).set_body_json(response))
            .mount(&self.server)
            .await;
    }

    /// Mock tool delete endpoint
    pub async fn mock_tool_delete(&self, tool_id: &str) {
        Mock::given(method("DELETE"))
            .and(path(format!("/nhi/tools/{}", tool_id)))
            .respond_with(ResponseTemplate::new(204))
            .mount(&self.server)
            .await;
    }

    // =========================================================================
    // Config Apply/Export Mocks
    // =========================================================================

    /// Mock config apply endpoint
    pub async fn mock_config_apply(&self) {
        Mock::given(method("POST"))
            .and(path("/config/apply"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "status": "applied",
                "changes": {
                    "agents_created": 1,
                    "agents_updated": 0,
                    "agents_deleted": 0,
                    "tools_created": 2,
                    "tools_updated": 0,
                    "tools_deleted": 0
                }
            })))
            .mount(&self.server)
            .await;
    }

    /// Mock config export endpoint
    pub async fn mock_config_export(&self, config_yaml: &str) {
        Mock::given(method("GET"))
            .and(path("/config/export"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(config_yaml)
                    .insert_header("Content-Type", "application/x-yaml"),
            )
            .mount(&self.server)
            .await;
    }

    // =========================================================================
    // Whoami Mock
    // =========================================================================

    /// Mock whoami endpoint for authenticated user
    pub async fn mock_whoami(&self, user_info: Value) {
        Mock::given(method("GET"))
            .and(path("/userinfo"))
            .and(header("Authorization", "Bearer test-access-token-xyz"))
            .respond_with(ResponseTemplate::new(200).set_body_json(user_info))
            .mount(&self.server)
            .await;
    }
}

// =========================================================================
// Fixture Generators (T007)
// =========================================================================

/// Generate a test agent fixture
pub fn create_agent_fixture(name: &str) -> Value {
    let id = Uuid::new_v4();
    json!({
        "id": id.to_string(),
        "name": name,
        "description": format!("Test agent: {}", name),
        "agent_type": "service_account",
        "status": "active",
        "created_at": Utc::now().to_rfc3339(),
        "updated_at": Utc::now().to_rfc3339()
    })
}

/// Generate a test tool fixture
pub fn create_tool_fixture(name: &str) -> Value {
    let id = Uuid::new_v4();
    json!({
        "id": id.to_string(),
        "name": name,
        "description": format!("Test tool: {}", name),
        "tool_type": "api",
        "endpoint": format!("https://example.com/{}", name),
        "status": "active",
        "created_at": Utc::now().to_rfc3339(),
        "updated_at": Utc::now().to_rfc3339()
    })
}

/// Generate a test user info fixture
pub fn create_user_fixture(email: &str) -> Value {
    json!({
        "sub": Uuid::new_v4().to_string(),
        "email": email,
        "email_verified": true,
        "name": "Test User",
        "preferred_username": email.split('@').next().unwrap_or("user"),
        "tenant_id": Uuid::new_v4().to_string()
    })
}

/// Generate test credentials JSON
pub fn create_credentials_json() -> Value {
    let expires_at = Utc::now() + Duration::hours(1);
    json!({
        "access_token": "test-access-token-xyz",
        "refresh_token": "test-refresh-token-abc",
        "expires_at": expires_at.to_rfc3339(),
        "token_type": "Bearer"
    })
}

/// Generate expired credentials JSON
pub fn create_expired_credentials_json() -> Value {
    let expires_at = Utc::now() - Duration::hours(1);
    json!({
        "access_token": "expired-access-token",
        "refresh_token": "expired-refresh-token",
        "expires_at": expires_at.to_rfc3339(),
        "token_type": "Bearer"
    })
}

// =========================================================================
// Credential File Helpers (T008)
// =========================================================================

/// Write credentials to a temporary file for testing
pub fn write_test_credentials(dir: &std::path::Path, credentials: &Value) -> PathBuf {
    let credentials_file = dir.join("credentials.json");
    std::fs::write(
        &credentials_file,
        serde_json::to_string_pretty(credentials).expect("Failed to serialize credentials"),
    )
    .expect("Failed to write credentials file");
    credentials_file
}

/// Write config to a temporary file for testing
pub fn write_test_config(dir: &std::path::Path, api_url: &str) -> PathBuf {
    let config_file = dir.join("config.yaml");
    let config_content = format!(
        r#"api_url: {}
client_id: xavyo-cli
timeout_secs: 30
"#,
        api_url
    );
    std::fs::write(&config_file, config_content).expect("Failed to write config file");
    config_file
}

/// Check if credentials file exists
pub fn credentials_exist(dir: &std::path::Path) -> bool {
    dir.join("credentials.json").exists()
}

/// Delete credentials file if it exists
pub fn delete_credentials(dir: &std::path::Path) {
    let credentials_file = dir.join("credentials.json");
    if credentials_file.exists() {
        std::fs::remove_file(credentials_file).expect("Failed to delete credentials file");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_agent_fixture() {
        let agent = create_agent_fixture("test-agent");
        assert_eq!(agent["name"], "test-agent");
        assert!(agent["id"].as_str().is_some());
    }

    #[test]
    fn test_create_tool_fixture() {
        let tool = create_tool_fixture("test-tool");
        assert_eq!(tool["name"], "test-tool");
        assert!(tool["id"].as_str().is_some());
    }

    #[test]
    fn test_create_user_fixture() {
        let user = create_user_fixture("test@example.com");
        assert_eq!(user["email"], "test@example.com");
    }

    #[tokio::test]
    async fn test_context_creation() {
        let ctx = TestContext::new().await;
        assert!(!ctx.base_url().is_empty());
        assert!(ctx.credentials_path().exists());
        assert!(ctx.config_path().exists());
    }
}
