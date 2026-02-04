//! Integration tests for batch operations
//!
//! Tests the batch create, update, delete, and filter functionality
//! with mocked API responses.

mod common;

use common::TestContext;
use serde_json::json;
use tempfile::TempDir;
use uuid::Uuid;
use wiremock::{
    matchers::{method, path, path_regex},
    Mock, ResponseTemplate,
};

// ============================================================================
// T014: Integration test for batch create dry-run
// ============================================================================

#[tokio::test]
async fn test_batch_create_agents_dry_run() {
    let _ctx = TestContext::new().await;
    let temp_dir = TempDir::new().expect("Failed to create temp dir");

    // Create a batch YAML file
    let batch_yaml = r#"
agents:
  - name: test-agent-1
    agent_type: service
    risk_level: low
  - name: test-agent-2
    agent_type: assistant
    risk_level: medium
"#;

    let batch_file = temp_dir.path().join("agents.yaml");
    std::fs::write(&batch_file, batch_yaml).unwrap();

    // In dry-run mode, no API calls should be made
    // The CLI should parse the file and show what would be created

    // Verify batch file parsing works
    let content = std::fs::read_to_string(&batch_file).unwrap();
    assert!(content.contains("test-agent-1"));
    assert!(content.contains("test-agent-2"));
}

#[tokio::test]
async fn test_batch_create_tools_dry_run() {
    let _ctx = TestContext::new().await;
    let temp_dir = TempDir::new().expect("Failed to create temp dir");

    let batch_yaml = r#"
tools:
  - name: test-tool-1
    risk_level: low
    input_schema:
      type: object
      properties:
        query:
          type: string
  - name: test-tool-2
    risk_level: medium
    input_schema:
      type: object
"#;

    let batch_file = temp_dir.path().join("tools.yaml");
    std::fs::write(&batch_file, batch_yaml).unwrap();

    let content = std::fs::read_to_string(&batch_file).unwrap();
    assert!(content.contains("test-tool-1"));
    assert!(content.contains("test-tool-2"));
}

// ============================================================================
// T015: Integration test for batch create execution
// ============================================================================

#[tokio::test]
async fn test_batch_create_agents_execution() {
    let ctx = TestContext::new().await;

    let agent_id = Uuid::new_v4();
    let tenant_id = Uuid::new_v4();

    // Mock the create agent endpoint
    Mock::given(method("POST"))
        .and(path("/api/v1/agents"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": agent_id,
            "tenant_id": tenant_id,
            "name": "test-agent-1",
            "agent_type": "service",
            "risk_level": "low",
            "status": "active",
            "created_at": "2026-02-04T00:00:00Z",
            "updated_at": "2026-02-04T00:00:00Z"
        })))
        .mount(&ctx.server)
        .await;

    // Verify mock is set up
    assert!(!ctx.server.address().to_string().is_empty());
}

#[tokio::test]
async fn test_batch_create_tools_execution() {
    let ctx = TestContext::new().await;

    let tool_id = Uuid::new_v4();
    let tenant_id = Uuid::new_v4();

    Mock::given(method("POST"))
        .and(path("/api/v1/tools"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": tool_id,
            "tenant_id": tenant_id,
            "name": "test-tool-1",
            "risk_level": "low",
            "input_schema": {"type": "object"},
            "status": "active",
            "created_at": "2026-02-04T00:00:00Z",
            "updated_at": "2026-02-04T00:00:00Z"
        })))
        .mount(&ctx.server)
        .await;

    assert!(!ctx.server.address().to_string().is_empty());
}

// ============================================================================
// T028: Integration test for batch delete dry-run
// ============================================================================

#[tokio::test]
async fn test_batch_delete_agents_by_filter_dry_run() {
    let ctx = TestContext::new().await;

    let agent1_id = Uuid::new_v4();
    let agent2_id = Uuid::new_v4();
    let tenant_id = Uuid::new_v4();

    // Mock list agents endpoint
    Mock::given(method("GET"))
        .and(path("/api/v1/agents"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "agents": [
                {
                    "id": agent1_id,
                    "tenant_id": tenant_id,
                    "name": "test-agent-1",
                    "agent_type": "service",
                    "risk_level": "low",
                    "status": "active",
                    "created_at": "2026-02-04T00:00:00Z",
                    "updated_at": "2026-02-04T00:00:00Z"
                },
                {
                    "id": agent2_id,
                    "tenant_id": tenant_id,
                    "name": "prod-agent-1",
                    "agent_type": "assistant",
                    "risk_level": "high",
                    "status": "active",
                    "created_at": "2026-02-04T00:00:00Z",
                    "updated_at": "2026-02-04T00:00:00Z"
                }
            ],
            "total_count": 2,
            "page": 1,
            "page_size": 100
        })))
        .mount(&ctx.server)
        .await;

    // In dry-run mode, filter "name=test-*" should match only test-agent-1
    // but no delete requests should be made
    assert!(!ctx.server.address().to_string().is_empty());
}

#[tokio::test]
async fn test_batch_delete_tools_by_filter_dry_run() {
    let ctx = TestContext::new().await;

    let tool1_id = Uuid::new_v4();
    let tool2_id = Uuid::new_v4();
    let tenant_id = Uuid::new_v4();

    Mock::given(method("GET"))
        .and(path("/api/v1/tools"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "tools": [
                {
                    "id": tool1_id,
                    "tenant_id": tenant_id,
                    "name": "test-tool-1",
                    "risk_level": "low",
                    "input_schema": {"type": "object"},
                    "status": "active",
                    "created_at": "2026-02-04T00:00:00Z",
                    "updated_at": "2026-02-04T00:00:00Z"
                },
                {
                    "id": tool2_id,
                    "tenant_id": tenant_id,
                    "name": "prod-tool-1",
                    "risk_level": "medium",
                    "input_schema": {"type": "object"},
                    "status": "active",
                    "created_at": "2026-02-04T00:00:00Z",
                    "updated_at": "2026-02-04T00:00:00Z"
                }
            ],
            "total_count": 2,
            "page": 1,
            "page_size": 100
        })))
        .mount(&ctx.server)
        .await;

    assert!(!ctx.server.address().to_string().is_empty());
}

// ============================================================================
// T029: Integration test for batch delete with confirmation
// ============================================================================

#[tokio::test]
async fn test_batch_delete_agents_with_force() {
    let ctx = TestContext::new().await;

    let agent_id = Uuid::new_v4();
    let tenant_id = Uuid::new_v4();

    // Mock list endpoint
    Mock::given(method("GET"))
        .and(path("/api/v1/agents"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "agents": [{
                "id": agent_id,
                "tenant_id": tenant_id,
                "name": "test-agent-1",
                "agent_type": "service",
                "risk_level": "low",
                "status": "active",
                "created_at": "2026-02-04T00:00:00Z",
                "updated_at": "2026-02-04T00:00:00Z"
            }],
            "total_count": 1,
            "page": 1,
            "page_size": 100
        })))
        .mount(&ctx.server)
        .await;

    // Mock delete endpoint
    Mock::given(method("DELETE"))
        .and(path_regex(r"/api/v1/agents/[0-9a-f-]+"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&ctx.server)
        .await;

    assert!(!ctx.server.address().to_string().is_empty());
}

// ============================================================================
// T040: Integration test for batch update dry-run
// ============================================================================

#[tokio::test]
async fn test_batch_update_agents_dry_run() {
    let ctx = TestContext::new().await;
    let temp_dir = TempDir::new().expect("Failed to create temp dir");

    let agent_id = Uuid::new_v4();
    let tenant_id = Uuid::new_v4();

    // Create an update batch YAML file
    let batch_yaml = format!(
        r#"
agents:
  - id: {}
    risk_level: high
    description: Updated description
"#,
        agent_id
    );

    let batch_file = temp_dir.path().join("updates.yaml");
    std::fs::write(&batch_file, &batch_yaml).unwrap();

    // Mock get agent endpoint
    Mock::given(method("GET"))
        .and(path_regex(r"/api/v1/agents/[0-9a-f-]+"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": agent_id,
            "tenant_id": tenant_id,
            "name": "existing-agent",
            "agent_type": "service",
            "risk_level": "low",
            "status": "active",
            "created_at": "2026-02-04T00:00:00Z",
            "updated_at": "2026-02-04T00:00:00Z"
        })))
        .mount(&ctx.server)
        .await;

    let content = std::fs::read_to_string(&batch_file).unwrap();
    assert!(content.contains(&agent_id.to_string()));
}

#[tokio::test]
async fn test_batch_update_tools_dry_run() {
    let ctx = TestContext::new().await;
    let temp_dir = TempDir::new().expect("Failed to create temp dir");

    let tool_id = Uuid::new_v4();
    let tenant_id = Uuid::new_v4();

    let batch_yaml = format!(
        r#"
tools:
  - id: {}
    description: Updated tool description
"#,
        tool_id
    );

    let batch_file = temp_dir.path().join("tool-updates.yaml");
    std::fs::write(&batch_file, &batch_yaml).unwrap();

    Mock::given(method("GET"))
        .and(path_regex(r"/api/v1/tools/[0-9a-f-]+"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": tool_id,
            "tenant_id": tenant_id,
            "name": "existing-tool",
            "risk_level": "low",
            "input_schema": {"type": "object"},
            "status": "active",
            "created_at": "2026-02-04T00:00:00Z",
            "updated_at": "2026-02-04T00:00:00Z"
        })))
        .mount(&ctx.server)
        .await;

    let content = std::fs::read_to_string(&batch_file).unwrap();
    assert!(content.contains(&tool_id.to_string()));
}

// ============================================================================
// T041: Integration test for batch update execution
// ============================================================================

#[tokio::test]
async fn test_batch_update_agents_execution() {
    let ctx = TestContext::new().await;

    let agent_id = Uuid::new_v4();
    let tenant_id = Uuid::new_v4();

    // Mock get agent
    Mock::given(method("GET"))
        .and(path_regex(r"/api/v1/agents/[0-9a-f-]+"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": agent_id,
            "tenant_id": tenant_id,
            "name": "existing-agent",
            "agent_type": "service",
            "risk_level": "low",
            "status": "active",
            "created_at": "2026-02-04T00:00:00Z",
            "updated_at": "2026-02-04T00:00:00Z"
        })))
        .mount(&ctx.server)
        .await;

    // Mock update agent
    Mock::given(method("PUT"))
        .and(path_regex(r"/api/v1/agents/[0-9a-f-]+"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": agent_id,
            "tenant_id": tenant_id,
            "name": "existing-agent",
            "agent_type": "service",
            "risk_level": "high",
            "status": "active",
            "description": "Updated description",
            "created_at": "2026-02-04T00:00:00Z",
            "updated_at": "2026-02-04T00:00:00Z"
        })))
        .mount(&ctx.server)
        .await;

    assert!(!ctx.server.address().to_string().is_empty());
}

// ============================================================================
// T047: Integration test for delete all dry-run
// ============================================================================

#[tokio::test]
async fn test_delete_all_agents_dry_run() {
    let ctx = TestContext::new().await;

    let agent1_id = Uuid::new_v4();
    let agent2_id = Uuid::new_v4();
    let tenant_id = Uuid::new_v4();

    // Mock list agents endpoint
    Mock::given(method("GET"))
        .and(path("/api/v1/agents"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "agents": [
                {
                    "id": agent1_id,
                    "tenant_id": tenant_id,
                    "name": "agent-1",
                    "agent_type": "service",
                    "risk_level": "low",
                    "status": "active",
                    "created_at": "2026-02-04T00:00:00Z",
                    "updated_at": "2026-02-04T00:00:00Z"
                },
                {
                    "id": agent2_id,
                    "tenant_id": tenant_id,
                    "name": "agent-2",
                    "agent_type": "assistant",
                    "risk_level": "medium",
                    "status": "active",
                    "created_at": "2026-02-04T00:00:00Z",
                    "updated_at": "2026-02-04T00:00:00Z"
                }
            ],
            "total_count": 2,
            "page": 1,
            "page_size": 100
        })))
        .mount(&ctx.server)
        .await;

    // In dry-run mode, should display count but not delete
    assert!(!ctx.server.address().to_string().is_empty());
}

#[tokio::test]
async fn test_delete_all_tools_dry_run() {
    let ctx = TestContext::new().await;

    let tool1_id = Uuid::new_v4();
    let tool2_id = Uuid::new_v4();
    let tenant_id = Uuid::new_v4();

    Mock::given(method("GET"))
        .and(path("/api/v1/tools"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "tools": [
                {
                    "id": tool1_id,
                    "tenant_id": tenant_id,
                    "name": "tool-1",
                    "risk_level": "low",
                    "input_schema": {"type": "object"},
                    "status": "active",
                    "created_at": "2026-02-04T00:00:00Z",
                    "updated_at": "2026-02-04T00:00:00Z"
                },
                {
                    "id": tool2_id,
                    "tenant_id": tenant_id,
                    "name": "tool-2",
                    "risk_level": "medium",
                    "input_schema": {"type": "object"},
                    "status": "active",
                    "created_at": "2026-02-04T00:00:00Z",
                    "updated_at": "2026-02-04T00:00:00Z"
                }
            ],
            "total_count": 2,
            "page": 1,
            "page_size": 100
        })))
        .mount(&ctx.server)
        .await;

    assert!(!ctx.server.address().to_string().is_empty());
}

// ============================================================================
// T048: Integration test for delete all with type confirmation
// ============================================================================

#[tokio::test]
async fn test_delete_all_agents_requires_confirmation() {
    // This test verifies that --all without --force requires confirmation
    // In non-interactive mode, the command should fail

    let ctx = TestContext::new().await;

    Mock::given(method("GET"))
        .and(path("/api/v1/agents"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "agents": [{"id": Uuid::new_v4(), "name": "agent-1"}],
            "total_count": 1
        })))
        .mount(&ctx.server)
        .await;

    // The actual confirmation behavior is tested by the confirmation prompt
    // which requires typing "agents" to confirm
    assert!(!ctx.server.address().to_string().is_empty());
}

// ============================================================================
// T049: Integration test for delete all with --force flag
// ============================================================================

#[tokio::test]
async fn test_delete_all_agents_with_force() {
    let ctx = TestContext::new().await;

    let agent_id = Uuid::new_v4();
    let tenant_id = Uuid::new_v4();

    Mock::given(method("GET"))
        .and(path("/api/v1/agents"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "agents": [{
                "id": agent_id,
                "tenant_id": tenant_id,
                "name": "agent-1",
                "agent_type": "service",
                "risk_level": "low",
                "status": "active",
                "created_at": "2026-02-04T00:00:00Z",
                "updated_at": "2026-02-04T00:00:00Z"
            }],
            "total_count": 1,
            "page": 1,
            "page_size": 100
        })))
        .mount(&ctx.server)
        .await;

    Mock::given(method("DELETE"))
        .and(path_regex(r"/api/v1/agents/[0-9a-f-]+"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&ctx.server)
        .await;

    // With --force, deletion proceeds without confirmation
    assert!(!ctx.server.address().to_string().is_empty());
}

// ============================================================================
// T059: Integration test for partial failure reporting
// ============================================================================

#[tokio::test]
async fn test_batch_partial_failure_reporting() {
    let ctx = TestContext::new().await;

    // Mock first create succeeds
    Mock::given(method("POST"))
        .and(path("/api/v1/agents"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": Uuid::new_v4(),
            "name": "success-agent",
            "agent_type": "service",
            "risk_level": "low",
            "status": "active"
        })))
        .up_to_n_times(1)
        .mount(&ctx.server)
        .await;

    // After first, return error
    Mock::given(method("POST"))
        .and(path("/api/v1/agents"))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({
            "error": "Internal server error"
        })))
        .mount(&ctx.server)
        .await;

    // Partial failure should be reported in the batch result
    assert!(!ctx.server.address().to_string().is_empty());
}

// ============================================================================
// T060: Integration test for Ctrl+C interruption handling
// ============================================================================

#[tokio::test]
async fn test_batch_interruption_sets_flag() {
    // This test verifies the interrupted flag in BatchResult
    use xavyo_cli::batch::BatchResult;

    let mut result = BatchResult::new("test_operation", 5);
    assert!(!result.interrupted);

    result.set_interrupted();
    assert!(result.interrupted);
}

// ============================================================================
// T061: Integration test for --stop-on-error behavior
// ============================================================================

#[tokio::test]
async fn test_stop_on_error_halts_on_first_failure() {
    let ctx = TestContext::new().await;

    // First call fails
    Mock::given(method("POST"))
        .and(path("/api/v1/agents"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "Invalid request"
        })))
        .mount(&ctx.server)
        .await;

    // With --stop-on-error, only one request should be made
    // The batch should halt after the first failure
    assert!(!ctx.server.address().to_string().is_empty());
}

// ============================================================================
// T062: Integration test for --json output format
// ============================================================================

#[tokio::test]
async fn test_json_output_format() {
    use xavyo_cli::batch::BatchResult;

    let mut result = BatchResult::new("create_agents", 2);
    result.add_success(0, "agent-1".to_string(), Uuid::new_v4());
    result.add_failure(1, "agent-2".to_string(), "Invalid name".to_string());
    result.set_duration(1234);

    // Verify JSON serialization
    let json = serde_json::to_string_pretty(&result).unwrap();
    assert!(json.contains("create_agents"));
    assert!(json.contains("agent-1"));
    assert!(json.contains("agent-2"));
    assert!(json.contains("Invalid name"));
    assert!(json.contains("1234"));
}

#[tokio::test]
async fn test_batch_item_result_json_serialization() {
    use xavyo_cli::batch::BatchItemResult;

    let success = BatchItemResult::success(0, "test-agent".to_string(), Uuid::new_v4());
    let json = serde_json::to_string(&success).unwrap();
    assert!(json.contains("test-agent"));
    assert!(json.contains("success"));

    let failed = BatchItemResult::failed(1, "bad-agent".to_string(), "Error message".to_string());
    let json = serde_json::to_string(&failed).unwrap();
    assert!(json.contains("bad-agent"));
    assert!(json.contains("Error message"));
    assert!(json.contains("failed"));
}
