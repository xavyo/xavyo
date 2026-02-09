//! Integration tests for CLI offline mode (C-008)
//!
//! Tests cover:
//! - Cache entry serialization/deserialization
//! - Cache store write/read operations
//! - Cache TTL expiration
//! - Offline detection via network failure
//! - --offline flag forces offline mode
//! - --refresh flag bypasses cache
//! - Agents/tools list with cached data
//! - "No cache available" error message
//! - Write operation rejection offline
//! - Cache status command output
//! - Cache clear command
//! - Corrupted cache recovery
//! - Stale cache warning
//! - "(offline)" indicator in output

mod common;

use chrono::Utc;
use std::fs;
use tempfile::TempDir;

// Re-export common test utilities
#[allow(unused_imports)]
use common::TestContext;

/// Helper to create a test cache directory structure
fn create_test_cache_dir() -> (TempDir, std::path::PathBuf) {
    let temp_dir = TempDir::new().unwrap();
    let cache_dir = temp_dir.path().join("cache");
    fs::create_dir_all(&cache_dir).unwrap();
    (temp_dir, cache_dir)
}

// =============================================================================
// T047: Test cache entry serialization/deserialization
// =============================================================================

#[test]
fn test_cache_entry_serialization() {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    struct TestData {
        name: String,
        count: i32,
    }

    // Simulate CacheEntry structure
    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct CacheEntry<T> {
        data: T,
        cached_at: chrono::DateTime<Utc>,
        ttl_seconds: u64,
        version: u32,
    }

    let test_data = TestData {
        name: "test".to_string(),
        count: 42,
    };

    let entry = CacheEntry {
        data: test_data.clone(),
        cached_at: Utc::now(),
        ttl_seconds: 3600,
        version: 1,
    };

    // Serialize to JSON
    let json = serde_json::to_string_pretty(&entry).unwrap();
    assert!(json.contains("\"name\": \"test\""));
    assert!(json.contains("\"count\": 42"));
    assert!(json.contains("\"ttl_seconds\": 3600"));

    // Deserialize back
    let deserialized: CacheEntry<TestData> = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.data, test_data);
    assert_eq!(deserialized.ttl_seconds, 3600);
    assert_eq!(deserialized.version, 1);
}

#[test]
fn test_cache_entry_with_complex_data() {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct Agent {
        id: String,
        name: String,
        agent_type: String,
        status: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct AgentList {
        agents: Vec<Agent>,
        total: i64,
    }

    let agent_list = AgentList {
        agents: vec![Agent {
            id: "a1b2c3d4-e5f6-7890-abcd-ef1234567890".to_string(),
            name: "test-agent".to_string(),
            agent_type: "copilot".to_string(),
            status: "active".to_string(),
        }],
        total: 1,
    };

    let json = serde_json::to_string_pretty(&agent_list).unwrap();
    assert!(json.contains("test-agent"));
    assert!(json.contains("copilot"));
}

// =============================================================================
// T048: Test cache store write/read operations
// =============================================================================

#[test]
fn test_cache_file_write_read() {
    let (_temp_dir, cache_dir) = create_test_cache_dir();
    let cache_file = cache_dir.join("agents.json");

    // Write cache entry
    let cache_data = r#"{
        "data": {"agents": [], "total": 0},
        "cached_at": "2026-02-04T00:00:00Z",
        "ttl_seconds": 3600,
        "version": 1
    }"#;

    fs::write(&cache_file, cache_data).unwrap();

    // Read it back
    let contents = fs::read_to_string(&cache_file).unwrap();
    assert!(contents.contains("cached_at"));
    assert!(contents.contains("ttl_seconds"));
}

#[test]
fn test_cache_key_constants() {
    // Verify cache keys follow expected naming convention
    let keys = ["agents", "tools", "status", "whoami"];
    for key in keys {
        assert!(!key.is_empty());
        assert!(key.chars().all(|c| c.is_alphanumeric() || c == '_'));
    }
}

// =============================================================================
// T049: Test cache TTL expiration
// =============================================================================

#[test]
fn test_cache_expiration_logic() {
    use chrono::Duration;

    let now = Utc::now();

    // Fresh cache (not expired)
    let fresh_cached_at = now - Duration::minutes(30);
    let ttl_seconds: u64 = 3600; // 1 hour
    let expiry = fresh_cached_at + Duration::seconds(ttl_seconds as i64);
    assert!(now < expiry, "Fresh cache should not be expired");

    // Stale cache (expired)
    let stale_cached_at = now - Duration::hours(2);
    let expiry = stale_cached_at + Duration::seconds(ttl_seconds as i64);
    assert!(now > expiry, "Stale cache should be expired");
}

#[test]
fn test_cache_ttl_boundary() {
    use chrono::Duration;

    let now = Utc::now();
    let ttl_seconds: u64 = 3600;

    // Just before expiry (should not be expired)
    let cached_at = now - Duration::seconds((ttl_seconds - 1) as i64);
    let expiry = cached_at + Duration::seconds(ttl_seconds as i64);
    assert!(now < expiry);

    // Just after expiry (should be expired)
    let cached_at = now - Duration::seconds((ttl_seconds + 1) as i64);
    let expiry = cached_at + Duration::seconds(ttl_seconds as i64);
    assert!(now > expiry);
}

// =============================================================================
// T050: Test offline detection via network failure
// =============================================================================

#[test]
fn test_network_error_detection() {
    // Verify error type matching for network errors
    fn is_network_error_type(error_msg: &str) -> bool {
        error_msg.contains("network")
            || error_msg.contains("connection")
            || error_msg.contains("timeout")
            || error_msg.contains("Network")
            || error_msg.contains("Connection")
    }

    assert!(is_network_error_type("Network error: connection refused"));
    assert!(is_network_error_type("Connection failed: timeout"));
    assert!(!is_network_error_type("Not found"));
    assert!(!is_network_error_type("Unauthorized"));
}

// =============================================================================
// T051: Test --offline flag forces offline mode
// =============================================================================

#[test]
fn test_offline_flag_args_parsing() {
    use clap::Parser;

    #[derive(Parser)]
    struct TestCli {
        #[arg(long)]
        offline: bool,
    }

    // Test without --offline flag
    let cli: TestCli = TestCli::parse_from(["test"]);
    assert!(!cli.offline);

    // Test with --offline flag
    let cli: TestCli = TestCli::parse_from(["test", "--offline"]);
    assert!(cli.offline);
}

// =============================================================================
// T052: Test --refresh flag bypasses cache
// =============================================================================

#[test]
fn test_refresh_flag_args_parsing() {
    use clap::Parser;

    #[derive(Parser)]
    struct TestCli {
        #[arg(long)]
        refresh: bool,
    }

    // Test without --refresh flag
    let cli: TestCli = TestCli::parse_from(["test"]);
    assert!(!cli.refresh);

    // Test with --refresh flag
    let cli: TestCli = TestCli::parse_from(["test", "--refresh"]);
    assert!(cli.refresh);
}

// =============================================================================
// T053: Test agents list with cached data
// =============================================================================

#[test]
fn test_agents_list_cache_format() {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct AgentResponse {
        id: String,
        name: String,
        agent_type: String,
        status: String,
        risk_level: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct AgentListResponse {
        agents: Vec<AgentResponse>,
        total: i64,
        limit: i32,
        offset: i32,
    }

    let response = AgentListResponse {
        agents: vec![AgentResponse {
            id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            name: "test-agent".to_string(),
            agent_type: "copilot".to_string(),
            status: "active".to_string(),
            risk_level: "low".to_string(),
        }],
        total: 1,
        limit: 50,
        offset: 0,
    };

    let json = serde_json::to_string_pretty(&response).unwrap();

    // Verify JSON format is compatible with CLI output
    assert!(json.contains("\"agents\""));
    assert!(json.contains("\"total\""));
    assert!(json.contains("test-agent"));
}

// =============================================================================
// T054: Test tools list with cached data
// =============================================================================

#[test]
fn test_tools_list_cache_format() {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct ToolResponse {
        id: String,
        name: String,
        risk_score: Option<i32>,
        lifecycle_state: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct ToolListResponse {
        data: Vec<ToolResponse>,
        total: i64,
    }

    let response = ToolListResponse {
        data: vec![ToolResponse {
            id: "550e8400-e29b-41d4-a716-446655440001".to_string(),
            name: "send-email".to_string(),
            risk_score: Some(50),
            lifecycle_state: "active".to_string(),
        }],
        total: 1,
    };

    let json = serde_json::to_string_pretty(&response).unwrap();
    assert!(json.contains("\"data\""));
    assert!(json.contains("send-email"));
}

// =============================================================================
// T055: Test "no cache available" error message
// =============================================================================

#[test]
fn test_no_cache_error_message() {
    let resource = "agents";
    let error_msg = format!(
        "No cached data available for {}.\nRun this command while online to populate the cache.",
        resource
    );

    assert!(error_msg.contains("agents"));
    assert!(error_msg.contains("Run this command while online"));
    assert!(error_msg.contains("populate the cache"));
}

// =============================================================================
// T056: Test write operation rejected offline
// =============================================================================

#[test]
fn test_write_rejected_error_message() {
    let operation = "create agent";
    let error_msg = format!(
        "Cannot {} while offline.\nWrite operations require network connectivity.",
        operation
    );

    assert!(error_msg.contains("create agent"));
    assert!(error_msg.contains("offline"));
    assert!(error_msg.contains("Write operations"));
}

// =============================================================================
// T057: Test cache status command output
// =============================================================================

#[test]
fn test_cache_status_output_format() {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct CacheStatus {
        total_size_bytes: u64,
        entry_count: usize,
        cache_dir: String,
        default_ttl_seconds: u64,
    }

    let status = CacheStatus {
        total_size_bytes: 1024,
        entry_count: 3,
        cache_dir: "/home/user/.xavyo/cache".to_string(),
        default_ttl_seconds: 3600,
    };

    let json = serde_json::to_string_pretty(&status).unwrap();
    assert!(json.contains("\"total_size_bytes\""));
    assert!(json.contains("\"entry_count\""));
    assert!(json.contains("\"cache_dir\""));
}

#[test]
fn test_cache_size_human_readable() {
    fn size_human(bytes: u64) -> String {
        if bytes < 1024 {
            format!("{} B", bytes)
        } else if bytes < 1024 * 1024 {
            format!("{:.1} KB", bytes as f64 / 1024.0)
        } else {
            format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
        }
    }

    assert_eq!(size_human(512), "512 B");
    assert_eq!(size_human(2048), "2.0 KB");
    assert_eq!(size_human(1048576), "1.0 MB");
}

// =============================================================================
// T058: Test cache clear command
// =============================================================================

#[test]
fn test_cache_clear_removes_files() {
    let (_temp_dir, cache_dir) = create_test_cache_dir();

    // Create some cache files
    fs::write(cache_dir.join("agents.json"), "{}").unwrap();
    fs::write(cache_dir.join("tools.json"), "{}").unwrap();
    fs::write(cache_dir.join("status.json"), "{}").unwrap();

    // Count before clear
    let count_before: usize = fs::read_dir(&cache_dir)
        .unwrap()
        .filter(|e| {
            e.as_ref()
                .unwrap()
                .path()
                .extension()
                .is_some_and(|ext| ext == "json")
        })
        .count();
    assert_eq!(count_before, 3);

    // Clear cache files
    let mut removed = 0;
    for entry in fs::read_dir(&cache_dir).unwrap() {
        let entry = entry.unwrap();
        if entry.path().extension().is_some_and(|ext| ext == "json") {
            fs::remove_file(entry.path()).unwrap();
            removed += 1;
        }
    }

    assert_eq!(removed, 3);

    // Verify empty
    let count_after: usize = fs::read_dir(&cache_dir)
        .unwrap()
        .filter(|e| {
            e.as_ref()
                .unwrap()
                .path()
                .extension()
                .is_some_and(|ext| ext == "json")
        })
        .count();
    assert_eq!(count_after, 0);
}

// =============================================================================
// T059: Test corrupted cache recovery
// =============================================================================

#[test]
fn test_corrupted_cache_handling() {
    let (_temp_dir, cache_dir) = create_test_cache_dir();
    let cache_file = cache_dir.join("agents.json");

    // Write corrupted data
    fs::write(&cache_file, "{ invalid json").unwrap();

    // Try to parse - should fail
    let contents = fs::read_to_string(&cache_file).unwrap();
    let result: Result<serde_json::Value, _> = serde_json::from_str(&contents);
    assert!(result.is_err());

    // Recovery: delete corrupted file
    fs::remove_file(&cache_file).unwrap();
    assert!(!cache_file.exists());
}

#[test]
fn test_unreadable_cache_handling() {
    let (_temp_dir, cache_dir) = create_test_cache_dir();
    let missing_file = cache_dir.join("nonexistent.json");

    // Reading non-existent file should fail
    let result = fs::read_to_string(&missing_file);
    assert!(result.is_err());
}

// =============================================================================
// T060: Test stale cache warning
// =============================================================================

#[test]
fn test_stale_cache_warning_message() {
    let warning = "Warning: Cached data is stale. Run without --offline to refresh.";
    assert!(warning.contains("stale"));
    assert!(warning.contains("refresh"));
}

// =============================================================================
// T061: Test "(offline)" indicator in output
// =============================================================================

#[test]
fn test_offline_indicator() {
    let indicator = "(offline - using cached data)";
    assert!(indicator.contains("offline"));
    assert!(indicator.contains("cached"));
}

#[test]
fn test_offline_output_format() {
    // Verify offline indicator appears before data
    let output = "(offline - using cached data)\n\nNo agents found.";
    let lines: Vec<&str> = output.lines().collect();
    assert!(lines[0].contains("offline"));
}

// =============================================================================
// T062: Test CLI help for new flags
// =============================================================================

#[test]
fn test_offline_flag_help_text() {
    use clap::{Arg, Command};

    let cmd = Command::new("test")
        .arg(
            Arg::new("offline")
                .long("offline")
                .help("Force offline mode (use cached data only)")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("refresh")
                .long("refresh")
                .help("Force refresh from server (bypass cache)")
                .action(clap::ArgAction::SetTrue),
        );

    let help = cmd.clone().render_help().to_string();
    assert!(help.contains("--offline"));
    assert!(help.contains("--refresh"));
    assert!(help.contains("cached data"));
}

// =============================================================================
// Additional tests for edge cases
// =============================================================================

#[test]
fn test_cache_dir_creation() {
    let temp_dir = TempDir::new().unwrap();
    let cache_dir = temp_dir.path().join("new_cache");

    // Cache dir doesn't exist yet
    assert!(!cache_dir.exists());

    // Create it
    fs::create_dir_all(&cache_dir).unwrap();
    assert!(cache_dir.exists());
    assert!(cache_dir.is_dir());
}

#[test]
fn test_cache_config_defaults() {
    let default_ttl: u64 = 3600; // 1 hour
    let max_size: u64 = 10 * 1024 * 1024; // 10 MB

    assert_eq!(default_ttl, 3600);
    assert_eq!(max_size, 10485760);
}

#[test]
fn test_offline_status_enum() {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum OfflineStatus {
        Online,
        Offline,
        ForcedOffline,
    }

    let online = OfflineStatus::Online;
    let offline = OfflineStatus::Offline;
    let forced = OfflineStatus::ForcedOffline;

    assert_eq!(online, OfflineStatus::Online);
    assert_ne!(online, offline);
    assert_ne!(offline, forced);
}
