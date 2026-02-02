//! SIEM request/response models for governance API (F078).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;

use xavyo_db::models::SiemDestination;

// ---------------------------------------------------------------------------
// Destination DTOs
// ---------------------------------------------------------------------------

/// Request to create a SIEM destination.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateSiemDestinationRequest {
    /// Destination name (unique per tenant).
    #[validate(length(min = 1, max = 255, message = "Name must be 1-255 characters"))]
    pub name: String,

    /// Destination type: syslog_tcp_tls, syslog_udp, webhook, splunk_hec.
    #[validate(length(min = 1, max = 50))]
    pub destination_type: String,

    /// Hostname or IP of the destination.
    #[validate(length(min = 1, max = 512))]
    pub endpoint_host: String,

    /// Port (optional — defaults per type).
    pub endpoint_port: Option<i32>,

    /// Export format: cef, syslog_rfc5424, json, csv.
    #[validate(length(min = 1, max = 20))]
    pub export_format: String,

    /// Base64-encoded auth config (tokens, certs).
    pub auth_config_b64: Option<String>,

    /// Event types to export (JSON array of category strings, empty = all).
    pub event_type_filter: Option<serde_json::Value>,

    /// Max events per second to this destination.
    pub rate_limit_per_second: Option<i32>,

    /// Queue buffer size for delivery resilience.
    pub queue_buffer_size: Option<i32>,

    /// Number of consecutive failures before circuit breaker opens.
    pub circuit_breaker_threshold: Option<i32>,

    /// Seconds to wait before retrying after circuit breaker opens.
    pub circuit_breaker_cooldown_secs: Option<i32>,

    /// Whether destination is enabled.
    pub enabled: Option<bool>,

    // Splunk-specific
    pub splunk_source: Option<String>,
    pub splunk_sourcetype: Option<String>,
    pub splunk_index: Option<String>,
    pub splunk_ack_enabled: Option<bool>,

    // Syslog-specific
    pub syslog_facility: Option<i16>,

    /// Verify TLS certificates.
    pub tls_verify_cert: Option<bool>,
}

/// Request to update a SIEM destination.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct UpdateSiemDestinationRequest {
    #[validate(length(min = 1, max = 255, message = "Name must be 1-255 characters"))]
    pub name: Option<String>,
    pub endpoint_host: Option<String>,
    pub endpoint_port: Option<i32>,
    pub export_format: Option<String>,
    pub auth_config_b64: Option<String>,
    pub event_type_filter: Option<serde_json::Value>,
    pub rate_limit_per_second: Option<i32>,
    pub queue_buffer_size: Option<i32>,
    pub circuit_breaker_threshold: Option<i32>,
    pub circuit_breaker_cooldown_secs: Option<i32>,
    pub enabled: Option<bool>,
    pub splunk_source: Option<String>,
    pub splunk_sourcetype: Option<String>,
    pub splunk_index: Option<String>,
    pub splunk_ack_enabled: Option<bool>,
    pub syslog_facility: Option<i16>,
    pub tls_verify_cert: Option<bool>,
}

/// Maximum allowed limit for pagination.
const MAX_LIMIT: i64 = 100;

/// Query parameters for listing SIEM destinations.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListSiemDestinationsQuery {
    /// Filter by enabled status.
    pub enabled: Option<bool>,
    /// Maximum number of results (1-100, default 50).
    #[serde(default = "default_limit")]
    pub limit: i64,
    /// Number of results to skip (default 0).
    #[serde(default)]
    pub offset: i64,
}

impl ListSiemDestinationsQuery {
    /// Validate and clamp pagination values.
    ///
    /// SECURITY: Prevents DoS via unbounded pagination.
    pub fn validated(self) -> Self {
        Self {
            enabled: self.enabled,
            limit: self.limit.clamp(1, MAX_LIMIT),
            offset: self.offset.max(0),
        }
    }
}

fn default_limit() -> i64 {
    50
}

/// SIEM destination response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SiemDestinationResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub destination_type: String,
    pub endpoint_host: String,
    pub endpoint_port: Option<i32>,
    pub export_format: String,
    /// Whether auth is configured (never returns raw auth data).
    pub has_auth_config: bool,
    pub event_type_filter: serde_json::Value,
    pub rate_limit_per_second: i32,
    pub queue_buffer_size: i32,
    pub circuit_breaker_threshold: i32,
    pub circuit_breaker_cooldown_secs: i32,
    pub circuit_state: String,
    pub circuit_last_failure_at: Option<DateTime<Utc>>,
    pub enabled: bool,
    pub splunk_source: Option<String>,
    pub splunk_sourcetype: Option<String>,
    pub splunk_index: Option<String>,
    pub splunk_ack_enabled: bool,
    pub syslog_facility: i16,
    pub tls_verify_cert: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: Uuid,
}

impl From<SiemDestination> for SiemDestinationResponse {
    fn from(d: SiemDestination) -> Self {
        Self {
            id: d.id,
            tenant_id: d.tenant_id,
            name: d.name,
            destination_type: d.destination_type,
            endpoint_host: d.endpoint_host,
            endpoint_port: d.endpoint_port,
            export_format: d.export_format,
            has_auth_config: d.auth_config.is_some(),
            event_type_filter: d.event_type_filter,
            rate_limit_per_second: d.rate_limit_per_second,
            queue_buffer_size: d.queue_buffer_size,
            circuit_breaker_threshold: d.circuit_breaker_threshold,
            circuit_breaker_cooldown_secs: d.circuit_breaker_cooldown_secs,
            circuit_state: d.circuit_state,
            circuit_last_failure_at: d.circuit_last_failure_at,
            enabled: d.enabled,
            splunk_source: d.splunk_source,
            splunk_sourcetype: d.splunk_sourcetype,
            splunk_index: d.splunk_index,
            splunk_ack_enabled: d.splunk_ack_enabled,
            syslog_facility: d.syslog_facility,
            tls_verify_cert: d.tls_verify_cert,
            created_at: d.created_at,
            updated_at: d.updated_at,
            created_by: d.created_by,
        }
    }
}

/// Paginated list of SIEM destinations.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SiemDestinationListResponse {
    pub items: Vec<SiemDestinationResponse>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

/// Test connectivity result.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TestConnectivityResponse {
    pub success: bool,
    pub latency_ms: Option<u64>,
    pub error: Option<String>,
}

// ---------------------------------------------------------------------------
// Batch Export DTOs
// ---------------------------------------------------------------------------

/// Request to create a batch export.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateBatchExportRequest {
    pub date_range_start: DateTime<Utc>,
    pub date_range_end: DateTime<Utc>,
    pub event_type_filter: Option<serde_json::Value>,
    #[validate(length(min = 1, max = 10))]
    pub output_format: String,
}

/// Query parameters for listing batch exports.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListBatchExportsQuery {
    pub status: Option<String>,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

/// Batch export response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SiemBatchExportResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub requested_by: Uuid,
    pub date_range_start: DateTime<Utc>,
    pub date_range_end: DateTime<Utc>,
    pub event_type_filter: serde_json::Value,
    pub output_format: String,
    pub status: String,
    pub total_events: Option<i64>,
    pub file_size_bytes: Option<i64>,
    pub error_detail: Option<String>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl From<xavyo_db::models::SiemBatchExport> for SiemBatchExportResponse {
    fn from(e: xavyo_db::models::SiemBatchExport) -> Self {
        Self {
            id: e.id,
            tenant_id: e.tenant_id,
            requested_by: e.requested_by,
            date_range_start: e.date_range_start,
            date_range_end: e.date_range_end,
            event_type_filter: e.event_type_filter,
            output_format: e.output_format,
            status: e.status,
            total_events: e.total_events,
            file_size_bytes: e.file_size_bytes,
            error_detail: e.error_detail,
            started_at: e.started_at,
            completed_at: e.completed_at,
            expires_at: e.expires_at,
            created_at: e.created_at,
        }
    }
}

/// Paginated list of batch exports.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SiemBatchExportListResponse {
    pub items: Vec<SiemBatchExportResponse>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

// ---------------------------------------------------------------------------
// Health DTOs
// ---------------------------------------------------------------------------

/// Delivery health summary response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SiemHealthSummaryResponse {
    pub destination_id: Uuid,
    pub total_events_sent: i64,
    pub total_events_delivered: i64,
    pub total_events_failed: i64,
    pub total_events_dropped: i64,
    pub avg_latency_ms: Option<i32>,
    pub last_success_at: Option<DateTime<Utc>>,
    pub last_failure_at: Option<DateTime<Utc>>,
    pub success_rate_percent: f64,
    pub circuit_state: String,
    pub dead_letter_count: i64,
}

/// Health history query parameters.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct HealthHistoryQuery {
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

/// Dead letter query parameters.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct DeadLetterQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

/// Re-delivery result.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RedeliverResponse {
    pub events_requeued: u64,
}
