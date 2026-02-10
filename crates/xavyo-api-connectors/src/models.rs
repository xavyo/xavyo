//! Request and response models for connector API.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;

use xavyo_db::models::{ConnectorStatus, ConnectorType};

/// Request to create a new connector.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateConnectorRequest {
    /// Connector display name.
    #[validate(length(min = 1, max = 255, message = "Name must be 1-255 characters"))]
    pub name: String,

    /// Connector type (ldap, database, rest).
    pub connector_type: ConnectorType,

    /// Optional description.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(length(max = 2000, message = "Description cannot exceed 2000 characters"))]
    pub description: Option<String>,

    /// Non-sensitive configuration (JSON).
    pub config: serde_json::Value,

    /// Sensitive credentials (will be encrypted).
    pub credentials: serde_json::Value,
}

/// Request to update a connector.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct UpdateConnectorRequest {
    /// New display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(length(min = 1, max = 255, message = "Name must be 1-255 characters"))]
    pub name: Option<String>,

    /// New description.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(length(max = 2000, message = "Description cannot exceed 2000 characters"))]
    pub description: Option<String>,

    /// Updated configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<serde_json::Value>,

    /// Updated credentials (will be encrypted).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credentials: Option<serde_json::Value>,
}

/// Query parameters for listing connectors.
#[derive(Debug, Clone, Serialize, Deserialize, IntoParams)]
pub struct ListConnectorsQuery {
    /// Filter by connector type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connector_type: Option<ConnectorType>,

    /// Filter by status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<ConnectorStatus>,

    /// Filter by name (partial match).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name_contains: Option<String>,

    /// Maximum number of results.
    #[serde(default = "default_limit")]
    pub limit: i64,

    /// Offset for pagination.
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    20
}

/// Response for a single connector.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ConnectorResponse {
    /// Connector ID.
    pub id: Uuid,

    /// Display name.
    pub name: String,

    /// Connector type.
    pub connector_type: ConnectorType,

    /// Description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Non-sensitive configuration.
    pub config: serde_json::Value,

    /// Current status.
    pub status: ConnectorStatus,

    /// Last connection test timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_connection_test: Option<DateTime<Utc>>,

    /// Last error message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,

    /// Creation timestamp.
    pub created_at: DateTime<Utc>,

    /// Last update timestamp.
    pub updated_at: DateTime<Utc>,
}

impl From<xavyo_db::models::ConnectorConfiguration> for ConnectorResponse {
    fn from(c: xavyo_db::models::ConnectorConfiguration) -> Self {
        Self {
            id: c.id,
            name: c.name,
            connector_type: c.connector_type,
            description: c.description,
            config: c.config,
            status: c.status,
            last_connection_test: c.last_connection_test,
            last_error: c.last_error,
            created_at: c.created_at,
            updated_at: c.updated_at,
        }
    }
}

/// Summary response for connector listing.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ConnectorSummaryResponse {
    /// Connector ID.
    pub id: Uuid,

    /// Display name.
    pub name: String,

    /// Connector type.
    pub connector_type: ConnectorType,

    /// Current status.
    pub status: ConnectorStatus,

    /// Last connection test timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_connection_test: Option<DateTime<Utc>>,

    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
}

impl From<xavyo_db::models::ConnectorSummary> for ConnectorSummaryResponse {
    fn from(s: xavyo_db::models::ConnectorSummary) -> Self {
        Self {
            id: s.id,
            name: s.name,
            connector_type: s.connector_type,
            status: s.status,
            last_connection_test: s.last_connection_test,
            created_at: s.created_at,
        }
    }
}

/// Response for listing connectors.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ConnectorListResponse {
    /// List of connectors.
    pub items: Vec<ConnectorSummaryResponse>,

    /// Total count (for pagination).
    pub total: i64,

    /// Requested limit.
    pub limit: i64,

    /// Requested offset.
    pub offset: i64,
}

/// Response for connection test.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ConnectionTestResponse {
    /// Whether the test succeeded.
    pub success: bool,

    /// Error message if failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,

    /// Timestamp of the test.
    pub tested_at: DateTime<Utc>,
}

/// Response for connector health status.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ConnectorHealthResponse {
    /// Connector ID.
    pub connector_id: Uuid,

    /// Whether the connector is currently online.
    pub is_online: bool,

    /// Number of consecutive failures.
    pub consecutive_failures: i32,

    /// When the connector went offline (if offline).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offline_since: Option<DateTime<Utc>>,

    /// Last successful operation time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_success_at: Option<DateTime<Utc>>,

    /// Last error message (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,

    /// Last health check time.
    pub last_check_at: DateTime<Utc>,
}
