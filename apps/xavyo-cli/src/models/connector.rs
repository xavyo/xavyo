//! Connector data models for the CLI

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Connector response from the API
#[derive(Debug, Serialize, Deserialize)]
pub struct ConnectorResponse {
    pub id: Uuid,
    pub name: String,
    #[serde(default)]
    pub connector_type: Option<String>,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub updated_at: Option<DateTime<Utc>>,
}

/// Connector list response
#[derive(Debug, Serialize, Deserialize)]
pub struct ConnectorListResponse {
    pub items: Vec<ConnectorResponse>,
    #[serde(default)]
    pub total: i64,
}

/// Create connector request
#[derive(Debug, Serialize)]
pub struct CreateConnectorRequest {
    pub name: String,
    pub connector_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<serde_json::Value>,
}
