//! Service account data models for the CLI

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Service account response from the API
#[derive(Debug, Serialize, Deserialize)]
pub struct ServiceAccountResponse {
    pub id: Uuid,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub owner_id: Option<Uuid>,
    #[serde(default)]
    pub risk_level: Option<String>,
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub updated_at: Option<DateTime<Utc>>,
}

/// Service account list response
#[derive(Debug, Serialize, Deserialize)]
pub struct ServiceAccountListResponse {
    pub items: Vec<ServiceAccountResponse>,
    #[serde(default)]
    pub total: i64,
}

/// Create service account request
#[derive(Debug, Serialize)]
pub struct CreateServiceAccountRequest {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_id: Option<Uuid>,
}

/// Update service account request
#[derive(Debug, Serialize)]
pub struct UpdateServiceAccountRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}
