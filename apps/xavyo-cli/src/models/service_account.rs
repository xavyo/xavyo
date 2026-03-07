//! Service account data models for the CLI

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Service account response from the API (mirrors NhiServiceAccountWithIdentity)
#[derive(Debug, Serialize, Deserialize)]
pub struct ServiceAccountResponse {
    pub id: Uuid,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub lifecycle_state: String,
    #[serde(default)]
    pub owner_id: Option<Uuid>,
    #[serde(default)]
    pub risk_score: Option<i32>,
    pub purpose: String,
    #[serde(default)]
    pub environment: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Service account list response
#[derive(Debug, Serialize, Deserialize)]
pub struct ServiceAccountListResponse {
    pub data: Vec<ServiceAccountResponse>,
    #[serde(default)]
    pub total: i64,
    #[serde(default)]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

/// Create service account request
#[derive(Debug, Serialize)]
pub struct CreateServiceAccountRequest {
    pub name: String,
    pub purpose: String,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
}
