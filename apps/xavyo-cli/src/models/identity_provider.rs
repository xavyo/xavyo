//! Identity provider data models for the CLI

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Identity provider response from the API
#[derive(Debug, Serialize, Deserialize)]
pub struct IdentityProviderResponse {
    pub id: Uuid,
    pub name: String,
    #[serde(default)]
    pub provider_type: Option<String>,
    #[serde(default)]
    pub issuer_url: Option<String>,
    #[serde(default)]
    pub is_enabled: bool,
    #[serde(default)]
    pub is_validated: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Identity provider list response
#[derive(Debug, Serialize, Deserialize)]
pub struct IdentityProviderListResponse {
    pub identity_providers: Vec<IdentityProviderResponse>,
    pub total: i64,
}

/// Create identity provider request
#[derive(Debug, Serialize)]
pub struct CreateIdentityProviderRequest {
    pub name: String,
    pub provider_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
}
