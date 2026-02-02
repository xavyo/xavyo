//! OAuth2 client models.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// OAuth2 client type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ClientType {
    /// Confidential client (can securely store secrets).
    Confidential,
    /// Public client (cannot store secrets, e.g., SPA, mobile).
    Public,
}

impl std::fmt::Display for ClientType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientType::Confidential => write!(f, "confidential"),
            ClientType::Public => write!(f, "public"),
        }
    }
}

impl std::str::FromStr for ClientType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "confidential" => Ok(ClientType::Confidential),
            "public" => Ok(ClientType::Public),
            _ => Err(format!("Invalid client type: {}", s)),
        }
    }
}

/// Request to create a new OAuth2 client.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct CreateClientRequest {
    /// Human-readable client name.
    pub name: String,
    /// Client type (confidential or public).
    pub client_type: ClientType,
    /// Allowed redirect URIs.
    pub redirect_uris: Vec<String>,
    /// Allowed grant types.
    pub grant_types: Vec<String>,
    /// Allowed scopes.
    pub scopes: Vec<String>,
}

/// Request to update an OAuth2 client.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct UpdateClientRequest {
    /// Human-readable client name.
    pub name: Option<String>,
    /// Allowed redirect URIs.
    pub redirect_uris: Option<Vec<String>>,
    /// Allowed grant types.
    pub grant_types: Option<Vec<String>>,
    /// Allowed scopes.
    pub scopes: Option<Vec<String>>,
    /// Whether the client is active.
    pub is_active: Option<bool>,
}

/// OAuth2 client response.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ClientResponse {
    /// Internal ID.
    pub id: Uuid,
    /// Public client ID.
    pub client_id: String,
    /// Human-readable name.
    pub name: String,
    /// Client type.
    pub client_type: ClientType,
    /// Allowed redirect URIs.
    pub redirect_uris: Vec<String>,
    /// Allowed grant types.
    pub grant_types: Vec<String>,
    /// Allowed scopes.
    pub scopes: Vec<String>,
    /// Whether the client is active.
    pub is_active: bool,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Last update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// OAuth2 client creation response (includes secret for confidential clients).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct CreateClientResponse {
    /// Client details.
    #[serde(flatten)]
    pub client: ClientResponse,
    /// Client secret (only for confidential clients, only shown once).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
}

/// OAuth2 client list response.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ClientListResponse {
    /// List of clients.
    pub clients: Vec<ClientResponse>,
    /// Total count.
    pub total: i64,
}
