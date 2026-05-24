//! `OAuth2` client models.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// `OAuth2` client type.
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
            _ => Err(format!("Invalid client type: {s}")),
        }
    }
}

/// Request to create a new `OAuth2` client.
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
    /// Client logo URL (shown on consent page).
    pub logo_url: Option<String>,
    /// Client description (shown on consent page).
    pub description: Option<String>,
    /// Optional NHI identity to bind to this client.
    /// When set, client_credentials tokens use this NHI ID as the JWT subject.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nhi_id: Option<Uuid>,
    /// Allowed post-logout redirect URIs (OIDC RP-Initiated Logout).
    #[serde(default)]
    pub post_logout_redirect_uris: Vec<String>,
}

/// Request to update an `OAuth2` client.
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
    /// Client logo URL (shown on consent page).
    pub logo_url: Option<String>,
    /// Client description (shown on consent page).
    pub description: Option<String>,
    /// Allowed post-logout redirect URIs (OIDC RP-Initiated Logout).
    pub post_logout_redirect_uris: Option<Vec<String>>,
}

/// `OAuth2` client response.
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
    /// Client logo URL (shown on consent page).
    pub logo_url: Option<String>,
    /// Client description (shown on consent page).
    pub description: Option<String>,
    /// Bound NHI identity (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nhi_id: Option<Uuid>,
    /// Allowed post-logout redirect URIs (OIDC RP-Initiated Logout).
    pub post_logout_redirect_uris: Vec<String>,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Last update timestamp.
    pub updated_at: DateTime<Utc>,
    /// RFC 9449: client requires DPoP-bound (sender-constrained) tokens.
    #[serde(default)]
    pub require_dpop: bool,
    /// FAPI 2.0 Security Profile opt-in (§5.3.2): implies PAR + DPoP mandatory.
    #[serde(default)]
    pub fapi_profile: bool,
    /// Inline JWKS for `private_key_jwt` client-assertion verification (RFC 7523).
    /// `None` ⇒ the client does not use `private_key_jwt`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks: Option<serde_json::Value>,
}

impl ClientResponse {
    /// Whether this client must present a DPoP proof and receive a
    /// sender-constrained token (explicit `require_dpop`, or FAPI 2.0 which
    /// mandates sender-constrained tokens, §5.3.2.1-5).
    #[must_use]
    pub fn requires_dpop(&self) -> bool {
        self.require_dpop || self.fapi_profile
    }

    /// Whether this client must use PAR (RFC 9126) — FAPI 2.0 §5.3.2.2.
    #[must_use]
    pub fn requires_par(&self) -> bool {
        self.fapi_profile
    }
}

/// `OAuth2` client creation response (includes secret for confidential clients).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct CreateClientResponse {
    /// Client details.
    #[serde(flatten)]
    pub client: ClientResponse,
    /// Client secret (only for confidential clients, only shown once).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
}

/// `OAuth2` client list response.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ClientListResponse {
    /// List of clients.
    pub clients: Vec<ClientResponse>,
    /// Total count.
    pub total: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal `ClientResponse` with both profile flags off.
    fn base() -> ClientResponse {
        ClientResponse {
            id: Uuid::nil(),
            client_id: "c".to_string(),
            name: "c".to_string(),
            client_type: ClientType::Confidential,
            redirect_uris: vec![],
            grant_types: vec![],
            scopes: vec![],
            is_active: true,
            logo_url: None,
            description: None,
            nhi_id: None,
            post_logout_redirect_uris: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
            require_dpop: false,
            fapi_profile: false,
            jwks: None,
        }
    }

    #[test]
    fn plain_client_requires_neither() {
        let c = base();
        assert!(!c.requires_dpop());
        assert!(!c.requires_par());
    }

    #[test]
    fn require_dpop_flag_requires_dpop_only() {
        let c = ClientResponse {
            require_dpop: true,
            ..base()
        };
        assert!(c.requires_dpop());
        assert!(!c.requires_par(), "require_dpop alone does not mandate PAR");
    }

    #[test]
    fn fapi_profile_implies_both_par_and_dpop() {
        // FAPI 2.0 §5.3.2: profile clients must use PAR and sender-constrained tokens.
        let c = ClientResponse {
            fapi_profile: true,
            ..base()
        };
        assert!(
            c.requires_dpop(),
            "FAPI 2.0 mandates sender-constrained tokens"
        );
        assert!(c.requires_par(), "FAPI 2.0 mandates PAR");
    }
}
