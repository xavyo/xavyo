//! Response models for OIDC Federation API.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;
use xavyo_db::models::{IdentityProviderDomain, TenantIdentityProvider};

use super::requests::ClaimMappingConfig;

/// Response for realm discovery.
///
/// Only returns the authentication method (federated vs standard).
/// IdP details are intentionally omitted to prevent information leakage
/// on this unauthenticated endpoint.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DiscoverResponse {
    pub authentication_method: AuthenticationMethod,
}

/// Authentication method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationMethod {
    Federated,
    Standard,
}

/// Full identity provider response.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct IdentityProviderResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub provider_type: String,
    pub issuer_url: String,
    pub client_id: String,
    pub scopes: String,
    pub claim_mapping: ClaimMappingConfig,
    pub sync_on_login: bool,
    pub is_enabled: bool,
    pub validation_status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_validated_at: Option<DateTime<Utc>>,
    pub domains: Vec<DomainResponse>,
    pub linked_users_count: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl IdentityProviderResponse {
    /// Create from database model with domains and linked user count.
    pub fn from_model(
        idp: TenantIdentityProvider,
        domains: Vec<IdentityProviderDomain>,
        linked_users_count: i64,
    ) -> Self {
        let claim_mapping: ClaimMappingConfig =
            serde_json::from_value(idp.claim_mapping.clone()).unwrap_or_default();

        Self {
            id: idp.id,
            tenant_id: idp.tenant_id,
            name: idp.name,
            provider_type: idp.provider_type,
            issuer_url: idp.issuer_url,
            client_id: idp.client_id,
            scopes: idp.scopes,
            claim_mapping,
            sync_on_login: idp.sync_on_login,
            is_enabled: idp.is_enabled,
            validation_status: idp.validation_status,
            last_validated_at: idp.last_validated_at,
            domains: domains.into_iter().map(DomainResponse::from).collect(),
            linked_users_count,
            created_at: idp.created_at,
            updated_at: idp.updated_at,
        }
    }
}

/// Domain response.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DomainResponse {
    pub id: Uuid,
    pub domain: String,
    pub priority: i32,
    pub created_at: DateTime<Utc>,
}

impl From<IdentityProviderDomain> for DomainResponse {
    fn from(d: IdentityProviderDomain) -> Self {
        Self {
            id: d.id,
            domain: d.domain,
            priority: d.priority,
            created_at: d.created_at,
        }
    }
}

/// List response with pagination.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct IdentityProviderListResponse {
    pub items: Vec<IdentityProviderResponse>,
    pub total: i64,
    pub offset: i64,
    pub limit: i64,
}

/// Domain list response.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DomainListResponse {
    pub items: Vec<DomainResponse>,
}

/// Validation result response.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ValidationResultResponse {
    pub is_valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discovered_endpoints: Option<DiscoveredEndpointsResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Discovered endpoints in validation response.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DiscoveredEndpointsResponse {
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_endpoint: Option<String>,
    pub jwks_uri: String,
}

impl From<crate::services::DiscoveredEndpoints> for DiscoveredEndpointsResponse {
    fn from(e: crate::services::DiscoveredEndpoints) -> Self {
        Self {
            authorization_endpoint: e.authorization_endpoint,
            token_endpoint: e.token_endpoint,
            userinfo_endpoint: e.userinfo_endpoint,
            jwks_uri: e.jwks_uri,
        }
    }
}

/// Token response after successful federation.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct FederationTokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub refresh_token: Option<String>,
}

/// Error response.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}
