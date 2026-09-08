//! API response types for social authentication.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::ProviderType;

/// Response for the available providers endpoint.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AvailableProvidersResponse {
    pub providers: Vec<AvailableProvider>,
}

/// An available social provider for login.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AvailableProvider {
    pub provider: String,
    pub name: String,
    pub authorize_url: String,
}

impl AvailableProvider {
    #[must_use]
    pub fn new(provider: ProviderType, base_url: &str) -> Self {
        let (name, provider_str) = match provider {
            ProviderType::Google => ("Google", "google"),
            ProviderType::Microsoft => ("Microsoft", "microsoft"),
            ProviderType::Apple => ("Apple", "apple"),
            ProviderType::Github => ("GitHub", "github"),
        };

        Self {
            provider: provider_str.to_string(),
            name: name.to_string(),
            authorize_url: format!("{base_url}/auth/social/{provider_str}/authorize"),
        }
    }
}

/// Response for a social connection.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SocialConnectionResponse {
    pub id: Uuid,
    pub provider: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub is_private_email: bool,
    pub created_at: DateTime<Utc>,
}

/// Response for listing user's social connections.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ConnectionsListResponse {
    pub connections: Vec<SocialConnectionResponse>,
}

/// Request for linking a social account.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LinkAccountRequest {
    /// Authorization code from OAuth flow.
    pub code: String,
    /// State parameter for CSRF protection.
    pub state: String,
}

/// Response for a tenant provider configuration.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TenantProviderResponse {
    pub provider: String,
    pub enabled: bool,
    pub client_id: String,
    /// Whether client secret is configured (never expose actual secret).
    pub has_client_secret: bool,
    pub scopes: Option<Vec<String>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Response for listing tenant providers.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TenantProvidersListResponse {
    pub providers: Vec<TenantProviderResponse>,
}

/// Request for updating a tenant provider configuration.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UpdateProviderRequest {
    pub enabled: bool,
    /// Required when first configuring a provider. Omitted for a plain
    /// enable/disable toggle, in which case the stored value is preserved.
    #[serde(default)]
    pub client_id: String,
    /// Only required when enabling or changing.
    pub client_secret: Option<String>,
    pub additional_config: Option<serde_json::Value>,
    pub scopes: Option<Vec<String>>,
}

/// OAuth callback query parameters.
#[derive(Debug, Clone, Deserialize)]
pub struct OAuthCallbackQuery {
    /// Authorization code from provider.
    pub code: Option<String>,
    /// State parameter for CSRF protection.
    pub state: String,
    /// Error code if authorization failed.
    pub error: Option<String>,
    /// Error description.
    pub error_description: Option<String>,
}

/// Apple callback form data (`form_post` response mode).
#[derive(Debug, Clone, Deserialize)]
pub struct AppleCallbackForm {
    /// Authorization code.
    pub code: Option<String>,
    /// State parameter.
    pub state: String,
    /// ID token (Apple provides this directly).
    pub id_token: Option<String>,
    /// JSON-encoded user info (first login only).
    pub user: Option<String>,
    /// Error if authorization failed.
    pub error: Option<String>,
}

/// Parsed Apple user info from the callback.
#[derive(Debug, Clone, Deserialize)]
pub struct AppleUserInfo {
    pub name: Option<AppleName>,
    pub email: Option<String>,
}

/// Apple name structure.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppleName {
    pub first_name: Option<String>,
    pub last_name: Option<String>,
}

/// Authorize query parameters.
#[derive(Debug, Clone, Deserialize)]
pub struct AuthorizeQuery {
    /// URL to redirect to after successful login.
    pub redirect_after: Option<String>,
}

/// Success response after social login.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SocialLoginSuccessResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
}

#[cfg(test)]
mod tests {
    use super::UpdateProviderRequest;

    /// Regression: the admin UI's enable/disable toggle sends only
    /// `{ "enabled": <bool> }`. `client_id` must be `#[serde(default)]` so this
    /// deserializes (previously it 422'd as a missing required field). The empty
    /// client_id is then treated as "preserve stored value" by the service.
    #[test]
    fn update_provider_request_deserializes_from_enabled_only() {
        let req: UpdateProviderRequest =
            serde_json::from_str(r#"{"enabled":true}"#).expect("enabled-only toggle must parse");
        assert!(req.enabled);
        assert_eq!(req.client_id, "");
        assert!(req.client_secret.is_none());
        assert!(req.scopes.is_none());
    }
}
