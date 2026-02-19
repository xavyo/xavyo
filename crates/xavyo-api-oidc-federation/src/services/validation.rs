//! Identity Provider validation service.

use crate::error::{FederationError, FederationResult};
use crate::models::ValidationResultResponse;
use crate::services::{DiscoveredEndpoints, DiscoveryService};
use sqlx::PgPool;
use tracing::instrument;
use uuid::Uuid;
use xavyo_db::models::{TenantIdentityProvider, ValidationStatus};

/// Service for validating identity provider configurations.
#[derive(Clone)]
pub struct ValidationService {
    pool: PgPool,
    discovery: DiscoveryService,
}

impl ValidationService {
    /// Create a new validation service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            discovery: DiscoveryService::new(),
        }
    }

    /// Validate an identity provider configuration.
    #[instrument(skip(self))]
    pub async fn validate(
        &self,
        tenant_id: Uuid,
        idp_id: Uuid,
    ) -> FederationResult<ValidationResultResponse> {
        // Get the identity provider
        let idp = TenantIdentityProvider::find_by_id_and_tenant(&self.pool, idp_id, tenant_id)
            .await?
            .ok_or(FederationError::IdpNotFound(idp_id))?;

        // Try to discover endpoints
        match self.discovery.discover(&idp.issuer_url).await {
            Ok(endpoints) => {
                // Update validation status to valid
                TenantIdentityProvider::update_validation_status(
                    &self.pool,
                    tenant_id,
                    idp_id,
                    ValidationStatus::Valid,
                )
                .await?;

                tracing::info!(idp_id = %idp_id, "Identity provider validation successful");

                Ok(ValidationResultResponse {
                    is_valid: true,
                    discovered_endpoints: Some(endpoints.into()),
                    error: None,
                })
            }
            Err(e) => {
                // Update validation status to invalid
                TenantIdentityProvider::update_validation_status(
                    &self.pool,
                    tenant_id,
                    idp_id,
                    ValidationStatus::Invalid,
                )
                .await?;

                let error_message = e.to_string();
                tracing::warn!(idp_id = %idp_id, error = %error_message, "Identity provider validation failed");

                Ok(ValidationResultResponse {
                    is_valid: false,
                    discovered_endpoints: None,
                    error: Some(
                        "Failed to discover OIDC endpoints for the configured issuer".to_string(),
                    ),
                })
            }
        }
    }

    /// Validate issuer URL without updating database.
    ///
    /// Returns `Ok(None)` if the issuer is unreachable or not a valid OIDC provider.
    /// Propagates security-related errors (e.g., SSRF protection) as `Err`.
    #[instrument(skip(self))]
    pub async fn validate_issuer_url(
        &self,
        issuer_url: &str,
    ) -> FederationResult<Option<DiscoveredEndpoints>> {
        match self.discovery.discover(issuer_url).await {
            Ok(endpoints) => Ok(Some(endpoints)),
            // Discovery failure means unreachable or not a valid OIDC provider
            Err(FederationError::DiscoveryFailed { .. }) => Ok(None),
            // HTTP errors mean the provider is unreachable
            Err(FederationError::HttpRequest(_)) => Ok(None),
            // All other errors (InvalidConfiguration/SSRF, Database, etc.) must propagate
            Err(e) => Err(e),
        }
    }
}
