//! Identity Provider configuration service.

use crate::error::{FederationError, FederationResult};
use crate::models::{
    ClaimMappingConfig, CreateIdentityProviderRequest, UpdateIdentityProviderRequest,
};
use crate::services::{DiscoveryService, EncryptionService};
use sqlx::PgPool;
use tracing::instrument;
use uuid::Uuid;
use xavyo_db::models::{
    CreateDomain, CreateIdentityProvider, FederatedAuthSession, IdentityProviderDomain,
    ProviderType, TenantIdentityProvider, UpdateIdentityProvider, UserIdentityLink,
    ValidationStatus,
};

/// Service for managing identity provider configurations.
#[derive(Clone)]
pub struct IdpConfigService {
    pool: PgPool,
    encryption: EncryptionService,
    discovery: DiscoveryService,
}

impl IdpConfigService {
    /// Create a new `IdP` configuration service.
    #[must_use]
    pub fn new(pool: PgPool, encryption: EncryptionService) -> Self {
        Self {
            pool,
            encryption,
            discovery: DiscoveryService::new(),
        }
    }

    /// List identity providers for a tenant.
    #[instrument(skip(self))]
    pub async fn list(
        &self,
        tenant_id: Uuid,
        offset: i64,
        limit: i64,
    ) -> FederationResult<(Vec<TenantIdentityProvider>, i64)> {
        let idps =
            TenantIdentityProvider::list_by_tenant(&self.pool, tenant_id, offset, limit).await?;
        let total = TenantIdentityProvider::count_by_tenant(&self.pool, tenant_id).await?;
        Ok((idps, total))
    }

    /// Get a single identity provider by ID.
    #[instrument(skip(self))]
    pub async fn get(
        &self,
        tenant_id: Uuid,
        idp_id: Uuid,
    ) -> FederationResult<TenantIdentityProvider> {
        TenantIdentityProvider::find_by_id_and_tenant(&self.pool, idp_id, tenant_id)
            .await?
            .ok_or(FederationError::IdpNotFound(idp_id))
    }

    /// Get domains for an identity provider within a tenant.
    #[instrument(skip(self))]
    pub async fn get_domains(
        &self,
        tenant_id: Uuid,
        idp_id: Uuid,
    ) -> FederationResult<Vec<IdentityProviderDomain>> {
        Ok(IdentityProviderDomain::list_by_idp(&self.pool, tenant_id, idp_id).await?)
    }

    /// Get linked user count for an identity provider within a tenant.
    #[instrument(skip(self))]
    pub async fn get_linked_users_count(
        &self,
        tenant_id: Uuid,
        idp_id: Uuid,
    ) -> FederationResult<i64> {
        Ok(UserIdentityLink::count_by_idp(&self.pool, tenant_id, idp_id).await?)
    }

    /// Create a new identity provider.
    #[instrument(skip(self, req))]
    pub async fn create(
        &self,
        tenant_id: Uuid,
        req: CreateIdentityProviderRequest,
    ) -> FederationResult<TenantIdentityProvider> {
        // Parse provider type
        let provider_type: ProviderType = req
            .provider_type
            .parse()
            .map_err(|e: String| FederationError::InvalidConfiguration(e))?;

        // Check if issuer already exists
        if TenantIdentityProvider::issuer_exists(&self.pool, tenant_id, &req.issuer_url, None)
            .await?
        {
            return Err(FederationError::IssuerAlreadyExists);
        }

        // Validate the configuration by testing discovery
        let validation_result = self.discovery.validate_issuer(&req.issuer_url).await?;
        let validation_status = if validation_result {
            ValidationStatus::Valid
        } else {
            return Err(FederationError::DiscoveryFailed {
                issuer: req.issuer_url.clone(),
                message: "Failed to discover OIDC endpoints".to_string(),
            });
        };

        // Encrypt client secret
        let client_secret_encrypted = self.encryption.encrypt(tenant_id, &req.client_secret)?;

        // Build claim mapping
        let claim_mapping = req
            .claim_mapping
            .unwrap_or_else(ClaimMappingConfig::default_mapping)
            .to_json();

        // Create the identity provider
        let input = CreateIdentityProvider {
            tenant_id,
            name: req.name,
            provider_type,
            issuer_url: req.issuer_url,
            client_id: req.client_id,
            client_secret_encrypted,
            claim_mapping,
            scopes: req.scopes,
            sync_on_login: req.sync_on_login,
        };

        let idp = TenantIdentityProvider::create(&self.pool, input).await?;

        // Update validation status
        let idp = TenantIdentityProvider::update_validation_status(
            &self.pool,
            tenant_id,
            idp.id,
            validation_status,
        )
        .await?;

        // Add initial domains
        for domain in req.domains {
            if IdentityProviderDomain::validate_domain(&domain) {
                let _ = IdentityProviderDomain::create(
                    &self.pool,
                    CreateDomain {
                        tenant_id,
                        identity_provider_id: idp.id,
                        domain,
                        priority: 0,
                    },
                )
                .await;
            }
        }

        tracing::info!(idp_id = %idp.id, "Created identity provider");
        Ok(idp)
    }

    /// Update an identity provider.
    #[instrument(skip(self, req))]
    pub async fn update(
        &self,
        tenant_id: Uuid,
        idp_id: Uuid,
        req: UpdateIdentityProviderRequest,
    ) -> FederationResult<TenantIdentityProvider> {
        // Verify IdP exists and belongs to tenant
        let _existing = self.get(tenant_id, idp_id).await?;

        // If issuer URL is being changed, check uniqueness
        if let Some(ref issuer_url) = req.issuer_url {
            if TenantIdentityProvider::issuer_exists(
                &self.pool,
                tenant_id,
                issuer_url,
                Some(idp_id),
            )
            .await?
            {
                return Err(FederationError::IssuerAlreadyExists);
            }
        }

        // Encrypt new client secret if provided
        let client_secret_encrypted = match req.client_secret {
            Some(ref secret) => Some(self.encryption.encrypt(tenant_id, secret)?),
            None => None,
        };

        // Build claim mapping if provided
        let claim_mapping = req.claim_mapping.map(|c| c.to_json());

        let input = UpdateIdentityProvider {
            name: req.name,
            issuer_url: req.issuer_url.clone(),
            client_id: req.client_id,
            client_secret_encrypted,
            claim_mapping,
            scopes: req.scopes,
            sync_on_login: req.sync_on_login,
        };

        let idp = TenantIdentityProvider::update(&self.pool, tenant_id, idp_id, input).await?;

        // If issuer URL changed, re-validate
        if req.issuer_url.is_some() {
            let validation_result = self.discovery.validate_issuer(&idp.issuer_url).await?;
            let status = if validation_result {
                ValidationStatus::Valid
            } else {
                ValidationStatus::Invalid
            };
            return Ok(TenantIdentityProvider::update_validation_status(
                &self.pool, tenant_id, idp_id, status,
            )
            .await?);
        }

        tracing::info!(idp_id = %idp.id, "Updated identity provider");
        Ok(idp)
    }

    /// Delete an identity provider.
    #[instrument(skip(self))]
    pub async fn delete(&self, tenant_id: Uuid, idp_id: Uuid) -> FederationResult<()> {
        // Verify IdP exists and belongs to tenant
        let _ = self.get(tenant_id, idp_id).await?;

        // Check for linked users
        let linked_count = UserIdentityLink::count_by_idp(&self.pool, tenant_id, idp_id).await?;
        if linked_count > 0 {
            return Err(FederationError::IdpHasLinkedUsers(linked_count));
        }

        // Clean up active auth sessions for this IdP
        let sessions_deleted =
            FederatedAuthSession::delete_by_idp(&self.pool, tenant_id, idp_id).await?;
        if sessions_deleted > 0 {
            tracing::info!(
                idp_id = %idp_id,
                sessions_deleted = sessions_deleted,
                "Cleaned up active auth sessions for deleted IdP"
            );
        }

        // Delete domains first (cascade should handle this, but be explicit)
        IdentityProviderDomain::delete_by_idp(&self.pool, tenant_id, idp_id).await?;

        // Delete the identity provider
        TenantIdentityProvider::delete(&self.pool, tenant_id, idp_id).await?;

        tracing::info!(idp_id = %idp_id, "Deleted identity provider");
        Ok(())
    }

    /// Toggle identity provider enabled status.
    #[instrument(skip(self))]
    pub async fn set_enabled(
        &self,
        tenant_id: Uuid,
        idp_id: Uuid,
        is_enabled: bool,
    ) -> FederationResult<TenantIdentityProvider> {
        // Verify IdP exists and belongs to tenant
        let _ = self.get(tenant_id, idp_id).await?;

        let idp =
            TenantIdentityProvider::set_enabled(&self.pool, tenant_id, idp_id, is_enabled).await?;

        tracing::info!(idp_id = %idp_id, is_enabled = %is_enabled, "Toggled identity provider");
        Ok(idp)
    }

    /// Add a domain to an identity provider.
    #[instrument(skip(self))]
    pub async fn add_domain(
        &self,
        tenant_id: Uuid,
        idp_id: Uuid,
        domain: String,
        priority: i32,
    ) -> FederationResult<IdentityProviderDomain> {
        // Verify IdP exists and belongs to tenant
        let _ = self.get(tenant_id, idp_id).await?;

        // Validate domain format
        if !IdentityProviderDomain::validate_domain(&domain) {
            return Err(FederationError::InvalidDomain(domain));
        }

        // Check if domain already exists for this IdP
        if IdentityProviderDomain::domain_exists_for_idp(&self.pool, tenant_id, idp_id, &domain)
            .await?
        {
            return Err(FederationError::DomainAlreadyExists(domain));
        }

        let domain = IdentityProviderDomain::create(
            &self.pool,
            CreateDomain {
                tenant_id,
                identity_provider_id: idp_id,
                domain: domain.clone(),
                priority,
            },
        )
        .await?;

        tracing::info!(idp_id = %idp_id, domain = %domain.domain, "Added domain to identity provider");
        Ok(domain)
    }

    /// Remove a domain from an identity provider.
    #[instrument(skip(self))]
    pub async fn remove_domain(
        &self,
        tenant_id: Uuid,
        idp_id: Uuid,
        domain_id: Uuid,
    ) -> FederationResult<()> {
        // Verify IdP exists and belongs to tenant
        let _ = self.get(tenant_id, idp_id).await?;

        // Verify domain exists and belongs to tenant
        let domain = IdentityProviderDomain::find_by_id(&self.pool, tenant_id, domain_id)
            .await?
            .ok_or(FederationError::IdpNotFound(domain_id))?;

        // Verify domain belongs to this IdP
        if domain.identity_provider_id != idp_id {
            return Err(FederationError::IdpNotFound(domain_id));
        }

        IdentityProviderDomain::delete(&self.pool, tenant_id, domain_id).await?;

        tracing::info!(idp_id = %idp_id, domain_id = %domain_id, "Removed domain from identity provider");
        Ok(())
    }

    /// Decrypt client secret for use in auth flow.
    pub fn decrypt_client_secret(
        &self,
        tenant_id: Uuid,
        encrypted: &[u8],
    ) -> FederationResult<String> {
        self.encryption.decrypt(tenant_id, encrypted)
    }
}
