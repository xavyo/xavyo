//! User provisioning service for Just-In-Time user creation and sync.

use crate::error::{FederationError, FederationResult};
use crate::services::auth_flow::IdTokenClaims;
use crate::services::ClaimsService;
use sqlx::PgPool;
use tracing::instrument;
use uuid::Uuid;
use xavyo_db::models::{
    CreateUserIdentityLink, TenantIdentityProvider, UpdateUserIdentityLink, User, UserIdentityLink,
};

/// User provisioning service.
#[derive(Clone)]
pub struct ProvisioningService {
    pool: PgPool,
    claims: ClaimsService,
}

/// Result of provisioning - user and identity link.
pub type ProvisioningResult = (User, UserIdentityLink);

impl ProvisioningService {
    /// Create a new provisioning service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            claims: ClaimsService::new(),
        }
    }

    /// Provision or sync a user based on `IdP` claims.
    #[instrument(skip(self, claims))]
    pub async fn provision_or_sync(
        &self,
        tenant_id: Uuid,
        idp_id: Uuid,
        claims: &IdTokenClaims,
    ) -> FederationResult<ProvisioningResult> {
        // Get IdP configuration for claim mapping
        let idp = TenantIdentityProvider::find_by_id_and_tenant(&self.pool, idp_id, tenant_id)
            .await?
            .ok_or(FederationError::IdpNotFound(idp_id))?;

        // Check if user is already linked
        let existing_link =
            UserIdentityLink::find_by_subject(&self.pool, tenant_id, idp_id, &claims.sub).await?;

        if let Some(link) = existing_link {
            // User exists - sync if enabled (include tenant_id for defense-in-depth)
            let user = User::find_by_id_in_tenant(&self.pool, tenant_id, link.user_id)
                .await?
                .ok_or(FederationError::UserNotFound(link.user_id))?;

            if idp.sync_on_login {
                let updated_user = self.sync_user(&idp, &user, claims).await?;
                let updated_link = self.update_link(&link, claims).await?;

                tracing::info!(
                    tenant_id = %tenant_id,
                    user_id = %updated_user.id,
                    subject = %claims.sub,
                    "Synced existing user from IdP"
                );

                Ok((updated_user, updated_link))
            } else {
                // Just update last login
                let updated_link = self.update_link(&link, claims).await?;

                tracing::info!(
                    tenant_id = %tenant_id,
                    user_id = %user.id,
                    subject = %claims.sub,
                    "User logged in via IdP (sync disabled)"
                );

                Ok((user, updated_link))
            }
        } else {
            // New user - provision
            let (user, link) = self
                .provision_new_user(tenant_id, idp_id, &idp, claims)
                .await?;

            tracing::info!(
                tenant_id = %tenant_id,
                user_id = %user.id,
                subject = %claims.sub,
                "Provisioned new user from IdP"
            );

            Ok((user, link))
        }
    }

    /// Provision a new user from `IdP` claims.
    async fn provision_new_user(
        &self,
        tenant_id: Uuid,
        idp_id: Uuid,
        idp: &TenantIdentityProvider,
        claims: &IdTokenClaims,
    ) -> FederationResult<ProvisioningResult> {
        // Extract mapped claims
        let mapped = self.claims.map_claims(idp, claims)?;

        // Get email (required)
        let email = mapped
            .get("email")
            .and_then(|v| v.as_str())
            .or(claims.email.as_deref())
            .ok_or_else(|| {
                FederationError::ProvisioningFailed("Email claim is required".to_string())
            })?;

        // Get display name (optional)
        let display_name = mapped
            .get("display_name")
            .and_then(|v| v.as_str())
            .or(claims.name.as_deref())
            .map(String::from);

        // Check if user with this email already exists
        let existing_user = User::find_by_email(&self.pool, tenant_id, email).await?;

        let user = if let Some(user) = existing_user {
            // Link to existing user
            tracing::info!(
                tenant_id = %tenant_id,
                user_id = %user.id,
                email = %email,
                "Linking IdP to existing user"
            );
            user
        } else {
            // Create new user
            let new_user =
                User::create_federated(&self.pool, tenant_id, email.to_string(), display_name)
                    .await?;

            tracing::info!(
                tenant_id = %tenant_id,
                user_id = %new_user.id,
                email = %email,
                "Created new federated user"
            );

            new_user
        };

        // Create identity link
        let link = UserIdentityLink::create(
            &self.pool,
            CreateUserIdentityLink {
                tenant_id,
                user_id: user.id,
                identity_provider_id: idp_id,
                subject: claims.sub.clone(),
                issuer: claims.iss.clone(),
                raw_claims: Some(serde_json::to_value(claims).unwrap_or_default()),
            },
        )
        .await?;

        Ok((user, link))
    }

    /// Sync existing user with new claims.
    async fn sync_user(
        &self,
        idp: &TenantIdentityProvider,
        user: &User,
        claims: &IdTokenClaims,
    ) -> FederationResult<User> {
        // Extract mapped claims
        let mapped = self.claims.map_claims(idp, claims)?;

        // Get display name if different
        let new_display_name = mapped
            .get("display_name")
            .and_then(|v| v.as_str())
            .or(claims.name.as_deref());

        // Only update if there's a change
        if let Some(name) = new_display_name {
            if user.display_name.as_deref() != Some(name) {
                let updated = User::update_display_name(
                    &self.pool,
                    idp.tenant_id,
                    user.id,
                    Some(name.to_string()),
                )
                .await?
                .ok_or_else(|| FederationError::UserNotFound(user.id))?;
                return Ok(updated);
            }
        }

        Ok(user.clone())
    }

    /// Update identity link with latest login info.
    async fn update_link(
        &self,
        link: &UserIdentityLink,
        claims: &IdTokenClaims,
    ) -> FederationResult<UserIdentityLink> {
        let updated = UserIdentityLink::update(
            &self.pool,
            link.id,
            UpdateUserIdentityLink {
                raw_claims: Some(serde_json::to_value(claims).unwrap_or_default()),
            },
        )
        .await?;

        Ok(updated)
    }

    /// Unlink a user from an `IdP`.
    #[instrument(skip(self))]
    pub async fn unlink(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        idp_id: Uuid,
    ) -> FederationResult<()> {
        // Find and delete the link
        let link = UserIdentityLink::find_by_user_and_idp(&self.pool, tenant_id, user_id, idp_id)
            .await?
            .ok_or(FederationError::LinkNotFound)?;

        UserIdentityLink::delete(&self.pool, link.id).await?;

        tracing::info!(
            tenant_id = %tenant_id,
            user_id = %user_id,
            idp_id = %idp_id,
            "Unlinked user from IdP"
        );

        Ok(())
    }

    /// Get all identity links for a user.
    pub async fn get_user_links(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> FederationResult<Vec<UserIdentityLink>> {
        let links = UserIdentityLink::list_by_user(&self.pool, tenant_id, user_id).await?;
        Ok(links)
    }
}
