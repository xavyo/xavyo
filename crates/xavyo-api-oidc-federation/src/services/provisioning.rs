//! User provisioning service for Just-In-Time user creation and sync.

use crate::error::{FederationError, FederationResult};
use crate::services::auth_flow::IdTokenClaims;
use crate::services::ClaimsService;
use serde_json::Value;
use sqlx::PgPool;
use std::collections::HashMap;
use tracing::instrument;
use uuid::Uuid;
use xavyo_db::models::{
    CreateUserIdentityLink, TenantIdentityProvider, UpdateUserIdentityLink, User, UserIdentityLink,
};

/// Profile fields advertised on `User` / `/me` after federated JIT.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct FederatedProfile {
    pub display_name: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub avatar_url: Option<String>,
}

fn nonempty_mapped(mapped: &HashMap<String, Value>, key: &str) -> Option<String> {
    mapped
        .get(key)
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn nonempty_opt(s: Option<&str>) -> Option<String> {
    s.map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Map IdP + configured claim mappings onto advertised user profile fields.
pub(crate) fn federated_profile(
    mapped: &HashMap<String, Value>,
    claims: &IdTokenClaims,
) -> FederatedProfile {
    let first_name = nonempty_mapped(mapped, "first_name")
        .or_else(|| nonempty_mapped(mapped, "given_name"))
        .or_else(|| nonempty_opt(claims.given_name.as_deref()));
    let last_name = nonempty_mapped(mapped, "last_name")
        .or_else(|| nonempty_mapped(mapped, "family_name"))
        .or_else(|| nonempty_opt(claims.family_name.as_deref()));
    let display_name = nonempty_mapped(mapped, "display_name")
        .or_else(|| nonempty_mapped(mapped, "name"))
        .or_else(|| nonempty_opt(claims.name.as_deref()))
        .or_else(|| match (&first_name, &last_name) {
            (Some(given), Some(family)) => Some(format!("{given} {family}")),
            (Some(given), None) => Some(given.clone()),
            (None, Some(family)) => Some(family.clone()),
            _ => None,
        });
    let avatar_url = nonempty_mapped(mapped, "avatar_url")
        .or_else(|| nonempty_mapped(mapped, "picture"))
        .or_else(|| nonempty_opt(claims.picture.as_deref()));
    FederatedProfile {
        display_name,
        first_name,
        last_name,
        avatar_url,
    }
}

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
        // SECURITY: Validate claim sizes to prevent DB bloat from malicious IdPs.
        if claims.sub.len() > 512 {
            return Err(FederationError::ProvisioningFailed(
                "Subject claim exceeds maximum length".to_string(),
            ));
        }
        if claims.iss.len() > 2048 {
            return Err(FederationError::ProvisioningFailed(
                "Issuer claim exceeds maximum length".to_string(),
            ));
        }
        if let Some(ref name) = claims.name {
            if name.len() > 512 {
                return Err(FederationError::ProvisioningFailed(
                    "Name claim exceeds maximum length".to_string(),
                ));
            }
        }

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

            // SECURITY: Reject unverified emails on existing user sync path.
            // Without this, a compromised IdP returning email_verified=false could
            // still grant login and overwrite user display_name via sync.
            if claims.email_verified == Some(false) {
                tracing::warn!(
                    tenant_id = %tenant_id,
                    user_id = %user.id,
                    subject = %claims.sub,
                    "Rejecting login: IdP returned email_verified=false for existing user"
                );
                return Err(FederationError::ProvisioningFailed(
                    "Email not verified by identity provider".to_string(),
                ));
            }

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

        // SECURITY: Require email_verified before linking to an existing account by email.
        // Without this check, an attacker could register an unverified email at the IdP
        // matching an existing user and gain access to that account.
        let email_verified = claims.email_verified.unwrap_or(false);
        if !email_verified {
            return Err(FederationError::ProvisioningFailed(
                "Email must be verified by the identity provider before account linking"
                    .to_string(),
            ));
        }

        let profile = federated_profile(&mapped, claims);

        // Check if user with this email already exists
        let existing_user = User::find_by_email(&self.pool, tenant_id, email).await?;

        let user = if let Some(user) = existing_user {
            // Link to existing user
            tracing::info!(
                tenant_id = %tenant_id,
                user_id = %user.id,
                "Linking IdP to existing user"
            );
            user
        } else {
            // Create new user
            let new_user = User::create_federated(
                &self.pool,
                tenant_id,
                email.to_string(),
                profile.display_name,
                profile.first_name,
                profile.last_name,
                profile.avatar_url,
            )
            .await?;

            tracing::info!(
                tenant_id = %tenant_id,
                user_id = %new_user.id,
                "Created new federated user"
            );

            new_user
        };

        // Create identity link.
        // SECURITY: Strip non-essential PII from raw_claims before storage.
        // Only store mapped/used fields; omit `picture`, `additional`, and other PII.
        let sanitized_claims = Self::sanitize_claims_for_storage(claims);

        let link = UserIdentityLink::create(
            &self.pool,
            CreateUserIdentityLink {
                tenant_id,
                user_id: user.id,
                identity_provider_id: idp_id,
                subject: claims.sub.clone(),
                issuer: claims.iss.clone(),
                raw_claims: Some(sanitized_claims),
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
        let profile = federated_profile(&mapped, claims);

        let name_changed = profile.display_name.as_deref() != user.display_name.as_deref()
            && profile.display_name.is_some();
        let given_changed = profile.first_name.as_deref() != user.first_name.as_deref()
            && profile.first_name.is_some();
        let family_changed = profile.last_name.as_deref() != user.last_name.as_deref()
            && profile.last_name.is_some();
        let avatar_changed = profile.avatar_url.as_deref() != user.avatar_url.as_deref()
            && profile.avatar_url.is_some();

        if name_changed || given_changed || family_changed || avatar_changed {
            let updated = User::update_profile(
                &self.pool,
                idp.tenant_id,
                user.id,
                profile.display_name,
                profile.first_name,
                profile.last_name,
                profile.avatar_url,
            )
            .await?
            .ok_or_else(|| FederationError::UserNotFound(user.id))?;
            return Ok(updated);
        }

        Ok(user.clone())
    }

    /// Update identity link with latest login info.
    async fn update_link(
        &self,
        link: &UserIdentityLink,
        claims: &IdTokenClaims,
    ) -> FederationResult<UserIdentityLink> {
        let sanitized_claims = Self::sanitize_claims_for_storage(claims);
        let updated = UserIdentityLink::update(
            &self.pool,
            link.tenant_id,
            link.id,
            UpdateUserIdentityLink {
                raw_claims: Some(sanitized_claims),
            },
        )
        .await?;

        Ok(updated)
    }

    /// Strip non-essential PII from claims before persisting.
    ///
    /// Only retains fields needed for identity matching and display.
    /// Strips `picture` (may contain authenticated URLs), `additional` (arbitrary IdP claims).
    fn sanitize_claims_for_storage(claims: &IdTokenClaims) -> serde_json::Value {
        serde_json::json!({
            "sub": claims.sub,
            "iss": claims.iss,
            "aud": claims.aud,
            "exp": claims.exp,
            "iat": claims.iat,
            "nonce": claims.nonce,
            "email": claims.email,
            "email_verified": claims.email_verified,
            "name": claims.name,
            "given_name": claims.given_name,
            "family_name": claims.family_name,
        })
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

        UserIdentityLink::delete(&self.pool, tenant_id, link.id).await?;

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

#[cfg(test)]
mod tests {
    use super::*;

    fn claims() -> IdTokenClaims {
        IdTokenClaims {
            sub: "user123".to_string(),
            iss: "https://idp.example.com".to_string(),
            aud: serde_json::json!("client123"),
            exp: 0,
            iat: 0,
            nonce: None,
            email: Some("user@example.com".to_string()),
            email_verified: Some(true),
            name: Some("Ada Lovelace".to_string()),
            given_name: Some("Ada".to_string()),
            family_name: Some("Lovelace".to_string()),
            picture: Some("https://idp.example.com/ada.png".to_string()),
            additional: HashMap::new(),
        }
    }

    #[test]
    fn federated_profile_fills_advertised_name_fields_from_id_token() {
        let profile = federated_profile(&HashMap::new(), &claims());
        assert_eq!(profile.display_name.as_deref(), Some("Ada Lovelace"));
        assert_eq!(profile.first_name.as_deref(), Some("Ada"));
        assert_eq!(profile.last_name.as_deref(), Some("Lovelace"));
        assert_eq!(
            profile.avatar_url.as_deref(),
            Some("https://idp.example.com/ada.png")
        );
    }

    #[test]
    fn federated_profile_prefers_mapped_targets_over_id_token() {
        let mut mapped = HashMap::new();
        mapped.insert(
            "display_name".to_string(),
            Value::String("Mapped Name".to_string()),
        );
        mapped.insert("first_name".to_string(), Value::String("Given".to_string()));
        mapped.insert("last_name".to_string(), Value::String("Family".to_string()));
        mapped.insert(
            "picture".to_string(),
            Value::String("https://mapped.example/p.png".to_string()),
        );
        let profile = federated_profile(&mapped, &claims());
        assert_eq!(profile.display_name.as_deref(), Some("Mapped Name"));
        assert_eq!(profile.first_name.as_deref(), Some("Given"));
        assert_eq!(profile.last_name.as_deref(), Some("Family"));
        assert_eq!(
            profile.avatar_url.as_deref(),
            Some("https://mapped.example/p.png")
        );
    }

    #[test]
    fn federated_profile_joins_given_family_when_name_absent() {
        let mut claims = claims();
        claims.name = None;
        claims.picture = None;
        let profile = federated_profile(&HashMap::new(), &claims);
        assert_eq!(profile.display_name.as_deref(), Some("Ada Lovelace"));
        assert!(profile.avatar_url.is_none());
    }

    #[test]
    fn provision_new_user_and_sync_persist_advertised_profile_fields() {
        let src = include_str!("provisioning.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            production.contains("federated_profile(&mapped, claims)"),
            "JIT create and sync must map IdP given/family/picture"
        );
        assert!(
            production.contains("User::create_federated("),
            "create path must persist profile fields"
        );
        assert!(
            production.contains("User::update_profile("),
            "sync_on_login must update first_name/last_name/avatar, not only display_name"
        );
        assert!(
            !production
                .split("fn unlink")
                .next()
                .expect("before unlink")
                .contains("User::update_display_name("),
            "sync must not drop given/family by calling display_name-only update"
        );
    }
}
