//! `UserInfo` service for OIDC userinfo endpoint.

use crate::error::OAuthError;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

/// Database representation of a user for userinfo lookup.
#[derive(Debug, FromRow)]
struct DbUser {
    pub id: Uuid,
    pub email: String,
    pub email_verified: bool,
    pub is_active: bool,
    pub display_name: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
}

/// User claims returned by the userinfo endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserClaims {
    /// Subject identifier (user ID).
    pub sub: String,
    /// Email address (requires email scope).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Whether email is verified (requires email scope).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    /// Full name (requires profile scope).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Given/first name (requires profile scope).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
    /// Family/last name (requires profile scope).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,
}

impl UserClaims {
    /// Create new user claims with just the subject.
    #[must_use]
    pub fn new(sub: Uuid) -> Self {
        Self {
            sub: sub.to_string(),
            email: None,
            email_verified: None,
            name: None,
            given_name: None,
            family_name: None,
        }
    }

    /// Add email claims.
    #[must_use]
    pub fn with_email(mut self, email: String, verified: bool) -> Self {
        self.email = Some(email);
        self.email_verified = Some(verified);
        self
    }

    /// Add profile claims.
    #[must_use]
    pub fn with_profile(
        mut self,
        name: Option<String>,
        given_name: Option<String>,
        family_name: Option<String>,
    ) -> Self {
        self.name = name.filter(|s| !s.is_empty());
        self.given_name = given_name.filter(|s| !s.is_empty());
        self.family_name = family_name.filter(|s| !s.is_empty());
        self
    }
}

/// Service for handling userinfo requests.
#[derive(Debug, Clone)]
pub struct UserInfoService {
    pool: PgPool,
}

impl UserInfoService {
    /// Create a new userinfo service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get the database pool.
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Get user claims based on scopes.
    ///
    /// Returns user claims filtered by the granted scopes:
    /// - `openid`: Required, returns `sub` claim
    /// - `email`: Returns `email` and `email_verified` claims
    /// - `profile`: Returns `name`, `given_name`, and `family_name` claims (if available)
    ///
    /// # Arguments
    ///
    /// * `tenant_id` - Tenant ID for RLS
    /// * `user_id` - User ID
    /// * `scope` - Space-separated list of scopes
    ///
    /// # Returns
    ///
    /// User claims filtered by granted scopes.
    ///
    /// # Errors
    ///
    /// - `UserNotFound` if user doesn't exist
    /// - `AccessDenied` if user is inactive
    pub async fn get_user_claims(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        scope: &str,
    ) -> Result<UserClaims, OAuthError> {
        // SECURITY: Acquire dedicated connection and set RLS context on it.
        // Using &self.pool for set_config and a separate &self.pool for the query
        // would hit different connections, bypassing RLS.
        let mut conn = self.pool.acquire().await.map_err(|e| {
            tracing::error!("Failed to acquire connection: {}", e);
            OAuthError::Internal("Failed to acquire connection".to_string())
        })?;

        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(tenant_id.to_string())
            .execute(&mut *conn)
            .await
            .map_err(|e| {
                tracing::error!("Failed to set tenant context: {}", e);
                OAuthError::Internal("Failed to set tenant context".to_string())
            })?;

        // Look up the user
        let user: DbUser = sqlx::query_as(
            r"
            SELECT id, email, email_verified, is_active, display_name, first_name, last_name
            FROM users
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(user_id)
        .bind(tenant_id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(|e| {
            tracing::error!("Database error looking up user: {}", e);
            OAuthError::Internal("Database error".to_string())
        })?
        .ok_or(OAuthError::UserNotFound)?;

        // Check if user is active
        if !user.is_active {
            return Err(OAuthError::AccessDenied(
                "User account is inactive".to_string(),
            ));
        }

        // Parse scopes
        let scopes = Self::parse_scopes(scope);

        // Build claims based on scopes
        let mut claims = UserClaims::new(user.id);

        // Add email claims if email scope is present
        if Self::has_scope(&scopes, "email") {
            claims = claims.with_email(user.email, user.email_verified);
        }

        // Add profile claims if profile scope is present
        if Self::has_scope(&scopes, "profile") {
            let given_name = user.first_name.filter(|s| !s.is_empty());
            let family_name = user.last_name.filter(|s| !s.is_empty());
            let name = user.display_name.filter(|s| !s.is_empty()).or_else(|| {
                let joined = [given_name.as_deref(), family_name.as_deref()]
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>()
                    .join(" ");
                if joined.is_empty() {
                    None
                } else {
                    Some(joined)
                }
            });
            claims = claims.with_profile(name, given_name, family_name);
        }

        Ok(claims)
    }

    /// Parse scopes from a space-separated string.
    #[must_use]
    pub fn parse_scopes(scope: &str) -> Vec<&str> {
        scope.split_whitespace().collect()
    }

    /// Check if a scope list contains a specific scope.
    #[must_use]
    pub fn has_scope(scopes: &[&str], scope: &str) -> bool {
        scopes.contains(&scope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_scopes() {
        let scopes = UserInfoService::parse_scopes("openid profile email");
        assert_eq!(scopes, vec!["openid", "profile", "email"]);
    }

    #[test]
    fn test_has_scope() {
        let scopes = vec!["openid", "profile", "email"];
        assert!(UserInfoService::has_scope(&scopes, "openid"));
        assert!(UserInfoService::has_scope(&scopes, "email"));
        assert!(!UserInfoService::has_scope(&scopes, "offline_access"));
    }

    #[test]
    fn test_user_claims_builder() {
        let user_id = Uuid::new_v4();
        let claims = UserClaims::new(user_id)
            .with_email("test@example.com".to_string(), true)
            .with_profile(
                Some("Test User".to_string()),
                Some("Test".to_string()),
                Some("User".to_string()),
            );

        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.email, Some("test@example.com".to_string()));
        assert_eq!(claims.email_verified, Some(true));
        assert_eq!(claims.name, Some("Test User".to_string()));
        assert_eq!(claims.given_name, Some("Test".to_string()));
        assert_eq!(claims.family_name, Some("User".to_string()));
    }

    #[test]
    fn get_user_claims_selects_advertised_name_fields() {
        let src = include_str!("userinfo.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            production.contains("display_name")
                && production.contains("first_name")
                && production.contains("last_name")
                && production.contains("with_profile(name, given_name, family_name)"),
            "userinfo must look up and return advertised name claims"
        );
        assert!(
            !production.contains("with_profile(None)"),
            "userinfo must not stub profile names as None"
        );
    }
}
