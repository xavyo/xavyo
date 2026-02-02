//! JWT claims structure with standard and custom claims.
//!
//! Provides the `JwtClaims` struct containing both RFC 7519 standard claims
//! and Xavyo-specific custom claims (tenant_id, roles).

use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use xavyo_core::TenantId;

/// JWT claims containing standard and custom claims.
///
/// # Standard Claims (RFC 7519)
///
/// - `sub`: Subject (typically user ID)
/// - `iss`: Issuer (who created the token)
/// - `aud`: Audience (intended recipients)
/// - `exp`: Expiration time (Unix timestamp)
/// - `iat`: Issued at (Unix timestamp)
/// - `jti`: JWT ID (unique identifier)
///
/// # Custom Claims (Xavyo-specific)
///
/// - `tid`: Tenant ID (for multi-tenant isolation)
/// - `roles`: User roles for authorization
///
/// # Example
///
/// ```rust
/// use xavyo_auth::JwtClaims;
/// use xavyo_core::TenantId;
///
/// let claims = JwtClaims::builder()
///     .subject("user-123")
///     .issuer("xavyo")
///     .audience(vec!["xavyo-api"])
///     .tenant_id(TenantId::new())
///     .roles(vec!["admin", "user"])
///     .expires_in_secs(3600)
///     .build();
///
/// assert_eq!(claims.sub, "user-123");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JwtClaims {
    /// Subject - typically the user ID.
    pub sub: String,

    /// Issuer - who created the token.
    pub iss: String,

    /// Audience - intended recipients.
    #[serde(default)]
    pub aud: Vec<String>,

    /// Expiration time as Unix timestamp.
    pub exp: i64,

    /// Issued at as Unix timestamp.
    pub iat: i64,

    /// JWT ID - unique identifier for this token.
    pub jti: String,

    /// Tenant ID for multi-tenant isolation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tid: Option<Uuid>,

    /// User roles for authorization.
    #[serde(default)]
    pub roles: Vec<String>,

    /// Token purpose (e.g., "mfa_verification" for partial tokens).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,

    /// User email address (optional, included in user tokens).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
}

impl JwtClaims {
    /// Create a new builder for constructing JWT claims.
    #[must_use]
    pub fn builder() -> JwtClaimsBuilder {
        JwtClaimsBuilder::default()
    }

    /// Check if the token is expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        Utc::now().timestamp() > self.exp
    }

    /// Get the tenant ID if present.
    #[must_use]
    pub fn tenant_id(&self) -> Option<TenantId> {
        self.tid.map(TenantId::from_uuid)
    }

    /// Check if the claims contain a specific role.
    #[must_use]
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }

    /// Check if the claims contain any of the specified roles.
    #[must_use]
    pub fn has_any_role(&self, roles: &[&str]) -> bool {
        roles.iter().any(|r| self.has_role(r))
    }
}

/// Builder for constructing JWT claims.
#[derive(Debug, Default)]
pub struct JwtClaimsBuilder {
    sub: Option<String>,
    iss: Option<String>,
    aud: Vec<String>,
    exp: Option<i64>,
    iat: Option<i64>,
    jti: Option<String>,
    tid: Option<Uuid>,
    roles: Vec<String>,
    purpose: Option<String>,
    email: Option<String>,
}

impl JwtClaimsBuilder {
    /// Set the subject (user ID).
    #[must_use]
    pub fn subject(mut self, sub: impl Into<String>) -> Self {
        self.sub = Some(sub.into());
        self
    }

    /// Set the issuer.
    #[must_use]
    pub fn issuer(mut self, iss: impl Into<String>) -> Self {
        self.iss = Some(iss.into());
        self
    }

    /// Set the audience.
    #[must_use]
    pub fn audience(mut self, aud: Vec<impl Into<String>>) -> Self {
        self.aud = aud.into_iter().map(Into::into).collect();
        self
    }

    /// Set expiration time as Unix timestamp.
    #[must_use]
    pub fn expiration(mut self, exp: i64) -> Self {
        self.exp = Some(exp);
        self
    }

    /// Set expiration time as seconds from now.
    #[must_use]
    pub fn expires_in_secs(mut self, secs: i64) -> Self {
        self.exp = Some(Utc::now().timestamp() + secs);
        self
    }

    /// Set expiration time using a Duration.
    #[must_use]
    pub fn expires_in(mut self, duration: Duration) -> Self {
        self.exp = Some((Utc::now() + duration).timestamp());
        self
    }

    /// Set the issued at time.
    #[must_use]
    pub fn issued_at(mut self, iat: i64) -> Self {
        self.iat = Some(iat);
        self
    }

    /// Set the JWT ID.
    #[must_use]
    pub fn jwt_id(mut self, jti: impl Into<String>) -> Self {
        self.jti = Some(jti.into());
        self
    }

    /// Set the tenant ID.
    #[must_use]
    pub fn tenant_id(mut self, tid: TenantId) -> Self {
        self.tid = Some(*tid.as_uuid());
        self
    }

    /// Set the tenant ID from a UUID.
    #[must_use]
    pub fn tenant_uuid(mut self, tid: Uuid) -> Self {
        self.tid = Some(tid);
        self
    }

    /// Set the roles.
    #[must_use]
    pub fn roles(mut self, roles: Vec<impl Into<String>>) -> Self {
        self.roles = roles.into_iter().map(Into::into).collect();
        self
    }

    /// Add a single role.
    #[must_use]
    pub fn add_role(mut self, role: impl Into<String>) -> Self {
        self.roles.push(role.into());
        self
    }

    /// Set the token purpose (e.g., "mfa_verification").
    #[must_use]
    pub fn purpose(mut self, purpose: impl Into<String>) -> Self {
        self.purpose = Some(purpose.into());
        self
    }

    /// Set the user's email address.
    #[must_use]
    pub fn email(mut self, email: impl Into<String>) -> Self {
        self.email = Some(email.into());
        self
    }

    /// Build the JWT claims.
    ///
    /// # Defaults
    ///
    /// - `sub`: Empty string if not set
    /// - `iss`: "xavyo" if not set
    /// - `aud`: Empty vec if not set
    /// - `exp`: 1 hour from now if not set
    /// - `iat`: Current time if not set
    /// - `jti`: New UUID v4 if not set
    #[must_use]
    pub fn build(self) -> JwtClaims {
        let now = Utc::now().timestamp();

        JwtClaims {
            sub: self.sub.unwrap_or_default(),
            iss: self.iss.unwrap_or_else(|| "xavyo".to_string()),
            aud: self.aud,
            exp: self.exp.unwrap_or(now + 3600), // Default: 1 hour
            iat: self.iat.unwrap_or(now),
            jti: self.jti.unwrap_or_else(|| Uuid::new_v4().to_string()),
            tid: self.tid,
            roles: self.roles,
            purpose: self.purpose,
            email: self.email,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_claims_builder_basic() {
        let claims = JwtClaims::builder()
            .subject("user-123")
            .issuer("test-issuer")
            .build();

        assert_eq!(claims.sub, "user-123");
        assert_eq!(claims.iss, "test-issuer");
        assert!(!claims.jti.is_empty());
    }

    #[test]
    fn test_claims_builder_with_tenant() {
        let tenant_id = TenantId::new();
        let claims = JwtClaims::builder()
            .subject("user-123")
            .tenant_id(tenant_id)
            .build();

        assert_eq!(claims.tenant_id(), Some(tenant_id));
    }

    #[test]
    fn test_claims_builder_with_roles() {
        let claims = JwtClaims::builder()
            .subject("user-123")
            .roles(vec!["admin", "user"])
            .build();

        assert!(claims.has_role("admin"));
        assert!(claims.has_role("user"));
        assert!(!claims.has_role("superadmin"));
    }

    #[test]
    fn test_claims_has_any_role() {
        let claims = JwtClaims::builder()
            .subject("user-123")
            .roles(vec!["admin"])
            .build();

        assert!(claims.has_any_role(&["admin", "user"]));
        assert!(!claims.has_any_role(&["superadmin", "moderator"]));
    }

    #[test]
    fn test_claims_expiration() {
        // Token expiring in 1 hour
        let claims = JwtClaims::builder()
            .subject("user-123")
            .expires_in_secs(3600)
            .build();

        assert!(!claims.is_expired());

        // Token that expired 1 hour ago
        let claims = JwtClaims::builder()
            .subject("user-123")
            .expiration(Utc::now().timestamp() - 3600)
            .build();

        assert!(claims.is_expired());
    }

    #[test]
    fn test_claims_serialization() {
        let claims = JwtClaims::builder()
            .subject("user-123")
            .issuer("xavyo")
            .audience(vec!["xavyo-api"])
            .roles(vec!["admin"])
            .build();

        let json = serde_json::to_string(&claims).unwrap();
        let deserialized: JwtClaims = serde_json::from_str(&json).unwrap();

        assert_eq!(claims.sub, deserialized.sub);
        assert_eq!(claims.iss, deserialized.iss);
        assert_eq!(claims.roles, deserialized.roles);
    }

    #[test]
    fn test_claims_without_tenant_serialization() {
        let claims = JwtClaims::builder().subject("user-123").build();

        let json = serde_json::to_string(&claims).unwrap();

        // tid should not be present in JSON when None
        assert!(!json.contains("tid"));
    }

    #[test]
    fn test_claims_add_role() {
        let claims = JwtClaims::builder()
            .subject("user-123")
            .add_role("admin")
            .add_role("user")
            .build();

        assert_eq!(claims.roles.len(), 2);
        assert!(claims.has_role("admin"));
        assert!(claims.has_role("user"));
    }
}
