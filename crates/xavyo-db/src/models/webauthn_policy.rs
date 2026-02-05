//! `WebAuthn` policy model.
//!
//! Stores tenant-level `WebAuthn` configuration and policies.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgExecutor};
use uuid::Uuid;

/// User verification requirement for `WebAuthn` ceremonies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum UserVerification {
    /// Do not require user verification (basic security).
    Discouraged,
    /// Request user verification if available (recommended default).
    #[default]
    Preferred,
    /// Require user verification (highest security).
    Required,
}

impl std::fmt::Display for UserVerification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Discouraged => write!(f, "discouraged"),
            Self::Preferred => write!(f, "preferred"),
            Self::Required => write!(f, "required"),
        }
    }
}

impl std::str::FromStr for UserVerification {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "discouraged" => Ok(Self::Discouraged),
            "preferred" => Ok(Self::Preferred),
            "required" => Ok(Self::Required),
            _ => Err(format!("Invalid user verification: {s}")),
        }
    }
}

/// Default maximum credentials per user.
pub const DEFAULT_MAX_CREDENTIALS: i32 = 10;

/// Tenant-level `WebAuthn` policy configuration.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct TenantWebAuthnPolicy {
    /// The tenant this policy applies to.
    pub tenant_id: Uuid,

    /// Whether `WebAuthn` registration is enabled for this tenant.
    pub webauthn_enabled: bool,

    /// Whether attestation verification is required.
    pub require_attestation: bool,

    /// User verification requirement (discouraged, preferred, required).
    pub user_verification: String,

    /// Allowed authenticator types (NULL = all, or array of: platform, cross-platform).
    pub allowed_authenticator_types: Option<Vec<String>>,

    /// Maximum number of credentials per user (1-20).
    pub max_credentials_per_user: i32,

    /// When this policy was created.
    pub created_at: DateTime<Utc>,

    /// When this policy was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Data for creating or updating a `WebAuthn` policy.
#[derive(Debug, Clone, Deserialize)]
pub struct UpsertWebAuthnPolicy {
    pub webauthn_enabled: Option<bool>,
    pub require_attestation: Option<bool>,
    pub user_verification: Option<String>,
    pub allowed_authenticator_types: Option<Vec<String>>,
    pub max_credentials_per_user: Option<i32>,
}

impl TenantWebAuthnPolicy {
    /// Get the user verification requirement as an enum.
    #[must_use]
    pub fn user_verification_requirement(&self) -> UserVerification {
        self.user_verification.parse().unwrap_or_default()
    }

    /// Check if a specific authenticator type is allowed.
    #[must_use]
    pub fn is_authenticator_type_allowed(&self, auth_type: &str) -> bool {
        match &self.allowed_authenticator_types {
            None => true, // All types allowed
            Some(types) => types.iter().any(|t| t.eq_ignore_ascii_case(auth_type)),
        }
    }

    /// Get the policy for a tenant, creating a default one if it doesn't exist.
    pub async fn get_or_create<'e, E>(executor: E, tenant_id: Uuid) -> Result<Self, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as(
            r"
            INSERT INTO tenant_webauthn_policies (tenant_id)
            VALUES ($1)
            ON CONFLICT (tenant_id) DO UPDATE SET tenant_id = EXCLUDED.tenant_id
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .fetch_one(executor)
        .await
    }

    /// Get the policy for a tenant if it exists.
    pub async fn get<'e, E>(executor: E, tenant_id: Uuid) -> Result<Option<Self>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as("SELECT * FROM tenant_webauthn_policies WHERE tenant_id = $1")
            .bind(tenant_id)
            .fetch_optional(executor)
            .await
    }

    /// Update the policy for a tenant (creates default if not exists).
    pub async fn update<'e, E>(
        executor: E,
        tenant_id: Uuid,
        data: UpsertWebAuthnPolicy,
    ) -> Result<Self, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        // Use upsert pattern to create if not exists and update
        sqlx::query_as(
            r"
            INSERT INTO tenant_webauthn_policies (
                tenant_id, webauthn_enabled, require_attestation, user_verification,
                allowed_authenticator_types, max_credentials_per_user
            )
            VALUES ($1, COALESCE($2, true), COALESCE($3, false), COALESCE($4, 'preferred'),
                    $5, COALESCE($6, 10))
            ON CONFLICT (tenant_id) DO UPDATE SET
                webauthn_enabled = COALESCE($2, tenant_webauthn_policies.webauthn_enabled),
                require_attestation = COALESCE($3, tenant_webauthn_policies.require_attestation),
                user_verification = COALESCE($4, tenant_webauthn_policies.user_verification),
                allowed_authenticator_types = COALESCE($5, tenant_webauthn_policies.allowed_authenticator_types),
                max_credentials_per_user = COALESCE($6, tenant_webauthn_policies.max_credentials_per_user),
                updated_at = NOW()
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(data.webauthn_enabled)
        .bind(data.require_attestation)
        .bind(&data.user_verification)
        .bind(&data.allowed_authenticator_types)
        .bind(data.max_credentials_per_user)
        .fetch_one(executor)
        .await
    }

    /// Check if `WebAuthn` is enabled for a tenant.
    pub async fn is_enabled<'e, E>(executor: E, tenant_id: Uuid) -> Result<bool, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        let result: Option<(bool,)> = sqlx::query_as(
            "SELECT webauthn_enabled FROM tenant_webauthn_policies WHERE tenant_id = $1",
        )
        .bind(tenant_id)
        .fetch_optional(executor)
        .await?;

        // Default to enabled if no policy exists
        Ok(result.is_none_or(|r| r.0))
    }

    /// Delete the policy for a tenant (resets to defaults).
    pub async fn delete<'e, E>(executor: E, tenant_id: Uuid) -> Result<bool, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        let result = sqlx::query("DELETE FROM tenant_webauthn_policies WHERE tenant_id = $1")
            .bind(tenant_id)
            .execute(executor)
            .await?;
        Ok(result.rows_affected() > 0)
    }
}

/// Default policy values for display/documentation.
impl Default for TenantWebAuthnPolicy {
    fn default() -> Self {
        Self {
            tenant_id: Uuid::nil(),
            webauthn_enabled: true,
            require_attestation: false,
            user_verification: "preferred".to_string(),
            allowed_authenticator_types: None,
            max_credentials_per_user: DEFAULT_MAX_CREDENTIALS,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_verification_display() {
        assert_eq!(UserVerification::Discouraged.to_string(), "discouraged");
        assert_eq!(UserVerification::Preferred.to_string(), "preferred");
        assert_eq!(UserVerification::Required.to_string(), "required");
    }

    #[test]
    fn test_user_verification_parse() {
        assert_eq!(
            "discouraged".parse::<UserVerification>().unwrap(),
            UserVerification::Discouraged
        );
        assert_eq!(
            "PREFERRED".parse::<UserVerification>().unwrap(),
            UserVerification::Preferred
        );
        assert_eq!(
            "Required".parse::<UserVerification>().unwrap(),
            UserVerification::Required
        );
        assert!("invalid".parse::<UserVerification>().is_err());
    }

    #[test]
    fn test_is_authenticator_type_allowed() {
        // All allowed when None
        let policy = TenantWebAuthnPolicy::default();
        assert!(policy.is_authenticator_type_allowed("platform"));
        assert!(policy.is_authenticator_type_allowed("cross-platform"));

        // Restricted to platform only
        let policy_platform = TenantWebAuthnPolicy {
            allowed_authenticator_types: Some(vec!["platform".to_string()]),
            ..Default::default()
        };
        assert!(policy_platform.is_authenticator_type_allowed("platform"));
        assert!(!policy_platform.is_authenticator_type_allowed("cross-platform"));
    }

    #[test]
    fn test_user_verification_requirement() {
        let policy = TenantWebAuthnPolicy {
            user_verification: "required".to_string(),
            ..Default::default()
        };
        assert_eq!(
            policy.user_verification_requirement(),
            UserVerification::Required
        );
    }
}
