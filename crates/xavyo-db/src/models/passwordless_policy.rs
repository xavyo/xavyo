//! Passwordless authentication policy entity model.
//!
//! Per-tenant configuration controlling which passwordless methods
//! are available and their parameters.

use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

/// Enabled methods for passwordless authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnabledMethods {
    /// Passwordless authentication is completely disabled.
    Disabled,
    /// Only magic link is available.
    MagicLinkOnly,
    /// Only email OTP is available.
    OtpOnly,
    /// Both magic link and email OTP are available.
    AllMethods,
}

impl EnabledMethods {
    /// Convert to database string representation.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::MagicLinkOnly => "magic_link_only",
            Self::OtpOnly => "otp_only",
            Self::AllMethods => "all_methods",
        }
    }

    /// Parse from database string representation.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "disabled" => Some(Self::Disabled),
            "magic_link_only" => Some(Self::MagicLinkOnly),
            "otp_only" => Some(Self::OtpOnly),
            "all_methods" => Some(Self::AllMethods),
            _ => None,
        }
    }

    /// Check if magic link is enabled.
    #[must_use]
    pub fn magic_link_enabled(&self) -> bool {
        matches!(self, Self::MagicLinkOnly | Self::AllMethods)
    }

    /// Check if email OTP is enabled.
    #[must_use]
    pub fn email_otp_enabled(&self) -> bool {
        matches!(self, Self::OtpOnly | Self::AllMethods)
    }
}

/// A passwordless authentication policy record in the database.
#[derive(Debug, Clone, FromRow)]
pub struct PasswordlessPolicy {
    /// Unique identifier.
    pub id: Uuid,
    /// The tenant this policy belongs to.
    pub tenant_id: Uuid,
    /// Which methods are enabled: 'disabled', '`magic_link_only`', '`otp_only`', '`all_methods`'.
    pub enabled_methods: String,
    /// Magic link expiry in minutes.
    pub magic_link_expiry_minutes: i32,
    /// OTP expiry in minutes.
    pub otp_expiry_minutes: i32,
    /// Maximum OTP verification attempts.
    pub otp_max_attempts: i32,
    /// Whether MFA is required after passwordless authentication.
    pub require_mfa_after_passwordless: bool,
    /// When the policy was created.
    pub created_at: DateTime<Utc>,
    /// When the policy was last updated.
    pub updated_at: DateTime<Utc>,
}

impl PasswordlessPolicy {
    /// Get the parsed enabled methods.
    #[must_use]
    pub fn parsed_enabled_methods(&self) -> EnabledMethods {
        EnabledMethods::parse(&self.enabled_methods).unwrap_or(EnabledMethods::AllMethods)
    }

    /// Check if magic link is enabled for this policy.
    #[must_use]
    pub fn magic_link_enabled(&self) -> bool {
        self.parsed_enabled_methods().magic_link_enabled()
    }

    /// Check if email OTP is enabled for this policy.
    #[must_use]
    pub fn email_otp_enabled(&self) -> bool {
        self.parsed_enabled_methods().email_otp_enabled()
    }

    /// Create a default policy (used when no row exists for a tenant).
    #[must_use]
    pub fn default_for_tenant(tenant_id: Uuid) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            tenant_id,
            enabled_methods: "all_methods".to_string(),
            magic_link_expiry_minutes: 15,
            otp_expiry_minutes: 10,
            otp_max_attempts: 5,
            require_mfa_after_passwordless: false,
            created_at: now,
            updated_at: now,
        }
    }

    /// Find the policy for a tenant.
    pub async fn find_by_tenant(
        pool: &PgPool,
        tenant_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        let policy = sqlx::query_as::<_, Self>(
            r"
            SELECT id, tenant_id, enabled_methods, magic_link_expiry_minutes,
                   otp_expiry_minutes, otp_max_attempts, require_mfa_after_passwordless,
                   created_at, updated_at
            FROM passwordless_policies
            WHERE tenant_id = $1
            ",
        )
        .bind(tenant_id)
        .fetch_optional(pool)
        .await?;

        Ok(policy)
    }

    /// Get the policy for a tenant, returning defaults if no row exists.
    pub async fn get_or_default(pool: &PgPool, tenant_id: Uuid) -> Result<Self, sqlx::Error> {
        match Self::find_by_tenant(pool, tenant_id).await? {
            Some(policy) => Ok(policy),
            None => Ok(Self::default_for_tenant(tenant_id)),
        }
    }

    /// Create or update (upsert) the policy for a tenant.
    pub async fn upsert(
        pool: &PgPool,
        tenant_id: Uuid,
        enabled_methods: &str,
        magic_link_expiry_minutes: i32,
        otp_expiry_minutes: i32,
        otp_max_attempts: i32,
        require_mfa_after_passwordless: bool,
    ) -> Result<Self, sqlx::Error> {
        let policy = sqlx::query_as::<_, Self>(
            r"
            INSERT INTO passwordless_policies
                (tenant_id, enabled_methods, magic_link_expiry_minutes,
                 otp_expiry_minutes, otp_max_attempts, require_mfa_after_passwordless)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (tenant_id) DO UPDATE SET
                enabled_methods = EXCLUDED.enabled_methods,
                magic_link_expiry_minutes = EXCLUDED.magic_link_expiry_minutes,
                otp_expiry_minutes = EXCLUDED.otp_expiry_minutes,
                otp_max_attempts = EXCLUDED.otp_max_attempts,
                require_mfa_after_passwordless = EXCLUDED.require_mfa_after_passwordless,
                updated_at = NOW()
            RETURNING id, tenant_id, enabled_methods, magic_link_expiry_minutes,
                      otp_expiry_minutes, otp_max_attempts, require_mfa_after_passwordless,
                      created_at, updated_at
            ",
        )
        .bind(tenant_id)
        .bind(enabled_methods)
        .bind(magic_link_expiry_minutes)
        .bind(otp_expiry_minutes)
        .bind(otp_max_attempts)
        .bind(require_mfa_after_passwordless)
        .fetch_one(pool)
        .await?;

        Ok(policy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enabled_methods_parsing() {
        assert_eq!(
            EnabledMethods::parse("disabled"),
            Some(EnabledMethods::Disabled)
        );
        assert_eq!(
            EnabledMethods::parse("magic_link_only"),
            Some(EnabledMethods::MagicLinkOnly)
        );
        assert_eq!(
            EnabledMethods::parse("otp_only"),
            Some(EnabledMethods::OtpOnly)
        );
        assert_eq!(
            EnabledMethods::parse("all_methods"),
            Some(EnabledMethods::AllMethods)
        );
        assert_eq!(EnabledMethods::parse("invalid"), None);
    }

    #[test]
    fn test_enabled_methods_flags() {
        assert!(!EnabledMethods::Disabled.magic_link_enabled());
        assert!(!EnabledMethods::Disabled.email_otp_enabled());

        assert!(EnabledMethods::MagicLinkOnly.magic_link_enabled());
        assert!(!EnabledMethods::MagicLinkOnly.email_otp_enabled());

        assert!(!EnabledMethods::OtpOnly.magic_link_enabled());
        assert!(EnabledMethods::OtpOnly.email_otp_enabled());

        assert!(EnabledMethods::AllMethods.magic_link_enabled());
        assert!(EnabledMethods::AllMethods.email_otp_enabled());
    }

    #[test]
    fn test_default_policy() {
        let tenant_id = Uuid::new_v4();
        let policy = PasswordlessPolicy::default_for_tenant(tenant_id);

        assert_eq!(policy.tenant_id, tenant_id);
        assert_eq!(policy.enabled_methods, "all_methods");
        assert_eq!(policy.magic_link_expiry_minutes, 15);
        assert_eq!(policy.otp_expiry_minutes, 10);
        assert_eq!(policy.otp_max_attempts, 5);
        assert!(!policy.require_mfa_after_passwordless);
        assert!(policy.magic_link_enabled());
        assert!(policy.email_otp_enabled());
    }

    #[test]
    fn test_policy_methods() {
        let tenant_id = Uuid::new_v4();
        let mut policy = PasswordlessPolicy::default_for_tenant(tenant_id);

        policy.enabled_methods = "otp_only".to_string();
        assert!(!policy.magic_link_enabled());
        assert!(policy.email_otp_enabled());

        policy.enabled_methods = "magic_link_only".to_string();
        assert!(policy.magic_link_enabled());
        assert!(!policy.email_otp_enabled());

        policy.enabled_methods = "disabled".to_string();
        assert!(!policy.magic_link_enabled());
        assert!(!policy.email_otp_enabled());
    }
}
