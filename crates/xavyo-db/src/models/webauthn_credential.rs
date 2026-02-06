//! `WebAuthn` credential model.
//!
//! Stores registered WebAuthn/FIDO2 credentials for MFA authentication.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgExecutor};
use uuid::Uuid;

/// Authenticator type for `WebAuthn` credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "varchar", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum AuthenticatorType {
    /// Platform authenticator (Touch ID, Windows Hello, Face ID).
    Platform,
    /// Cross-platform authenticator (`YubiKey`, security keys).
    #[serde(rename = "cross-platform")]
    #[sqlx(rename = "cross-platform")]
    CrossPlatform,
}

impl std::fmt::Display for AuthenticatorType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Platform => write!(f, "platform"),
            Self::CrossPlatform => write!(f, "cross-platform"),
        }
    }
}

impl std::str::FromStr for AuthenticatorType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "platform" => Ok(Self::Platform),
            "cross-platform" | "crossplatform" => Ok(Self::CrossPlatform),
            _ => Err(format!("Invalid authenticator type: {s}")),
        }
    }
}

/// A user's `WebAuthn` credential for MFA authentication.
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct UserWebAuthnCredential {
    /// Unique identifier for this credential record.
    pub id: Uuid,

    /// The user this credential belongs to.
    pub user_id: Uuid,

    /// The tenant this user belongs to.
    pub tenant_id: Uuid,

    /// Authenticator-generated credential ID (raw bytes).
    #[serde(skip_serializing)]
    pub credential_id: Vec<u8>,

    /// COSE-encoded public key.
    #[serde(skip_serializing)]
    pub public_key: Vec<u8>,

    /// Counter for clone detection.
    pub sign_count: i64,

    /// Authenticator Attestation GUID (16 bytes, optional).
    #[serde(skip_serializing)]
    pub aaguid: Option<Vec<u8>>,

    /// User-assigned friendly name for this credential.
    pub name: String,

    /// Type of authenticator (platform or cross-platform).
    pub authenticator_type: String,

    /// Supported transports (usb, nfc, ble, internal, hybrid).
    pub transports: Option<Vec<String>>,

    /// Whether credential supports backup (passkey sync).
    pub backup_eligible: bool,

    /// Whether credential is currently backed up.
    pub backup_state: bool,

    /// Whether this credential is active.
    pub is_enabled: bool,

    /// When this credential was last used for authentication.
    pub last_used_at: Option<DateTime<Utc>>,

    /// When this credential was registered.
    pub created_at: DateTime<Utc>,

    /// When this credential was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Data required to create a new `WebAuthn` credential.
#[derive(Debug)]
pub struct CreateWebAuthnCredential {
    pub user_id: Uuid,
    pub tenant_id: Uuid,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub sign_count: i64,
    pub aaguid: Option<Vec<u8>>,
    pub name: String,
    pub authenticator_type: String,
    pub transports: Option<Vec<String>>,
    pub backup_eligible: bool,
    pub backup_state: bool,
}

/// Credential information returned to clients (without sensitive data).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CredentialInfo {
    pub id: Uuid,
    pub name: String,
    pub authenticator_type: String,
    pub transports: Option<Vec<String>>,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub last_used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl From<UserWebAuthnCredential> for CredentialInfo {
    fn from(cred: UserWebAuthnCredential) -> Self {
        Self {
            id: cred.id,
            name: cred.name,
            authenticator_type: cred.authenticator_type,
            transports: cred.transports,
            backup_eligible: cred.backup_eligible,
            backup_state: cred.backup_state,
            last_used_at: cred.last_used_at,
            created_at: cred.created_at,
        }
    }
}

impl UserWebAuthnCredential {
    /// Create a new `WebAuthn` credential.
    pub async fn create<'e, E>(
        executor: E,
        data: CreateWebAuthnCredential,
    ) -> Result<Self, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as(
            r"
            INSERT INTO user_webauthn_credentials (
                user_id, tenant_id, credential_id, public_key, sign_count,
                aaguid, name, authenticator_type, transports, backup_eligible, backup_state
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            RETURNING *
            ",
        )
        .bind(data.user_id)
        .bind(data.tenant_id)
        .bind(&data.credential_id)
        .bind(&data.public_key)
        .bind(data.sign_count)
        .bind(&data.aaguid)
        .bind(&data.name)
        .bind(&data.authenticator_type)
        .bind(&data.transports)
        .bind(data.backup_eligible)
        .bind(data.backup_state)
        .fetch_one(executor)
        .await
    }

    /// Find a credential by its ID.
    ///
    /// **SECURITY WARNING**: This method does NOT filter by `tenant_id`.
    /// Use `find_by_id_and_tenant()` for tenant-isolated queries.
    #[deprecated(
        since = "0.1.0",
        note = "Use find_by_id_and_tenant() for tenant-isolated queries"
    )]
    pub async fn find_by_id<'e, E>(executor: E, id: Uuid) -> Result<Option<Self>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as(
            "SELECT * FROM user_webauthn_credentials WHERE id = $1 AND is_enabled = true",
        )
        .bind(id)
        .fetch_optional(executor)
        .await
    }

    /// Find a credential by its ID with tenant isolation.
    ///
    /// SECURITY: This method ensures tenant isolation by requiring `tenant_id`.
    pub async fn find_by_id_and_tenant<'e, E>(
        executor: E,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as(
            "SELECT * FROM user_webauthn_credentials WHERE id = $1 AND tenant_id = $2 AND is_enabled = true",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(executor)
        .await
    }

    /// Find a credential by its `credential_id` bytes.
    ///
    /// **SECURITY WARNING**: This method does NOT filter by `tenant_id`.
    /// Use `find_by_credential_id_and_tenant()` for tenant-isolated queries.
    #[deprecated(
        since = "0.1.0",
        note = "Use find_by_credential_id_and_tenant() for tenant-isolated queries"
    )]
    pub async fn find_by_credential_id<'e, E>(
        executor: E,
        credential_id: &[u8],
    ) -> Result<Option<Self>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as(
            "SELECT * FROM user_webauthn_credentials WHERE credential_id = $1 AND is_enabled = true",
        )
        .bind(credential_id)
        .fetch_optional(executor)
        .await
    }

    /// Find a credential by its `credential_id` bytes with tenant isolation.
    ///
    /// SECURITY: This method ensures tenant isolation by requiring `tenant_id`.
    pub async fn find_by_credential_id_and_tenant<'e, E>(
        executor: E,
        tenant_id: Uuid,
        credential_id: &[u8],
    ) -> Result<Option<Self>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as(
            "SELECT * FROM user_webauthn_credentials WHERE credential_id = $1 AND tenant_id = $2 AND is_enabled = true",
        )
        .bind(credential_id)
        .bind(tenant_id)
        .fetch_optional(executor)
        .await
    }

    /// Find all credentials for a user.
    ///
    /// SECURITY: Caller must validate that `user_id` belongs to the current tenant.
    pub async fn find_by_user_id<'e, E>(
        executor: E,
        user_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as(
            "SELECT * FROM user_webauthn_credentials WHERE user_id = $1 AND is_enabled = true ORDER BY created_at DESC",
        )
        .bind(user_id)
        .fetch_all(executor)
        .await
    }

    /// Find all credentials for a user with tenant isolation.
    ///
    /// SECURITY: This method ensures tenant isolation by requiring `tenant_id`.
    pub async fn find_by_user_id_and_tenant<'e, E>(
        executor: E,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as(
            "SELECT * FROM user_webauthn_credentials WHERE user_id = $1 AND tenant_id = $2 AND is_enabled = true ORDER BY created_at DESC",
        )
        .bind(user_id)
        .bind(tenant_id)
        .fetch_all(executor)
        .await
    }

    /// Count credentials for a user.
    ///
    /// SECURITY: Caller must validate that `user_id` belongs to the current tenant.
    pub async fn count_by_user_id<'e, E>(executor: E, user_id: Uuid) -> Result<i64, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        let result: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM user_webauthn_credentials WHERE user_id = $1 AND is_enabled = true",
        )
        .bind(user_id)
        .fetch_one(executor)
        .await?;
        Ok(result.0)
    }

    /// Count credentials for a user with tenant isolation.
    ///
    /// SECURITY: This method ensures tenant isolation by requiring `tenant_id`.
    pub async fn count_by_user_id_and_tenant<'e, E>(
        executor: E,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<i64, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        let result: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM user_webauthn_credentials WHERE user_id = $1 AND tenant_id = $2 AND is_enabled = true",
        )
        .bind(user_id)
        .bind(tenant_id)
        .fetch_one(executor)
        .await?;
        Ok(result.0)
    }

    /// Check if a credential ID already exists for a tenant.
    pub async fn exists_by_credential_id<'e, E>(
        executor: E,
        tenant_id: Uuid,
        credential_id: &[u8],
    ) -> Result<bool, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        let result: (bool,) = sqlx::query_as(
            "SELECT EXISTS(SELECT 1 FROM user_webauthn_credentials WHERE tenant_id = $1 AND credential_id = $2)",
        )
        .bind(tenant_id)
        .bind(credential_id)
        .fetch_one(executor)
        .await?;
        Ok(result.0)
    }

    /// Update the sign counter after successful authentication.
    ///
    /// SECURITY: This method requires `tenant_id` to ensure tenant isolation.
    pub async fn update_sign_count<'e, E>(
        executor: E,
        tenant_id: Uuid,
        id: Uuid,
        new_count: i64,
    ) -> Result<(), sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query(
            r"
            UPDATE user_webauthn_credentials
            SET sign_count = $3, last_used_at = NOW(), updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(new_count)
        .execute(executor)
        .await?;
        Ok(())
    }

    /// Rename a credential.
    ///
    /// SECURITY: This method requires `tenant_id` to ensure tenant isolation.
    pub async fn rename<'e, E>(
        executor: E,
        tenant_id: Uuid,
        id: Uuid,
        new_name: &str,
    ) -> Result<Self, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as(
            r"
            UPDATE user_webauthn_credentials
            SET name = $3, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(new_name)
        .fetch_one(executor)
        .await
    }

    /// Delete a credential (hard delete).
    ///
    /// SECURITY: This method requires `tenant_id` to ensure tenant isolation.
    pub async fn delete<'e, E>(executor: E, tenant_id: Uuid, id: Uuid) -> Result<bool, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        let result =
            sqlx::query("DELETE FROM user_webauthn_credentials WHERE id = $1 AND tenant_id = $2")
                .bind(id)
                .bind(tenant_id)
                .execute(executor)
                .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Disable a credential (soft delete).
    pub async fn disable<'e, E>(executor: E, tenant_id: Uuid, id: Uuid) -> Result<bool, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        let result = sqlx::query(
            "UPDATE user_webauthn_credentials SET is_enabled = false, updated_at = NOW() WHERE id = $1 AND tenant_id = $2",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(executor)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Check if user has any enabled `WebAuthn` credentials.
    pub async fn has_enabled_credentials<'e, E>(
        executor: E,
        user_id: Uuid,
    ) -> Result<bool, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        let result: (bool,) = sqlx::query_as(
            "SELECT EXISTS(SELECT 1 FROM user_webauthn_credentials WHERE user_id = $1 AND is_enabled = true)",
        )
        .bind(user_id)
        .fetch_one(executor)
        .await?;
        Ok(result.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authenticator_type_display() {
        assert_eq!(AuthenticatorType::Platform.to_string(), "platform");
        assert_eq!(
            AuthenticatorType::CrossPlatform.to_string(),
            "cross-platform"
        );
    }

    #[test]
    fn test_authenticator_type_parse() {
        assert_eq!(
            "platform".parse::<AuthenticatorType>().unwrap(),
            AuthenticatorType::Platform
        );
        assert_eq!(
            "cross-platform".parse::<AuthenticatorType>().unwrap(),
            AuthenticatorType::CrossPlatform
        );
        assert_eq!(
            "crossplatform".parse::<AuthenticatorType>().unwrap(),
            AuthenticatorType::CrossPlatform
        );
        assert!("invalid".parse::<AuthenticatorType>().is_err());
    }

    #[test]
    fn test_credential_info_from() {
        let cred = UserWebAuthnCredential {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            credential_id: vec![1, 2, 3],
            public_key: vec![4, 5, 6],
            sign_count: 5,
            aaguid: Some(vec![0; 16]),
            name: "My YubiKey".to_string(),
            authenticator_type: "cross-platform".to_string(),
            transports: Some(vec!["usb".to_string()]),
            backup_eligible: false,
            backup_state: false,
            is_enabled: true,
            last_used_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let info: CredentialInfo = cred.into();
        assert_eq!(info.name, "My YubiKey");
        assert_eq!(info.authenticator_type, "cross-platform");
    }
}
