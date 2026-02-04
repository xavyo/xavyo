//! NHI Credential model.
//!
//! Stores hashed credentials for NHIs. Plaintext is never stored.
//! Supports both service accounts and AI agents via the `nhi_type` field.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Type of NHI credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_nhi_credential_type", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum NhiCredentialType {
    /// API key credential.
    ApiKey,
    /// Secret/password credential.
    Secret,
    /// X.509 certificate credential.
    Certificate,
}

/// Type of NHI entity that owns the credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "text")]
#[serde(rename_all = "snake_case")]
pub enum NhiEntityType {
    /// Service account NHI.
    #[default]
    #[sqlx(rename = "service_account")]
    #[serde(rename = "service_account")]
    ServiceAccount,
    /// AI agent NHI.
    #[sqlx(rename = "agent")]
    #[serde(rename = "agent")]
    Agent,
}

impl std::fmt::Display for NhiEntityType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NhiEntityType::ServiceAccount => write!(f, "service_account"),
            NhiEntityType::Agent => write!(f, "agent"),
        }
    }
}

impl std::str::FromStr for NhiEntityType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "service_account" => Ok(NhiEntityType::ServiceAccount),
            "agent" => Ok(NhiEntityType::Agent),
            _ => Err(format!("Unknown NHI entity type: {s}")),
        }
    }
}

/// An NHI credential record.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovNhiCredential {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant this credential belongs to.
    pub tenant_id: Uuid,

    /// The NHI this credential belongs to.
    pub nhi_id: Uuid,

    /// Type of credential.
    pub credential_type: NhiCredentialType,

    /// Hash of the credential (Argon2id).
    pub credential_hash: String,

    /// When the credential becomes valid.
    pub valid_from: DateTime<Utc>,

    /// When the credential expires.
    pub valid_until: DateTime<Utc>,

    /// Whether the credential is active (can be used for authentication).
    pub is_active: bool,

    /// Who triggered the rotation that created this credential.
    pub rotated_by: Option<Uuid>,

    /// When the credential was created.
    pub created_at: DateTime<Utc>,

    /// Type of NHI entity (`service_account` or agent).
    #[sqlx(default)]
    pub nhi_type: NhiEntityType,
}

/// Request to create a new NHI credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovNhiCredential {
    pub nhi_id: Uuid,
    pub credential_type: NhiCredentialType,
    pub credential_hash: String,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub rotated_by: Option<Uuid>,
    /// Type of NHI entity (`service_account` or agent).
    #[serde(default)]
    pub nhi_type: NhiEntityType,
}

/// Filter options for listing NHI credentials.
#[derive(Debug, Clone, Default)]
pub struct NhiCredentialFilter {
    pub nhi_id: Option<Uuid>,
    pub credential_type: Option<NhiCredentialType>,
    pub is_active: Option<bool>,
}

impl GovNhiCredential {
    /// Check if this credential is currently valid.
    #[must_use] 
    pub fn is_valid(&self) -> bool {
        let now = Utc::now();
        self.is_active && self.valid_from <= now && self.valid_until > now
    }

    /// Get days until expiration.
    #[must_use] 
    pub fn days_until_expiry(&self) -> i64 {
        let duration = self.valid_until.signed_duration_since(Utc::now());
        duration.num_days()
    }

    /// Verify a credential against the stored hash.
    ///
    /// Uses Argon2id for password hashing verification.
    /// Returns true if the credential matches the stored hash.
    #[cfg(feature = "argon2")]
    #[must_use] 
    pub fn verify_credential(&self, credential: &str) -> bool {
        use argon2::{Argon2, PasswordHash, PasswordVerifier};

        let parsed_hash = match PasswordHash::new(&self.credential_hash) {
            Ok(hash) => hash,
            Err(_) => return false,
        };

        Argon2::default()
            .verify_password(credential.as_bytes(), &parsed_hash)
            .is_ok()
    }

    /// Verify a credential (stub when argon2 feature is disabled).
    #[cfg(not(feature = "argon2"))]
    pub fn verify_credential(&self, _credential: &str) -> bool {
        false
    }

    /// Find a credential by ID.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_nhi_credentials
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find a credential by hash (for authentication).
    pub async fn find_by_hash(
        pool: &sqlx::PgPool,
        credential_hash: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_nhi_credentials
            WHERE credential_hash = $1 AND is_active = true
            ",
        )
        .bind(credential_hash)
        .fetch_optional(pool)
        .await
    }

    /// List credentials for an NHI.
    pub async fn list_by_nhi(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        nhi_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_nhi_credentials
            WHERE tenant_id = $1 AND nhi_id = $2
            ORDER BY created_at DESC
            ",
        )
        .bind(tenant_id)
        .bind(nhi_id)
        .fetch_all(pool)
        .await
    }

    /// List active credentials for an NHI.
    pub async fn list_active_by_nhi(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        nhi_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_nhi_credentials
            WHERE tenant_id = $1 AND nhi_id = $2 AND is_active = true
            ORDER BY valid_from DESC
            ",
        )
        .bind(tenant_id)
        .bind(nhi_id)
        .fetch_all(pool)
        .await
    }

    /// Create a new credential.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        data: CreateGovNhiCredential,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO gov_nhi_credentials (
                tenant_id, nhi_id, credential_type, credential_hash,
                valid_from, valid_until, rotated_by, nhi_type
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(data.nhi_id)
        .bind(data.credential_type)
        .bind(&data.credential_hash)
        .bind(data.valid_from)
        .bind(data.valid_until)
        .bind(data.rotated_by)
        .bind(data.nhi_type.to_string())
        .fetch_one(pool)
        .await
    }

    /// Deactivate a credential.
    pub async fn deactivate(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_nhi_credentials
            SET is_active = false
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Deactivate all credentials for an NHI.
    pub async fn deactivate_all_for_nhi(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        nhi_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE gov_nhi_credentials
            SET is_active = false
            WHERE tenant_id = $1 AND nhi_id = $2 AND is_active = true
            ",
        )
        .bind(tenant_id)
        .bind(nhi_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Delete expired inactive credentials (cleanup).
    pub async fn delete_expired_inactive(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_nhi_credentials
            WHERE tenant_id = $1
                AND is_active = false
                AND valid_until < NOW() - INTERVAL '7 days'
            ",
        )
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Find credentials expiring within the specified number of days.
    pub async fn find_expiring_soon(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        days: i32,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_nhi_credentials
            WHERE tenant_id = $1
                AND is_active = true
                AND valid_until > NOW()
                AND valid_until < NOW() + ($2 || ' days')::INTERVAL
            ORDER BY valid_until ASC
            ",
        )
        .bind(tenant_id)
        .bind(days)
        .fetch_all(pool)
        .await
    }

    /// Find all active credentials for authentication validation.
    /// Returns credentials that are active and within their validity window.
    pub async fn find_all_active_for_auth(pool: &sqlx::PgPool) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_nhi_credentials
            WHERE is_active = true
                AND valid_from <= NOW()
                AND valid_until > NOW()
            ",
        )
        .fetch_all(pool)
        .await
    }

    /// Find active credentials by NHI type for authentication.
    pub async fn find_active_by_nhi_type(
        pool: &sqlx::PgPool,
        nhi_type: NhiEntityType,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_nhi_credentials
            WHERE is_active = true
                AND valid_from <= NOW()
                AND valid_until > NOW()
                AND nhi_type = $1
            ",
        )
        .bind(nhi_type.to_string())
        .fetch_all(pool)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credential_type_serialization() {
        let api_key = NhiCredentialType::ApiKey;
        let json = serde_json::to_string(&api_key).unwrap();
        assert_eq!(json, "\"api_key\"");

        let secret = NhiCredentialType::Secret;
        let json = serde_json::to_string(&secret).unwrap();
        assert_eq!(json, "\"secret\"");

        let cert = NhiCredentialType::Certificate;
        let json = serde_json::to_string(&cert).unwrap();
        assert_eq!(json, "\"certificate\"");
    }

    #[test]
    fn test_nhi_entity_type_serialization() {
        let sa = NhiEntityType::ServiceAccount;
        let json = serde_json::to_string(&sa).unwrap();
        assert_eq!(json, "\"service_account\"");

        let agent = NhiEntityType::Agent;
        let json = serde_json::to_string(&agent).unwrap();
        assert_eq!(json, "\"agent\"");
    }

    #[test]
    fn test_nhi_entity_type_display() {
        assert_eq!(NhiEntityType::ServiceAccount.to_string(), "service_account");
        assert_eq!(NhiEntityType::Agent.to_string(), "agent");
    }

    #[test]
    fn test_nhi_entity_type_from_str() {
        assert_eq!(
            "service_account".parse::<NhiEntityType>().unwrap(),
            NhiEntityType::ServiceAccount
        );
        assert_eq!(
            "agent".parse::<NhiEntityType>().unwrap(),
            NhiEntityType::Agent
        );
        assert!("unknown".parse::<NhiEntityType>().is_err());
    }

    #[test]
    fn test_nhi_entity_type_default() {
        assert_eq!(NhiEntityType::default(), NhiEntityType::ServiceAccount);
    }
}
