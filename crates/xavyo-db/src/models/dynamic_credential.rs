//! Dynamic Credential model for ephemeral secrets provisioning.
//!
//! Represents credentials issued to AI agents with TTL-based expiration.
//! Part of the `SecretlessAI` feature (F120).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Status of a dynamic credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CredentialStatus {
    /// Credential is active and valid.
    Active,
    /// Credential has expired (TTL passed).
    Expired,
    /// Credential was manually revoked.
    Revoked,
}

impl std::fmt::Display for CredentialStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CredentialStatus::Active => write!(f, "active"),
            CredentialStatus::Expired => write!(f, "expired"),
            CredentialStatus::Revoked => write!(f, "revoked"),
        }
    }
}

impl std::str::FromStr for CredentialStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "active" => Ok(CredentialStatus::Active),
            "expired" => Ok(CredentialStatus::Expired),
            "revoked" => Ok(CredentialStatus::Revoked),
            _ => Err(format!("Invalid credential status: {s}")),
        }
    }
}

/// Provider type for dynamic secrets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SecretProviderType {
    /// `OpenBao` (`HashiCorp` Vault fork, MPL 2.0).
    Openbao,
    /// Infisical (MIT licensed).
    Infisical,
    /// Internal PostgreSQL-backed storage.
    Internal,
    /// AWS Secrets Manager (optional).
    Aws,
}

impl std::fmt::Display for SecretProviderType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecretProviderType::Openbao => write!(f, "openbao"),
            SecretProviderType::Infisical => write!(f, "infisical"),
            SecretProviderType::Internal => write!(f, "internal"),
            SecretProviderType::Aws => write!(f, "aws"),
        }
    }
}

impl std::str::FromStr for SecretProviderType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "openbao" => Ok(SecretProviderType::Openbao),
            "infisical" => Ok(SecretProviderType::Infisical),
            "internal" => Ok(SecretProviderType::Internal),
            "aws" => Ok(SecretProviderType::Aws),
            _ => Err(format!("Invalid provider type: {s}")),
        }
    }
}

/// An ephemeral credential issued to an AI agent.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DynamicCredential {
    /// Unique identifier for this credential.
    pub id: Uuid,

    /// Tenant that owns this credential.
    pub tenant_id: Uuid,

    /// Agent that was issued this credential.
    pub agent_id: Uuid,

    /// Type of secret (e.g., "postgres-readonly").
    pub secret_type: String,

    /// Encrypted credential value (AES-256-GCM).
    pub credential_value: String,

    /// When the credential was issued.
    pub issued_at: DateTime<Utc>,

    /// When the credential expires.
    pub expires_at: DateTime<Utc>,

    /// Current status (active, expired, revoked).
    pub status: String,

    /// Provider that generated this credential.
    pub provider_type: String,

    /// Provider-specific lease ID (for `OpenBao` revocation).
    pub provider_lease_id: Option<String>,

    /// Record creation timestamp.
    pub created_at: DateTime<Utc>,
}

impl DynamicCredential {
    /// Parse the status as an enum.
    pub fn status_enum(&self) -> Result<CredentialStatus, String> {
        self.status.parse()
    }

    /// Parse the provider type as an enum.
    pub fn provider_type_enum(&self) -> Result<SecretProviderType, String> {
        self.provider_type.parse()
    }

    /// Check if the credential is currently valid.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.status == "active" && self.expires_at > Utc::now()
    }

    /// Check if the credential has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.expires_at <= Utc::now() || self.status == "expired"
    }

    /// Get TTL in seconds from now (0 if expired).
    #[must_use]
    pub fn ttl_seconds(&self) -> i64 {
        let remaining = self.expires_at.signed_duration_since(Utc::now());
        remaining.num_seconds().max(0)
    }
}

/// Request to create a new dynamic credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateDynamicCredential {
    /// Agent receiving the credential.
    pub agent_id: Uuid,

    /// Type of secret.
    pub secret_type: String,

    /// Encrypted credential value.
    pub credential_value: String,

    /// TTL in seconds.
    pub ttl_seconds: i32,

    /// Provider type.
    pub provider_type: String,

    /// Provider lease ID (optional).
    pub provider_lease_id: Option<String>,
}

/// Filter options for listing credentials.
#[derive(Debug, Clone, Default)]
pub struct DynamicCredentialFilter {
    /// Filter by agent ID.
    pub agent_id: Option<Uuid>,

    /// Filter by secret type.
    pub secret_type: Option<String>,

    /// Filter by status.
    pub status: Option<String>,

    /// Filter by provider type.
    pub provider_type: Option<String>,

    /// Only include active (non-expired) credentials.
    pub active_only: bool,
}

impl DynamicCredential {
    /// Find a credential by ID.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM dynamic_credentials
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List credentials for a tenant with filtering.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &DynamicCredentialFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT * FROM dynamic_credentials
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.agent_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND agent_id = ${param_count}"));
        }

        if filter.secret_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND secret_type = ${param_count}"));
        }

        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${param_count}"));
        }

        if filter.provider_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND provider_type = ${param_count}"));
        }

        if filter.active_only {
            query.push_str(" AND status = 'active' AND expires_at > NOW()");
        }

        query.push_str(&format!(
            " ORDER BY created_at DESC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, DynamicCredential>(&query).bind(tenant_id);

        if let Some(agent_id) = filter.agent_id {
            q = q.bind(agent_id);
        }
        if let Some(ref secret_type) = filter.secret_type {
            q = q.bind(secret_type);
        }
        if let Some(ref status) = filter.status {
            q = q.bind(status);
        }
        if let Some(ref provider_type) = filter.provider_type {
            q = q.bind(provider_type);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Create a new dynamic credential.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateDynamicCredential,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO dynamic_credentials (
                tenant_id, agent_id, secret_type, credential_value,
                expires_at, provider_type, provider_lease_id
            )
            VALUES ($1, $2, $3, $4, NOW() + ($5 || ' seconds')::interval, $6, $7)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(input.agent_id)
        .bind(&input.secret_type)
        .bind(&input.credential_value)
        .bind(input.ttl_seconds.to_string())
        .bind(&input.provider_type)
        .bind(&input.provider_lease_id)
        .fetch_one(pool)
        .await
    }

    /// Revoke a credential.
    pub async fn revoke(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE dynamic_credentials
            SET status = 'revoked'
            WHERE id = $1 AND tenant_id = $2 AND status = 'active'
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Mark expired credentials as expired.
    pub async fn expire_stale(pool: &sqlx::PgPool, tenant_id: Uuid) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE dynamic_credentials
            SET status = 'expired'
            WHERE tenant_id = $1 AND status = 'active' AND expires_at <= NOW()
            ",
        )
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Count active credentials for an agent.
    pub async fn count_active_for_agent(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        agent_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM dynamic_credentials
            WHERE tenant_id = $1 AND agent_id = $2 AND status = 'active' AND expires_at > NOW()
            ",
        )
        .bind(tenant_id)
        .bind(agent_id)
        .fetch_one(pool)
        .await
    }

    /// Count active credentials for a specific secret type (for deletion checks).
    pub async fn count_active_by_secret_type(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        secret_type: &str,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM dynamic_credentials
            WHERE tenant_id = $1 AND secret_type = $2 AND status = 'active'
            ",
        )
        .bind(tenant_id)
        .bind(secret_type)
        .fetch_one(pool)
        .await
    }

    /// Find credentials by lease ID (for provider revocation callbacks).
    pub async fn find_by_lease_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        lease_id: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM dynamic_credentials
            WHERE tenant_id = $1 AND provider_lease_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(lease_id)
        .fetch_optional(pool)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credential_status_display() {
        assert_eq!(CredentialStatus::Active.to_string(), "active");
        assert_eq!(CredentialStatus::Expired.to_string(), "expired");
        assert_eq!(CredentialStatus::Revoked.to_string(), "revoked");
    }

    #[test]
    fn test_credential_status_from_str() {
        assert_eq!(
            "active".parse::<CredentialStatus>().unwrap(),
            CredentialStatus::Active
        );
        assert_eq!(
            "EXPIRED".parse::<CredentialStatus>().unwrap(),
            CredentialStatus::Expired
        );
        assert!("invalid".parse::<CredentialStatus>().is_err());
    }

    #[test]
    fn test_provider_type_display() {
        assert_eq!(SecretProviderType::Openbao.to_string(), "openbao");
        assert_eq!(SecretProviderType::Infisical.to_string(), "infisical");
        assert_eq!(SecretProviderType::Internal.to_string(), "internal");
        assert_eq!(SecretProviderType::Aws.to_string(), "aws");
    }

    #[test]
    fn test_provider_type_from_str() {
        assert_eq!(
            "openbao".parse::<SecretProviderType>().unwrap(),
            SecretProviderType::Openbao
        );
        assert_eq!(
            "INFISICAL".parse::<SecretProviderType>().unwrap(),
            SecretProviderType::Infisical
        );
        assert!("invalid".parse::<SecretProviderType>().is_err());
    }

    #[test]
    fn test_dynamic_credential_helper_methods() {
        use chrono::Duration;

        let active_cred = DynamicCredential {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            secret_type: "postgres-readonly".to_string(),
            credential_value: "encrypted-value".to_string(),
            issued_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(5),
            status: "active".to_string(),
            provider_type: "openbao".to_string(),
            provider_lease_id: Some("lease-123".to_string()),
            created_at: Utc::now(),
        };

        assert!(active_cred.is_valid());
        assert!(!active_cred.is_expired());
        assert!(active_cred.ttl_seconds() > 0);

        let expired_cred = DynamicCredential {
            expires_at: Utc::now() - Duration::minutes(1),
            ..active_cred.clone()
        };

        assert!(!expired_cred.is_valid());
        assert!(expired_cred.is_expired());
        assert_eq!(expired_cred.ttl_seconds(), 0);
    }
}
