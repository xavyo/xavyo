//! Agent Certificate model for PKI (F127).
//!
//! Represents X.509 certificates issued to AI agents
//! for mTLS authentication.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Certificate status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CertificateStatus {
    /// Certificate is active and valid.
    Active,
    /// Certificate has been revoked.
    Revoked,
    /// Certificate has expired.
    Expired,
}

impl std::fmt::Display for CertificateStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CertificateStatus::Active => write!(f, "active"),
            CertificateStatus::Revoked => write!(f, "revoked"),
            CertificateStatus::Expired => write!(f, "expired"),
        }
    }
}

impl std::str::FromStr for CertificateStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "active" => Ok(CertificateStatus::Active),
            "revoked" => Ok(CertificateStatus::Revoked),
            "expired" => Ok(CertificateStatus::Expired),
            _ => Err(format!("Invalid certificate status: {}", s)),
        }
    }
}

/// An X.509 certificate issued to an AI agent.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AgentCertificate {
    /// Unique identifier for the certificate.
    pub id: Uuid,

    /// The tenant this certificate belongs to.
    pub tenant_id: Uuid,

    /// The agent this certificate was issued to.
    pub agent_id: Uuid,

    /// Certificate serial number (hex-encoded, globally unique).
    pub serial_number: String,

    /// Certificate in PEM format.
    pub certificate_pem: String,

    /// SHA-256 fingerprint for quick lookup during mTLS validation.
    pub fingerprint_sha256: String,

    /// Subject Distinguished Name.
    pub subject_dn: String,

    /// Issuer Distinguished Name (from CA).
    pub issuer_dn: String,

    /// Certificate not valid before.
    pub not_before: DateTime<Utc>,

    /// Certificate not valid after.
    pub not_after: DateTime<Utc>,

    /// Certificate status (active, revoked, expired).
    pub status: String,

    /// The CA that issued this certificate.
    pub ca_id: Uuid,

    /// When the certificate was revoked (if revoked).
    pub revoked_at: Option<DateTime<Utc>>,

    /// RFC 5280 revocation reason code (0-10).
    pub revocation_reason: Option<i16>,

    /// When the certificate was created.
    pub created_at: DateTime<Utc>,

    /// User who created/requested this certificate.
    pub created_by: Option<Uuid>,
}

impl AgentCertificate {
    /// Returns the certificate status as an enum.
    pub fn status_enum(&self) -> Result<CertificateStatus, String> {
        self.status.parse()
    }

    /// Check if the certificate is active.
    pub fn is_active(&self) -> bool {
        self.status == "active"
    }

    /// Check if the certificate is revoked.
    pub fn is_revoked(&self) -> bool {
        self.status == "revoked"
    }

    /// Check if the certificate has expired (by date).
    pub fn is_expired_by_date(&self) -> bool {
        self.not_after < Utc::now()
    }

    /// Check if the certificate is not yet valid.
    pub fn is_not_yet_valid(&self) -> bool {
        self.not_before > Utc::now()
    }

    /// Check if the certificate is currently valid for use.
    pub fn is_valid(&self) -> bool {
        self.is_active() && !self.is_expired_by_date() && !self.is_not_yet_valid()
    }

    /// Get remaining validity in seconds.
    pub fn remaining_validity_seconds(&self) -> i64 {
        (self.not_after - Utc::now()).num_seconds().max(0)
    }
}

/// Request to issue a new certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct IssueCertificateRequest {
    /// Validity period in days (default: 90).
    #[serde(default = "default_validity_days")]
    pub validity_days: i32,

    /// Key algorithm (rsa2048, rsa4096, ecdsa_p256, ecdsa_p384).
    #[serde(default = "default_key_algorithm")]
    pub key_algorithm: String,

    /// Optional CA ID (uses default CA if not specified).
    pub ca_id: Option<Uuid>,

    /// Optional additional Subject Alternative Names (URIs).
    pub additional_sans: Option<Vec<String>>,
}

fn default_validity_days() -> i32 {
    90
}

fn default_key_algorithm() -> String {
    "ecdsa_p256".to_string()
}

impl Default for IssueCertificateRequest {
    fn default() -> Self {
        Self {
            validity_days: default_validity_days(),
            key_algorithm: default_key_algorithm(),
            ca_id: None,
            additional_sans: None,
        }
    }
}

/// Response after issuing a certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct IssueCertificateResponse {
    /// The issued certificate.
    pub certificate: AgentCertificate,

    /// Private key in PEM format (only returned once at issuance).
    pub private_key_pem: String,

    /// CA certificate chain in PEM format.
    pub ca_chain_pem: String,
}

/// Filter options for listing certificates.
#[derive(Debug, Clone, Default)]
pub struct AgentCertificateFilter {
    /// Filter by agent ID.
    pub agent_id: Option<Uuid>,

    /// Filter by CA ID.
    pub ca_id: Option<Uuid>,

    /// Filter by status.
    pub status: Option<String>,

    /// Filter by expiring within N days.
    pub expiring_within_days: Option<i32>,
}

impl AgentCertificate {
    /// Find a certificate by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM agent_certificates
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find a certificate by serial number within a tenant.
    pub async fn find_by_serial(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        serial_number: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM agent_certificates
            WHERE tenant_id = $1 AND serial_number = $2
            "#,
        )
        .bind(tenant_id)
        .bind(serial_number)
        .fetch_optional(pool)
        .await
    }

    /// Find a certificate by fingerprint within a tenant (for mTLS validation).
    pub async fn find_by_fingerprint(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        fingerprint: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM agent_certificates
            WHERE tenant_id = $1 AND fingerprint_sha256 = $2
            "#,
        )
        .bind(tenant_id)
        .bind(fingerprint)
        .fetch_optional(pool)
        .await
    }

    /// Find a certificate by fingerprint without tenant filter.
    ///
    /// **Security Warning**: Only use for mTLS validation where tenant is
    /// extracted from the certificate itself. Always verify tenant_id after lookup.
    pub async fn find_by_fingerprint_any_tenant(
        pool: &sqlx::PgPool,
        fingerprint: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM agent_certificates
            WHERE fingerprint_sha256 = $1
            "#,
        )
        .bind(fingerprint)
        .fetch_optional(pool)
        .await
    }

    /// Find the active certificate for an agent (most recent).
    pub async fn find_active_for_agent(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        agent_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM agent_certificates
            WHERE tenant_id = $1 AND agent_id = $2 AND status = 'active'
            ORDER BY not_after DESC
            LIMIT 1
            "#,
        )
        .bind(tenant_id)
        .bind(agent_id)
        .fetch_optional(pool)
        .await
    }

    /// List certificates for a tenant with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &AgentCertificateFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT * FROM agent_certificates
            WHERE tenant_id = $1
            "#,
        );
        let mut param_count = 1;

        if filter.agent_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND agent_id = ${}", param_count));
        }

        if filter.ca_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND ca_id = ${}", param_count));
        }

        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${}", param_count));
        }

        if filter.expiring_within_days.is_some() {
            param_count += 1;
            query.push_str(&format!(
                " AND status = 'active' AND not_after <= NOW() + INTERVAL '1 day' * ${}",
                param_count
            ));
        }

        query.push_str(&format!(
            " ORDER BY created_at DESC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, AgentCertificate>(&query).bind(tenant_id);

        if let Some(agent_id) = filter.agent_id {
            q = q.bind(agent_id);
        }
        if let Some(ca_id) = filter.ca_id {
            q = q.bind(ca_id);
        }
        if let Some(ref status) = filter.status {
            q = q.bind(status);
        }
        if let Some(days) = filter.expiring_within_days {
            q = q.bind(days);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count certificates for an agent.
    pub async fn count_for_agent(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        agent_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM agent_certificates
            WHERE tenant_id = $1 AND agent_id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(agent_id)
        .fetch_one(pool)
        .await
    }

    /// Count active (non-revoked, non-expired) certificates for a CA.
    ///
    /// Used to prevent CA deletion while certificates are still active.
    pub async fn count_active_by_ca(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        ca_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM agent_certificates
            WHERE tenant_id = $1 AND ca_id = $2 AND status = 'active' AND not_after > NOW()
            "#,
        )
        .bind(tenant_id)
        .bind(ca_id)
        .fetch_one(pool)
        .await
    }

    /// List certificates expiring soon.
    pub async fn list_expiring(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        within_days: i32,
        limit: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM agent_certificates
            WHERE tenant_id = $1
              AND status = 'active'
              AND not_after > NOW()
              AND not_after <= NOW() + INTERVAL '1 day' * $2
            ORDER BY not_after ASC
            LIMIT $3
            "#,
        )
        .bind(tenant_id)
        .bind(within_days)
        .bind(limit)
        .fetch_all(pool)
        .await
    }

    /// Create a new certificate record.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        agent_id: Uuid,
        serial_number: &str,
        certificate_pem: &str,
        fingerprint_sha256: &str,
        subject_dn: &str,
        issuer_dn: &str,
        not_before: DateTime<Utc>,
        not_after: DateTime<Utc>,
        ca_id: Uuid,
        created_by: Option<Uuid>,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r#"
            INSERT INTO agent_certificates (
                tenant_id, agent_id, serial_number, certificate_pem, fingerprint_sha256,
                subject_dn, issuer_dn, not_before, not_after, ca_id, created_by
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(agent_id)
        .bind(serial_number)
        .bind(certificate_pem)
        .bind(fingerprint_sha256)
        .bind(subject_dn)
        .bind(issuer_dn)
        .bind(not_before)
        .bind(not_after)
        .bind(ca_id)
        .bind(created_by)
        .fetch_one(pool)
        .await
    }

    /// Revoke a certificate.
    pub async fn revoke(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        reason: i16,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE agent_certificates
            SET status = 'revoked', revoked_at = NOW(), revocation_reason = $3
            WHERE id = $1 AND tenant_id = $2 AND status = 'active'
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(reason)
        .fetch_optional(pool)
        .await
    }

    /// Mark a certificate as expired.
    pub async fn mark_expired(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE agent_certificates
            SET status = 'expired'
            WHERE id = $1 AND tenant_id = $2 AND status = 'active' AND not_after < NOW()
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Batch update expired certificates to expired status.
    pub async fn update_expired_batch(pool: &sqlx::PgPool) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            UPDATE agent_certificates
            SET status = 'expired'
            WHERE status = 'active' AND not_after < NOW()
            "#,
        )
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Delete a certificate (for cleanup).
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM agent_certificates
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certificate_status_display() {
        assert_eq!(CertificateStatus::Active.to_string(), "active");
        assert_eq!(CertificateStatus::Revoked.to_string(), "revoked");
        assert_eq!(CertificateStatus::Expired.to_string(), "expired");
    }

    #[test]
    fn test_certificate_status_from_str() {
        assert_eq!(
            "active".parse::<CertificateStatus>().unwrap(),
            CertificateStatus::Active
        );
        assert_eq!(
            "REVOKED".parse::<CertificateStatus>().unwrap(),
            CertificateStatus::Revoked
        );
        assert_eq!(
            "Expired".parse::<CertificateStatus>().unwrap(),
            CertificateStatus::Expired
        );
        assert!("invalid".parse::<CertificateStatus>().is_err());
    }

    #[test]
    fn test_issue_certificate_request_defaults() {
        let request = IssueCertificateRequest::default();
        assert_eq!(request.validity_days, 90);
        assert_eq!(request.key_algorithm, "ecdsa_p256");
        assert!(request.ca_id.is_none());
        assert!(request.additional_sans.is_none());
    }

    #[test]
    fn test_agent_certificate_helper_methods() {
        use chrono::Duration;

        let cert = AgentCertificate {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            serial_number: "01ABCDEF".to_string(),
            certificate_pem: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
                .to_string(),
            fingerprint_sha256: "AB:CD:EF:01:23:45:67:89".to_string(),
            subject_dn: "CN=agent-123,O=Xavyo".to_string(),
            issuer_dn: "CN=Xavyo CA,O=Xavyo".to_string(),
            not_before: Utc::now() - Duration::days(1),
            not_after: Utc::now() + Duration::days(89),
            status: "active".to_string(),
            ca_id: Uuid::new_v4(),
            revoked_at: None,
            revocation_reason: None,
            created_at: Utc::now(),
            created_by: Some(Uuid::new_v4()),
        };

        assert!(cert.is_active());
        assert!(!cert.is_revoked());
        assert!(!cert.is_expired_by_date());
        assert!(!cert.is_not_yet_valid());
        assert!(cert.is_valid());
        assert!(cert.remaining_validity_seconds() > 0);
        assert_eq!(cert.status_enum().unwrap(), CertificateStatus::Active);
    }

    #[test]
    fn test_agent_certificate_expired() {
        use chrono::Duration;

        let expired_cert = AgentCertificate {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            serial_number: "02EXPIRED".to_string(),
            certificate_pem: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
                .to_string(),
            fingerprint_sha256: "EX:PI:RE:D0".to_string(),
            subject_dn: "CN=expired-agent".to_string(),
            issuer_dn: "CN=Xavyo CA".to_string(),
            not_before: Utc::now() - Duration::days(100),
            not_after: Utc::now() - Duration::days(10),
            status: "active".to_string(),
            ca_id: Uuid::new_v4(),
            revoked_at: None,
            revocation_reason: None,
            created_at: Utc::now() - Duration::days(100),
            created_by: None,
        };

        assert!(expired_cert.is_expired_by_date());
        assert!(!expired_cert.is_valid());
        assert_eq!(expired_cert.remaining_validity_seconds(), 0);
    }

    #[test]
    fn test_agent_certificate_revoked() {
        use chrono::Duration;

        let revoked_cert = AgentCertificate {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            serial_number: "03REVOKED".to_string(),
            certificate_pem: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
                .to_string(),
            fingerprint_sha256: "RE:VO:KE:D0".to_string(),
            subject_dn: "CN=revoked-agent".to_string(),
            issuer_dn: "CN=Xavyo CA".to_string(),
            not_before: Utc::now() - Duration::days(30),
            not_after: Utc::now() + Duration::days(60),
            status: "revoked".to_string(),
            ca_id: Uuid::new_v4(),
            revoked_at: Some(Utc::now() - Duration::days(5)),
            revocation_reason: Some(1), // keyCompromise
            created_at: Utc::now() - Duration::days(30),
            created_by: None,
        };

        assert!(revoked_cert.is_revoked());
        assert!(!revoked_cert.is_active());
        assert!(!revoked_cert.is_valid());
    }

    #[test]
    fn test_agent_certificate_filter() {
        let filter = AgentCertificateFilter {
            agent_id: Some(Uuid::new_v4()),
            ca_id: None,
            status: Some("active".to_string()),
            expiring_within_days: Some(30),
        };

        assert!(filter.agent_id.is_some());
        assert!(filter.ca_id.is_none());
        assert_eq!(filter.status, Some("active".to_string()));
        assert_eq!(filter.expiring_within_days, Some(30));
    }
}
