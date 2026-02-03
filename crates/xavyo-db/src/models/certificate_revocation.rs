//! Certificate Revocation model for PKI (F127).
//!
//! Stores certificate revocation audit events for CRL/OCSP support.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// RFC 5280 revocation reason codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(i16)]
pub enum RevocationReasonCode {
    /// Unspecified reason.
    Unspecified = 0,
    /// Key has been compromised.
    KeyCompromise = 1,
    /// CA has been compromised.
    CaCompromise = 2,
    /// Affiliation has changed.
    AffiliationChanged = 3,
    /// Certificate has been superseded by a new one.
    Superseded = 4,
    /// Operation has ceased.
    CessationOfOperation = 5,
    /// Certificate is on hold (can be reactivated).
    CertificateHold = 6,
    /// Reserved (not used).
    Reserved7 = 7,
    /// Removed from CRL (for CertificateHold).
    RemoveFromCrl = 8,
    /// Privilege withdrawn.
    PrivilegeWithdrawn = 9,
    /// AA has been compromised.
    AaCompromise = 10,
}

impl RevocationReasonCode {
    /// Convert from i16 to RevocationReasonCode.
    pub fn from_i16(value: i16) -> Option<Self> {
        match value {
            0 => Some(RevocationReasonCode::Unspecified),
            1 => Some(RevocationReasonCode::KeyCompromise),
            2 => Some(RevocationReasonCode::CaCompromise),
            3 => Some(RevocationReasonCode::AffiliationChanged),
            4 => Some(RevocationReasonCode::Superseded),
            5 => Some(RevocationReasonCode::CessationOfOperation),
            6 => Some(RevocationReasonCode::CertificateHold),
            7 => Some(RevocationReasonCode::Reserved7),
            8 => Some(RevocationReasonCode::RemoveFromCrl),
            9 => Some(RevocationReasonCode::PrivilegeWithdrawn),
            10 => Some(RevocationReasonCode::AaCompromise),
            _ => None,
        }
    }

    /// Get a human-readable description of the reason.
    pub fn description(&self) -> &'static str {
        match self {
            RevocationReasonCode::Unspecified => "Unspecified",
            RevocationReasonCode::KeyCompromise => "Key Compromise",
            RevocationReasonCode::CaCompromise => "CA Compromise",
            RevocationReasonCode::AffiliationChanged => "Affiliation Changed",
            RevocationReasonCode::Superseded => "Superseded",
            RevocationReasonCode::CessationOfOperation => "Cessation of Operation",
            RevocationReasonCode::CertificateHold => "Certificate Hold",
            RevocationReasonCode::Reserved7 => "Reserved",
            RevocationReasonCode::RemoveFromCrl => "Remove from CRL",
            RevocationReasonCode::PrivilegeWithdrawn => "Privilege Withdrawn",
            RevocationReasonCode::AaCompromise => "AA Compromise",
        }
    }
}

impl std::fmt::Display for RevocationReasonCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.description())
    }
}

/// A certificate revocation audit record.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CertificateRevocation {
    /// Unique identifier for this revocation record.
    pub id: Uuid,

    /// The tenant this revocation belongs to.
    pub tenant_id: Uuid,

    /// The certificate that was revoked.
    pub certificate_id: Uuid,

    /// Serial number of the revoked certificate (for CRL lookup).
    pub serial_number: String,

    /// RFC 5280 revocation reason code (0-10).
    pub reason_code: i16,

    /// When the certificate was revoked.
    pub revoked_at: DateTime<Utc>,

    /// User who performed the revocation.
    pub revoked_by: Uuid,

    /// Optional notes about the revocation.
    pub notes: Option<String>,

    /// When this record was created.
    pub created_at: DateTime<Utc>,
}

impl CertificateRevocation {
    /// Get the revocation reason as an enum.
    pub fn reason(&self) -> Option<RevocationReasonCode> {
        RevocationReasonCode::from_i16(self.reason_code)
    }

    /// Get a human-readable reason description.
    pub fn reason_description(&self) -> &'static str {
        self.reason().map(|r| r.description()).unwrap_or("Unknown")
    }
}

/// Request to revoke a certificate.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RevokeCertificateRequest {
    /// RFC 5280 revocation reason code (0-10).
    /// Default: 0 (unspecified).
    #[serde(default)]
    pub reason_code: i16,

    /// Optional notes about the revocation.
    pub notes: Option<String>,
}

/// Filter options for listing revocations.
#[derive(Debug, Clone, Default)]
pub struct CertificateRevocationFilter {
    /// Filter by certificate ID.
    pub certificate_id: Option<Uuid>,

    /// Filter by reason code.
    pub reason_code: Option<i16>,

    /// Filter by revoked_by user.
    pub revoked_by: Option<Uuid>,

    /// Filter revocations after this date.
    pub revoked_after: Option<DateTime<Utc>>,

    /// Filter revocations before this date.
    pub revoked_before: Option<DateTime<Utc>>,
}

impl CertificateRevocation {
    /// Find a revocation by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM certificate_revocations
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find a revocation by certificate ID.
    pub async fn find_by_certificate(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        certificate_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM certificate_revocations
            WHERE tenant_id = $1 AND certificate_id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(certificate_id)
        .fetch_optional(pool)
        .await
    }

    /// Check if a serial number is revoked (for OCSP/CRL).
    pub async fn is_serial_revoked(
        pool: &sqlx::PgPool,
        serial_number: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM certificate_revocations
            WHERE serial_number = $1
            "#,
        )
        .bind(serial_number)
        .fetch_optional(pool)
        .await
    }

    /// List revocations for a tenant with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &CertificateRevocationFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT * FROM certificate_revocations
            WHERE tenant_id = $1
            "#,
        );
        let mut param_count = 1;

        if filter.certificate_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND certificate_id = ${}", param_count));
        }

        if filter.reason_code.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND reason_code = ${}", param_count));
        }

        if filter.revoked_by.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND revoked_by = ${}", param_count));
        }

        if filter.revoked_after.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND revoked_at >= ${}", param_count));
        }

        if filter.revoked_before.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND revoked_at <= ${}", param_count));
        }

        query.push_str(&format!(
            " ORDER BY revoked_at DESC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, CertificateRevocation>(&query).bind(tenant_id);

        if let Some(certificate_id) = filter.certificate_id {
            q = q.bind(certificate_id);
        }
        if let Some(reason_code) = filter.reason_code {
            q = q.bind(reason_code);
        }
        if let Some(revoked_by) = filter.revoked_by {
            q = q.bind(revoked_by);
        }
        if let Some(revoked_after) = filter.revoked_after {
            q = q.bind(revoked_after);
        }
        if let Some(revoked_before) = filter.revoked_before {
            q = q.bind(revoked_before);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// List all revocations for CRL generation.
    pub async fn list_for_crl(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM certificate_revocations
            WHERE tenant_id = $1
            ORDER BY revoked_at ASC
            "#,
        )
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// List revocations since a given time (for incremental CRL updates).
    pub async fn list_since(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        since: DateTime<Utc>,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM certificate_revocations
            WHERE tenant_id = $1 AND revoked_at > $2
            ORDER BY revoked_at ASC
            "#,
        )
        .bind(tenant_id)
        .bind(since)
        .fetch_all(pool)
        .await
    }

    /// Count revocations for a tenant.
    pub async fn count_by_tenant(pool: &sqlx::PgPool, tenant_id: Uuid) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM certificate_revocations
            WHERE tenant_id = $1
            "#,
        )
        .bind(tenant_id)
        .fetch_one(pool)
        .await
    }

    /// Create a revocation record.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        certificate_id: Uuid,
        serial_number: &str,
        reason_code: i16,
        revoked_by: Uuid,
        notes: Option<&str>,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r#"
            INSERT INTO certificate_revocations (
                tenant_id, certificate_id, serial_number, reason_code,
                revoked_at, revoked_by, notes
            )
            VALUES ($1, $2, $3, $4, NOW(), $5, $6)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(certificate_id)
        .bind(serial_number)
        .bind(reason_code)
        .bind(revoked_by)
        .bind(notes)
        .fetch_one(pool)
        .await
    }

    /// Delete a revocation record (admin only, for corrections).
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM certificate_revocations
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
    fn test_revocation_reason_code_from_i16() {
        assert_eq!(
            RevocationReasonCode::from_i16(0),
            Some(RevocationReasonCode::Unspecified)
        );
        assert_eq!(
            RevocationReasonCode::from_i16(1),
            Some(RevocationReasonCode::KeyCompromise)
        );
        assert_eq!(
            RevocationReasonCode::from_i16(4),
            Some(RevocationReasonCode::Superseded)
        );
        assert_eq!(
            RevocationReasonCode::from_i16(5),
            Some(RevocationReasonCode::CessationOfOperation)
        );
        assert_eq!(
            RevocationReasonCode::from_i16(10),
            Some(RevocationReasonCode::AaCompromise)
        );
        assert_eq!(RevocationReasonCode::from_i16(11), None);
        assert_eq!(RevocationReasonCode::from_i16(-1), None);
    }

    #[test]
    fn test_revocation_reason_code_description() {
        assert_eq!(
            RevocationReasonCode::Unspecified.description(),
            "Unspecified"
        );
        assert_eq!(
            RevocationReasonCode::KeyCompromise.description(),
            "Key Compromise"
        );
        assert_eq!(
            RevocationReasonCode::CessationOfOperation.description(),
            "Cessation of Operation"
        );
    }

    #[test]
    fn test_revocation_reason_code_display() {
        assert_eq!(
            format!("{}", RevocationReasonCode::Unspecified),
            "Unspecified"
        );
        assert_eq!(
            format!("{}", RevocationReasonCode::KeyCompromise),
            "Key Compromise"
        );
    }

    #[test]
    fn test_revoke_certificate_request_default() {
        let request = RevokeCertificateRequest::default();
        assert_eq!(request.reason_code, 0);
        assert!(request.notes.is_none());
    }

    #[test]
    fn test_certificate_revocation_helper_methods() {
        let revocation = CertificateRevocation {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            certificate_id: Uuid::new_v4(),
            serial_number: "01ABCDEF".to_string(),
            reason_code: 1,
            revoked_at: Utc::now(),
            revoked_by: Uuid::new_v4(),
            notes: Some("Key was compromised".to_string()),
            created_at: Utc::now(),
        };

        assert_eq!(
            revocation.reason(),
            Some(RevocationReasonCode::KeyCompromise)
        );
        assert_eq!(revocation.reason_description(), "Key Compromise");
    }

    #[test]
    fn test_certificate_revocation_unknown_reason() {
        let revocation = CertificateRevocation {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            certificate_id: Uuid::new_v4(),
            serial_number: "02UNKNOWN".to_string(),
            reason_code: 99, // Invalid reason code
            revoked_at: Utc::now(),
            revoked_by: Uuid::new_v4(),
            notes: None,
            created_at: Utc::now(),
        };

        assert_eq!(revocation.reason(), None);
        assert_eq!(revocation.reason_description(), "Unknown");
    }

    #[test]
    fn test_certificate_revocation_filter() {
        let filter = CertificateRevocationFilter {
            certificate_id: Some(Uuid::new_v4()),
            reason_code: Some(1),
            revoked_by: None,
            revoked_after: Some(Utc::now() - chrono::Duration::days(7)),
            revoked_before: None,
        };

        assert!(filter.certificate_id.is_some());
        assert_eq!(filter.reason_code, Some(1));
        assert!(filter.revoked_by.is_none());
        assert!(filter.revoked_after.is_some());
    }
}
