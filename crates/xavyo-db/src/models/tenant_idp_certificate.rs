//! Tenant IdP Certificate model

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Represents a tenant's IdP signing certificate
#[derive(Debug, Clone, Serialize, FromRow)]
pub struct TenantIdpCertificate {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub certificate: String,
    #[serde(skip_serializing)]
    pub private_key_encrypted: Vec<u8>,
    pub key_id: String,
    pub subject_dn: String,
    pub issuer_dn: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
}

/// Request to upload a new certificate
#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UploadCertificateRequest {
    pub certificate: String,
    pub private_key: String,
}

/// Public certificate info (without private key)
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CertificateInfo {
    pub id: Uuid,
    pub key_id: String,
    pub subject_dn: String,
    pub issuer_dn: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
}

impl From<TenantIdpCertificate> for CertificateInfo {
    fn from(cert: TenantIdpCertificate) -> Self {
        Self {
            id: cert.id,
            key_id: cert.key_id,
            subject_dn: cert.subject_dn,
            issuer_dn: cert.issuer_dn,
            not_before: cert.not_before,
            not_after: cert.not_after,
            is_active: cert.is_active,
            created_at: cert.created_at,
        }
    }
}

impl TenantIdpCertificate {
    /// Check if certificate is currently valid
    pub fn is_valid(&self) -> bool {
        let now = Utc::now();
        now >= self.not_before && now <= self.not_after
    }

    /// Check if certificate is expiring soon (within 30 days)
    pub fn is_expiring_soon(&self) -> bool {
        let thirty_days = chrono::Duration::days(30);
        let expiry_threshold = Utc::now() + thirty_days;
        self.not_after <= expiry_threshold
    }
}
