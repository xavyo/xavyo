//! Certificate Authority model for PKI (F127).
//!
//! Represents Certificate Authority configurations for issuing
//! X.509 certificates to AI agents.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Certificate Authority type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaType {
    /// Internal CA using rcgen for certificate generation.
    Internal,
    /// External CA using step-ca.
    StepCa,
    /// External CA using HashiCorp Vault PKI.
    VaultPki,
}

impl std::fmt::Display for CaType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CaType::Internal => write!(f, "internal"),
            CaType::StepCa => write!(f, "step_ca"),
            CaType::VaultPki => write!(f, "vault_pki"),
        }
    }
}

impl std::str::FromStr for CaType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "internal" => Ok(CaType::Internal),
            "step_ca" => Ok(CaType::StepCa),
            "vault_pki" => Ok(CaType::VaultPki),
            _ => Err(format!("Invalid CA type: {}", s)),
        }
    }
}

/// A Certificate Authority configuration.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CertificateAuthority {
    /// Unique identifier for the CA.
    pub id: Uuid,

    /// The tenant this CA belongs to.
    pub tenant_id: Uuid,

    /// CA display name (unique per tenant).
    pub name: String,

    /// CA type (internal, step_ca, vault_pki).
    pub ca_type: String,

    /// CA certificate in PEM format.
    pub certificate_pem: String,

    /// Certificate chain in PEM format (intermediate certs).
    pub chain_pem: Option<String>,

    /// AES-256-GCM encrypted private key (internal CA only).
    pub private_key_encrypted: Option<Vec<u8>>,

    /// Reference to private key in xavyo-secrets (alternative to encrypted key).
    pub private_key_ref: Option<String>,

    /// Provider-specific configuration (step-ca URL, Vault mount, etc.).
    pub external_config: Option<serde_json::Value>,

    /// Whether this CA is active and can issue certificates.
    pub is_active: bool,

    /// Whether this is the default CA for the tenant.
    pub is_default: bool,

    /// Maximum certificate validity period in days.
    pub max_validity_days: i32,

    /// Subject Distinguished Name of the CA.
    pub subject_dn: String,

    /// CA certificate not valid before.
    pub not_before: DateTime<Utc>,

    /// CA certificate not valid after.
    pub not_after: DateTime<Utc>,

    /// CRL distribution point URL.
    pub crl_url: Option<String>,

    /// OCSP responder URL.
    pub ocsp_url: Option<String>,

    /// When the CA was created.
    pub created_at: DateTime<Utc>,

    /// When the CA was last updated.
    pub updated_at: DateTime<Utc>,
}

impl CertificateAuthority {
    /// Returns the CA type as an enum.
    pub fn ca_type_enum(&self) -> Result<CaType, String> {
        self.ca_type.parse()
    }

    /// Check if the CA is internal.
    pub fn is_internal(&self) -> bool {
        self.ca_type == "internal"
    }

    /// Check if the CA certificate has expired.
    pub fn is_expired(&self) -> bool {
        self.not_after < Utc::now()
    }

    /// Check if the CA certificate is not yet valid.
    pub fn is_not_yet_valid(&self) -> bool {
        self.not_before > Utc::now()
    }

    /// Check if the CA is usable (active, not expired, valid).
    pub fn is_usable(&self) -> bool {
        self.is_active && !self.is_expired() && !self.is_not_yet_valid()
    }
}

/// Request to create an internal CA.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreateInternalCa {
    /// CA display name (unique per tenant).
    pub name: String,

    /// Subject Distinguished Name for the CA certificate.
    pub subject_dn: String,

    /// Validity period in days for the CA certificate.
    #[serde(default = "default_ca_validity_days")]
    pub validity_days: i32,

    /// Maximum certificate validity period in days.
    #[serde(default = "default_max_cert_validity_days")]
    pub max_validity_days: i32,

    /// Key algorithm (rsa2048, rsa4096, ecdsa_p256, ecdsa_p384).
    #[serde(default = "default_key_algorithm")]
    pub key_algorithm: String,

    /// Whether this should be the default CA.
    #[serde(default)]
    pub is_default: bool,

    /// CRL distribution point URL.
    pub crl_url: Option<String>,

    /// OCSP responder URL.
    pub ocsp_url: Option<String>,
}

fn default_ca_validity_days() -> i32 {
    3650 // 10 years
}

fn default_max_cert_validity_days() -> i32 {
    365 // 1 year
}

fn default_key_algorithm() -> String {
    "ecdsa_p256".to_string()
}

/// Request to create an external CA configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreateExternalCa {
    /// CA display name (unique per tenant).
    pub name: String,

    /// CA type (step_ca, vault_pki).
    pub ca_type: String,

    /// CA certificate in PEM format.
    pub certificate_pem: String,

    /// Certificate chain in PEM format.
    pub chain_pem: Option<String>,

    /// Provider-specific configuration.
    pub external_config: serde_json::Value,

    /// Maximum certificate validity period in days.
    #[serde(default = "default_max_cert_validity_days")]
    pub max_validity_days: i32,

    /// Whether this should be the default CA.
    #[serde(default)]
    pub is_default: bool,

    /// CRL distribution point URL.
    pub crl_url: Option<String>,

    /// OCSP responder URL.
    pub ocsp_url: Option<String>,
}

/// Request to update a CA.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UpdateCertificateAuthority {
    /// Updated CA name.
    pub name: Option<String>,

    /// Updated active status.
    pub is_active: Option<bool>,

    /// Updated default status.
    pub is_default: Option<bool>,

    /// Updated max validity days.
    pub max_validity_days: Option<i32>,

    /// Updated CRL URL.
    pub crl_url: Option<Option<String>>,

    /// Updated OCSP URL.
    pub ocsp_url: Option<Option<String>>,

    /// Updated external configuration.
    pub external_config: Option<serde_json::Value>,
}

/// Filter options for listing CAs.
#[derive(Debug, Clone, Default)]
pub struct CertificateAuthorityFilter {
    /// Filter by CA type.
    pub ca_type: Option<String>,

    /// Filter by active status.
    pub is_active: Option<bool>,

    /// Filter by default status.
    pub is_default: Option<bool>,

    /// Search by name prefix.
    pub name_prefix: Option<String>,
}

impl CertificateAuthority {
    /// Find a CA by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM certificate_authorities
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find a CA by ID without tenant restriction.
    ///
    /// This is used during mTLS validation where the tenant ID is extracted
    /// from the certificate itself, not from the request context.
    ///
    /// **Security Note**: This method bypasses tenant isolation and should
    /// only be used in mTLS validation contexts where the certificate's
    /// embedded tenant claim has already been verified.
    pub async fn find_by_id_any_tenant(
        pool: &sqlx::PgPool,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM certificate_authorities
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(pool)
        .await
    }

    /// Find a CA by name within a tenant.
    pub async fn find_by_name(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        name: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM certificate_authorities
            WHERE tenant_id = $1 AND name = $2
            "#,
        )
        .bind(tenant_id)
        .bind(name)
        .fetch_optional(pool)
        .await
    }

    /// Find the default CA for a tenant.
    pub async fn find_default(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM certificate_authorities
            WHERE tenant_id = $1 AND is_default = true AND is_active = true
            "#,
        )
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List CAs for a tenant with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &CertificateAuthorityFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT * FROM certificate_authorities
            WHERE tenant_id = $1
            "#,
        );
        let mut param_count = 1;

        if filter.ca_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND ca_type = ${}", param_count));
        }

        if filter.is_active.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND is_active = ${}", param_count));
        }

        if filter.is_default.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND is_default = ${}", param_count));
        }

        if filter.name_prefix.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND name ILIKE ${} || '%'", param_count));
        }

        query.push_str(&format!(
            " ORDER BY is_default DESC, name LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, CertificateAuthority>(&query).bind(tenant_id);

        if let Some(ref ca_type) = filter.ca_type {
            q = q.bind(ca_type);
        }
        if let Some(is_active) = filter.is_active {
            q = q.bind(is_active);
        }
        if let Some(is_default) = filter.is_default {
            q = q.bind(is_default);
        }
        if let Some(ref prefix) = filter.name_prefix {
            q = q.bind(prefix);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count CAs in a tenant with filtering.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &CertificateAuthorityFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT COUNT(*) FROM certificate_authorities
            WHERE tenant_id = $1
            "#,
        );
        let mut param_count = 1;

        if filter.ca_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND ca_type = ${}", param_count));
        }

        if filter.is_active.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND is_active = ${}", param_count));
        }

        if filter.is_default.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND is_default = ${}", param_count));
        }

        if filter.name_prefix.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND name ILIKE ${} || '%'", param_count));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(ref ca_type) = filter.ca_type {
            q = q.bind(ca_type);
        }
        if let Some(is_active) = filter.is_active {
            q = q.bind(is_active);
        }
        if let Some(is_default) = filter.is_default {
            q = q.bind(is_default);
        }
        if let Some(ref prefix) = filter.name_prefix {
            q = q.bind(prefix);
        }

        q.fetch_one(pool).await
    }

    /// Create an internal CA (certificate and key generated externally).
    pub async fn create_internal(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        name: &str,
        certificate_pem: &str,
        private_key_encrypted: Vec<u8>,
        subject_dn: &str,
        not_before: DateTime<Utc>,
        not_after: DateTime<Utc>,
        max_validity_days: i32,
        is_default: bool,
        crl_url: Option<&str>,
        ocsp_url: Option<&str>,
    ) -> Result<Self, sqlx::Error> {
        // If setting as default, clear other defaults first
        if is_default {
            sqlx::query(
                r#"
                UPDATE certificate_authorities
                SET is_default = false, updated_at = NOW()
                WHERE tenant_id = $1 AND is_default = true
                "#,
            )
            .bind(tenant_id)
            .execute(pool)
            .await?;
        }

        sqlx::query_as(
            r#"
            INSERT INTO certificate_authorities (
                tenant_id, name, ca_type, certificate_pem, private_key_encrypted,
                subject_dn, not_before, not_after, max_validity_days, is_default,
                crl_url, ocsp_url
            )
            VALUES ($1, $2, 'internal', $3, $4, $5, $6, $7, $8, $9, $10, $11)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(name)
        .bind(certificate_pem)
        .bind(private_key_encrypted)
        .bind(subject_dn)
        .bind(not_before)
        .bind(not_after)
        .bind(max_validity_days)
        .bind(is_default)
        .bind(crl_url)
        .bind(ocsp_url)
        .fetch_one(pool)
        .await
    }

    /// Create an external CA configuration.
    pub async fn create_external(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateExternalCa,
        subject_dn: &str,
        not_before: DateTime<Utc>,
        not_after: DateTime<Utc>,
    ) -> Result<Self, sqlx::Error> {
        // If setting as default, clear other defaults first
        if input.is_default {
            sqlx::query(
                r#"
                UPDATE certificate_authorities
                SET is_default = false, updated_at = NOW()
                WHERE tenant_id = $1 AND is_default = true
                "#,
            )
            .bind(tenant_id)
            .execute(pool)
            .await?;
        }

        sqlx::query_as(
            r#"
            INSERT INTO certificate_authorities (
                tenant_id, name, ca_type, certificate_pem, chain_pem, external_config,
                subject_dn, not_before, not_after, max_validity_days, is_default,
                crl_url, ocsp_url
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(&input.name)
        .bind(&input.ca_type)
        .bind(&input.certificate_pem)
        .bind(&input.chain_pem)
        .bind(&input.external_config)
        .bind(subject_dn)
        .bind(not_before)
        .bind(not_after)
        .bind(input.max_validity_days)
        .bind(input.is_default)
        .bind(&input.crl_url)
        .bind(&input.ocsp_url)
        .fetch_one(pool)
        .await
    }

    /// Update a CA.
    pub async fn update(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateCertificateAuthority,
    ) -> Result<Option<Self>, sqlx::Error> {
        // If setting as default, clear other defaults first
        if input.is_default == Some(true) {
            sqlx::query(
                r#"
                UPDATE certificate_authorities
                SET is_default = false, updated_at = NOW()
                WHERE tenant_id = $1 AND is_default = true AND id != $2
                "#,
            )
            .bind(tenant_id)
            .bind(id)
            .execute(pool)
            .await?;
        }

        let mut updates = vec!["updated_at = NOW()".to_string()];
        let mut param_idx = 3;

        if input.name.is_some() {
            updates.push(format!("name = ${}", param_idx));
            param_idx += 1;
        }
        if input.is_active.is_some() {
            updates.push(format!("is_active = ${}", param_idx));
            param_idx += 1;
        }
        if input.is_default.is_some() {
            updates.push(format!("is_default = ${}", param_idx));
            param_idx += 1;
        }
        if input.max_validity_days.is_some() {
            updates.push(format!("max_validity_days = ${}", param_idx));
            param_idx += 1;
        }
        if input.crl_url.is_some() {
            updates.push(format!("crl_url = ${}", param_idx));
            param_idx += 1;
        }
        if input.ocsp_url.is_some() {
            updates.push(format!("ocsp_url = ${}", param_idx));
            param_idx += 1;
        }
        if input.external_config.is_some() {
            updates.push(format!("external_config = ${}", param_idx));
            // param_idx += 1;
        }

        let query = format!(
            "UPDATE certificate_authorities SET {} WHERE id = $1 AND tenant_id = $2 RETURNING *",
            updates.join(", ")
        );

        let mut q = sqlx::query_as::<_, CertificateAuthority>(&query)
            .bind(id)
            .bind(tenant_id);

        if let Some(ref name) = input.name {
            q = q.bind(name);
        }
        if let Some(is_active) = input.is_active {
            q = q.bind(is_active);
        }
        if let Some(is_default) = input.is_default {
            q = q.bind(is_default);
        }
        if let Some(max_validity_days) = input.max_validity_days {
            q = q.bind(max_validity_days);
        }
        if let Some(ref crl_opt) = input.crl_url {
            q = q.bind(crl_opt.clone());
        }
        if let Some(ref ocsp_opt) = input.ocsp_url {
            q = q.bind(ocsp_opt.clone());
        }
        if let Some(ref external_config) = input.external_config {
            q = q.bind(external_config);
        }

        q.fetch_optional(pool).await
    }

    /// Delete a CA.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM certificate_authorities
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Set a CA as the default for the tenant.
    pub async fn set_default(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        // Clear other defaults
        sqlx::query(
            r#"
            UPDATE certificate_authorities
            SET is_default = false, updated_at = NOW()
            WHERE tenant_id = $1 AND is_default = true
            "#,
        )
        .bind(tenant_id)
        .execute(pool)
        .await?;

        // Set new default
        sqlx::query_as(
            r#"
            UPDATE certificate_authorities
            SET is_default = true, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ca_type_display() {
        assert_eq!(CaType::Internal.to_string(), "internal");
        assert_eq!(CaType::StepCa.to_string(), "step_ca");
        assert_eq!(CaType::VaultPki.to_string(), "vault_pki");
    }

    #[test]
    fn test_ca_type_from_str() {
        assert_eq!("internal".parse::<CaType>().unwrap(), CaType::Internal);
        assert_eq!("step_ca".parse::<CaType>().unwrap(), CaType::StepCa);
        assert_eq!("vault_pki".parse::<CaType>().unwrap(), CaType::VaultPki);
        assert!("invalid".parse::<CaType>().is_err());
    }

    #[test]
    fn test_create_internal_ca_defaults() {
        let input = CreateInternalCa {
            name: "test-ca".to_string(),
            subject_dn: "CN=Test CA,O=Xavyo,C=FR".to_string(),
            validity_days: default_ca_validity_days(),
            max_validity_days: default_max_cert_validity_days(),
            key_algorithm: default_key_algorithm(),
            is_default: false,
            crl_url: None,
            ocsp_url: None,
        };

        assert_eq!(input.validity_days, 3650);
        assert_eq!(input.max_validity_days, 365);
        assert_eq!(input.key_algorithm, "ecdsa_p256");
    }

    #[test]
    fn test_certificate_authority_helper_methods() {
        use chrono::Duration;

        let ca = CertificateAuthority {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "test-ca".to_string(),
            ca_type: "internal".to_string(),
            certificate_pem: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----".to_string(),
            chain_pem: None,
            private_key_encrypted: Some(vec![1, 2, 3]),
            private_key_ref: None,
            external_config: None,
            is_active: true,
            is_default: true,
            max_validity_days: 365,
            subject_dn: "CN=Test CA,O=Xavyo".to_string(),
            not_before: Utc::now() - Duration::days(1),
            not_after: Utc::now() + Duration::days(365),
            crl_url: Some("https://crl.xavyo.io/ca.crl".to_string()),
            ocsp_url: Some("https://ocsp.xavyo.io".to_string()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        assert!(ca.is_internal());
        assert!(!ca.is_expired());
        assert!(!ca.is_not_yet_valid());
        assert!(ca.is_usable());
        assert_eq!(ca.ca_type_enum().unwrap(), CaType::Internal);
    }

    #[test]
    fn test_certificate_authority_expired() {
        use chrono::Duration;

        let expired_ca = CertificateAuthority {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "expired-ca".to_string(),
            ca_type: "internal".to_string(),
            certificate_pem: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----".to_string(),
            chain_pem: None,
            private_key_encrypted: Some(vec![1, 2, 3]),
            private_key_ref: None,
            external_config: None,
            is_active: true,
            is_default: false,
            max_validity_days: 365,
            subject_dn: "CN=Expired CA".to_string(),
            not_before: Utc::now() - Duration::days(400),
            not_after: Utc::now() - Duration::days(35),
            crl_url: None,
            ocsp_url: None,
            created_at: Utc::now() - Duration::days(400),
            updated_at: Utc::now() - Duration::days(400),
        };

        assert!(expired_ca.is_expired());
        assert!(!expired_ca.is_usable());
    }

    #[test]
    fn test_update_certificate_authority_struct() {
        let update = UpdateCertificateAuthority {
            name: Some("renamed-ca".to_string()),
            is_active: Some(false),
            ..Default::default()
        };

        assert!(update.name.is_some());
        assert!(update.is_active.is_some());
        assert!(update.is_default.is_none());
    }

    #[test]
    fn test_certificate_authority_filter() {
        let filter = CertificateAuthorityFilter {
            ca_type: Some("internal".to_string()),
            is_active: Some(true),
            is_default: None,
            name_prefix: Some("test".to_string()),
        };

        assert_eq!(filter.ca_type, Some("internal".to_string()));
        assert_eq!(filter.is_active, Some(true));
        assert!(filter.is_default.is_none());
    }
}
