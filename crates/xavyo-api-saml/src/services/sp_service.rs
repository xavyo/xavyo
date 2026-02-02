//! Service Provider configuration service

use crate::error::{SamlError, SamlResult};
use sqlx::PgPool;
use uuid::Uuid;
use xavyo_db::models::{
    CreateServiceProviderRequest, SamlServiceProvider, TenantIdpCertificate,
    UpdateServiceProviderRequest, UploadCertificateRequest,
};

/// Service for SP configuration CRUD operations
pub struct SpService {
    pool: PgPool,
}

impl SpService {
    /// Create a new SpService
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get SP by ID
    pub async fn get_sp(&self, tenant_id: Uuid, sp_id: Uuid) -> SamlResult<SamlServiceProvider> {
        sqlx::query_as::<_, SamlServiceProvider>(
            r#"
            SELECT id, tenant_id, entity_id, name, acs_urls, certificate,
                   attribute_mapping, name_id_format, sign_assertions,
                   validate_signatures, assertion_validity_seconds, enabled,
                   metadata_url, created_at, updated_at
            FROM saml_service_providers
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(sp_id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| SamlError::ServiceProviderNotFound(sp_id.to_string()))
    }

    /// Get SP by entity ID
    pub async fn get_sp_by_entity_id(
        &self,
        tenant_id: Uuid,
        entity_id: &str,
    ) -> SamlResult<SamlServiceProvider> {
        sqlx::query_as::<_, SamlServiceProvider>(
            r#"
            SELECT id, tenant_id, entity_id, name, acs_urls, certificate,
                   attribute_mapping, name_id_format, sign_assertions,
                   validate_signatures, assertion_validity_seconds, enabled,
                   metadata_url, created_at, updated_at
            FROM saml_service_providers
            WHERE entity_id = $1 AND tenant_id = $2
            "#,
        )
        .bind(entity_id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| SamlError::UnknownServiceProvider(entity_id.to_string()))
    }

    /// List all SPs for a tenant
    pub async fn list_sps(
        &self,
        tenant_id: Uuid,
        limit: i32,
        offset: i32,
        enabled: Option<bool>,
    ) -> SamlResult<(Vec<SamlServiceProvider>, i64)> {
        let sps = if let Some(enabled_filter) = enabled {
            sqlx::query_as::<_, SamlServiceProvider>(
                r#"
                SELECT id, tenant_id, entity_id, name, acs_urls, certificate,
                       attribute_mapping, name_id_format, sign_assertions,
                       validate_signatures, assertion_validity_seconds, enabled,
                       metadata_url, created_at, updated_at
                FROM saml_service_providers
                WHERE tenant_id = $1 AND enabled = $2
                ORDER BY name ASC
                LIMIT $3 OFFSET $4
                "#,
            )
            .bind(tenant_id)
            .bind(enabled_filter)
            .bind(limit as i64)
            .bind(offset as i64)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query_as::<_, SamlServiceProvider>(
                r#"
                SELECT id, tenant_id, entity_id, name, acs_urls, certificate,
                       attribute_mapping, name_id_format, sign_assertions,
                       validate_signatures, assertion_validity_seconds, enabled,
                       metadata_url, created_at, updated_at
                FROM saml_service_providers
                WHERE tenant_id = $1
                ORDER BY name ASC
                LIMIT $2 OFFSET $3
                "#,
            )
            .bind(tenant_id)
            .bind(limit as i64)
            .bind(offset as i64)
            .fetch_all(&self.pool)
            .await?
        };

        let total: i64 = if let Some(enabled_filter) = enabled {
            sqlx::query_scalar(
                r#"SELECT COUNT(*) FROM saml_service_providers WHERE tenant_id = $1 AND enabled = $2"#,
            )
            .bind(tenant_id)
            .bind(enabled_filter)
            .fetch_one(&self.pool)
            .await?
        } else {
            sqlx::query_scalar(
                r#"SELECT COUNT(*) FROM saml_service_providers WHERE tenant_id = $1"#,
            )
            .bind(tenant_id)
            .fetch_one(&self.pool)
            .await?
        };

        Ok((sps, total))
    }

    /// Create a new SP
    pub async fn create_sp(
        &self,
        tenant_id: Uuid,
        req: CreateServiceProviderRequest,
    ) -> SamlResult<SamlServiceProvider> {
        // Check for duplicate entity_id
        let existing: Option<Uuid> = sqlx::query_scalar(
            r#"SELECT id FROM saml_service_providers WHERE tenant_id = $1 AND entity_id = $2"#,
        )
        .bind(tenant_id)
        .bind(&req.entity_id)
        .fetch_optional(&self.pool)
        .await?;

        if existing.is_some() {
            return Err(SamlError::EntityIdConflict(req.entity_id));
        }

        // Validate ACS URLs
        if req.acs_urls.is_empty() {
            return Err(SamlError::InvalidAuthnRequest(
                "At least one ACS URL is required".to_string(),
            ));
        }

        let attribute_mapping = req.attribute_mapping.unwrap_or(serde_json::json!({}));

        let sp = sqlx::query_as::<_, SamlServiceProvider>(
            r#"
            INSERT INTO saml_service_providers
                (tenant_id, entity_id, name, acs_urls, certificate, attribute_mapping,
                 name_id_format, sign_assertions, validate_signatures,
                 assertion_validity_seconds, metadata_url)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            RETURNING id, tenant_id, entity_id, name, acs_urls, certificate,
                      attribute_mapping, name_id_format, sign_assertions,
                      validate_signatures, assertion_validity_seconds, enabled,
                      metadata_url, created_at, updated_at
            "#,
        )
        .bind(tenant_id)
        .bind(&req.entity_id)
        .bind(&req.name)
        .bind(&req.acs_urls)
        .bind(&req.certificate)
        .bind(&attribute_mapping)
        .bind(&req.name_id_format)
        .bind(req.sign_assertions)
        .bind(req.validate_signatures)
        .bind(req.assertion_validity_seconds)
        .bind(&req.metadata_url)
        .fetch_one(&self.pool)
        .await?;

        tracing::info!(
            tenant_id = %tenant_id,
            sp_id = %sp.id,
            entity_id = %sp.entity_id,
            "SAML SP created"
        );

        Ok(sp)
    }

    /// Update an SP
    pub async fn update_sp(
        &self,
        tenant_id: Uuid,
        sp_id: Uuid,
        req: UpdateServiceProviderRequest,
    ) -> SamlResult<SamlServiceProvider> {
        // First verify SP exists
        let existing = self.get_sp(tenant_id, sp_id).await?;

        let name = req.name.unwrap_or(existing.name);
        let acs_urls = req.acs_urls.unwrap_or(existing.acs_urls);
        let certificate = req.certificate.or(existing.certificate);
        let attribute_mapping = req.attribute_mapping.unwrap_or(existing.attribute_mapping);
        let name_id_format = req.name_id_format.unwrap_or(existing.name_id_format);
        let sign_assertions = req.sign_assertions.unwrap_or(existing.sign_assertions);
        let validate_signatures = req
            .validate_signatures
            .unwrap_or(existing.validate_signatures);
        let assertion_validity_seconds = req
            .assertion_validity_seconds
            .unwrap_or(existing.assertion_validity_seconds);
        let enabled = req.enabled.unwrap_or(existing.enabled);
        let metadata_url = req.metadata_url.or(existing.metadata_url);

        let sp = sqlx::query_as::<_, SamlServiceProvider>(
            r#"
            UPDATE saml_service_providers
            SET name = $3, acs_urls = $4, certificate = $5, attribute_mapping = $6,
                name_id_format = $7, sign_assertions = $8, validate_signatures = $9,
                assertion_validity_seconds = $10, enabled = $11, metadata_url = $12
            WHERE id = $1 AND tenant_id = $2
            RETURNING id, tenant_id, entity_id, name, acs_urls, certificate,
                      attribute_mapping, name_id_format, sign_assertions,
                      validate_signatures, assertion_validity_seconds, enabled,
                      metadata_url, created_at, updated_at
            "#,
        )
        .bind(sp_id)
        .bind(tenant_id)
        .bind(&name)
        .bind(&acs_urls)
        .bind(&certificate)
        .bind(&attribute_mapping)
        .bind(&name_id_format)
        .bind(sign_assertions)
        .bind(validate_signatures)
        .bind(assertion_validity_seconds)
        .bind(enabled)
        .bind(&metadata_url)
        .fetch_one(&self.pool)
        .await?;

        tracing::info!(
            tenant_id = %tenant_id,
            sp_id = %sp_id,
            "SAML SP updated"
        );

        Ok(sp)
    }

    /// Delete an SP
    pub async fn delete_sp(&self, tenant_id: Uuid, sp_id: Uuid) -> SamlResult<()> {
        let result =
            sqlx::query(r#"DELETE FROM saml_service_providers WHERE id = $1 AND tenant_id = $2"#)
                .bind(sp_id)
                .bind(tenant_id)
                .execute(&self.pool)
                .await?;

        if result.rows_affected() == 0 {
            return Err(SamlError::ServiceProviderNotFound(sp_id.to_string()));
        }

        tracing::info!(
            tenant_id = %tenant_id,
            sp_id = %sp_id,
            "SAML SP deleted"
        );

        Ok(())
    }

    // Certificate management

    /// Get active certificate for tenant
    pub async fn get_active_certificate(
        &self,
        tenant_id: Uuid,
    ) -> SamlResult<TenantIdpCertificate> {
        sqlx::query_as::<_, TenantIdpCertificate>(
            r#"
            SELECT id, tenant_id, certificate, private_key_encrypted,
                   key_id, subject_dn, issuer_dn, not_before, not_after,
                   is_active, created_at
            FROM tenant_idp_certificates
            WHERE tenant_id = $1 AND is_active = TRUE
            "#,
        )
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(SamlError::NoActiveCertificate)
    }

    /// List all certificates for tenant
    pub async fn list_certificates(
        &self,
        tenant_id: Uuid,
    ) -> SamlResult<Vec<TenantIdpCertificate>> {
        let certs = sqlx::query_as::<_, TenantIdpCertificate>(
            r#"
            SELECT id, tenant_id, certificate, private_key_encrypted,
                   key_id, subject_dn, issuer_dn, not_before, not_after,
                   is_active, created_at
            FROM tenant_idp_certificates
            WHERE tenant_id = $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(certs)
    }

    /// Upload a new certificate
    pub async fn upload_certificate(
        &self,
        tenant_id: Uuid,
        req: UploadCertificateRequest,
        encryption_key: &[u8],
    ) -> SamlResult<TenantIdpCertificate> {
        use crate::saml::SigningCredentials;

        // Parse and validate certificate/key pair
        let creds = SigningCredentials::from_pem(&req.certificate, &req.private_key)?;

        // Encrypt private key
        let encrypted_key = encrypt_private_key(req.private_key.as_bytes(), encryption_key)?;

        let cert = sqlx::query_as::<_, TenantIdpCertificate>(
            r#"
            INSERT INTO tenant_idp_certificates
                (tenant_id, certificate, private_key_encrypted, key_id,
                 subject_dn, issuer_dn, not_before, not_after, is_active)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, TRUE)
            RETURNING id, tenant_id, certificate, private_key_encrypted,
                      key_id, subject_dn, issuer_dn, not_before, not_after,
                      is_active, created_at
            "#,
        )
        .bind(tenant_id)
        .bind(&req.certificate)
        .bind(&encrypted_key)
        .bind(creds.key_id())
        .bind(creds.subject_dn())
        .bind(creds.issuer_dn())
        .bind(creds.not_before())
        .bind(creds.not_after())
        .fetch_one(&self.pool)
        .await?;

        tracing::info!(
            tenant_id = %tenant_id,
            cert_id = %cert.id,
            key_id = %cert.key_id,
            "IdP certificate uploaded"
        );

        Ok(cert)
    }

    /// Activate a certificate
    pub async fn activate_certificate(
        &self,
        tenant_id: Uuid,
        cert_id: Uuid,
    ) -> SamlResult<TenantIdpCertificate> {
        let cert = sqlx::query_as::<_, TenantIdpCertificate>(
            r#"
            UPDATE tenant_idp_certificates
            SET is_active = TRUE
            WHERE id = $1 AND tenant_id = $2
            RETURNING id, tenant_id, certificate, private_key_encrypted,
                      key_id, subject_dn, issuer_dn, not_before, not_after,
                      is_active, created_at
            "#,
        )
        .bind(cert_id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| SamlError::CertificateNotFound(cert_id.to_string()))?;

        tracing::info!(
            tenant_id = %tenant_id,
            cert_id = %cert_id,
            "IdP certificate activated"
        );

        Ok(cert)
    }

    /// Decrypt private key for signing
    pub fn decrypt_private_key(
        &self,
        encrypted: &[u8],
        encryption_key: &[u8],
    ) -> SamlResult<String> {
        decrypt_private_key(encrypted, encryption_key)
    }
}

/// Encrypt private key using AES-256-GCM
fn encrypt_private_key(key_pem: &[u8], encryption_key: &[u8]) -> SamlResult<Vec<u8>> {
    use openssl::symm::{encrypt_aead, Cipher};

    let cipher = Cipher::aes_256_gcm();

    // Generate random IV
    let mut iv = vec![0u8; 12];
    openssl::rand::rand_bytes(&mut iv)
        .map_err(|e| SamlError::InternalError(format!("Failed to generate IV: {}", e)))?;

    let mut tag = vec![0u8; 16];

    let ciphertext = encrypt_aead(cipher, encryption_key, Some(&iv), &[], key_pem, &mut tag)
        .map_err(|e| SamlError::InternalError(format!("Encryption failed: {}", e)))?;

    // Format: IV (12 bytes) + tag (16 bytes) + ciphertext
    let mut result = iv;
    result.extend(&tag);
    result.extend(&ciphertext);

    Ok(result)
}

/// Decrypt private key using AES-256-GCM
fn decrypt_private_key(encrypted: &[u8], encryption_key: &[u8]) -> SamlResult<String> {
    use openssl::symm::{decrypt_aead, Cipher};

    if encrypted.len() < 28 {
        return Err(SamlError::PrivateKeyError(
            "Invalid encrypted data".to_string(),
        ));
    }

    let iv = &encrypted[0..12];
    let tag = &encrypted[12..28];
    let ciphertext = &encrypted[28..];

    let cipher = Cipher::aes_256_gcm();

    let plaintext = decrypt_aead(cipher, encryption_key, Some(iv), &[], ciphertext, tag)
        .map_err(|e| SamlError::PrivateKeyError(format!("Decryption failed: {}", e)))?;

    String::from_utf8(plaintext)
        .map_err(|e| SamlError::PrivateKeyError(format!("Invalid UTF-8: {}", e)))
}
