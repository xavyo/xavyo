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
    /// Create a new `SpService`
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get SP by ID
    pub async fn get_sp(&self, tenant_id: Uuid, sp_id: Uuid) -> SamlResult<SamlServiceProvider> {
        sqlx::query_as::<_, SamlServiceProvider>(
            r"
            SELECT id, tenant_id, entity_id, name, acs_urls, certificate,
                   attribute_mapping, name_id_format, sign_assertions,
                   validate_signatures, assertion_validity_seconds, enabled,
                   metadata_url, created_at, updated_at,
                   group_attribute_name, group_value_format, group_filter,
                   include_groups, omit_empty_groups, group_dn_base,
                   slo_url, slo_binding
            FROM saml_service_providers
            WHERE id = $1 AND tenant_id = $2
            ",
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
            r"
            SELECT id, tenant_id, entity_id, name, acs_urls, certificate,
                   attribute_mapping, name_id_format, sign_assertions,
                   validate_signatures, assertion_validity_seconds, enabled,
                   metadata_url, created_at, updated_at,
                   group_attribute_name, group_value_format, group_filter,
                   include_groups, omit_empty_groups, group_dn_base,
                   slo_url, slo_binding
            FROM saml_service_providers
            WHERE entity_id = $1 AND tenant_id = $2
            ",
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
        // R8: Cap limit to prevent unbounded queries (OOM/DB pressure)
        let limit = limit.clamp(1, 100);
        let offset = offset.max(0);
        let sps = if let Some(enabled_filter) = enabled {
            sqlx::query_as::<_, SamlServiceProvider>(
                r"
                SELECT id, tenant_id, entity_id, name, acs_urls, certificate,
                       attribute_mapping, name_id_format, sign_assertions,
                       validate_signatures, assertion_validity_seconds, enabled,
                       metadata_url, created_at, updated_at,
                       group_attribute_name, group_value_format, group_filter,
                       include_groups, omit_empty_groups, group_dn_base,
                       slo_url, slo_binding
                FROM saml_service_providers
                WHERE tenant_id = $1 AND enabled = $2
                ORDER BY name ASC
                LIMIT $3 OFFSET $4
                ",
            )
            .bind(tenant_id)
            .bind(enabled_filter)
            .bind(i64::from(limit))
            .bind(i64::from(offset))
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query_as::<_, SamlServiceProvider>(
                r"
                SELECT id, tenant_id, entity_id, name, acs_urls, certificate,
                       attribute_mapping, name_id_format, sign_assertions,
                       validate_signatures, assertion_validity_seconds, enabled,
                       metadata_url, created_at, updated_at,
                       group_attribute_name, group_value_format, group_filter,
                       include_groups, omit_empty_groups, group_dn_base,
                       slo_url, slo_binding
                FROM saml_service_providers
                WHERE tenant_id = $1
                ORDER BY name ASC
                LIMIT $2 OFFSET $3
                ",
            )
            .bind(tenant_id)
            .bind(i64::from(limit))
            .bind(i64::from(offset))
            .fetch_all(&self.pool)
            .await?
        };

        let total: i64 = if let Some(enabled_filter) = enabled {
            sqlx::query_scalar(
                r"SELECT COUNT(*) FROM saml_service_providers WHERE tenant_id = $1 AND enabled = $2",
            )
            .bind(tenant_id)
            .bind(enabled_filter)
            .fetch_one(&self.pool)
            .await?
        } else {
            sqlx::query_scalar(r"SELECT COUNT(*) FROM saml_service_providers WHERE tenant_id = $1")
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
        // SECURITY: Bound entity_id and name lengths to prevent DB bloat and large XML allocations.
        if req.entity_id.len() > 1024 {
            return Err(SamlError::InvalidAuthnRequest(
                "entity_id too long (max 1024 bytes)".to_string(),
            ));
        }
        if req.name.len() > 256 {
            return Err(SamlError::InvalidAuthnRequest(
                "name too long (max 256 bytes)".to_string(),
            ));
        }

        // Check for duplicate entity_id
        let existing: Option<Uuid> = sqlx::query_scalar(
            r"SELECT id FROM saml_service_providers WHERE tenant_id = $1 AND entity_id = $2",
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

        // R9: Cap ACS URL count to prevent storage abuse
        if req.acs_urls.len() > 20 {
            return Err(SamlError::InvalidAuthnRequest(
                "Too many ACS URLs (max 20)".to_string(),
            ));
        }

        // R9: Validate metadata_url if provided
        if let Some(ref url) = req.metadata_url {
            if let Ok(parsed) = url::Url::parse(url) {
                if parsed.scheme() != "https" {
                    return Err(SamlError::InvalidAuthnRequest(
                        "metadata_url must use HTTPS".to_string(),
                    ));
                }
            } else {
                return Err(SamlError::InvalidAuthnRequest(
                    "Invalid metadata_url format".to_string(),
                ));
            }
        }

        // SECURITY: Enforce HTTPS for ACS URLs to prevent assertion interception via MITM.
        for acs_url in &req.acs_urls {
            if let Ok(parsed) = url::Url::parse(acs_url) {
                if parsed.scheme() != "https" {
                    return Err(SamlError::InvalidAuthnRequest(format!(
                        "ACS URL must use HTTPS: {acs_url}"
                    )));
                }
            } else {
                return Err(SamlError::InvalidAuthnRequest(format!(
                    "Invalid ACS URL format: {acs_url}"
                )));
            }
        }

        // SECURITY: Validate SLO URL if provided (must be HTTPS or localhost)
        if let Some(ref slo_url) = req.slo_url {
            if !slo_url.is_empty() {
                if let Ok(parsed) = url::Url::parse(slo_url) {
                    let scheme = parsed.scheme();
                    let host = parsed.host_str().unwrap_or("");
                    if scheme == "http"
                        && host != "localhost"
                        && host != "127.0.0.1"
                        && host != "[::1]"
                    {
                        return Err(SamlError::InvalidAuthnRequest(
                            "SLO URL must use HTTPS (HTTP only for localhost)".to_string(),
                        ));
                    }
                    if scheme != "http" && scheme != "https" {
                        return Err(SamlError::InvalidAuthnRequest(format!(
                            "SLO URL must use HTTPS, got scheme: {scheme}"
                        )));
                    }
                } else {
                    return Err(SamlError::InvalidAuthnRequest(
                        "Invalid SLO URL format".to_string(),
                    ));
                }
            }
        }

        // SECURITY (H10): Cap assertion_validity_seconds to prevent excessively long-lived assertions.
        // Max 24 hours (86400s). Values <= 0 are also rejected.
        if req.assertion_validity_seconds <= 0 || req.assertion_validity_seconds > 86400 {
            return Err(SamlError::InvalidAuthnRequest(format!(
                "assertion_validity_seconds must be between 1 and 86400, got {}",
                req.assertion_validity_seconds
            )));
        }

        let attribute_mapping = req.attribute_mapping.unwrap_or(serde_json::json!({}));

        let sp = sqlx::query_as::<_, SamlServiceProvider>(
            r"
            INSERT INTO saml_service_providers
                (tenant_id, entity_id, name, acs_urls, certificate, attribute_mapping,
                 name_id_format, sign_assertions, validate_signatures,
                 assertion_validity_seconds, metadata_url, slo_url, slo_binding)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            RETURNING id, tenant_id, entity_id, name, acs_urls, certificate,
                      attribute_mapping, name_id_format, sign_assertions,
                      validate_signatures, assertion_validity_seconds, enabled,
                      metadata_url, created_at, updated_at,
                      group_attribute_name, group_value_format, group_filter,
                      include_groups, omit_empty_groups, group_dn_base,
                      slo_url, slo_binding
            ",
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
        .bind(&req.slo_url)
        .bind(&req.slo_binding)
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

        // R9: Validate name length on update (same as create)
        if name.len() > 256 {
            return Err(SamlError::InvalidAuthnRequest(
                "name too long (max 256 bytes)".to_string(),
            ));
        }

        let acs_urls = req.acs_urls.unwrap_or(existing.acs_urls);

        // R9: Cap ACS URL count on update
        if acs_urls.len() > 20 {
            return Err(SamlError::InvalidAuthnRequest(
                "Too many ACS URLs (max 20)".to_string(),
            ));
        }

        // SECURITY: Re-validate HTTPS for ACS URLs on update (same check as create_sp).
        for acs_url in &acs_urls {
            if let Ok(parsed) = url::Url::parse(acs_url) {
                if parsed.scheme() != "https" {
                    return Err(SamlError::InvalidAuthnRequest(format!(
                        "ACS URL must use HTTPS: {acs_url}"
                    )));
                }
            } else {
                return Err(SamlError::InvalidAuthnRequest(format!(
                    "Invalid ACS URL format: {acs_url}"
                )));
            }
        }
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
        // SECURITY (H10): Cap assertion_validity_seconds on update too.
        if assertion_validity_seconds <= 0 || assertion_validity_seconds > 86400 {
            return Err(SamlError::InvalidAuthnRequest(format!(
                "assertion_validity_seconds must be between 1 and 86400, got {}",
                assertion_validity_seconds
            )));
        }
        let enabled = req.enabled.unwrap_or(existing.enabled);
        let metadata_url = req.metadata_url.or(existing.metadata_url);

        // SECURITY: Validate SLO URL if provided (must be HTTPS or localhost)
        if let Some(ref slo_url) = req.slo_url {
            if !slo_url.is_empty() {
                if let Ok(parsed) = url::Url::parse(slo_url) {
                    let scheme = parsed.scheme();
                    let host = parsed.host_str().unwrap_or("");
                    if scheme == "http"
                        && host != "localhost"
                        && host != "127.0.0.1"
                        && host != "[::1]"
                    {
                        return Err(SamlError::InvalidAuthnRequest(
                            "SLO URL must use HTTPS (HTTP only for localhost)".to_string(),
                        ));
                    }
                    if scheme != "http" && scheme != "https" {
                        return Err(SamlError::InvalidAuthnRequest(format!(
                            "SLO URL must use HTTPS, got scheme: {scheme}"
                        )));
                    }
                } else {
                    return Err(SamlError::InvalidAuthnRequest(
                        "Invalid SLO URL format".to_string(),
                    ));
                }
            }
        }

        let slo_url = req.slo_url.or(existing.slo_url);
        let slo_binding = req.slo_binding.unwrap_or(existing.slo_binding);

        let sp = sqlx::query_as::<_, SamlServiceProvider>(
            r"
            UPDATE saml_service_providers
            SET name = $3, acs_urls = $4, certificate = $5, attribute_mapping = $6,
                name_id_format = $7, sign_assertions = $8, validate_signatures = $9,
                assertion_validity_seconds = $10, enabled = $11, metadata_url = $12,
                slo_url = $13, slo_binding = $14
            WHERE id = $1 AND tenant_id = $2
            RETURNING id, tenant_id, entity_id, name, acs_urls, certificate,
                      attribute_mapping, name_id_format, sign_assertions,
                      validate_signatures, assertion_validity_seconds, enabled,
                      metadata_url, created_at, updated_at,
                      group_attribute_name, group_value_format, group_filter,
                      include_groups, omit_empty_groups, group_dn_base,
                      slo_url, slo_binding
            ",
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
        .bind(&slo_url)
        .bind(&slo_binding)
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
            sqlx::query(r"DELETE FROM saml_service_providers WHERE id = $1 AND tenant_id = $2")
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

    /// Get active certificate for tenant.
    ///
    /// Also validates that the certificate is within its validity period.
    pub async fn get_active_certificate(
        &self,
        tenant_id: Uuid,
    ) -> SamlResult<TenantIdpCertificate> {
        let cert = sqlx::query_as::<_, TenantIdpCertificate>(
            r"
            SELECT id, tenant_id, certificate, private_key_encrypted,
                   key_id, subject_dn, issuer_dn, not_before, not_after,
                   is_active, created_at
            FROM tenant_idp_certificates
            WHERE tenant_id = $1 AND is_active = TRUE
            ",
        )
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(SamlError::NoActiveCertificate)?;

        // SECURITY: Check certificate validity at signing time, not just at activation.
        if !cert.is_valid() {
            return Err(SamlError::InvalidCertificate(format!(
                "Active certificate has expired or is not yet valid (valid from {} to {})",
                cert.not_before, cert.not_after
            )));
        }

        if cert.is_expiring_soon() {
            tracing::warn!(
                tenant_id = %tenant_id,
                cert_id = %cert.id,
                not_after = %cert.not_after,
                "Active IdP certificate is expiring soon — rotate before expiry"
            );
        }

        Ok(cert)
    }

    /// List all certificates for tenant
    pub async fn list_certificates(
        &self,
        tenant_id: Uuid,
    ) -> SamlResult<Vec<TenantIdpCertificate>> {
        let certs = sqlx::query_as::<_, TenantIdpCertificate>(
            r"
            SELECT id, tenant_id, certificate, private_key_encrypted,
                   key_id, subject_dn, issuer_dn, not_before, not_after,
                   is_active, created_at
            FROM tenant_idp_certificates
            WHERE tenant_id = $1
            ORDER BY created_at DESC
            ",
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

        // SECURITY: Atomically deactivate all existing certs and insert the new one as active.
        // This prevents having multiple active certificates simultaneously.
        let mut tx =
            self.pool.begin().await.map_err(|e| {
                SamlError::InternalError(format!("Failed to start transaction: {e}"))
            })?;

        // Deactivate all existing active certificates for this tenant
        sqlx::query(
            "UPDATE tenant_idp_certificates SET is_active = FALSE WHERE tenant_id = $1 AND is_active = TRUE"
        )
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;

        let cert = sqlx::query_as::<_, TenantIdpCertificate>(
            r"
            INSERT INTO tenant_idp_certificates
                (tenant_id, certificate, private_key_encrypted, key_id,
                 subject_dn, issuer_dn, not_before, not_after, is_active)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, TRUE)
            RETURNING id, tenant_id, certificate, private_key_encrypted,
                      key_id, subject_dn, issuer_dn, not_before, not_after,
                      is_active, created_at
            ",
        )
        .bind(tenant_id)
        .bind(&req.certificate)
        .bind(&encrypted_key)
        .bind(creds.key_id())
        .bind(creds.subject_dn())
        .bind(creds.issuer_dn())
        .bind(creds.not_before())
        .bind(creds.not_after())
        .fetch_one(&mut *tx)
        .await?;

        tx.commit()
            .await
            .map_err(|e| SamlError::InternalError(format!("Failed to commit transaction: {e}")))?;

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
        // SECURITY: Use a transaction to atomically check validity and activate in one go,
        // preventing TOCTOU race where a certificate could expire between the check and the update.
        let mut tx =
            self.pool.begin().await.map_err(|e| {
                SamlError::InternalError(format!("Failed to start transaction: {e}"))
            })?;

        // Fetch the certificate (locked within transaction)
        let cert = sqlx::query_as::<_, TenantIdpCertificate>(
            r"
            SELECT id, tenant_id, certificate, private_key_encrypted,
                   key_id, subject_dn, issuer_dn, not_before, not_after,
                   is_active, created_at
            FROM tenant_idp_certificates
            WHERE id = $1 AND tenant_id = $2
            FOR UPDATE
            ",
        )
        .bind(cert_id)
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| SamlError::CertificateNotFound(cert_id.to_string()))?;

        // Validate certificate is not expired
        if !cert.is_valid() {
            return Err(SamlError::InvalidCertificate(format!(
                "Certificate has expired or is not yet valid (valid from {} to {})",
                cert.not_before, cert.not_after
            )));
        }

        // R8: Split into two queries to avoid returning the wrong row.
        // The previous single UPDATE with `SET is_active = (id = $1)` updated ALL rows
        // and `fetch_optional` returned an arbitrary row (not necessarily the activated one).

        // Step 1: Deactivate all certificates for this tenant
        sqlx::query("UPDATE tenant_idp_certificates SET is_active = FALSE WHERE tenant_id = $1")
            .bind(tenant_id)
            .execute(&mut *tx)
            .await?;

        // Step 2: Activate the target certificate and return it
        let updated_cert = sqlx::query_as::<_, TenantIdpCertificate>(
            r"
            UPDATE tenant_idp_certificates
            SET is_active = TRUE
            WHERE id = $1 AND tenant_id = $2
            RETURNING id, tenant_id, certificate, private_key_encrypted,
                      key_id, subject_dn, issuer_dn, not_before, not_after,
                      is_active, created_at
            ",
        )
        .bind(cert_id)
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| SamlError::CertificateNotFound(cert_id.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| SamlError::InternalError(format!("Failed to commit transaction: {e}")))?;

        tracing::info!(
            tenant_id = %tenant_id,
            cert_id = %cert_id,
            "IdP certificate activated (deactivated all other certs for tenant)"
        );

        Ok(updated_cert)
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

    // SECURITY: Validate key length for AES-256-GCM (must be exactly 32 bytes).
    if encryption_key.len() != 32 {
        return Err(SamlError::InternalError(format!(
            "AES-256-GCM requires 32-byte key, got {} bytes",
            encryption_key.len()
        )));
    }

    let cipher = Cipher::aes_256_gcm();

    // Generate random IV
    let mut iv = vec![0u8; 12];
    openssl::rand::rand_bytes(&mut iv)
        .map_err(|e| SamlError::InternalError(format!("Failed to generate IV: {e}")))?;

    let mut tag = vec![0u8; 16];

    let ciphertext = encrypt_aead(cipher, encryption_key, Some(&iv), &[], key_pem, &mut tag)
        .map_err(|e| SamlError::InternalError(format!("Encryption failed: {e}")))?;

    // Format: IV (12 bytes) + tag (16 bytes) + ciphertext
    let mut result = iv;
    result.extend(&tag);
    result.extend(&ciphertext);

    Ok(result)
}

/// Decrypt private key using AES-256-GCM
fn decrypt_private_key(encrypted: &[u8], encryption_key: &[u8]) -> SamlResult<String> {
    use openssl::symm::{decrypt_aead, Cipher};

    // SECURITY: Validate key length for AES-256-GCM (must be exactly 32 bytes).
    if encryption_key.len() != 32 {
        return Err(SamlError::PrivateKeyError(format!(
            "AES-256-GCM requires 32-byte key, got {} bytes",
            encryption_key.len()
        )));
    }

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
        .map_err(|e| SamlError::PrivateKeyError(format!("Decryption failed: {e}")))?;

    String::from_utf8(plaintext)
        .map_err(|e| SamlError::PrivateKeyError(format!("Invalid UTF-8: {e}")))
}
