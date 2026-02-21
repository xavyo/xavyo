//! SAML Single Logout orchestration service

use crate::error::{SamlError, SamlResult};
use crate::handlers::metadata::SamlState;
use crate::services::logout_parser::ParsedLogoutRequest;
use crate::services::slo_builder::SloBuilder;
use crate::services::SpService;
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;
use xavyo_db::models::SamlServiceProvider;

/// Result of an IdP-initiated SLO dispatch
#[derive(Debug, Clone, Serialize)]
pub struct SloResult {
    /// Total number of SPs with active sessions
    pub total: usize,
    /// Number of SPs successfully notified
    pub succeeded: usize,
    /// Number of SPs where notification failed
    pub failed: usize,
    /// Number of SPs with no SLO URL configured
    pub no_slo_url: usize,
}

/// Result of processing an SP-initiated LogoutRequest
pub struct SpLogoutResult {
    /// Base64-encoded LogoutResponse XML
    pub response_xml: String,
    /// The user ID whose sessions were revoked
    pub user_id: Uuid,
}

/// Service for SAML Single Logout orchestration
pub struct SloService {
    pool: PgPool,
    http_client: reqwest::Client,
}

impl SloService {
    /// Create a new SLO service
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            // Explicitly enforce TLS verification (default, but being explicit)
            .danger_accept_invalid_certs(false)
            .build()
            .unwrap_or_default();

        Self { pool, http_client }
    }

    /// IdP-initiated SLO: send LogoutRequests to all SPs with active sessions.
    ///
    /// Uses back-channel POST with a 10s timeout per SP. Failures are logged
    /// but non-blocking — we revoke sessions regardless of SP response.
    pub async fn dispatch_logout_to_sps(
        &self,
        state: &SamlState,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> SamlResult<SloResult> {
        // Get all active SP sessions for the user
        let sessions = state
            .sp_session_store
            .get_active_for_user(tenant_id, user_id)
            .await
            .map_err(|e| SamlError::SpSessionError(format!("Failed to get SP sessions: {e}")))?;

        if sessions.is_empty() {
            // Revoke sessions anyway (in case there are stale ones)
            let _ = state
                .sp_session_store
                .revoke_all_for_user(tenant_id, user_id)
                .await;

            return Ok(SloResult {
                total: 0,
                succeeded: 0,
                failed: 0,
                no_slo_url: 0,
            });
        }

        let sp_service = SpService::new(self.pool.clone());

        // Get IdP signing credentials
        let cert = sp_service.get_active_certificate(tenant_id).await?;
        let key_pem = sp_service
            .decrypt_private_key(&cert.private_key_encrypted, state.encryption_key.as_ref())?;
        let credentials = crate::saml::SigningCredentials::from_pem(&cert.certificate, &key_pem)?;
        let idp_entity_id = format!("{}/saml/metadata?tenant={}", state.base_url, tenant_id);
        let builder = SloBuilder::new(idp_entity_id, credentials);

        let total = sessions.len();
        let mut succeeded = 0usize;
        let mut failed = 0usize;
        let mut no_slo_url = 0usize;

        // Group sessions by SP to avoid sending duplicate requests
        let mut seen_sps = std::collections::HashSet::new();

        for session in &sessions {
            if !seen_sps.insert(session.sp_id) {
                continue; // Already sent to this SP
            }

            let sp = match sp_service.get_sp(tenant_id, session.sp_id).await {
                Ok(sp) => sp,
                Err(e) => {
                    tracing::warn!(
                        sp_id = %session.sp_id,
                        error = %e,
                        "Failed to look up SP for SLO dispatch"
                    );
                    failed += 1;
                    continue;
                }
            };

            let slo_url = match &sp.slo_url {
                Some(url) if !url.is_empty() => url.clone(),
                _ => {
                    tracing::debug!(
                        sp_id = %sp.id,
                        sp_entity_id = %sp.entity_id,
                        "SP has no SLO URL configured, skipping"
                    );
                    no_slo_url += 1;
                    continue;
                }
            };

            // Validate SLO URL scheme (HTTPS required for non-localhost)
            if !is_safe_slo_url(&slo_url) {
                tracing::warn!(
                    sp_id = %sp.id,
                    slo_url = %slo_url,
                    "SLO URL is not safe (must be HTTPS or localhost), skipping"
                );
                failed += 1;
                continue;
            }

            // Build LogoutRequest for this SP
            let encoded_request = match builder.build_logout_request(
                &slo_url,
                &session.name_id,
                &session.name_id_format,
                &session.session_index,
            ) {
                Ok(req) => req,
                Err(e) => {
                    tracing::error!(
                        sp_id = %sp.id,
                        error = %e,
                        "Failed to build LogoutRequest"
                    );
                    failed += 1;
                    continue;
                }
            };

            // Send back-channel POST
            match self
                .http_client
                .post(&slo_url)
                .form(&[("SAMLRequest", &encoded_request)])
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    tracing::info!(
                        sp_id = %sp.id,
                        sp_entity_id = %sp.entity_id,
                        slo_url = %slo_url,
                        "LogoutRequest sent successfully"
                    );
                    succeeded += 1;
                }
                Ok(resp) => {
                    tracing::warn!(
                        sp_id = %sp.id,
                        sp_entity_id = %sp.entity_id,
                        status = %resp.status(),
                        "LogoutRequest received non-success response"
                    );
                    failed += 1;
                }
                Err(e) => {
                    tracing::warn!(
                        sp_id = %sp.id,
                        sp_entity_id = %sp.entity_id,
                        error = %e,
                        "Failed to send LogoutRequest"
                    );
                    failed += 1;
                }
            }
        }

        // Revoke all SP sessions for this user regardless of SP responses
        let revoked = state
            .sp_session_store
            .revoke_all_for_user(tenant_id, user_id)
            .await
            .map_err(|e| SamlError::SpSessionError(format!("Failed to revoke sessions: {e}")))?;

        tracing::info!(
            tenant_id = %tenant_id,
            user_id = %user_id,
            total = total,
            succeeded = succeeded,
            failed = failed,
            no_slo_url = no_slo_url,
            revoked = revoked,
            "SLO dispatch completed"
        );

        Ok(SloResult {
            total,
            succeeded,
            failed,
            no_slo_url,
        })
    }

    /// SP-initiated SLO: process incoming LogoutRequest from an SP.
    ///
    /// The SP has already been looked up and signature validated by the handler.
    /// This method identifies the user from the NameID, revokes sessions
    /// (honoring SessionIndex if provided), and returns a signed LogoutResponse.
    pub async fn process_sp_logout_for_sp(
        &self,
        state: &SamlState,
        tenant_id: Uuid,
        sp: &SamlServiceProvider,
        request: &ParsedLogoutRequest,
    ) -> SamlResult<SpLogoutResult> {
        let sp_service = SpService::new(self.pool.clone());

        // Find the user by NameID — look through active SP sessions
        let user_id = self
            .find_user_by_name_id(tenant_id, sp.id, &request.name_id)
            .await?;

        // Honor SessionIndex: if provided, only revoke that specific session.
        // If not provided, revoke all sessions for the user (per SAML 2.0 Core §3.7.1).
        if let Some(ref session_index) = request.session_index {
            let revoked = self
                .revoke_session_by_index(tenant_id, user_id, session_index)
                .await?;
            tracing::info!(
                tenant_id = %tenant_id,
                user_id = %user_id,
                session_index = %session_index,
                revoked = revoked,
                "SP-initiated SLO: specific session revoked"
            );
        } else {
            let revoked = state
                .sp_session_store
                .revoke_all_for_user(tenant_id, user_id)
                .await
                .map_err(|e| {
                    SamlError::SpSessionError(format!("Failed to revoke sessions: {e}"))
                })?;
            tracing::info!(
                tenant_id = %tenant_id,
                user_id = %user_id,
                sp_entity_id = %sp.entity_id,
                revoked = revoked,
                "SP-initiated SLO: all sessions revoked"
            );
        }

        // Build signed LogoutResponse — use SP's SLO URL as Destination.
        // If no SLO URL is configured, use the first ACS URL as fallback.
        let slo_url = sp
            .slo_url
            .as_deref()
            .or_else(|| sp.acs_urls.first().map(String::as_str))
            .ok_or_else(|| {
                SamlError::InternalError(
                    "SP has no SLO URL or ACS URL configured for LogoutResponse Destination"
                        .to_string(),
                )
            })?;

        let cert = sp_service.get_active_certificate(tenant_id).await?;
        let key_pem = sp_service
            .decrypt_private_key(&cert.private_key_encrypted, state.encryption_key.as_ref())?;
        let credentials = crate::saml::SigningCredentials::from_pem(&cert.certificate, &key_pem)?;
        let idp_entity_id = format!("{}/saml/metadata?tenant={}", state.base_url, tenant_id);
        let builder = SloBuilder::new(idp_entity_id, credentials);

        let response_xml = builder.build_logout_response(&request.id, slo_url, true)?;

        Ok(SpLogoutResult {
            response_xml,
            user_id,
        })
    }

    /// Revoke a specific SP session by session_index.
    async fn revoke_session_by_index(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        session_index: &str,
    ) -> SamlResult<u64> {
        let mut conn =
            self.pool.acquire().await.map_err(|e| {
                SamlError::InternalError(format!("Failed to acquire connection: {e}"))
            })?;

        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(tenant_id.to_string())
            .execute(&mut *conn)
            .await
            .map_err(|e| SamlError::InternalError(format!("Failed to set tenant context: {e}")))?;

        let result = sqlx::query(
            r"
            UPDATE saml_sp_sessions
            SET revoked_at = NOW()
            WHERE tenant_id = $1 AND user_id = $2 AND session_index = $3 AND revoked_at IS NULL
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(session_index)
        .execute(&mut *conn)
        .await
        .map_err(|e| SamlError::InternalError(format!("Failed to revoke session by index: {e}")))?;

        Ok(result.rows_affected())
    }

    /// Find a user by NameID from active SP sessions
    async fn find_user_by_name_id(
        &self,
        tenant_id: Uuid,
        sp_id: Uuid,
        name_id: &str,
    ) -> SamlResult<Uuid> {
        // Query the saml_sp_sessions table for matching name_id
        let mut conn =
            self.pool.acquire().await.map_err(|e| {
                SamlError::InternalError(format!("Failed to acquire connection: {e}"))
            })?;

        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(tenant_id.to_string())
            .execute(&mut *conn)
            .await
            .map_err(|e| SamlError::InternalError(format!("Failed to set tenant context: {e}")))?;

        let user_id: Option<Uuid> = sqlx::query_scalar(
            r"
            SELECT user_id FROM saml_sp_sessions
            WHERE tenant_id = $1 AND sp_id = $2 AND name_id = $3
              AND revoked_at IS NULL AND expires_at > NOW()
            ORDER BY created_at DESC
            LIMIT 1
            ",
        )
        .bind(tenant_id)
        .bind(sp_id)
        .bind(name_id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(|e| SamlError::InternalError(format!("Failed to find user by NameID: {e}")))?;

        // Fallback: look up user by email if NameID is email format
        if let Some(uid) = user_id {
            return Ok(uid);
        }

        // Try looking up by email in the users table (same connection, RLS already set)
        let user_id: Option<Uuid> = sqlx::query_scalar(
            r"SELECT id FROM users WHERE tenant_id = $1 AND LOWER(email) = LOWER($2)",
        )
        .bind(tenant_id)
        .bind(name_id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(|e| SamlError::InternalError(format!("Failed to look up user by email: {e}")))?;

        // SECURITY: Do not include the NameID in error messages to prevent user enumeration
        user_id.ok_or_else(|| {
            tracing::warn!(
                tenant_id = %tenant_id,
                sp_id = %sp_id,
                "No active session or user found for provided NameID"
            );
            SamlError::InvalidLogoutRequest(
                "No active session found for the provided identity".to_string(),
            )
        })
    }
}

/// Validate that an SLO URL is safe (HTTPS, no internal IPs).
fn is_safe_slo_url(url: &str) -> bool {
    let Ok(parsed) = url::Url::parse(url) else {
        return false;
    };

    let scheme = parsed.scheme();
    let host = parsed.host_str().unwrap_or("");

    // Allow HTTP only for localhost (development)
    if scheme == "http" {
        return host == "localhost" || host == "127.0.0.1" || host == "[::1]";
    }

    // Must be HTTPS
    if scheme != "https" {
        return false;
    }

    // Block internal/private IP ranges to prevent SSRF
    match parsed.host() {
        Some(url::Host::Ipv4(ip)) => {
            if ip.is_loopback() || ip.is_private() || ip.is_link_local() {
                return false;
            }
            // Block 169.254.x.x (link-local / cloud metadata)
            let octets = ip.octets();
            if octets[0] == 169 && octets[1] == 254 {
                return false;
            }
        }
        Some(url::Host::Ipv6(ip)) => {
            // Block IPv6 loopback (::1), link-local (fe80::/10), and
            // IPv4-mapped private addresses (::ffff:10.x.x.x, etc.)
            if ip.is_loopback() {
                return false;
            }
            let segments = ip.segments();
            // fe80::/10 — link-local
            if segments[0] & 0xffc0 == 0xfe80 {
                return false;
            }
            // fc00::/7 — unique local addresses (private)
            if segments[0] & 0xfe00 == 0xfc00 {
                return false;
            }
            // ::ffff:0:0/96 — IPv4-mapped, check the embedded IPv4
            if segments[0] == 0
                && segments[1] == 0
                && segments[2] == 0
                && segments[3] == 0
                && segments[4] == 0
                && segments[5] == 0xffff
            {
                let ip4 = std::net::Ipv4Addr::new(
                    (segments[6] >> 8) as u8,
                    segments[6] as u8,
                    (segments[7] >> 8) as u8,
                    segments[7] as u8,
                );
                if ip4.is_loopback() || ip4.is_private() || ip4.is_link_local() {
                    return false;
                }
            }
        }
        _ => {}
    }

    true
}
