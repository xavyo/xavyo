//! Webhook service for delivering A2A task completion notifications.
//!
//! This service handles webhook delivery with HMAC signing and
//! exponential backoff retry logic.
//!
//! # Security
//!
//! This service includes SSRF (Server-Side Request Forgery) protection
//! to prevent webhook URLs from targeting internal services.

use crate::error::ApiAgentsError;
use crate::models::{A2aTaskWebhookPayload, ApprovalWebhookPayload};
use chrono::Utc;
use reqwest::Client;
use sqlx::PgPool;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::time::Duration;
use tracing::{debug, error, info, warn};
use url::Url;
use uuid::Uuid;
use xavyo_db::models::{A2aTask, CallbackStatus};

/// Maximum number of delivery attempts.
pub const MAX_DELIVERY_ATTEMPTS: i32 = 3;

/// Base delay for exponential backoff (in seconds).
const BASE_RETRY_DELAY_SECS: u64 = 5;

/// SSRF protection: Check if a URL is safe to fetch (not targeting internal services).
///
/// This function validates webhook URLs to prevent Server-Side Request Forgery attacks.
/// It blocks requests to:
/// - Private IPv4 ranges (10.x.x.x, 172.16-31.x.x, 192.168.x.x)
/// - Loopback addresses (127.x.x.x, `::1`)
/// - Link-local addresses (169.254.x.x, `fe80::/10`)
/// - Documentation/test ranges
/// - Unspecified addresses (0.0.0.0, ::)
///
/// # Security
///
/// This protection prevents attackers from using webhook callbacks to:
/// - Scan internal networks
/// - Access internal services (metadata APIs, admin panels)
/// - Exfiltrate data through DNS rebinding
pub fn validate_webhook_url(url_str: &str) -> Result<(), String> {
    // Parse the URL
    let url = Url::parse(url_str).map_err(|e| format!("Invalid URL: {e}"))?;

    // Only allow HTTPS in production (HTTP allowed for localhost in dev)
    let scheme = url.scheme();
    if scheme != "https" && scheme != "http" {
        return Err(format!("Unsupported scheme: {scheme}"));
    }

    // Get the host
    let host = url
        .host_str()
        .ok_or_else(|| "URL has no host".to_string())?;

    // Check if it's an IP address directly
    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_private_ip(&ip) {
            return Err(format!(
                "Private/internal IP addresses are not allowed: {ip}"
            ));
        }
    } else {
        // It's a hostname - resolve it and check all IPs
        // Use port 443 as default for resolution
        let port = url.port().unwrap_or(443);
        let addr_str = format!("{host}:{port}");

        match addr_str.to_socket_addrs() {
            Ok(addrs) => {
                for addr in addrs {
                    if is_private_ip(&addr.ip()) {
                        return Err(format!(
                            "Hostname {} resolves to private/internal IP: {}",
                            host,
                            addr.ip()
                        ));
                    }
                }
            }
            Err(e) => {
                // DNS resolution failed - this could be a typo or intentional
                // We'll let it fail at request time with a proper error
                warn!("DNS resolution failed for {}: {}", host, e);
            }
        }
    }

    // Block common internal hostnames
    let lower_host = host.to_lowercase();
    let blocked_hosts = [
        "localhost",
        "127.0.0.1",
        "::1",
        "0.0.0.0",
        "metadata",
        "metadata.google.internal",
        "169.254.169.254", // AWS/GCP metadata
        "fd00:ec2::254",   // AWS EC2 metadata IPv6
    ];

    for blocked in blocked_hosts {
        if lower_host == blocked || lower_host.ends_with(&format!(".{blocked}")) {
            return Err(format!("Blocked internal hostname: {host}"));
        }
    }

    Ok(())
}

/// Check if an IP address is private/internal.
fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => is_private_ipv4(ipv4),
        IpAddr::V6(ipv6) => is_private_ipv6(ipv6),
    }
}

/// Check if an IPv4 address is private/internal.
fn is_private_ipv4(ip: &Ipv4Addr) -> bool {
    // Loopback (127.0.0.0/8)
    if ip.is_loopback() {
        return true;
    }

    // Private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
    if ip.is_private() {
        return true;
    }

    // Link-local (169.254.0.0/16)
    if ip.is_link_local() {
        return true;
    }

    // Broadcast/unspecified
    if ip.is_broadcast() || ip.is_unspecified() {
        return true;
    }

    // Documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
    if ip.is_documentation() {
        return true;
    }

    // Shared address space (100.64.0.0/10) - used for carrier-grade NAT
    let octets = ip.octets();
    if octets[0] == 100 && (octets[1] >= 64 && octets[1] <= 127) {
        return true;
    }

    false
}

/// Check if an IPv6 address is private/internal.
fn is_private_ipv6(ip: &Ipv6Addr) -> bool {
    // Loopback (::1)
    if ip.is_loopback() {
        return true;
    }

    // Unspecified (::)
    if ip.is_unspecified() {
        return true;
    }

    // Check for IPv4-mapped addresses (::ffff:0:0/96)
    if let Some(ipv4) = ip.to_ipv4_mapped() {
        return is_private_ipv4(&ipv4);
    }

    // Unique local addresses (fc00::/7) - IPv6 equivalent of private
    let segments = ip.segments();
    if (segments[0] & 0xfe00) == 0xfc00 {
        return true;
    }

    // Link-local (fe80::/10)
    if (segments[0] & 0xffc0) == 0xfe80 {
        return true;
    }

    false
}

/// Webhook service for callback delivery.
#[derive(Clone)]
pub struct WebhookService {
    pool: PgPool,
    client: Client,
    /// HMAC signing secret (in production, this should come from config).
    signing_secret: String,
}

impl WebhookService {
    /// Create a new webhook service.
    ///
    /// # Errors
    ///
    /// Returns `ApiAgentsError::Internal` if the HTTP client cannot be built.
    pub fn new(pool: PgPool) -> Result<Self, ApiAgentsError> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| ApiAgentsError::Internal(format!("Failed to create HTTP client: {e}")))?;

        Ok(Self {
            pool,
            client,
            // In production, load from environment/config
            signing_secret: std::env::var("WEBHOOK_SIGNING_SECRET")
                .unwrap_or_else(|_| "default-signing-secret".to_string()),
        })
    }

    /// Create with custom signing secret.
    ///
    /// # Errors
    ///
    /// Returns `ApiAgentsError::Internal` if the HTTP client cannot be built.
    pub fn with_signing_secret(
        pool: PgPool,
        signing_secret: String,
    ) -> Result<Self, ApiAgentsError> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| ApiAgentsError::Internal(format!("Failed to create HTTP client: {e}")))?;

        Ok(Self {
            pool,
            client,
            signing_secret,
        })
    }

    /// Deliver a webhook for approval request notification (F092).
    ///
    /// This is fire-and-forget - the approval creation completes immediately
    /// while webhook delivery happens asynchronously with retries.
    ///
    /// # Security
    ///
    /// The callback URL is validated against SSRF attacks before delivery.
    pub async fn deliver_approval_webhook(
        &self,
        tenant_id: Uuid,
        approval_id: Uuid,
        callback_url: &str,
        payload: &ApprovalWebhookPayload,
    ) -> Result<(), ApiAgentsError> {
        // SSRF protection: validate the callback URL
        validate_webhook_url(callback_url).map_err(|e| {
            warn!(
                approval_id = %approval_id,
                callback_url = %callback_url,
                error = %e,
                "Webhook URL validation failed (SSRF protection)"
            );
            ApiAgentsError::Validation(format!("Invalid callback URL: {e}"))
        })?;

        let payload_json =
            serde_json::to_string(payload).map_err(|e| ApiAgentsError::Internal(e.to_string()))?;

        // Spawn async delivery with retries
        let service = self.clone();
        let url = callback_url.to_string();
        tokio::spawn(async move {
            service
                .deliver_approval_with_retry(tenant_id, approval_id, &url, &payload_json)
                .await;
        });

        Ok(())
    }

    /// Deliver approval webhook with exponential backoff retry.
    async fn deliver_approval_with_retry(
        &self,
        _tenant_id: Uuid,
        approval_id: Uuid,
        url: &str,
        payload_json: &str,
    ) {
        for attempt in 1..=MAX_DELIVERY_ATTEMPTS {
            match self.deliver_once(url, payload_json).await {
                Ok(()) => {
                    info!(
                        approval_id = %approval_id,
                        attempt = attempt,
                        "Approval webhook delivered successfully"
                    );
                    return;
                }
                Err(e) => {
                    warn!(
                        approval_id = %approval_id,
                        attempt = attempt,
                        max_attempts = MAX_DELIVERY_ATTEMPTS,
                        error = %e,
                        "Approval webhook delivery failed"
                    );

                    if attempt < MAX_DELIVERY_ATTEMPTS {
                        // Exponential backoff: 5s, 10s, 20s
                        let delay =
                            Duration::from_secs(BASE_RETRY_DELAY_SECS * (1 << (attempt - 1)));
                        debug!(
                            approval_id = %approval_id,
                            delay_secs = delay.as_secs(),
                            "Retrying approval webhook delivery after delay"
                        );
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        }

        // All attempts failed
        error!(
            approval_id = %approval_id,
            url = url,
            "Approval webhook delivery failed after {} attempts",
            MAX_DELIVERY_ATTEMPTS
        );
    }

    /// Deliver a webhook for task completion.
    ///
    /// # Security
    ///
    /// The callback URL is validated against SSRF attacks before delivery.
    #[allow(clippy::too_many_arguments)]
    pub async fn deliver_task_webhook(
        &self,
        tenant_id: Uuid,
        task_id: Uuid,
        callback_url: &str,
        state: &str,
        result: Option<serde_json::Value>,
        error_code: Option<String>,
        error_message: Option<String>,
    ) -> Result<(), ApiAgentsError> {
        // SSRF protection: validate the callback URL
        validate_webhook_url(callback_url).map_err(|e| {
            warn!(
                task_id = %task_id,
                callback_url = %callback_url,
                error = %e,
                "Webhook URL validation failed (SSRF protection)"
            );
            ApiAgentsError::Validation(format!("Invalid callback URL: {e}"))
        })?;

        let payload = A2aTaskWebhookPayload {
            task_id,
            state: state.to_string(),
            result,
            error_code,
            error_message,
            completed_at: Utc::now(),
        };

        // Spawn async delivery with retries
        let service = self.clone();
        let url = callback_url.to_string();
        tokio::spawn(async move {
            service
                .deliver_with_retry(tenant_id, task_id, &url, &payload)
                .await;
        });

        Ok(())
    }

    /// Deliver webhook with exponential backoff retry.
    async fn deliver_with_retry(
        &self,
        tenant_id: Uuid,
        task_id: Uuid,
        url: &str,
        payload: &A2aTaskWebhookPayload,
    ) {
        let payload_json =
            serde_json::to_string(payload).expect("Failed to serialize webhook payload");

        for attempt in 1..=MAX_DELIVERY_ATTEMPTS {
            match self.deliver_once(url, &payload_json).await {
                Ok(()) => {
                    info!(
                        task_id = %task_id,
                        attempt = attempt,
                        "Webhook delivered successfully"
                    );
                    // Update callback status to delivered
                    if let Err(e) = A2aTask::update_callback_status(
                        &self.pool,
                        tenant_id,
                        task_id,
                        CallbackStatus::Delivered,
                    )
                    .await
                    {
                        warn!(task_id = %task_id, error = %e, "Failed to update callback status");
                    }
                    return;
                }
                Err(e) => {
                    warn!(
                        task_id = %task_id,
                        attempt = attempt,
                        max_attempts = MAX_DELIVERY_ATTEMPTS,
                        error = %e,
                        "Webhook delivery failed"
                    );

                    // Update attempt count
                    if let Err(e) = A2aTask::update_callback_status(
                        &self.pool,
                        tenant_id,
                        task_id,
                        CallbackStatus::Pending,
                    )
                    .await
                    {
                        warn!(task_id = %task_id, error = %e, "Failed to update callback attempts");
                    }

                    if attempt < MAX_DELIVERY_ATTEMPTS {
                        // Exponential backoff: 5s, 10s, 20s
                        let delay =
                            Duration::from_secs(BASE_RETRY_DELAY_SECS * (1 << (attempt - 1)));
                        debug!(
                            task_id = %task_id,
                            delay_secs = delay.as_secs(),
                            "Retrying webhook delivery after delay"
                        );
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        }

        // All attempts failed
        error!(
            task_id = %task_id,
            url = url,
            "Webhook delivery failed after {} attempts",
            MAX_DELIVERY_ATTEMPTS
        );

        // Update status to failed
        if let Err(e) =
            A2aTask::update_callback_status(&self.pool, tenant_id, task_id, CallbackStatus::Failed)
                .await
        {
            warn!(task_id = %task_id, error = %e, "Failed to update callback status to failed");
        }
    }

    /// Attempt a single webhook delivery.
    async fn deliver_once(&self, url: &str, payload_json: &str) -> Result<(), String> {
        // Compute HMAC signature
        let signature = self.compute_signature(payload_json);

        let response = self
            .client
            .post(url)
            .header("Content-Type", "application/json")
            .header("X-Webhook-Signature", format!("sha256={signature}"))
            .body(payload_json.to_string())
            .send()
            .await
            .map_err(|e| format!("Request failed: {e}"))?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(format!(
                "Server returned status {}",
                response.status().as_u16()
            ))
        }
    }

    /// Compute HMAC-SHA256 signature for the payload.
    fn compute_signature(&self, payload: &str) -> String {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;

        let mut mac =
            HmacSha256::new_from_slice(self.signing_secret.as_bytes()).expect("Invalid key length");
        mac.update(payload.as_bytes());
        let result = mac.finalize();

        hex::encode(result.into_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to compute HMAC signature without needing the full service.
    fn compute_test_signature(secret: &str, payload: &str) -> String {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;

        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("Invalid key length");
        mac.update(payload.as_bytes());
        let result = mac.finalize();

        hex::encode(result.into_bytes())
    }

    #[test]
    fn test_signature_computation() {
        let payload = r#"{"task_id":"test"}"#;
        let signature = compute_test_signature("test-secret", payload);

        // Verify signature is a valid hex string
        assert!(hex::decode(&signature).is_ok());
        // Verify it's SHA-256 length (32 bytes = 64 hex chars)
        assert_eq!(signature.len(), 64);
    }

    #[test]
    fn test_consistent_signatures() {
        let payload = r#"{"task_id":"test"}"#;
        let sig1 = compute_test_signature("test-secret", payload);
        let sig2 = compute_test_signature("test-secret", payload);

        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_different_secrets_produce_different_signatures() {
        let payload = r#"{"task_id":"test"}"#;
        let sig1 = compute_test_signature("secret-1", payload);
        let sig2 = compute_test_signature("secret-2", payload);

        assert_ne!(sig1, sig2);
    }

    // SSRF Protection Tests

    #[test]
    fn test_ssrf_allows_public_https_url() {
        assert!(validate_webhook_url("https://example.com/webhook").is_ok());
        assert!(validate_webhook_url("https://api.github.com/webhook").is_ok());
    }

    #[test]
    fn test_ssrf_blocks_localhost() {
        assert!(validate_webhook_url("http://localhost/webhook").is_err());
        assert!(validate_webhook_url("http://localhost:8080/webhook").is_err());
        assert!(validate_webhook_url("https://localhost/webhook").is_err());
    }

    #[test]
    fn test_ssrf_blocks_loopback_ip() {
        assert!(validate_webhook_url("http://127.0.0.1/webhook").is_err());
        assert!(validate_webhook_url("http://127.0.0.1:8080/webhook").is_err());
        assert!(validate_webhook_url("http://127.1.2.3/webhook").is_err());
    }

    #[test]
    fn test_ssrf_blocks_private_ip_10() {
        assert!(validate_webhook_url("http://10.0.0.1/webhook").is_err());
        assert!(validate_webhook_url("http://10.255.255.255/webhook").is_err());
    }

    #[test]
    fn test_ssrf_blocks_private_ip_172() {
        assert!(validate_webhook_url("http://172.16.0.1/webhook").is_err());
        assert!(validate_webhook_url("http://172.31.255.255/webhook").is_err());
    }

    #[test]
    fn test_ssrf_blocks_private_ip_192() {
        assert!(validate_webhook_url("http://192.168.0.1/webhook").is_err());
        assert!(validate_webhook_url("http://192.168.255.255/webhook").is_err());
    }

    #[test]
    fn test_ssrf_blocks_link_local() {
        assert!(validate_webhook_url("http://169.254.169.254/webhook").is_err());
        assert!(validate_webhook_url("http://169.254.1.1/webhook").is_err());
    }

    #[test]
    fn test_ssrf_blocks_metadata_service() {
        // AWS/GCP metadata service
        assert!(validate_webhook_url("http://169.254.169.254/latest/meta-data/").is_err());
        assert!(validate_webhook_url("http://metadata.google.internal/").is_err());
    }

    #[test]
    fn test_ssrf_blocks_ipv6_loopback() {
        assert!(validate_webhook_url("http://[::1]/webhook").is_err());
    }

    #[test]
    fn test_ssrf_blocks_unspecified_ip() {
        assert!(validate_webhook_url("http://0.0.0.0/webhook").is_err());
    }

    #[test]
    fn test_ssrf_rejects_invalid_urls() {
        assert!(validate_webhook_url("not-a-url").is_err());
        assert!(validate_webhook_url("ftp://example.com/file").is_err());
        assert!(validate_webhook_url("file:///etc/passwd").is_err());
    }

    #[test]
    fn test_is_private_ipv4() {
        // Private ranges
        assert!(is_private_ipv4(&Ipv4Addr::new(10, 0, 0, 1)));
        assert!(is_private_ipv4(&Ipv4Addr::new(172, 16, 0, 1)));
        assert!(is_private_ipv4(&Ipv4Addr::new(192, 168, 1, 1)));

        // Loopback
        assert!(is_private_ipv4(&Ipv4Addr::new(127, 0, 0, 1)));

        // Link-local
        assert!(is_private_ipv4(&Ipv4Addr::new(169, 254, 1, 1)));

        // Public IP should not be private
        assert!(!is_private_ipv4(&Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!is_private_ipv4(&Ipv4Addr::new(1, 1, 1, 1)));
    }

    #[test]
    fn test_is_private_ipv6() {
        // Loopback
        assert!(is_private_ipv6(&Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)));

        // Unspecified
        assert!(is_private_ipv6(&Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)));

        // Unique local (fc00::/7)
        assert!(is_private_ipv6(&Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1)));
        assert!(is_private_ipv6(&Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)));

        // Link-local (fe80::/10)
        assert!(is_private_ipv6(&Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)));

        // Global unicast should not be private
        assert!(!is_private_ipv6(&Ipv6Addr::new(
            0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888
        )));
    }
}
