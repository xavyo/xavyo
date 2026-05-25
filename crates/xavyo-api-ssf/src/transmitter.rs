//! SSF push transmitter (RFC 8935) — signs and delivers Security Event Tokens.
//!
//! [`SsfTransmitter::emit`] is the fan-out entry point: for a CAEP event about a
//! subject, it finds the tenant's enabled streams that deliver that event type,
//! re-applies the [`crate::ssrf`] guard to each receiver endpoint, signs a SET
//! ([`xavyo_ssf`]), and POSTs it. `deliver` is the pure transport step (no SSRF
//! check — `emit` validates first) so it is unit-testable against a local mock.
//!
//! DNS-rebinding note: `emit` re-validates the endpoint string, but a hostname
//! that *resolves* to a private IP at connect time is not yet pinned. A
//! resolving connector that re-checks the connect-time IP is a follow-up.

use std::sync::Arc;
use std::time::Duration;

use reqwest::Client;
use uuid::Uuid;
use xavyo_db::models::SsfStream;
use xavyo_ssf::{CaepEvent, SecurityEventToken, SubjectId};

use crate::ssrf::validate_receiver_url;

/// Media type for a delivered SET (SSF §4).
const SET_CONTENT_TYPE: &str = "application/secevent+jwt";

/// Per-delivery HTTP timeout.
const DELIVERY_TIMEOUT_SECS: u64 = 10;

/// Errors from SET delivery.
#[derive(Debug, thiserror::Error)]
pub enum DeliveryError {
    /// The receiver endpoint failed the SSRF guard.
    #[error("receiver endpoint blocked: {0}")]
    BlockedEndpoint(String),
    /// Signing the SET failed.
    #[error("failed to sign SET: {0}")]
    Signing(String),
    /// The HTTP request could not be completed.
    #[error("delivery transport error: {0}")]
    Transport(String),
    /// The receiver responded with a non-success status.
    #[error("receiver returned status {0}")]
    Status(u16),
}

/// Signs and pushes Security Event Tokens to stream receivers.
#[derive(Clone)]
pub struct SsfTransmitter {
    client: Client,
    /// RSA signing key (PEM) — the OAuth signing key.
    signing_key_pem: Arc<Vec<u8>>,
    /// Key id stamped into the SET header (JWKS lookup).
    kid: String,
    /// Transmitter issuer identifier (SET `iss`).
    issuer: String,
}

impl SsfTransmitter {
    /// Build a transmitter with the given RSA signing key (PEM), `kid`, and issuer.
    ///
    /// # Errors
    /// [`DeliveryError::Transport`] if the HTTP client cannot be constructed.
    pub fn new(
        signing_key_pem: Arc<Vec<u8>>,
        kid: impl Into<String>,
        issuer: impl Into<String>,
    ) -> Result<Self, DeliveryError> {
        let client = Client::builder()
            .timeout(Duration::from_secs(DELIVERY_TIMEOUT_SECS))
            // Never follow redirects — a redirect could bounce delivery to an
            // unvalidated (internal) target.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| DeliveryError::Transport(e.to_string()))?;
        Ok(Self {
            client,
            signing_key_pem,
            kid: kid.into(),
            issuer: issuer.into(),
        })
    }

    /// Build + sign a SET for `event`/`subject` addressed to `stream`'s receiver.
    ///
    /// # Errors
    /// [`DeliveryError::Signing`] if signing fails.
    pub fn build_set(
        &self,
        stream: &SsfStream,
        subject: &SubjectId,
        event: &CaepEvent,
    ) -> Result<String, DeliveryError> {
        let set = SecurityEventToken::new(
            self.issuer.clone(),
            stream.aud.clone(),
            subject.clone(),
            event.clone(),
        );
        let now = chrono::Utc::now().timestamp();
        let jti = Uuid::new_v4().to_string();
        set.sign(&self.signing_key_pem, &self.kid, now, &jti)
            .map_err(|e| DeliveryError::Signing(e.to_string()))
    }

    /// POST a signed SET to a receiver endpoint (pure transport — the caller
    /// MUST have already validated the endpoint with the SSRF guard).
    ///
    /// # Errors
    /// [`DeliveryError::Transport`] on a network failure; [`DeliveryError::Status`]
    /// if the receiver responds with a non-2xx status.
    pub async fn deliver(
        &self,
        endpoint_url: &str,
        auth_header: Option<&str>,
        set_jwt: &str,
    ) -> Result<(), DeliveryError> {
        let mut req = self
            .client
            .post(endpoint_url)
            .header(reqwest::header::CONTENT_TYPE, SET_CONTENT_TYPE)
            .body(set_jwt.to_string());
        if let Some(h) = auth_header {
            req = req.header(reqwest::header::AUTHORIZATION, h);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| DeliveryError::Transport(e.to_string()))?;
        let status = resp.status();
        if status.is_success() {
            Ok(())
        } else {
            Err(DeliveryError::Status(status.as_u16()))
        }
    }

    /// Emit a CAEP event to every enabled stream in the tenant that delivers its
    /// type. Re-validates each receiver endpoint (SSRF) before delivery; one bad
    /// receiver does not block the others. Returns per-stream outcomes (the
    /// caller logs/persists them).
    ///
    /// # Errors
    /// Returns the `sqlx` error only if the stream lookup itself fails.
    pub async fn emit(
        &self,
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        subject: &SubjectId,
        event: &CaepEvent,
    ) -> Result<Vec<(Uuid, Result<(), DeliveryError>)>, sqlx::Error> {
        let mut conn = pool.acquire().await?;
        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(tenant_id.to_string())
            .execute(&mut *conn)
            .await?;
        let streams =
            SsfStream::list_enabled_for_event(&mut *conn, tenant_id, event.type_uri()).await?;
        drop(conn);

        let mut outcomes = Vec::with_capacity(streams.len());
        for stream in streams {
            let outcome = self.emit_one(&stream, subject, event).await;
            if let Err(ref e) = outcome {
                tracing::warn!(
                    target: "ssf",
                    stream_id = %stream.stream_id,
                    error = %e,
                    "SSF SET delivery failed"
                );
            }
            outcomes.push((stream.stream_id, outcome));
        }
        Ok(outcomes)
    }

    /// Validate, sign, and deliver a SET to one stream.
    async fn emit_one(
        &self,
        stream: &SsfStream,
        subject: &SubjectId,
        event: &CaepEvent,
    ) -> Result<(), DeliveryError> {
        validate_receiver_url(&stream.endpoint_url)
            .map_err(|e| DeliveryError::BlockedEndpoint(e.to_string()))?;
        // DNS-rebinding mitigation: a public-looking hostname could resolve to a
        // private address. Resolve now and reject if any resolved IP is non-public.
        assert_endpoint_resolves_public(&stream.endpoint_url).await?;
        let set_jwt = self.build_set(stream, subject, event)?;
        self.deliver(
            &stream.endpoint_url,
            stream.delivery_authorization_header.as_deref(),
            &set_jwt,
        )
        .await
    }
}

/// Resolve a receiver endpoint's host and require every resolved IP to be public
/// (DNS-rebinding defense). IP-literal hosts are already vetted by the SSRF guard
/// at registration, so they are skipped here.
///
/// Residual TOCTOU: a resolver could return a different IP at connect time than
/// at this check. Eliminating it fully requires pinning the validated IP at the
/// socket layer — a documented follow-up.
async fn assert_endpoint_resolves_public(endpoint_url: &str) -> Result<(), DeliveryError> {
    let url = url::Url::parse(endpoint_url)
        .map_err(|e| DeliveryError::BlockedEndpoint(format!("invalid endpoint_url: {e}")))?;
    let host = url
        .host_str()
        .ok_or_else(|| DeliveryError::BlockedEndpoint("endpoint_url has no host".into()))?;
    // IP-literal hosts were already classified at registration.
    if host.parse::<std::net::IpAddr>().is_ok() {
        return Ok(());
    }
    let port = url.port_or_known_default().unwrap_or(443);
    let addrs = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| DeliveryError::BlockedEndpoint(format!("DNS resolution failed: {e}")))?;
    let mut resolved_any = false;
    for addr in addrs {
        resolved_any = true;
        if !crate::ssrf::is_public_ip(addr.ip()) {
            return Err(DeliveryError::BlockedEndpoint(
                "endpoint_url host resolves to a non-public IP".into(),
            ));
        }
    }
    if !resolved_any {
        return Err(DeliveryError::BlockedEndpoint(
            "endpoint_url host did not resolve".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn transmitter() -> SsfTransmitter {
        // deliver() never loads the key, so an empty PEM is fine for transport tests.
        SsfTransmitter::new(Arc::new(Vec::new()), "kid-1", "https://idp.example.com").unwrap()
    }

    #[tokio::test]
    async fn deliver_posts_set_with_content_type_and_succeeds() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/ssf"))
            .and(header("content-type", SET_CONTENT_TYPE))
            .respond_with(ResponseTemplate::new(202))
            .mount(&server)
            .await;

        let url = format!("{}/ssf", server.uri());
        let res = transmitter().deliver(&url, None, "a.b.c").await;
        assert!(res.is_ok(), "expected success, got {res:?}");
    }

    #[tokio::test]
    async fn deliver_forwards_authorization_header() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/ssf"))
            .and(header("authorization", "Bearer secret-token"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let url = format!("{}/ssf", server.uri());
        let res = transmitter()
            .deliver(&url, Some("Bearer secret-token"), "a.b.c")
            .await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn deliver_maps_non_2xx_to_status_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let url = format!("{}/ssf", server.uri());
        match transmitter().deliver(&url, None, "a.b.c").await {
            Err(DeliveryError::Status(500)) => {}
            other => panic!("expected Status(500), got {other:?}"),
        }
    }
}
