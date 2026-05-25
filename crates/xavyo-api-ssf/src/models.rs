//! Request/response models for the SSF Transmitter API (OpenID SSF 1.0 §7–§8).

use crate::error::SsfApiError;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;
use xavyo_db::models::{
    SsfStream, STREAM_STATUS_DISABLED, STREAM_STATUS_ENABLED, STREAM_STATUS_PAUSED,
};

/// Push delivery method URN (RFC 8935).
pub const PUSH_DELIVERY_METHOD: &str = "urn:ietf:rfc:8935";

/// Poll delivery method URN (RFC 8936).
pub const POLL_DELIVERY_METHOD: &str = "urn:ietf:rfc:8936";

/// SSF stream `delivery` object (SSF §8.1.1).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DeliveryConfig {
    /// Delivery method URN.
    pub method: String,
    /// Push endpoint the SETs are delivered to.
    pub endpoint_url: String,
}

/// Body for `POST /ssf/streams` (create a stream).
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct CreateStreamRequest {
    /// Receiver audience (becomes the SET `aud`).
    pub aud: String,
    /// Delivery configuration (push only in v1).
    pub delivery: DeliveryConfig,
    /// CAEP event type URIs the receiver wants.
    #[serde(default)]
    pub events_requested: Vec<String>,
    /// Optional bearer token to present to the receiver endpoint on delivery.
    #[serde(default)]
    pub delivery_authorization_header: Option<String>,
    /// Optional description.
    #[serde(default)]
    pub description: Option<String>,
}

impl CreateStreamRequest {
    /// Validate the request. Push delivery (RFC 8935) requires the receiver
    /// `endpoint_url` to pass the SSRF guard (https + public host); poll
    /// delivery (RFC 8936) does not call out, so its `endpoint_url` is
    /// informational and not SSRF-checked.
    ///
    /// # Errors
    /// [`SsfApiError::InvalidRequest`] on an unsupported delivery method or a
    /// push endpoint that fails [`crate::ssrf::validate_receiver_url`].
    pub fn validate(&self) -> Result<(), SsfApiError> {
        match self.delivery.method.as_str() {
            PUSH_DELIVERY_METHOD => crate::ssrf::validate_receiver_url(&self.delivery.endpoint_url),
            POLL_DELIVERY_METHOD => Ok(()),
            other => Err(SsfApiError::InvalidRequest(format!(
                "unsupported delivery method '{other}' \
                 (supported: {PUSH_DELIVERY_METHOD} push, {POLL_DELIVERY_METHOD} poll)"
            ))),
        }
    }

    /// Whether this request asks for poll-based delivery (RFC 8936).
    #[must_use]
    pub fn is_poll(&self) -> bool {
        self.delivery.method == POLL_DELIVERY_METHOD
    }
}

/// A stream configuration response (SSF §8.1.1).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct StreamResponse {
    /// Unique stream id.
    pub stream_id: Uuid,
    /// Transmitter issuer identifier.
    pub iss: String,
    /// Receiver audience.
    pub aud: String,
    /// Delivery configuration.
    pub delivery: DeliveryConfig,
    /// CAEP event type URIs requested.
    pub events_requested: Vec<String>,
    /// CAEP event type URIs the transmitter will deliver.
    pub events_delivered: Vec<String>,
    /// Stream status.
    pub status: String,
    /// Optional description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The per-stream poll bearer token (RFC 8936). Returned **once**, only on
    /// creation of a poll-delivery stream — store it, it cannot be retrieved
    /// again. Absent for push streams and on list/get.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub poll_token: Option<String>,
}

impl StreamResponse {
    /// Build a response from a stored stream, stamping the transmitter `iss`.
    /// `poll_token` is `None` (set explicitly via [`Self::with_poll_token`] on
    /// poll-stream creation).
    #[must_use]
    pub fn from_stream(stream: SsfStream, issuer: &str) -> Self {
        Self {
            stream_id: stream.stream_id,
            iss: issuer.to_string(),
            aud: stream.aud,
            delivery: DeliveryConfig {
                method: stream.delivery_method,
                endpoint_url: stream.endpoint_url,
            },
            events_requested: stream.events_requested,
            events_delivered: stream.events_delivered,
            status: stream.status,
            description: stream.description,
            poll_token: None,
        }
    }

    /// Attach the one-time poll bearer token (poll-stream creation only).
    #[must_use]
    pub fn with_poll_token(mut self, token: String) -> Self {
        self.poll_token = Some(token);
        self
    }
}

fn default_true() -> bool {
    true
}

/// Body for `POST /ssf/poll` — poll-based delivery (RFC 8936 §2.4).
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct PollRequest {
    /// Maximum SETs to return in this poll (clamped server-side).
    #[serde(default, rename = "maxEvents")]
    pub max_events: Option<i64>,
    /// RFC 8936: if `false` the transmitter MAY hold the request open (long
    /// poll). v1 always returns immediately; the field is accepted for
    /// compatibility.
    #[serde(default = "default_true", rename = "returnImmediately")]
    pub return_immediately: bool,
    /// `jti`s of SETs the receiver acknowledges as delivered — removed from the
    /// queue before the next batch is selected.
    #[serde(default)]
    pub ack: Vec<String>,
}

/// Response to `POST /ssf/poll` (RFC 8936 §2.4).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PollResponse {
    /// Map of SET `jti` → compact JWS for the returned batch.
    pub sets: std::collections::HashMap<String, String>,
    /// Whether more queued SETs remain beyond this batch.
    #[serde(rename = "moreAvailable")]
    pub more_available: bool,
}

/// Body for `POST /ssf/verify` — request a stream-verification event (SSF §7.1.4).
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct VerifyRequest {
    /// The stream to send the verification event to.
    pub stream_id: Uuid,
    /// Optional opaque value the receiver echoes back to correlate the check.
    #[serde(default)]
    pub state: Option<String>,
}

/// Body for `POST /ssf/status` (update stream status).
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct UpdateStatusRequest {
    /// Stream to update.
    pub stream_id: Uuid,
    /// New status: `enabled` | `paused` | `disabled`.
    pub status: String,
}

impl UpdateStatusRequest {
    /// # Errors
    /// [`SsfApiError::InvalidRequest`] if the status is not a valid value.
    pub fn validate(&self) -> Result<(), SsfApiError> {
        match self.status.as_str() {
            STREAM_STATUS_ENABLED | STREAM_STATUS_PAUSED | STREAM_STATUS_DISABLED => Ok(()),
            other => Err(SsfApiError::InvalidRequest(format!(
                "invalid status `{other}` (expected enabled|paused|disabled)"
            ))),
        }
    }
}

/// Status response (SSF §8.1.2).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct StatusResponse {
    /// Stream id.
    pub stream_id: Uuid,
    /// Current status.
    pub status: String,
}

/// Query string carrying a `stream_id` (GET status / GET-DELETE stream).
#[derive(Debug, Clone, Deserialize)]
pub struct StreamIdQuery {
    /// Stream id.
    pub stream_id: Uuid,
}

/// Body for `POST /ssf/subjects:add` and `:remove`.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct SubjectRequest {
    /// Stream the subject is (de)registered on.
    pub stream_id: Uuid,
    /// The RFC 9493 Subject Identifier object.
    pub subject: serde_json::Value,
}

/// Transmitter configuration metadata (`/.well-known/ssf-configuration`, SSF §7).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SsfConfigurationMetadata {
    /// Transmitter issuer identifier.
    pub issuer: String,
    /// JWKS URI for verifying SET signatures.
    pub jwks_uri: String,
    /// Supported delivery methods.
    pub delivery_methods_supported: Vec<String>,
    /// Stream configuration endpoint.
    pub configuration_endpoint: String,
    /// Stream status endpoint.
    pub status_endpoint: String,
    /// Add-subject endpoint.
    pub add_subject_endpoint: String,
    /// Remove-subject endpoint.
    pub remove_subject_endpoint: String,
    /// Stream-verification endpoint (SSF §7.1.4).
    pub verification_endpoint: String,
}

impl SsfConfigurationMetadata {
    /// Build the metadata document for the given issuer base URL.
    #[must_use]
    pub fn new(issuer: &str) -> Self {
        let base = issuer.trim_end_matches('/');
        Self {
            issuer: issuer.to_string(),
            jwks_uri: format!("{base}/.well-known/jwks.json"),
            delivery_methods_supported: vec![
                PUSH_DELIVERY_METHOD.to_string(),
                POLL_DELIVERY_METHOD.to_string(),
            ],
            configuration_endpoint: format!("{base}/ssf/streams"),
            status_endpoint: format!("{base}/ssf/status"),
            add_subject_endpoint: format!("{base}/ssf/subjects:add"),
            remove_subject_endpoint: format!("{base}/ssf/subjects:remove"),
            verification_endpoint: format!("{base}/ssf/verify"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_endpoints_derive_from_issuer() {
        let m = SsfConfigurationMetadata::new("https://idp.example.com/");
        assert_eq!(m.issuer, "https://idp.example.com/");
        assert_eq!(
            m.configuration_endpoint,
            "https://idp.example.com/ssf/streams"
        );
        assert_eq!(m.status_endpoint, "https://idp.example.com/ssf/status");
        assert_eq!(
            m.add_subject_endpoint,
            "https://idp.example.com/ssf/subjects:add"
        );
        assert_eq!(
            m.delivery_methods_supported,
            vec![PUSH_DELIVERY_METHOD, POLL_DELIVERY_METHOD]
        );
    }

    #[test]
    fn create_request_accepts_poll_delivery() {
        // Poll delivery (RFC 8936) is now supported; endpoint_url is not
        // SSRF-checked because poll never calls out.
        let req = CreateStreamRequest {
            aud: "https://rp".into(),
            delivery: DeliveryConfig {
                method: POLL_DELIVERY_METHOD.into(),
                endpoint_url: "https://rp/poll".into(),
            },
            events_requested: vec![],
            delivery_authorization_header: None,
            description: None,
        };
        assert!(req.validate().is_ok());
        assert!(req.is_poll());
    }

    #[test]
    fn create_request_rejects_unknown_delivery() {
        let req = CreateStreamRequest {
            aud: "https://rp".into(),
            delivery: DeliveryConfig {
                method: "urn:example:carrier-pigeon".into(),
                endpoint_url: "https://rp/ssf".into(),
            },
            events_requested: vec![],
            delivery_authorization_header: None,
            description: None,
        };
        assert!(req.validate().is_err());
    }

    #[test]
    fn create_request_rejects_http_endpoint() {
        let req = CreateStreamRequest {
            aud: "https://rp".into(),
            delivery: DeliveryConfig {
                method: PUSH_DELIVERY_METHOD.into(),
                endpoint_url: "http://rp/ssf".into(),
            },
            events_requested: vec![],
            delivery_authorization_header: None,
            description: None,
        };
        assert!(req.validate().is_err());
    }

    #[test]
    fn create_request_accepts_https_push() {
        let req = CreateStreamRequest {
            aud: "https://rp".into(),
            delivery: DeliveryConfig {
                method: PUSH_DELIVERY_METHOD.into(),
                endpoint_url: "https://rp/ssf".into(),
            },
            events_requested: vec![xavyo_ssf::SESSION_REVOKED_URI.to_string()],
            delivery_authorization_header: Some("Bearer xyz".into()),
            description: Some("test".into()),
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn status_validation() {
        for s in ["enabled", "paused", "disabled"] {
            let r = UpdateStatusRequest {
                stream_id: Uuid::nil(),
                status: s.into(),
            };
            assert!(r.validate().is_ok());
        }
        let bad = UpdateStatusRequest {
            stream_id: Uuid::nil(),
            status: "frozen".into(),
        };
        assert!(bad.validate().is_err());
    }
}
