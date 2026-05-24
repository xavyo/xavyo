//! Request/response models for the SSF Transmitter API (OpenID SSF 1.0 §7–§8).

use crate::error::SsfApiError;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;
use xavyo_db::models::{
    SsfStream, STREAM_STATUS_DISABLED, STREAM_STATUS_ENABLED, STREAM_STATUS_PAUSED,
};

/// Push delivery method URN (RFC 8935) — the only delivery method in v1.
pub const PUSH_DELIVERY_METHOD: &str = "urn:ietf:rfc:8935";

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
    /// Validate the request. v1 accepts only push delivery, and the receiver
    /// `endpoint_url` must pass the SSRF guard (https + public host).
    ///
    /// # Errors
    /// [`SsfApiError::InvalidRequest`] on unsupported delivery or an endpoint
    /// that fails [`crate::ssrf::validate_receiver_url`].
    pub fn validate(&self) -> Result<(), SsfApiError> {
        if self.delivery.method != PUSH_DELIVERY_METHOD {
            return Err(SsfApiError::InvalidRequest(format!(
                "unsupported delivery method (v1 supports only {PUSH_DELIVERY_METHOD})"
            )));
        }
        crate::ssrf::validate_receiver_url(&self.delivery.endpoint_url)
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
}

impl StreamResponse {
    /// Build a response from a stored stream, stamping the transmitter `iss`.
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
        }
    }
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
}

impl SsfConfigurationMetadata {
    /// Build the metadata document for the given issuer base URL.
    #[must_use]
    pub fn new(issuer: &str) -> Self {
        let base = issuer.trim_end_matches('/');
        Self {
            issuer: issuer.to_string(),
            jwks_uri: format!("{base}/.well-known/jwks.json"),
            delivery_methods_supported: vec![PUSH_DELIVERY_METHOD.to_string()],
            configuration_endpoint: format!("{base}/ssf/streams"),
            status_endpoint: format!("{base}/ssf/status"),
            add_subject_endpoint: format!("{base}/ssf/subjects:add"),
            remove_subject_endpoint: format!("{base}/ssf/subjects:remove"),
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
        assert_eq!(m.delivery_methods_supported, vec![PUSH_DELIVERY_METHOD]);
    }

    #[test]
    fn create_request_rejects_non_push_delivery() {
        let req = CreateStreamRequest {
            aud: "https://rp".into(),
            delivery: DeliveryConfig {
                method: "urn:ietf:rfc:8936".into(), // poll, not supported in v1
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
