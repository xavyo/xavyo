pub mod auth;
pub mod client;
pub mod error;
pub mod mapper;
pub mod provisioner;
pub mod reconciler;
pub mod retry;
pub mod sync;

#[cfg(feature = "kafka")]
pub mod consumer;

pub use error::{ScimClientError, ScimClientResult};

use std::time::Duration;
use xavyo_connector::crypto::CredentialEncryption;
use xavyo_db::models::ScimTarget;
use xavyo_webhooks::{EventPublisher, WebhookEvent};

/// Build a [`client::ScimClient`] from a SCIM target by decrypting its
/// stored credentials.
///
/// This is the single shared helper used by sync, reconciler, and consumer
/// modules to avoid duplicating client construction logic.
pub fn build_scim_client_from_target(
    target: &ScimTarget,
    encryption: &CredentialEncryption,
    tenant_id: uuid::Uuid,
) -> ScimClientResult<client::ScimClient> {
    let decrypted = encryption
        .decrypt(tenant_id, &target.credentials_encrypted)
        .map_err(|e| {
            ScimClientError::EncryptionError(format!("credential decryption failed: {e}"))
        })?;

    let credentials: auth::ScimCredentials = serde_json::from_slice(&decrypted)?;

    let http_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(target.request_timeout_secs as u64))
        .danger_accept_invalid_certs(!target.tls_verify)
        .build()
        .map_err(|e| ScimClientError::InvalidConfig(format!("failed to build HTTP client: {e}")))?;

    let auth = auth::ScimAuth::new(credentials, http_client);

    client::ScimClient::new(
        target.base_url.clone(),
        auth,
        Duration::from_secs(target.request_timeout_secs as u64),
        target.tls_verify,
    )
}

/// Publish a webhook event if an [`EventPublisher`] is available.
///
/// This is a no-op if `publisher` is `None`.  Publishing errors are logged
/// internally but never propagate — the SCIM operation has already completed.
pub fn publish_scim_webhook(
    publisher: Option<&EventPublisher>,
    event_type: &str,
    tenant_id: uuid::Uuid,
    actor_id: Option<uuid::Uuid>,
    data: serde_json::Value,
) {
    if let Some(pub_ref) = publisher {
        pub_ref.publish(WebhookEvent {
            event_id: uuid::Uuid::new_v4(),
            event_type: event_type.to_string(),
            tenant_id,
            actor_id,
            timestamp: chrono::Utc::now(),
            data,
        });
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn scim_handlers_do_not_commit_on_target_failure() {
        let src = include_str!("consumer.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            production.contains("scim_target_provisioned(")
                && production.contains("scim_event_completed("),
            "SCIM target provision errors must fail closed"
        );
        assert!(
            !production.contains("don't fail the entire event")
                && !production.contains("Failed to build SCIM client, skipping target"),
            "must not report the event handled when a SCIM target failed"
        );
        assert!(
            production
                .matches("scim_event_completed(any_failed)")
                .count()
                >= 7,
            "all lifecycle handlers must fail the event when any target failed"
        );
    }
}
