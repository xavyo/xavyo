//! CAEP event types (OpenID CAEP 1.0).
//!
//! Each event is carried in the SET's `events` claim as a single-entry map
//! `{ "<type-uri>": { <payload> } }`. Every CAEP event payload carries an
//! `event_timestamp` (NumericDate, seconds — CAEP §3.1). v1 ships the two
//! events xavyo can emit from existing flows: `session-revoked` and
//! `credential-change`.

use serde::{Deserialize, Serialize};

/// CAEP `session-revoked` event type URI.
pub const SESSION_REVOKED_URI: &str =
    "https://schemas.openid.net/secevent/caep/event-type/session-revoked";

/// CAEP `credential-change` event type URI.
pub const CREDENTIAL_CHANGE_URI: &str =
    "https://schemas.openid.net/secevent/caep/event-type/credential-change";

/// The kind of credential change (CAEP §3.4 `change_type`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CredentialChangeType {
    /// A new credential was created.
    Create,
    /// A credential was revoked.
    Revoke,
    /// A credential was updated (e.g. password changed).
    Update,
    /// A credential was deleted.
    Delete,
}

/// A CAEP event (the value embedded under its type URI in the `events` claim).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaepEvent {
    /// CAEP §3.5 — a session was revoked. Receivers SHOULD terminate access for
    /// the identified subject's session.
    SessionRevoked {
        /// When the revocation occurred (NumericDate seconds).
        event_timestamp: i64,
        /// Optional admin-facing reason.
        reason: Option<String>,
    },
    /// CAEP §3.4 — a credential changed (e.g. password update, MFA enrollment).
    CredentialChange {
        /// When the change occurred (NumericDate seconds).
        event_timestamp: i64,
        /// The credential type affected (e.g. `"password"`, `"pin"`, `"fido2-roaming"`).
        credential_type: String,
        /// Whether it was created/revoked/updated/deleted.
        change_type: CredentialChangeType,
    },
}

impl CaepEvent {
    /// The event type URI used as the key in the `events` claim.
    #[must_use]
    pub fn type_uri(&self) -> &'static str {
        match self {
            CaepEvent::SessionRevoked { .. } => SESSION_REVOKED_URI,
            CaepEvent::CredentialChange { .. } => CREDENTIAL_CHANGE_URI,
        }
    }

    /// The event's payload object (the value under the type URI).
    #[must_use]
    pub fn payload(&self) -> serde_json::Value {
        match self {
            CaepEvent::SessionRevoked {
                event_timestamp,
                reason,
            } => {
                let mut obj = serde_json::Map::new();
                obj.insert("event_timestamp".into(), (*event_timestamp).into());
                if let Some(r) = reason {
                    obj.insert("reason_admin".into(), serde_json::json!({ "en": r }));
                }
                serde_json::Value::Object(obj)
            }
            CaepEvent::CredentialChange {
                event_timestamp,
                credential_type,
                change_type,
            } => serde_json::json!({
                "event_timestamp": event_timestamp,
                "credential_type": credential_type,
                "change_type": change_type,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn session_revoked_payload() {
        let e = CaepEvent::SessionRevoked {
            event_timestamp: 1_700_000_000,
            reason: Some("admin revoked".into()),
        };
        assert_eq!(e.type_uri(), SESSION_REVOKED_URI);
        assert_eq!(
            e.payload(),
            json!({"event_timestamp": 1_700_000_000, "reason_admin": {"en": "admin revoked"}})
        );
    }

    #[test]
    fn session_revoked_payload_without_reason_omits_it() {
        let e = CaepEvent::SessionRevoked {
            event_timestamp: 1,
            reason: None,
        };
        assert_eq!(e.payload(), json!({"event_timestamp": 1}));
    }

    #[test]
    fn credential_change_payload() {
        let e = CaepEvent::CredentialChange {
            event_timestamp: 42,
            credential_type: "password".into(),
            change_type: CredentialChangeType::Update,
        };
        assert_eq!(e.type_uri(), CREDENTIAL_CHANGE_URI);
        assert_eq!(
            e.payload(),
            json!({"event_timestamp": 42, "credential_type": "password", "change_type": "update"})
        );
    }
}
