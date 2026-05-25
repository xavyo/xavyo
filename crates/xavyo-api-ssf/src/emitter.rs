//! [`CaepEmitter`] implementation backed by the SSF push transmitter.
//!
//! `SsfStreamEmitter` turns a fire-and-forget emit call into an async fan-out:
//! it spawns a task that signs + pushes the CAEP event to the tenant's enabled
//! streams. The spawn keeps the caller (an auth flow) non-blocking; delivery
//! failures are logged inside the transmitter, never surfaced to the caller.

use std::sync::Arc;

use chrono::Utc;
use uuid::Uuid;
use xavyo_ssf::{CaepEmitter, CaepEvent, CredentialChangeType, SubjectId};

use crate::transmitter::SsfTransmitter;

/// A [`CaepEmitter`] that fans events out to registered SSF streams via the
/// push transmitter. Cheap to clone (Arc + pool handle).
#[derive(Clone)]
pub struct SsfStreamEmitter {
    transmitter: Arc<SsfTransmitter>,
    pool: sqlx::PgPool,
    /// Issuer used to build the `iss_sub` subject identifier (matches the SET `iss`).
    issuer: String,
}

impl SsfStreamEmitter {
    /// Build an emitter from a shared transmitter, DB pool, and issuer.
    #[must_use]
    pub fn new(
        transmitter: Arc<SsfTransmitter>,
        pool: sqlx::PgPool,
        issuer: impl Into<String>,
    ) -> Self {
        Self {
            transmitter,
            pool,
            issuer: issuer.into(),
        }
    }

    /// The `iss_sub` subject identifier for a user in this issuer.
    fn subject_for(&self, user_id: Uuid) -> SubjectId {
        SubjectId::iss_sub(self.issuer.clone(), user_id.to_string())
    }

    /// Spawn the fan-out for one event (fire-and-forget).
    fn spawn_emit(&self, tenant_id: Uuid, subject: SubjectId, event: CaepEvent) {
        let transmitter = self.transmitter.clone();
        let pool = self.pool.clone();
        tokio::spawn(async move {
            if let Err(e) = transmitter.emit(&pool, tenant_id, &subject, &event).await {
                tracing::warn!(
                    target: "ssf",
                    error = %e,
                    "CAEP emit fan-out query failed"
                );
            }
        });
    }
}

impl CaepEmitter for SsfStreamEmitter {
    fn session_revoked(&self, tenant_id: Uuid, user_id: Uuid, reason: Option<String>) {
        let subject = self.subject_for(user_id);
        self.spawn_emit(
            tenant_id,
            subject,
            CaepEvent::SessionRevoked {
                event_timestamp: Utc::now().timestamp(),
                reason,
            },
        );
    }

    fn credential_change(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        credential_type: String,
        change_type: CredentialChangeType,
    ) {
        let subject = self.subject_for(user_id);
        self.spawn_emit(
            tenant_id,
            subject,
            CaepEvent::CredentialChange {
                event_timestamp: Utc::now().timestamp(),
                credential_type,
                change_type,
            },
        );
    }

    fn token_claims_change(&self, tenant_id: Uuid, user_id: Uuid, claims: serde_json::Value) {
        let subject = self.subject_for(user_id);
        self.spawn_emit(
            tenant_id,
            subject,
            CaepEvent::TokenClaimsChange {
                event_timestamp: Utc::now().timestamp(),
                claims,
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn emit_is_fire_and_forget() {
        // A lazy pool to an unreachable DB — the spawned fan-out will fail
        // asynchronously and be logged; the emit call itself must return
        // immediately without blocking or panicking.
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://invalid")
            .unwrap();
        let tx = Arc::new(
            SsfTransmitter::new(Arc::new(Vec::new()), "kid", "https://idp.example.com").unwrap(),
        );
        let emitter = SsfStreamEmitter::new(tx, pool, "https://idp.example.com");
        emitter.session_revoked(Uuid::nil(), Uuid::nil(), Some("test".into()));
        emitter.credential_change(
            Uuid::nil(),
            Uuid::nil(),
            "password".into(),
            CredentialChangeType::Update,
        );
        // Give the spawned tasks a moment; they error internally, we don't await.
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}
