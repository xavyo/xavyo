//! Poll-based SET delivery (RFC 8936).
//!
//! A poll-delivery stream's SETs are queued (not pushed); the receiver pulls
//! them here and acknowledges them. Unlike the stream-management API, the poll
//! endpoint is **receiver-facing** and authenticates with a per-stream bearer
//! token (not the tenant JWT), so it must be mounted OUTSIDE the tenant-auth
//! middleware. The token resolves to its stream + tenant before any
//! RLS-scoped access — the caller never supplies a tenant id.

use axum::{extract::State, http::HeaderMap, routing::post, Json, Router};
use rand::RngCore;
use sha2::{Digest, Sha256};
use xavyo_db::models::{SsfPollToken, SsfQueuedEvent};

use crate::error::SsfApiError;
use crate::handlers::{tenant_conn, SsfState};
use crate::models::{PollRequest, PollResponse};

/// Default SETs returned per poll when `maxEvents` is omitted.
const DEFAULT_MAX_EVENTS: i64 = 100;
/// Hard cap on a single poll response.
const MAX_EVENTS_CAP: i64 = 500;

/// Generate a new 256-bit poll bearer token (hex). Returned once to the creator;
/// only its [`hash_poll_token`] is stored.
#[must_use]
pub fn generate_poll_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// SHA-256 (hex) of a poll token — what is stored and compared.
#[must_use]
pub fn hash_poll_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

/// The receiver-facing poll router. Mount OUTSIDE the tenant-auth middleware —
/// it authenticates with the per-stream bearer token, not a tenant JWT.
pub fn ssf_poll_router(state: SsfState) -> Router {
    Router::new().route("/poll", post(poll)).with_state(state)
}

/// Extract a `Bearer` token from the `Authorization` header.
fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

/// `POST /ssf/poll` — poll-based SET delivery (RFC 8936 §2.4).
///
/// Authenticated by the per-stream poll bearer token. Acks the previous batch
/// (deleting those `jti`s), then returns up to `maxEvents` of the oldest queued
/// SETs and whether more remain.
///
/// # Errors
/// [`SsfApiError::Unauthorized`] when the bearer token is missing or unknown;
/// [`SsfApiError::Database`] on a storage failure.
pub async fn poll(
    State(state): State<SsfState>,
    headers: HeaderMap,
    Json(req): Json<PollRequest>,
) -> Result<Json<PollResponse>, SsfApiError> {
    // 1. Authenticate: hash the presented token, resolve it to stream + tenant.
    //    The token is the capability; tenant scope comes from the resolution,
    //    never from caller input.
    let token = bearer_token(&headers).ok_or(SsfApiError::Unauthorized)?;
    let resolved = SsfPollToken::resolve(&state.pool, &hash_poll_token(token))
        .await?
        .ok_or(SsfApiError::Unauthorized)?;
    let (tenant_id, stream_id) = (resolved.tenant_id, resolved.stream_id);

    // 2. Set the tenant RLS context for all queue access below.
    let mut conn = tenant_conn(&state.pool, tenant_id).await?;

    // 3. Ack first (RFC 8936 §2.4: an ack in a poll confirms the prior batch).
    //    A stale jti is a no-op, so a replayed ack can't delete fresh SETs.
    if !req.ack.is_empty() {
        SsfQueuedEvent::ack(&mut *conn, tenant_id, stream_id, &req.ack).await?;
    }

    // 4. Return the oldest queued SETs (FIFO), bounded by maxEvents.
    let max = req
        .max_events
        .unwrap_or(DEFAULT_MAX_EVENTS)
        .clamp(1, MAX_EVENTS_CAP);
    let queued = SsfQueuedEvent::poll(&mut *conn, tenant_id, stream_id, max).await?;
    let total = SsfQueuedEvent::count_for_stream(&mut *conn, tenant_id, stream_id).await?;
    let more_available = total > queued.len() as i64;

    let sets = queued.into_iter().map(|e| (e.jti, e.set_jwt)).collect();
    Ok(Json(PollResponse {
        sets,
        more_available,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_is_256_bit_hex_and_unique() {
        let a = generate_poll_token();
        let b = generate_poll_token();
        assert_eq!(a.len(), 64, "32 bytes => 64 hex chars");
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b, "tokens must be unique");
    }

    #[test]
    fn hash_is_stable_and_differs_from_token() {
        let token = "deadbeef";
        let h = hash_poll_token(token);
        assert_eq!(h, hash_poll_token(token), "hash is deterministic");
        assert_ne!(h, token, "hash differs from the token");
        assert_eq!(h.len(), 64, "SHA-256 => 64 hex chars");
        assert_ne!(
            hash_poll_token("other"),
            h,
            "different inputs hash differently"
        );
    }

    #[test]
    fn bearer_token_parsing() {
        let mut headers = HeaderMap::new();
        assert_eq!(bearer_token(&headers), None);
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Basic xyz".parse().unwrap(),
        );
        assert_eq!(bearer_token(&headers), None);
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer tok-123".parse().unwrap(),
        );
        assert_eq!(bearer_token(&headers), Some("tok-123"));
    }
}
