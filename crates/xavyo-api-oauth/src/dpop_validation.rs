//! Resource-side DPoP enforcement (RFC 9449).
//!
//! Call [`enforce_dpop`] on any endpoint that accepts an access token. If the
//! token is sender-constrained (`cnf.jkt` present), a valid matching DPoP proof
//! is required; otherwise it is a no-op (bearer tokens accepted, any presented
//! proof ignored — no alternate code path, per the design's downgrade rules).

use crate::error::OAuthError;
use crate::router::OAuthState;
use axum::http::HeaderMap;
use chrono::{Duration, Utc};
use xavyo_auth::dpop::DPOP_PROOF_MAX_AGE_SECS;
use xavyo_auth::{verify_resource_proof, JwtClaims};
use xavyo_db::models::DpopProofJti;

/// Enforce DPoP binding for a resource request.
///
/// - `cnf.jkt` absent ⇒ `Ok(())` (ordinary bearer token).
/// - `cnf.jkt` present ⇒ require a `DPoP` header whose proof: verifies against
///   its embedded JWK, has thumbprint == `cnf.jkt`, binds `htm`/`htu` to this
///   request (`htu` built from the configured issuer + `path`, proxy-safe),
///   carries `ath` == SHA-256(encoded token), and whose `jti` has not been
///   replayed (tenant-scoped).
///
/// `htm` is the HTTP method (e.g. `"GET"`); `path` is the endpoint path
/// (e.g. `"/oauth/userinfo"`).
///
/// # Errors
/// [`OAuthError::InvalidToken`] when a required/valid proof is absent or the
/// binding fails; [`OAuthError::Internal`] on a replay-store failure
/// (fail-closed).
pub async fn enforce_dpop(
    state: &OAuthState,
    headers: &HeaderMap,
    claims: &JwtClaims,
    encoded_access_token: &str,
    htm: &str,
    path: &str,
) -> Result<(), OAuthError> {
    let Some(jkt) = claims.dpop_jkt() else {
        return Ok(()); // bearer token — no DPoP required; ignore any presented proof
    };

    let proof = headers
        .get("dpop")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            tracing::warn!(
                target: "security",
                event_type = "dpop_proof_missing",
                "DPoP-bound token presented without a DPoP proof"
            );
            OAuthError::InvalidToken("DPoP-bound token requires a DPoP proof".to_string())
        })?;

    let expected_htu = format!("{}{}", state.issuer.trim_end_matches('/'), path);

    // Crypto validation (signature, htm/htu/iat/ath, thumbprint == cnf.jkt)
    // lives in xavyo-auth so the token middleware can share it.
    let validated = verify_resource_proof(
        proof,
        jkt,
        htm,
        &expected_htu,
        Utc::now().timestamp(),
        encoded_access_token,
    )
    .map_err(|e| {
        tracing::warn!(
            target: "security",
            event_type = "dpop_proof_invalid",
            error = %e,
            "DPoP proof rejected"
        );
        OAuthError::InvalidToken("invalid DPoP proof".to_string())
    })?;

    // Replay check, tenant-scoped (tenant from the presented access token).
    let tenant_id = claims
        .tid
        .ok_or_else(|| OAuthError::InvalidToken("DPoP-bound token missing tid".to_string()))?;

    let mut conn = state.pool.acquire().await.map_err(|e| {
        tracing::error!(error = %e, "DPoP replay: failed to acquire connection (fail-closed)");
        OAuthError::Internal("token verification failed".to_string())
    })?;
    if sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
        .bind(tenant_id.to_string())
        .execute(&mut *conn)
        .await
        .is_err()
    {
        return Err(OAuthError::Internal(
            "token verification failed".to_string(),
        ));
    }
    let expires_at = Utc::now() + Duration::seconds(DPOP_PROOF_MAX_AGE_SECS);
    let fresh = DpopProofJti::record_if_new(&mut *conn, tenant_id, &validated.jti, expires_at)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "DPoP replay: record failed (fail-closed)");
            OAuthError::Internal("token verification failed".to_string())
        })?;
    if !fresh {
        tracing::warn!(
            target: "security",
            event_type = "dpop_proof_replay",
            jti = %validated.jti,
            "DPoP proof replay rejected"
        );
        return Err(OAuthError::InvalidToken("DPoP proof replay".to_string()));
    }

    Ok(())
}
