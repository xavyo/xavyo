//! Revoke sessions and refresh tokens after identity changes.
//!
//! Session-only revoke left opaque refresh tokens valid, so the user could
//! mint a new access token without re-authenticating.

use sqlx::PgPool;
use uuid::Uuid;

/// Revoke browser sessions and both families of refresh tokens for a user.
///
/// Persist errors fail closed — callers must not report success if any write
/// failed.
pub async fn revoke_user_sessions_and_refresh_tokens(
    pool: &PgPool,
    tenant_id: Uuid,
    user_id: Uuid,
) -> Result<u64, sqlx::Error> {
    let sessions = sqlx::query(
        r"
        UPDATE sessions
        SET revoked_at = NOW()
        WHERE user_id = $1 AND tenant_id = $2 AND revoked_at IS NULL
        ",
    )
    .bind(user_id)
    .bind(tenant_id)
    .execute(pool)
    .await?
    .rows_affected();

    let refresh = sqlx::query(
        r"
        UPDATE refresh_tokens
        SET revoked_at = NOW()
        WHERE user_id = $1 AND tenant_id = $2 AND revoked_at IS NULL
        ",
    )
    .bind(user_id)
    .bind(tenant_id)
    .execute(pool)
    .await?
    .rows_affected();

    let oauth = sqlx::query(
        r"
        UPDATE oauth_refresh_tokens
        SET revoked = TRUE, revoked_at = now()
        WHERE user_id = $1 AND tenant_id = $2 AND revoked = FALSE
        ",
    )
    .bind(user_id)
    .bind(tenant_id)
    .execute(pool)
    .await?
    .rows_affected();

    Ok(sessions + refresh + oauth)
}

#[cfg(test)]
mod tests {
    #[test]
    fn revoke_helper_covers_sessions_and_both_refresh_tables() {
        let src = include_str!("revoke_auth.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            production.contains("UPDATE sessions"),
            "must revoke browser sessions"
        );
        assert!(
            production.contains("UPDATE refresh_tokens"),
            "must revoke opaque refresh tokens"
        );
        assert!(
            production.contains("UPDATE oauth_refresh_tokens"),
            "must revoke OAuth refresh tokens"
        );
        assert!(
            !production.contains("if let Ok"),
            "must not swallow persist errors"
        );
    }
}
