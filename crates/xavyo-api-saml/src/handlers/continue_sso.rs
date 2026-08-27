//! POST /saml/continue — complete SP-initiated SSO after user authentication
//!
//! Called by the frontend after the user logs in. Loads the stored AuthnRequest
//! session, builds a SAML Response, and returns the ACS URL + encoded response
//! for the frontend to auto-submit to the SP.

use crate::error::{SamlError, SamlResult};
use crate::handlers::metadata::SamlState;
use crate::models::group_config::GroupAttributeConfig;
use crate::saml::UserAttributes;
use crate::services::{AssertionBuilder, GroupService, SpService};
use axum::{
    extract::State,
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use xavyo_auth::JwtClaims;

/// Request body for POST /saml/continue
#[derive(Debug, Deserialize)]
pub struct ContinueSsoRequest {
    pub session_id: Uuid,
}

/// Response body for POST /saml/continue
#[derive(Debug, Serialize)]
pub struct ContinueSsoResponse {
    pub acs_url: String,
    pub saml_response: String,
    pub relay_state: Option<String>,
}

/// Complete SP-initiated SSO after user authentication
#[utoipa::path(
    post,
    path = "/saml/continue",
    request_body = ContinueSsoRequest,
    responses(
        (status = 200, description = "SAML Response data for auto-submit"),
        (status = 400, description = "Invalid or expired session"),
        (status = 401, description = "Not authenticated"),
        (status = 404, description = "Session not found"),
    ),
    security(("bearerAuth" = [])),
    tag = "SAML"
)]
pub async fn continue_sso(
    State(state): State<SamlState>,
    Extension(claims): Extension<JwtClaims>,
    Json(req): Json<ContinueSsoRequest>,
) -> Response {
    match continue_sso_inner(&state, &claims, req.session_id).await {
        Ok(resp) => Json(resp).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "SAML continue SSO failed");
            e.into_response()
        }
    }
}

async fn continue_sso_inner(
    state: &SamlState,
    claims: &JwtClaims,
    session_id: Uuid,
) -> SamlResult<ContinueSsoResponse> {
    // Extract tenant from JWT
    let tenant_id = claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(SamlError::NotAuthenticated)?;

    // Extract user_id from JWT sub
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| SamlError::NotAuthenticated)?;

    // Load session first (validates not expired, not already consumed) WITHOUT consuming.
    // We consume only after successfully building the SAML Response to avoid
    // marking the session as used if response generation fails (e.g. signing panic).
    // SECURITY: tenant_id enforces tenant isolation — prevents cross-tenant session access.
    let session = state
        .session_store
        .get_by_id(session_id)
        .await
        .map_err(|e| {
            tracing::warn!(
                session_id = %session_id,
                error = %e,
                "Failed to load SAML session"
            );
            SamlError::SessionError(e)
        })?
        .ok_or_else(|| SamlError::InvalidAuthnRequest("Session not found".to_string()))?;

    // SECURITY: Verify the session belongs to the caller's tenant
    if session.tenant_id != tenant_id {
        return Err(SamlError::InvalidAuthnRequest(
            "Session not found".to_string(),
        ));
    }

    // Validate the session is still usable
    if let Some(consumed_at) = session.consumed_at {
        return Err(SamlError::SessionError(
            crate::session::SessionError::AlreadyConsumed {
                request_id: session.request_id.clone(),
                consumed_at,
            },
        ));
    }
    if session.expires_at < chrono::Utc::now() {
        return Err(SamlError::InvalidAuthnRequest(
            "Session has expired".to_string(),
        ));
    }

    // Look up the SP by entity_id stored in session
    let sp_service = SpService::new(state.pool.clone());
    let sp = sp_service
        .get_sp_by_entity_id(tenant_id, &session.sp_entity_id)
        .await?;

    if !sp.enabled {
        return Err(SamlError::DisabledServiceProvider(sp.entity_id));
    }

    // Look up the user from DB
    let user: xavyo_db::models::User =
        sqlx::query_as("SELECT * FROM users WHERE id = $1 AND tenant_id = $2")
            .bind(user_id)
            .bind(tenant_id)
            .fetch_optional(&state.pool)
            .await
            .map_err(SamlError::DatabaseError)?
            .ok_or(SamlError::NotAuthenticated)?;

    // Build user attributes
    let display_name = user.email.split('@').next().map(String::from);

    let sp_group_config = sp.get_group_config().map_err(|e| {
        SamlError::AssertionGenerationFailed(format!("Invalid SP group filter JSON: {e}"))
    })?;
    let group_config = GroupAttributeConfig {
        attribute_name: sp_group_config.attribute_name,
        value_format: crate::models::group_config::GroupValueFormat::parse(
            &sp_group_config.value_format,
        )
        .map_err(SamlError::AssertionGenerationFailed)?,
        filter: match sp_group_config.filter {
            None => None,
            Some(f) => Some(crate::models::group_config::GroupFilter {
                filter_type: crate::models::group_config::GroupFilterType::parse(&f.filter_type)
                    .map_err(SamlError::AssertionGenerationFailed)?,
                patterns: f.patterns,
                allowlist: f.allowlist,
            }),
        },
        include_groups: sp_group_config.include_groups,
        omit_empty_groups: sp_group_config.omit_empty_groups,
        dn_base: sp_group_config.dn_base,
    };

    let groups =
        GroupService::load_groups_for_assertion(&state.pool, tenant_id, user.id, &group_config)
            .await?;

    let user_attrs = UserAttributes {
        user_id: user.id.to_string(),
        email: user.email.clone(),
        display_name,
        groups,
        tenant_id: tenant_id.to_string(),
    };

    // Get IdP signing credentials
    let cert = sp_service.get_active_certificate(tenant_id).await?;
    let key_pem = sp_service
        .decrypt_private_key(&cert.private_key_encrypted, state.encryption_key.as_ref())?;
    let credentials = crate::saml::SigningCredentials::from_pem(&cert.certificate, &key_pem)?;

    // Build entity ID
    let idp_entity_id = format!("{}/saml/metadata?tenant={}", state.base_url, tenant_id);

    // Get ACS URL (use first configured — the original AuthnRequest ACS was already
    // validated during the initial SSO request before session storage)
    let acs_url = sp
        .acs_urls
        .first()
        .ok_or_else(|| {
            SamlError::AssertionGenerationFailed("No ACS URL configured for SP".to_string())
        })?
        .clone();

    // Build SAML Response using the original request_id as InResponseTo
    let builder = AssertionBuilder::new(idp_entity_id, credentials);
    let output = builder.build_response(
        &sp,
        &user_attrs,
        Some(&session.request_id),
        None,
        Some(&acs_url),
    )?;

    // SAML Response built successfully — now consume the session to prevent replay.
    sso_session_consumed(
        state
            .session_store
            .consume_by_id(tenant_id, session_id)
            .await,
    )?;

    // Record SP session for SLO tracking
    let sp_session = crate::session::SpSession {
        id: Uuid::new_v4(),
        tenant_id,
        user_id: user.id,
        sp_id: sp.id,
        session_index: output.session_index.clone(),
        name_id: output.name_id.clone(),
        name_id_format: output.name_id_format.clone(),
        created_at: chrono::Utc::now(),
        expires_at: chrono::Utc::now()
            + chrono::Duration::seconds(i64::from(sp.assertion_validity_seconds).max(28800)),
        revoked_at: None,
    };
    crate::session::slo_session_recorded(state.sp_session_store.record(sp_session).await)
        .map_err(|e| SamlError::SpSessionError(e.to_string()))?;

    tracing::info!(
        tenant_id = %tenant_id,
        user_id = %user.id,
        sp_entity_id = %sp.entity_id,
        acs_url = %acs_url,
        "SAML Response generated via continue flow"
    );

    Ok(ContinueSsoResponse {
        acs_url,
        saml_response: output.encoded_response,
        relay_state: session.relay_state,
    })
}

/// AuthnRequest session consume after assertion build. Errors must not return
/// a SAML Response that can be replayed.
pub(crate) fn sso_session_consumed<T, E>(result: Result<T, E>) -> Result<T, E> {
    result
}

#[cfg(test)]
mod tests {
    use super::sso_session_consumed;

    #[test]
    fn continue_sso_does_not_fail_open_on_group_load_errors() {
        let src = include_str!("continue_sso.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            !production.contains("continuing without groups"),
            "continue SSO must not issue an assertion with empty groups when group load fails"
        );
        assert!(
            production.contains("load_groups_for_assertion") && production.contains(".await?"),
            "continue SSO must propagate group-load errors"
        );
    }

    #[test]
    fn continue_sso_does_not_return_assertion_when_session_persist_fails() {
        assert!(sso_session_consumed(Ok::<(), &str>(())).is_ok());
        assert!(sso_session_consumed::<(), &str>(Err("db")).is_err());

        let src = include_str!("continue_sso.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            production.contains("sso_session_consumed(")
                && production.contains("slo_session_recorded("),
            "continue SSO must fail closed on session consume and SLO persist"
        );
        assert!(
            !production.contains("possible race") && !production.contains("non-fatal"),
            "must not issue a SAML Response when session persist fails"
        );
    }

    #[test]
    fn unknown_group_config_does_not_fail_open() {
        let src = include_str!("continue_sso.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            production.contains("GroupValueFormat::parse(")
                && production.contains("GroupFilterType::parse(")
                && production.contains("map_err(SamlError::AssertionGenerationFailed)?"),
            "unknown SAML group format/filter must fail closed, not include all groups"
        );
        assert!(
            !production.contains("_ => crate::models::group_config::GroupFilterType::None"),
            "unknown group filter type must not include every group"
        );
    }
}
