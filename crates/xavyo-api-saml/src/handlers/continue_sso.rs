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

    // Consume the session atomically (validates not expired, not already consumed).
    // SECURITY: tenant_id enforces tenant isolation — prevents cross-tenant session consumption.
    let session = state
        .session_store
        .consume_by_id(tenant_id, session_id)
        .await
        .map_err(|e| {
            tracing::warn!(
                session_id = %session_id,
                error = %e,
                "Failed to consume SAML session"
            );
            SamlError::SessionError(e)
        })?;

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

    let sp_group_config = sp.get_group_config();
    let group_config = GroupAttributeConfig {
        attribute_name: sp_group_config.attribute_name,
        value_format: crate::models::group_config::GroupValueFormat::parse(
            &sp_group_config.value_format,
        ),
        filter: sp_group_config
            .filter
            .map(|f| crate::models::group_config::GroupFilter {
                filter_type: match f.filter_type.as_str() {
                    "pattern" => crate::models::group_config::GroupFilterType::Pattern,
                    "allowlist" => crate::models::group_config::GroupFilterType::Allowlist,
                    _ => crate::models::group_config::GroupFilterType::None,
                },
                patterns: f.patterns,
                allowlist: f.allowlist,
            }),
        include_groups: sp_group_config.include_groups,
        omit_empty_groups: sp_group_config.omit_empty_groups,
        dn_base: sp_group_config.dn_base,
    };

    let groups =
        GroupService::load_groups_for_assertion(&state.pool, tenant_id, user.id, &group_config)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(
                    tenant_id = %tenant_id,
                    user_id = %user.id,
                    error = %e,
                    "Failed to load user groups, continuing without groups"
                );
                vec![]
            });

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
    if let Err(e) = state.sp_session_store.record(sp_session).await {
        tracing::warn!(
            tenant_id = %tenant_id,
            user_id = %user.id,
            sp_id = %sp.id,
            error = %e,
            "Failed to record SP session for SLO (non-fatal)"
        );
    }

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
