//! IdP-initiated SSO handler

use crate::error::{SamlError, SamlResult};
use crate::handlers::metadata::SamlState;
use crate::models::group_config::GroupAttributeConfig;
use crate::models::{generate_auto_submit_form, InitiateSsoRequest};
use crate::saml::UserAttributes;
use crate::services::{AssertionBuilder, GroupService, SpService};
use axum::{
    extract::{Path, State},
    response::{Html, IntoResponse, Response},
    Extension, Json,
};
use uuid::Uuid;
use xavyo_core::TenantId;
use xavyo_db::models::User;

/// IdP-initiated SSO
#[utoipa::path(
    post,
    path = "/saml/initiate/{sp_id}",
    params(
        ("sp_id" = Uuid, Path, description = "Service Provider ID"),
    ),
    request_body = InitiateSsoRequest,
    responses(
        (status = 200, description = "SAML Response form"),
        (status = 401, description = "Not authenticated"),
        (status = 404, description = "Service provider not found"),
    ),
    security(("bearerAuth" = [])),
    tag = "SAML"
)]
pub async fn initiate_sso(
    State(state): State<SamlState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(user): Extension<Option<User>>,
    Path(sp_id): Path<Uuid>,
    Json(req): Json<InitiateSsoRequest>,
) -> Response {
    match initiate_sso_inner(
        &state,
        *tenant_id.as_uuid(),
        user,
        sp_id,
        req.relay_state.as_deref(),
    )
    .await
    {
        Ok(response) => response,
        Err(e) => {
            tracing::error!(error = %e, sp_id = %sp_id, "IdP-initiated SSO failed");
            e.into_response()
        }
    }
}

async fn initiate_sso_inner(
    state: &SamlState,
    tenant_id: Uuid,
    user: Option<User>,
    sp_id: Uuid,
    relay_state: Option<&str>,
) -> SamlResult<Response> {
    // Require authenticated user
    let user = user.ok_or(SamlError::NotAuthenticated)?;

    // Look up the SP
    let sp_service = SpService::new(state.pool.clone());
    let sp = sp_service.get_sp(tenant_id, sp_id).await?;

    // Check if SP is enabled
    if !sp.enabled {
        return Err(SamlError::DisabledServiceProvider(sp.entity_id.clone()));
    }

    tracing::info!(
        tenant_id = %tenant_id,
        user_id = %user.id,
        sp_id = %sp_id,
        sp_entity_id = %sp.entity_id,
        "IdP-initiated SSO started"
    );

    // Build user attributes
    // Note: User model doesn't have display_name, derive from email
    let display_name = user.email.split('@').next().map(String::from);

    // Load user groups with SP-specific configuration
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

    // Build unsolicited SAML Response
    let builder = AssertionBuilder::new(idp_entity_id, credentials);
    let saml_response = builder.build_unsolicited_response(&sp, &user_attrs, None)?;

    // Get ACS URL (use first configured)
    let acs_url = sp
        .acs_urls
        .first()
        .ok_or_else(|| SamlError::AssertionGenerationFailed("No ACS URL configured".to_string()))?;

    tracing::info!(
        tenant_id = %tenant_id,
        user_id = %user.id,
        sp_entity_id = %sp.entity_id,
        acs_url = %acs_url,
        "IdP-initiated SAML Response generated"
    );

    // Return auto-submit form
    let html = generate_auto_submit_form(acs_url, &saml_response, relay_state);

    Ok(Html(html).into_response())
}
