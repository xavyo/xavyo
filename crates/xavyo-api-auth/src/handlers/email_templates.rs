//! HTTP handlers for email template endpoints (F030).
//!
//! Admin endpoints for managing email templates:
//! - GET /admin/branding/email-templates - List templates
//! - GET /admin/branding/email-templates/:type - Get template
//! - PUT /admin/branding/email-templates/:type - Update template
//! - POST /admin/branding/email-templates/:type/preview - Preview template
//! - POST /admin/branding/email-templates/:type/reset - Reset to default

use axum::{
    extract::{Path, Query},
    Extension, Json,
};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;
use xavyo_auth::JwtClaims;
use xavyo_core::TenantId;
use xavyo_db::models::TemplateType;

use crate::error::ApiAuthError;
use crate::models::{
    EmailTemplatePreviewResponse, EmailTemplateResponse, EmailTemplateSummaryResponse,
    PreviewEmailTemplateRequest, UpdateEmailTemplateRequest,
};
use crate::services::EmailTemplateService;

/// Query parameters for listing templates.
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct ListTemplatesQuery {
    /// Filter by locale (optional, defaults to "en").
    pub locale: Option<String>,
}

/// Path parameters for template endpoints.
#[derive(Debug, Deserialize)]
pub struct TemplatePath {
    /// Template type (welcome, `password_reset`, etc.).
    pub template_type: String,
}

/// Query parameters for template endpoints.
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct TemplateQuery {
    /// Locale (optional, defaults to "en").
    pub locale: Option<String>,
}

// ============================================================================
// Email Template Handlers (US3)
// ============================================================================

/// List all email templates for the tenant.
#[utoipa::path(
    get,
    path = "/admin/branding/email-templates",
    params(ListTemplatesQuery),
    responses(
        (status = 200, description = "List of templates", body = Vec<EmailTemplateSummaryResponse>),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "Email Templates"
)]
pub async fn list_templates(
    Extension(tenant_id): Extension<TenantId>,
    Extension(template_service): Extension<Arc<EmailTemplateService>>,
    Query(query): Query<ListTemplatesQuery>,
) -> Result<Json<Vec<EmailTemplateSummaryResponse>>, ApiAuthError> {
    let tenant_uuid = *tenant_id.as_uuid();
    let templates = template_service
        .list_templates(tenant_uuid, query.locale.as_deref())
        .await?;
    Ok(Json(templates))
}

/// Get a specific email template.
#[utoipa::path(
    get,
    path = "/admin/branding/email-templates/{template_type}",
    params(
        ("template_type" = String, Path, description = "Template type"),
        TemplateQuery,
    ),
    responses(
        (status = 200, description = "Email template", body = EmailTemplateResponse),
        (status = 404, description = "Template not found"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "Email Templates"
)]
pub async fn get_template(
    Extension(tenant_id): Extension<TenantId>,
    Extension(template_service): Extension<Arc<EmailTemplateService>>,
    Path(path): Path<TemplatePath>,
    Query(query): Query<TemplateQuery>,
) -> Result<Json<EmailTemplateResponse>, ApiAuthError> {
    let tenant_uuid = *tenant_id.as_uuid();
    let template_type: TemplateType = path
        .template_type
        .parse()
        .map_err(|e: String| ApiAuthError::Validation(e))?;
    let locale = query.locale.as_deref().unwrap_or("en");

    let template = template_service
        .get_template(tenant_uuid, template_type, locale)
        .await?;
    Ok(Json(template))
}

/// Update an email template.
#[utoipa::path(
    put,
    path = "/admin/branding/email-templates/{template_type}",
    params(
        ("template_type" = String, Path, description = "Template type"),
        TemplateQuery,
    ),
    request_body = UpdateEmailTemplateRequest,
    responses(
        (status = 200, description = "Template updated", body = EmailTemplateResponse),
        (status = 400, description = "Invalid request"),
        (status = 404, description = "Template not found"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "Email Templates"
)]
pub async fn update_template(
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Extension(template_service): Extension<Arc<EmailTemplateService>>,
    Path(path): Path<TemplatePath>,
    Query(query): Query<TemplateQuery>,
    Json(request): Json<UpdateEmailTemplateRequest>,
) -> Result<Json<EmailTemplateResponse>, ApiAuthError> {
    let tenant_uuid = *tenant_id.as_uuid();
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiAuthError::Unauthorized)?;
    let template_type: TemplateType = path
        .template_type
        .parse()
        .map_err(|e: String| ApiAuthError::Validation(e))?;
    let locale = query.locale.as_deref().unwrap_or("en");

    let template = template_service
        .update_template(tenant_uuid, user_id, template_type, locale, request)
        .await?;
    Ok(Json(template))
}

/// Preview an email template with sample data.
#[utoipa::path(
    post,
    path = "/admin/branding/email-templates/{template_type}/preview",
    params(
        ("template_type" = String, Path, description = "Template type"),
        TemplateQuery,
    ),
    request_body = PreviewEmailTemplateRequest,
    responses(
        (status = 200, description = "Template preview", body = EmailTemplatePreviewResponse),
        (status = 400, description = "Invalid request"),
        (status = 404, description = "Template not found"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "Email Templates"
)]
pub async fn preview_template(
    Extension(tenant_id): Extension<TenantId>,
    Extension(template_service): Extension<Arc<EmailTemplateService>>,
    Path(path): Path<TemplatePath>,
    Query(query): Query<TemplateQuery>,
    Json(request): Json<PreviewEmailTemplateRequest>,
) -> Result<Json<EmailTemplatePreviewResponse>, ApiAuthError> {
    let tenant_uuid = *tenant_id.as_uuid();
    let template_type: TemplateType = path
        .template_type
        .parse()
        .map_err(|e: String| ApiAuthError::Validation(e))?;
    let locale = request
        .locale
        .as_deref()
        .or(query.locale.as_deref())
        .unwrap_or("en");

    let preview = template_service
        .preview_template(tenant_uuid, template_type, locale, request.sample_data)
        .await?;
    Ok(Json(preview))
}

/// Reset an email template to the default.
#[utoipa::path(
    post,
    path = "/admin/branding/email-templates/{template_type}/reset",
    params(
        ("template_type" = String, Path, description = "Template type"),
        TemplateQuery,
    ),
    responses(
        (status = 200, description = "Template reset to default", body = EmailTemplateResponse),
        (status = 404, description = "Template not found"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "Email Templates"
)]
pub async fn reset_template(
    Extension(tenant_id): Extension<TenantId>,
    Extension(template_service): Extension<Arc<EmailTemplateService>>,
    Path(path): Path<TemplatePath>,
    Query(query): Query<TemplateQuery>,
) -> Result<Json<EmailTemplateResponse>, ApiAuthError> {
    let tenant_uuid = *tenant_id.as_uuid();
    let template_type: TemplateType = path
        .template_type
        .parse()
        .map_err(|e: String| ApiAuthError::Validation(e))?;
    let locale = query.locale.as_deref().unwrap_or("en");

    let template = template_service
        .reset_template(tenant_uuid, template_type, locale)
        .await?;
    Ok(Json(template))
}
