//! Request and response types for branding API endpoints.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;
use validator::Validate;

/// Request to update tenant branding.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct UpdateBrandingRequest {
    pub logo_url: Option<String>,
    pub logo_dark_url: Option<String>,
    pub favicon_url: Option<String>,
    pub email_logo_url: Option<String>,
    pub primary_color: Option<String>,
    pub secondary_color: Option<String>,
    pub accent_color: Option<String>,
    pub background_color: Option<String>,
    pub text_color: Option<String>,
    pub font_family: Option<String>,
    pub custom_css: Option<String>,
    pub login_page_title: Option<String>,
    pub login_page_subtitle: Option<String>,
    pub login_page_background_url: Option<String>,
    pub footer_text: Option<String>,
    pub privacy_policy_url: Option<String>,
    pub terms_of_service_url: Option<String>,
    pub support_url: Option<String>,
    pub consent_page_title: Option<String>,
    pub consent_page_subtitle: Option<String>,
    pub consent_approval_button_text: Option<String>,
    pub consent_denial_button_text: Option<String>,
}

impl Validate for UpdateBrandingRequest {
    fn validate(&self) -> Result<(), validator::ValidationErrors> {
        let mut errors = validator::ValidationErrors::new();

        // URL fields: max 2048 chars
        let url_fields: &[(&Option<String>, &str)] = &[
            (&self.logo_url, "logo_url"),
            (&self.logo_dark_url, "logo_dark_url"),
            (&self.favicon_url, "favicon_url"),
            (&self.email_logo_url, "email_logo_url"),
            (&self.login_page_background_url, "login_page_background_url"),
            (&self.privacy_policy_url, "privacy_policy_url"),
            (&self.terms_of_service_url, "terms_of_service_url"),
            (&self.support_url, "support_url"),
        ];
        for (field, name) in url_fields {
            if let Some(v) = field {
                if v.len() > 2048 {
                    let mut err = validator::ValidationError::new("length");
                    err.message = Some(format!("{name} must be at most 2048 characters").into());
                    errors.add(name, err);
                }
            }
        }

        // Color fields: max 25 chars (e.g., #RRGGBB, rgb(), hsl())
        let color_fields: &[(&Option<String>, &str)] = &[
            (&self.primary_color, "primary_color"),
            (&self.secondary_color, "secondary_color"),
            (&self.accent_color, "accent_color"),
            (&self.background_color, "background_color"),
            (&self.text_color, "text_color"),
        ];
        for (field, name) in color_fields {
            if let Some(v) = field {
                if v.len() > 25 {
                    let mut err = validator::ValidationError::new("length");
                    err.message = Some(format!("{name} must be at most 25 characters").into());
                    errors.add(name, err);
                }
            }
        }

        // Font family: max 255 chars
        if let Some(ref v) = self.font_family {
            if v.len() > 255 {
                let mut err = validator::ValidationError::new("length");
                err.message = Some("font_family must be at most 255 characters".into());
                errors.add("font_family", err);
            }
        }

        // custom_css: max 50KB
        if let Some(ref v) = self.custom_css {
            if v.len() > 51_200 {
                let mut err = validator::ValidationError::new("length");
                err.message = Some("custom_css must be at most 50KB".into());
                errors.add("custom_css", err);
            }
        }

        // Text fields: max 500 chars
        let text_fields: &[(&Option<String>, &str)] = &[
            (&self.login_page_title, "login_page_title"),
            (&self.login_page_subtitle, "login_page_subtitle"),
            (&self.footer_text, "footer_text"),
        ];
        for (field, name) in text_fields {
            if let Some(v) = field {
                if v.len() > 500 {
                    let mut err = validator::ValidationError::new("length");
                    err.message = Some(format!("{name} must be at most 500 characters").into());
                    errors.add(name, err);
                }
            }
        }

        // Consent title: max 255 chars (VARCHAR(255))
        if let Some(ref v) = self.consent_page_title {
            if v.len() > 255 {
                let mut err = validator::ValidationError::new("length");
                err.message = Some("consent_page_title must be at most 255 characters".into());
                errors.add("consent_page_title", err);
            }
        }

        // Consent subtitle: max 500 chars (VARCHAR(500))
        if let Some(ref v) = self.consent_page_subtitle {
            if v.len() > 500 {
                let mut err = validator::ValidationError::new("length");
                err.message = Some("consent_page_subtitle must be at most 500 characters".into());
                errors.add("consent_page_subtitle", err);
            }
        }

        // Consent button text: max 100 chars (VARCHAR(100))
        let button_fields: &[(&Option<String>, &str)] = &[
            (
                &self.consent_approval_button_text,
                "consent_approval_button_text",
            ),
            (
                &self.consent_denial_button_text,
                "consent_denial_button_text",
            ),
        ];
        for (field, name) in button_fields {
            if let Some(v) = field {
                if v.len() > 100 {
                    let mut err = validator::ValidationError::new("length");
                    err.message = Some(format!("{name} must be at most 100 characters").into());
                    errors.add(name, err);
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

/// Response for tenant branding configuration.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct BrandingResponse {
    pub logo_url: Option<String>,
    pub logo_dark_url: Option<String>,
    pub favicon_url: Option<String>,
    pub email_logo_url: Option<String>,
    pub primary_color: Option<String>,
    pub secondary_color: Option<String>,
    pub accent_color: Option<String>,
    pub background_color: Option<String>,
    pub text_color: Option<String>,
    pub font_family: Option<String>,
    pub custom_css: Option<String>,
    pub login_page_title: Option<String>,
    pub login_page_subtitle: Option<String>,
    pub login_page_background_url: Option<String>,
    pub footer_text: Option<String>,
    pub privacy_policy_url: Option<String>,
    pub terms_of_service_url: Option<String>,
    pub support_url: Option<String>,
    pub consent_page_title: Option<String>,
    pub consent_page_subtitle: Option<String>,
    pub consent_approval_button_text: Option<String>,
    pub consent_denial_button_text: Option<String>,
    pub updated_at: Option<DateTime<Utc>>,
}

/// Response for public branding (login page).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PublicBrandingResponse {
    pub logo_url: Option<String>,
    pub logo_dark_url: Option<String>,
    pub favicon_url: Option<String>,
    pub primary_color: String,
    pub secondary_color: Option<String>,
    pub accent_color: Option<String>,
    pub background_color: Option<String>,
    pub text_color: Option<String>,
    pub font_family: Option<String>,
    pub login_page_title: String,
    pub login_page_subtitle: Option<String>,
    pub login_page_background_url: Option<String>,
    pub footer_text: Option<String>,
    pub privacy_policy_url: Option<String>,
    pub terms_of_service_url: Option<String>,
    pub support_url: Option<String>,
    pub consent_page_title: Option<String>,
    pub consent_page_subtitle: Option<String>,
    pub consent_approval_button_text: Option<String>,
    pub consent_denial_button_text: Option<String>,
}

/// Response for branding asset upload.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AssetResponse {
    pub id: Uuid,
    pub asset_type: String,
    pub filename: String,
    pub content_type: String,
    pub file_size: i32,
    pub url: String,
    pub width: i32,
    pub height: i32,
    pub checksum: String,
    pub created_at: DateTime<Utc>,
}

/// Summary of an email template.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct EmailTemplateSummaryResponse {
    pub template_type: String,
    pub locale: String,
    pub is_customized: bool,
    pub is_active: bool,
    pub updated_at: Option<DateTime<Utc>>,
}

/// Email template variable documentation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TemplateVariableInfo {
    pub name: String,
    pub description: String,
}

/// Full email template response.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct EmailTemplateResponse {
    pub template_type: String,
    pub locale: String,
    pub subject: String,
    pub body_html: String,
    pub body_text: Option<String>,
    pub available_variables: Vec<TemplateVariableInfo>,
    pub is_customized: bool,
    pub is_active: bool,
    pub updated_at: Option<DateTime<Utc>>,
}

/// Request to update an email template.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct UpdateEmailTemplateRequest {
    pub locale: Option<String>,
    pub subject: Option<String>,
    pub body_html: Option<String>,
    pub body_text: Option<String>,
    pub is_active: Option<bool>,
}

impl Validate for UpdateEmailTemplateRequest {
    fn validate(&self) -> Result<(), validator::ValidationErrors> {
        let mut errors = validator::ValidationErrors::new();

        if let Some(ref v) = self.locale {
            if v.len() > 10 {
                let mut err = validator::ValidationError::new("length");
                err.message = Some("locale must be at most 10 characters".into());
                errors.add("locale", err);
            }
        }
        if let Some(ref v) = self.subject {
            if v.len() > 500 {
                let mut err = validator::ValidationError::new("length");
                err.message = Some("subject must be at most 500 characters".into());
                errors.add("subject", err);
            }
        }
        if let Some(ref v) = self.body_html {
            if v.len() > 102_400 {
                let mut err = validator::ValidationError::new("length");
                err.message = Some("body_html must be at most 100KB".into());
                errors.add("body_html", err);
            }
        }
        if let Some(ref v) = self.body_text {
            if v.len() > 102_400 {
                let mut err = validator::ValidationError::new("length");
                err.message = Some("body_text must be at most 100KB".into());
                errors.add("body_text", err);
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

/// Request to preview an email template.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct PreviewEmailTemplateRequest {
    pub locale: Option<String>,
    pub sample_data: Option<std::collections::HashMap<String, String>>,
}

/// Response for email template preview.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct EmailTemplatePreviewResponse {
    pub subject: String,
    pub body_html: String,
    pub body_text: Option<String>,
}

impl From<xavyo_db::models::TenantBranding> for BrandingResponse {
    fn from(branding: xavyo_db::models::TenantBranding) -> Self {
        Self {
            logo_url: branding.logo_url,
            logo_dark_url: branding.logo_dark_url,
            favicon_url: branding.favicon_url,
            email_logo_url: branding.email_logo_url,
            primary_color: branding.primary_color,
            secondary_color: branding.secondary_color,
            accent_color: branding.accent_color,
            background_color: branding.background_color,
            text_color: branding.text_color,
            font_family: branding.font_family,
            custom_css: branding.custom_css,
            login_page_title: branding.login_page_title,
            login_page_subtitle: branding.login_page_subtitle,
            login_page_background_url: branding.login_page_background_url,
            footer_text: branding.footer_text,
            privacy_policy_url: branding.privacy_policy_url,
            terms_of_service_url: branding.terms_of_service_url,
            support_url: branding.support_url,
            consent_page_title: branding.consent_page_title,
            consent_page_subtitle: branding.consent_page_subtitle,
            consent_approval_button_text: branding.consent_approval_button_text,
            consent_denial_button_text: branding.consent_denial_button_text,
            updated_at: Some(branding.updated_at),
        }
    }
}

impl From<xavyo_db::models::PublicBranding> for PublicBrandingResponse {
    fn from(branding: xavyo_db::models::PublicBranding) -> Self {
        Self {
            logo_url: branding.logo_url,
            logo_dark_url: branding.logo_dark_url,
            favicon_url: branding.favicon_url,
            primary_color: branding.primary_color,
            secondary_color: branding.secondary_color,
            accent_color: branding.accent_color,
            background_color: branding.background_color,
            text_color: branding.text_color,
            font_family: branding.font_family,
            login_page_title: branding.login_page_title,
            login_page_subtitle: branding.login_page_subtitle,
            login_page_background_url: branding.login_page_background_url,
            footer_text: branding.footer_text,
            privacy_policy_url: branding.privacy_policy_url,
            terms_of_service_url: branding.terms_of_service_url,
            support_url: branding.support_url,
            consent_page_title: branding.consent_page_title,
            consent_page_subtitle: branding.consent_page_subtitle,
            consent_approval_button_text: branding.consent_approval_button_text,
            consent_denial_button_text: branding.consent_denial_button_text,
        }
    }
}

impl From<xavyo_db::models::BrandingAsset> for AssetResponse {
    fn from(asset: xavyo_db::models::BrandingAsset) -> Self {
        Self {
            id: asset.id,
            asset_type: asset.asset_type,
            filename: asset.filename,
            content_type: asset.content_type,
            file_size: asset.file_size,
            url: asset.storage_path,
            width: asset.width,
            height: asset.height,
            checksum: asset.checksum,
            created_at: asset.created_at,
        }
    }
}

impl BrandingResponse {
    /// Create a default branding response for a tenant with no branding configured.
    #[must_use]
    pub fn default_for_tenant(_tenant_id: Uuid) -> Self {
        Self {
            logo_url: None,
            logo_dark_url: None,
            favicon_url: None,
            email_logo_url: None,
            primary_color: Some("#1a73e8".to_string()),
            secondary_color: None,
            accent_color: None,
            background_color: None,
            text_color: None,
            font_family: None,
            custom_css: None,
            login_page_title: Some("Sign in".to_string()),
            login_page_subtitle: None,
            login_page_background_url: None,
            footer_text: None,
            privacy_policy_url: None,
            terms_of_service_url: None,
            support_url: None,
            consent_page_title: None,
            consent_page_subtitle: None,
            consent_approval_button_text: None,
            consent_denial_button_text: None,
            updated_at: None,
        }
    }
}

impl Default for PublicBrandingResponse {
    fn default() -> Self {
        Self {
            logo_url: None,
            logo_dark_url: None,
            favicon_url: None,
            primary_color: "#1a73e8".to_string(),
            secondary_color: None,
            accent_color: None,
            background_color: None,
            text_color: None,
            font_family: None,
            login_page_title: "Sign in".to_string(),
            login_page_subtitle: None,
            login_page_background_url: None,
            footer_text: None,
            privacy_policy_url: None,
            terms_of_service_url: None,
            support_url: None,
            consent_page_title: None,
            consent_page_subtitle: None,
            consent_approval_button_text: None,
            consent_denial_button_text: None,
        }
    }
}
