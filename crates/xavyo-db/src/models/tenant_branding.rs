//! Tenant branding model.
//!
//! Visual customization settings for a tenant's login pages and UI.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgExecutor};
use uuid::Uuid;

/// Tenant branding configuration.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct TenantBranding {
    /// The tenant this branding belongs to.
    pub tenant_id: Uuid,

    /// Primary logo URL.
    pub logo_url: Option<String>,

    /// Logo for dark mode.
    pub logo_dark_url: Option<String>,

    /// Favicon URL.
    pub favicon_url: Option<String>,

    /// Logo used in emails.
    pub email_logo_url: Option<String>,

    /// Primary brand color (#RRGGBB).
    pub primary_color: Option<String>,

    /// Secondary color.
    pub secondary_color: Option<String>,

    /// Accent/highlight color.
    pub accent_color: Option<String>,

    /// Background color.
    pub background_color: Option<String>,

    /// Main text color.
    pub text_color: Option<String>,

    /// Font family name.
    pub font_family: Option<String>,

    /// Sanitized custom CSS.
    pub custom_css: Option<String>,

    /// Login page heading.
    pub login_page_title: Option<String>,

    /// Login page subheading.
    pub login_page_subtitle: Option<String>,

    /// Login background image URL.
    pub login_page_background_url: Option<String>,

    /// Footer text.
    pub footer_text: Option<String>,

    /// Privacy policy link.
    pub privacy_policy_url: Option<String>,

    /// Terms of service link.
    pub terms_of_service_url: Option<String>,

    /// Support/help link.
    pub support_url: Option<String>,

    /// Consent page title (e.g., "Authorize Application").
    pub consent_page_title: Option<String>,

    /// Consent page subtitle (e.g., "{client_name} wants to access your account").
    pub consent_page_subtitle: Option<String>,

    /// Consent approval button text (e.g., "Allow").
    pub consent_approval_button_text: Option<String>,

    /// Consent denial button text (e.g., "Deny").
    pub consent_denial_button_text: Option<String>,

    /// User who last updated the branding.
    pub updated_by: Option<Uuid>,

    /// When the branding was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Data for updating tenant branding.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct UpdateBranding {
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

/// Public branding data (for unauthenticated login pages).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicBranding {
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

impl Default for PublicBranding {
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

impl From<TenantBranding> for PublicBranding {
    fn from(branding: TenantBranding) -> Self {
        Self {
            logo_url: branding.logo_url,
            logo_dark_url: branding.logo_dark_url,
            favicon_url: branding.favicon_url,
            primary_color: branding
                .primary_color
                .unwrap_or_else(|| "#1a73e8".to_string()),
            secondary_color: branding.secondary_color,
            accent_color: branding.accent_color,
            background_color: branding.background_color,
            text_color: branding.text_color,
            font_family: branding.font_family,
            login_page_title: branding
                .login_page_title
                .unwrap_or_else(|| "Sign in".to_string()),
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

impl TenantBranding {
    /// Find branding by tenant ID.
    pub async fn find_by_tenant<'e, E>(
        executor: E,
        tenant_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as("SELECT * FROM tenant_branding WHERE tenant_id = $1")
            .bind(tenant_id)
            .fetch_optional(executor)
            .await
    }

    /// Find branding by tenant slug (for public endpoint).
    pub async fn find_by_slug<'e, E>(executor: E, slug: &str) -> Result<Option<Self>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as(
            r"
            SELECT tb.*
            FROM tenant_branding tb
            JOIN tenants t ON t.id = tb.tenant_id
            WHERE t.slug = $1
            ",
        )
        .bind(slug)
        .fetch_optional(executor)
        .await
    }

    /// Create or update branding configuration.
    pub async fn upsert<'e, E>(
        executor: E,
        tenant_id: Uuid,
        data: UpdateBranding,
        updated_by: Option<Uuid>,
    ) -> Result<Self, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as(
            r"
            INSERT INTO tenant_branding (
                tenant_id,
                logo_url,
                logo_dark_url,
                favicon_url,
                email_logo_url,
                primary_color,
                secondary_color,
                accent_color,
                background_color,
                text_color,
                font_family,
                custom_css,
                login_page_title,
                login_page_subtitle,
                login_page_background_url,
                footer_text,
                privacy_policy_url,
                terms_of_service_url,
                support_url,
                consent_page_title,
                consent_page_subtitle,
                consent_approval_button_text,
                consent_denial_button_text,
                updated_by,
                updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, NOW())
            ON CONFLICT (tenant_id) DO UPDATE SET
                logo_url = COALESCE($2, tenant_branding.logo_url),
                logo_dark_url = COALESCE($3, tenant_branding.logo_dark_url),
                favicon_url = COALESCE($4, tenant_branding.favicon_url),
                email_logo_url = COALESCE($5, tenant_branding.email_logo_url),
                primary_color = COALESCE($6, tenant_branding.primary_color),
                secondary_color = COALESCE($7, tenant_branding.secondary_color),
                accent_color = COALESCE($8, tenant_branding.accent_color),
                background_color = COALESCE($9, tenant_branding.background_color),
                text_color = COALESCE($10, tenant_branding.text_color),
                font_family = COALESCE($11, tenant_branding.font_family),
                custom_css = COALESCE($12, tenant_branding.custom_css),
                login_page_title = COALESCE($13, tenant_branding.login_page_title),
                login_page_subtitle = COALESCE($14, tenant_branding.login_page_subtitle),
                login_page_background_url = COALESCE($15, tenant_branding.login_page_background_url),
                footer_text = COALESCE($16, tenant_branding.footer_text),
                privacy_policy_url = COALESCE($17, tenant_branding.privacy_policy_url),
                terms_of_service_url = COALESCE($18, tenant_branding.terms_of_service_url),
                support_url = COALESCE($19, tenant_branding.support_url),
                consent_page_title = COALESCE($20, tenant_branding.consent_page_title),
                consent_page_subtitle = COALESCE($21, tenant_branding.consent_page_subtitle),
                consent_approval_button_text = COALESCE($22, tenant_branding.consent_approval_button_text),
                consent_denial_button_text = COALESCE($23, tenant_branding.consent_denial_button_text),
                updated_by = $24,
                updated_at = NOW()
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(&data.logo_url)
        .bind(&data.logo_dark_url)
        .bind(&data.favicon_url)
        .bind(&data.email_logo_url)
        .bind(&data.primary_color)
        .bind(&data.secondary_color)
        .bind(&data.accent_color)
        .bind(&data.background_color)
        .bind(&data.text_color)
        .bind(&data.font_family)
        .bind(&data.custom_css)
        .bind(&data.login_page_title)
        .bind(&data.login_page_subtitle)
        .bind(&data.login_page_background_url)
        .bind(&data.footer_text)
        .bind(&data.privacy_policy_url)
        .bind(&data.terms_of_service_url)
        .bind(&data.support_url)
        .bind(&data.consent_page_title)
        .bind(&data.consent_page_subtitle)
        .bind(&data.consent_approval_button_text)
        .bind(&data.consent_denial_button_text)
        .bind(updated_by)
        .fetch_one(executor)
        .await
    }

    /// Delete branding for a tenant.
    pub async fn delete<'e, E>(executor: E, tenant_id: Uuid) -> Result<bool, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        let result = sqlx::query("DELETE FROM tenant_branding WHERE tenant_id = $1")
            .bind(tenant_id)
            .execute(executor)
            .await?;
        Ok(result.rows_affected() > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_branding_defaults() {
        let branding = PublicBranding::default();
        assert_eq!(branding.primary_color, "#1a73e8");
        assert_eq!(branding.login_page_title, "Sign in");
        assert!(branding.logo_url.is_none());
    }

    #[test]
    fn test_update_branding_defaults() {
        let update = UpdateBranding::default();
        assert!(update.logo_url.is_none());
        assert!(update.primary_color.is_none());
    }
}
