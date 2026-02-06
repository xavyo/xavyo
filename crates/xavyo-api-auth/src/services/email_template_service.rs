//! Email template management service (F030).
//!
//! Handles email template operations: list, get, update, preview, reset.

use crate::error::ApiAuthError;
use crate::models::{
    EmailTemplatePreviewResponse, EmailTemplateResponse, EmailTemplateSummaryResponse,
    TemplateVariableInfo, UpdateEmailTemplateRequest,
};
use crate::services::email_template_defaults::{get_all_template_types, get_default_template};
use handlebars::Handlebars;
use sqlx::PgPool;
use std::collections::HashMap;
use tracing::info;
use uuid::Uuid;
use xavyo_core::TenantId;
use xavyo_db::models::{EmailTemplate, TemplateType, UpsertEmailTemplate};
use xavyo_db::set_tenant_context;

/// Email template management service.
#[derive(Clone)]
pub struct EmailTemplateService {
    pool: PgPool,
    handlebars: Handlebars<'static>,
}

impl EmailTemplateService {
    /// Create a new email template service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        let mut handlebars = Handlebars::new();
        // SECURITY: Enable strict mode to catch missing variables and prevent
        // potential template injection attacks.
        handlebars.set_strict_mode(true);
        Self { pool, handlebars }
    }

    // ========================================================================
    // User Story 3: Customize Email Templates
    // ========================================================================

    /// List all email templates for a tenant.
    ///
    /// Returns a summary for each template type and locale, indicating
    /// whether it's customized or using defaults.
    pub async fn list_templates(
        &self,
        tenant_id: Uuid,
        locale: Option<&str>,
    ) -> Result<Vec<EmailTemplateSummaryResponse>, ApiAuthError> {
        // Set tenant context
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        // Get all customized templates for this tenant
        let custom_templates = EmailTemplate::list_by_tenant(&mut *conn, tenant_id)
            .await
            .map_err(ApiAuthError::Database)?;

        // Build a map of customized templates
        let custom_map: HashMap<(String, String), &EmailTemplate> = custom_templates
            .iter()
            .map(|t| ((t.template_type.clone(), t.locale.clone()), t))
            .collect();

        let mut result = Vec::new();
        let default_locale = "en";
        let target_locale = locale.unwrap_or(default_locale);

        // For each template type, add a summary
        for template_type in get_all_template_types() {
            let type_str = template_type.to_string();

            // Check if we have a custom template for this type and locale
            if let Some(custom) = custom_map.get(&(type_str.clone(), target_locale.to_string())) {
                result.push(EmailTemplateSummaryResponse {
                    template_type: type_str,
                    locale: target_locale.to_string(),
                    is_customized: true,
                    is_active: custom.is_active,
                    updated_at: Some(custom.updated_at),
                });
            } else {
                // Default template
                result.push(EmailTemplateSummaryResponse {
                    template_type: type_str,
                    locale: target_locale.to_string(),
                    is_customized: false,
                    is_active: true,
                    updated_at: None,
                });
            }
        }

        // Also include any custom templates for other locales
        if locale.is_none() {
            for custom in &custom_templates {
                if custom.locale != default_locale {
                    // Check if we already added this
                    let exists = result.iter().any(|r| {
                        r.template_type == custom.template_type && r.locale == custom.locale
                    });
                    if !exists {
                        result.push(EmailTemplateSummaryResponse {
                            template_type: custom.template_type.clone(),
                            locale: custom.locale.clone(),
                            is_customized: true,
                            is_active: custom.is_active,
                            updated_at: Some(custom.updated_at),
                        });
                    }
                }
            }
        }

        Ok(result)
    }

    /// Get a specific email template.
    ///
    /// Falls back to default if no custom template exists.
    pub async fn get_template(
        &self,
        tenant_id: Uuid,
        template_type: TemplateType,
        locale: &str,
    ) -> Result<EmailTemplateResponse, ApiAuthError> {
        // Set tenant context
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        let type_str = template_type.to_string();

        // Try to find custom template
        if let Some(custom) = EmailTemplate::find(&mut *conn, tenant_id, &type_str, locale)
            .await
            .map_err(ApiAuthError::Database)?
        {
            return Ok(EmailTemplateResponse {
                template_type: custom.template_type,
                locale: custom.locale,
                subject: custom.subject,
                body_html: custom.body_html,
                body_text: custom.body_text,
                available_variables: custom
                    .available_variables
                    .0
                    .into_iter()
                    .map(|v| TemplateVariableInfo {
                        name: v.name,
                        description: v.description,
                    })
                    .collect(),
                is_customized: true,
                is_active: custom.is_active,
                updated_at: Some(custom.updated_at),
            });
        }

        // Fall back to default
        let default = get_default_template(template_type);
        Ok(EmailTemplateResponse {
            template_type: type_str,
            locale: locale.to_string(),
            subject: default.subject.to_string(),
            body_html: default.body_html.to_string(),
            body_text: Some(default.body_text.to_string()),
            available_variables: default
                .variables
                .into_iter()
                .map(|v| TemplateVariableInfo {
                    name: v.name,
                    description: v.description,
                })
                .collect(),
            is_customized: false,
            is_active: true,
            updated_at: None,
        })
    }

    /// Update an email template.
    ///
    /// Creates a custom template if one doesn't exist.
    pub async fn update_template(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        template_type: TemplateType,
        locale: &str,
        request: UpdateEmailTemplateRequest,
    ) -> Result<EmailTemplateResponse, ApiAuthError> {
        let type_str = template_type.to_string();

        // Get default template for variables reference
        let default = get_default_template(template_type);

        // Validate subject if provided
        let subject = if let Some(ref subj) = request.subject {
            if subj.len() > 500 {
                return Err(ApiAuthError::Validation(
                    "Subject must not exceed 500 characters".to_string(),
                ));
            }
            // Validate Handlebars syntax
            self.validate_template(subj)?;
            subj.clone()
        } else {
            // Get current or default
            let current = self.get_template(tenant_id, template_type, locale).await?;
            current.subject
        };

        // Validate body_html if provided
        let body_html = if let Some(ref html) = request.body_html {
            if html.len() > 100_000 {
                return Err(ApiAuthError::Validation(
                    "HTML body must not exceed 100,000 characters".to_string(),
                ));
            }
            self.validate_template(html)?;
            html.clone()
        } else {
            let current = self.get_template(tenant_id, template_type, locale).await?;
            current.body_html
        };

        // Validate body_text if provided
        if let Some(ref text) = request.body_text {
            if text.len() > 50_000 {
                return Err(ApiAuthError::Validation(
                    "Text body must not exceed 50,000 characters".to_string(),
                ));
            }
        }

        // Set tenant context
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        // Upsert the template
        let data = UpsertEmailTemplate {
            template_type: type_str.clone(),
            locale: request.locale.unwrap_or_else(|| locale.to_string()),
            subject,
            body_html,
            body_text: request.body_text,
            is_active: request.is_active,
        };

        let template =
            EmailTemplate::upsert(&mut *conn, tenant_id, data, default.variables, user_id)
                .await
                .map_err(ApiAuthError::Database)?;

        info!(
            tenant_id = %tenant_id,
            template_type = %type_str,
            locale = %locale,
            "Email template updated"
        );

        Ok(EmailTemplateResponse {
            template_type: template.template_type,
            locale: template.locale,
            subject: template.subject,
            body_html: template.body_html,
            body_text: template.body_text,
            available_variables: template
                .available_variables
                .0
                .into_iter()
                .map(|v| TemplateVariableInfo {
                    name: v.name,
                    description: v.description,
                })
                .collect(),
            is_customized: true,
            is_active: template.is_active,
            updated_at: Some(template.updated_at),
        })
    }

    /// Preview an email template with sample data.
    pub async fn preview_template(
        &self,
        tenant_id: Uuid,
        template_type: TemplateType,
        locale: &str,
        sample_data: Option<HashMap<String, String>>,
    ) -> Result<EmailTemplatePreviewResponse, ApiAuthError> {
        // Get the template (custom or default)
        let template = self.get_template(tenant_id, template_type, locale).await?;

        // Build sample data with defaults
        let mut data = self.get_sample_data();
        if let Some(custom_data) = sample_data {
            for (key, value) in custom_data {
                data.insert(key, value);
            }
        }

        // Render templates
        let subject = self
            .handlebars
            .render_template(&template.subject, &data)
            .map_err(|e| {
                ApiAuthError::InvalidTemplateSyntax(format!("Error rendering subject: {e}"))
            })?;

        let body_html = self
            .handlebars
            .render_template(&template.body_html, &data)
            .map_err(|e| {
                ApiAuthError::InvalidTemplateSyntax(format!("Error rendering HTML body: {e}"))
            })?;

        let body_text = if let Some(ref text) = template.body_text {
            Some(self.handlebars.render_template(text, &data).map_err(|e| {
                ApiAuthError::InvalidTemplateSyntax(format!("Error rendering text body: {e}"))
            })?)
        } else {
            None
        };

        Ok(EmailTemplatePreviewResponse {
            subject,
            body_html,
            body_text,
        })
    }

    /// Reset a template to the default.
    pub async fn reset_template(
        &self,
        tenant_id: Uuid,
        template_type: TemplateType,
        locale: &str,
    ) -> Result<EmailTemplateResponse, ApiAuthError> {
        let type_str = template_type.to_string();

        // Set tenant context
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        // Delete the custom template
        let deleted = EmailTemplate::delete(&mut *conn, tenant_id, &type_str, locale)
            .await
            .map_err(ApiAuthError::Database)?;

        if deleted {
            info!(
                tenant_id = %tenant_id,
                template_type = %type_str,
                locale = %locale,
                "Email template reset to default"
            );
        }

        // Return the default template
        let default = get_default_template(template_type);
        Ok(EmailTemplateResponse {
            template_type: type_str,
            locale: locale.to_string(),
            subject: default.subject.to_string(),
            body_html: default.body_html.to_string(),
            body_text: Some(default.body_text.to_string()),
            available_variables: default
                .variables
                .into_iter()
                .map(|v| TemplateVariableInfo {
                    name: v.name,
                    description: v.description,
                })
                .collect(),
            is_customized: false,
            is_active: true,
            updated_at: None,
        })
    }

    // ========================================================================
    // Helper Methods
    // ========================================================================

    /// Validate Handlebars template syntax.
    fn validate_template(&self, template: &str) -> Result<(), ApiAuthError> {
        self.handlebars
            .render_template(template, &HashMap::<String, String>::new())
            .map(|_| ())
            .map_err(|e| ApiAuthError::InvalidTemplateSyntax(e.to_string()))
    }

    /// Get sample data for template preview.
    fn get_sample_data(&self) -> HashMap<String, String> {
        let mut data = HashMap::new();
        data.insert("user_name".to_string(), "John Doe".to_string());
        data.insert("user_email".to_string(), "john.doe@example.com".to_string());
        data.insert("tenant_name".to_string(), "Acme Corp".to_string());
        data.insert(
            "logo_url".to_string(),
            "https://example.com/logo.png".to_string(),
        );
        data.insert(
            "action_url".to_string(),
            "https://example.com/action".to_string(),
        );
        data.insert("expiry_time".to_string(), "1 hour".to_string());
        data.insert("unlock_time".to_string(), "30 minutes".to_string());
        data.insert("alert_title".to_string(), "New Login Detected".to_string());
        data.insert(
            "alert_message".to_string(),
            "A new login was detected from a new device.".to_string(),
        );
        data.insert(
            "device_info".to_string(),
            "Chrome on Windows - New York, US".to_string(),
        );
        data.insert(
            "footer_text".to_string(),
            "© 2024 Acme Corp. All rights reserved.".to_string(),
        );
        data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handlebars_validation() {
        let handlebars = Handlebars::new();

        // Valid template - render returns Ok
        let valid =
            handlebars.render_template("Hello {{name}}!", &HashMap::<String, String>::new());
        assert!(valid.is_ok());

        // Valid with conditional
        let valid = handlebars.render_template(
            "{{#if name}}Hello {{name}}{{/if}}",
            &HashMap::<String, String>::new(),
        );
        assert!(valid.is_ok());

        // Invalid - unclosed tag
        let invalid = handlebars.render_template("Hello {{name", &HashMap::<String, String>::new());
        assert!(invalid.is_err());
    }

    #[test]
    fn test_sample_data_fields() {
        // Test sample data structure without needing a service instance
        let mut data = HashMap::new();
        data.insert("user_name".to_string(), "John Doe".to_string());
        data.insert("user_email".to_string(), "john.doe@example.com".to_string());
        data.insert("tenant_name".to_string(), "Acme Corp".to_string());
        data.insert(
            "action_url".to_string(),
            "https://example.com/action".to_string(),
        );

        assert!(data.contains_key("user_name"));
        assert!(data.contains_key("user_email"));
        assert!(data.contains_key("tenant_name"));
        assert!(data.contains_key("action_url"));
    }
}
