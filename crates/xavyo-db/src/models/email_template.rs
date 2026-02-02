//! Email template model.
//!
//! Custom email templates for various system emails.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgExecutor, Type};
use uuid::Uuid;

/// Email template type enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type)]
#[sqlx(type_name = "varchar", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum TemplateType {
    Welcome,
    PasswordReset,
    EmailVerification,
    MfaSetup,
    SecurityAlert,
    AccountLocked,
}

impl std::fmt::Display for TemplateType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Welcome => write!(f, "welcome"),
            Self::PasswordReset => write!(f, "password_reset"),
            Self::EmailVerification => write!(f, "email_verification"),
            Self::MfaSetup => write!(f, "mfa_setup"),
            Self::SecurityAlert => write!(f, "security_alert"),
            Self::AccountLocked => write!(f, "account_locked"),
        }
    }
}

impl std::str::FromStr for TemplateType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "welcome" => Ok(Self::Welcome),
            "password_reset" => Ok(Self::PasswordReset),
            "email_verification" => Ok(Self::EmailVerification),
            "mfa_setup" => Ok(Self::MfaSetup),
            "security_alert" => Ok(Self::SecurityAlert),
            "account_locked" => Ok(Self::AccountLocked),
            _ => Err(format!("Invalid template type: {}", s)),
        }
    }
}

/// Template variable documentation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateVariable {
    pub name: String,
    pub description: String,
}

/// Email template.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct EmailTemplate {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant this template belongs to.
    pub tenant_id: Uuid,

    /// Type of template.
    pub template_type: String,

    /// Locale code (en, fr, etc.).
    pub locale: String,

    /// Email subject line.
    pub subject: String,

    /// HTML body with Handlebars variables.
    pub body_html: String,

    /// Plain text alternative.
    pub body_text: Option<String>,

    /// Documentation of available variables.
    pub available_variables: sqlx::types::Json<Vec<TemplateVariable>>,

    /// Whether template is active.
    pub is_active: bool,

    /// User who created/customized the template.
    pub created_by: Uuid,

    /// When the template was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Data for creating/updating an email template.
#[derive(Debug, Clone, Deserialize)]
pub struct UpsertEmailTemplate {
    pub template_type: String,
    pub locale: String,
    pub subject: String,
    pub body_html: String,
    pub body_text: Option<String>,
    pub is_active: Option<bool>,
}

/// Email template summary (for listing).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailTemplateSummary {
    pub template_type: String,
    pub locale: String,
    pub is_customized: bool,
    pub is_active: bool,
    pub updated_at: Option<DateTime<Utc>>,
}

impl EmailTemplate {
    /// Find template by tenant, type, and locale.
    pub async fn find<'e, E>(
        executor: E,
        tenant_id: Uuid,
        template_type: &str,
        locale: &str,
    ) -> Result<Option<Self>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as(
            r#"
            SELECT * FROM email_templates
            WHERE tenant_id = $1 AND template_type = $2 AND locale = $3
            "#,
        )
        .bind(tenant_id)
        .bind(template_type)
        .bind(locale)
        .fetch_optional(executor)
        .await
    }

    /// List all templates for a tenant.
    pub async fn list_by_tenant<'e, E>(
        executor: E,
        tenant_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as(
            r#"
            SELECT * FROM email_templates
            WHERE tenant_id = $1
            ORDER BY template_type, locale
            "#,
        )
        .bind(tenant_id)
        .fetch_all(executor)
        .await
    }

    /// Create or update an email template.
    pub async fn upsert<'e, E>(
        executor: E,
        tenant_id: Uuid,
        data: UpsertEmailTemplate,
        available_variables: Vec<TemplateVariable>,
        created_by: Uuid,
    ) -> Result<Self, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        let is_active = data.is_active.unwrap_or(true);

        sqlx::query_as(
            r#"
            INSERT INTO email_templates (
                tenant_id, template_type, locale, subject,
                body_html, body_text, available_variables,
                is_active, created_by, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
            ON CONFLICT (tenant_id, template_type, locale) DO UPDATE SET
                subject = EXCLUDED.subject,
                body_html = EXCLUDED.body_html,
                body_text = EXCLUDED.body_text,
                available_variables = EXCLUDED.available_variables,
                is_active = EXCLUDED.is_active,
                updated_at = NOW()
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(&data.template_type)
        .bind(&data.locale)
        .bind(&data.subject)
        .bind(&data.body_html)
        .bind(&data.body_text)
        .bind(sqlx::types::Json(available_variables))
        .bind(is_active)
        .bind(created_by)
        .fetch_one(executor)
        .await
    }

    /// Delete a template.
    pub async fn delete<'e, E>(
        executor: E,
        tenant_id: Uuid,
        template_type: &str,
        locale: &str,
    ) -> Result<bool, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        let result = sqlx::query(
            r#"
            DELETE FROM email_templates
            WHERE tenant_id = $1 AND template_type = $2 AND locale = $3
            "#,
        )
        .bind(tenant_id)
        .bind(template_type)
        .bind(locale)
        .execute(executor)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Update active status.
    pub async fn set_active<'e, E>(
        executor: E,
        tenant_id: Uuid,
        template_type: &str,
        locale: &str,
        is_active: bool,
    ) -> Result<bool, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        let result = sqlx::query(
            r#"
            UPDATE email_templates
            SET is_active = $4, updated_at = NOW()
            WHERE tenant_id = $1 AND template_type = $2 AND locale = $3
            "#,
        )
        .bind(tenant_id)
        .bind(template_type)
        .bind(locale)
        .bind(is_active)
        .execute(executor)
        .await?;
        Ok(result.rows_affected() > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_template_type_display() {
        assert_eq!(TemplateType::Welcome.to_string(), "welcome");
        assert_eq!(TemplateType::PasswordReset.to_string(), "password_reset");
        assert_eq!(
            TemplateType::EmailVerification.to_string(),
            "email_verification"
        );
        assert_eq!(TemplateType::MfaSetup.to_string(), "mfa_setup");
        assert_eq!(TemplateType::SecurityAlert.to_string(), "security_alert");
        assert_eq!(TemplateType::AccountLocked.to_string(), "account_locked");
    }

    #[test]
    fn test_template_type_from_str() {
        assert_eq!(
            "welcome".parse::<TemplateType>().unwrap(),
            TemplateType::Welcome
        );
        assert_eq!(
            "password_reset".parse::<TemplateType>().unwrap(),
            TemplateType::PasswordReset
        );
        assert_eq!(
            "email_verification".parse::<TemplateType>().unwrap(),
            TemplateType::EmailVerification
        );
        assert!("invalid".parse::<TemplateType>().is_err());
    }

    #[test]
    fn test_template_variable_serialization() {
        let var = TemplateVariable {
            name: "user_name".to_string(),
            description: "User's display name".to_string(),
        };
        let json = serde_json::to_string(&var).unwrap();
        assert!(json.contains("user_name"));
    }
}
