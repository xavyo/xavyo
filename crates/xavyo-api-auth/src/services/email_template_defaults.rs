//! Default email templates for branding (F030).
//!
//! System default templates used when no custom template exists.

use xavyo_db::models::{TemplateType, TemplateVariable};

/// Default template content.
pub struct DefaultTemplate {
    pub subject: &'static str,
    pub body_html: &'static str,
    pub body_text: &'static str,
    pub variables: Vec<TemplateVariable>,
}

/// Get the default template for a given type.
pub fn get_default_template(template_type: TemplateType) -> DefaultTemplate {
    match template_type {
        TemplateType::Welcome => DefaultTemplate {
            subject: "Welcome to {{tenant_name}}!",
            body_html: r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { text-align: center; padding: 20px 0; }
        .content { padding: 20px 0; }
        .button { display: inline-block; padding: 12px 24px; background-color: #1a73e8; color: white; text-decoration: none; border-radius: 4px; }
        .footer { text-align: center; color: #666; font-size: 12px; padding-top: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            {{#if logo_url}}<img src="{{logo_url}}" alt="{{tenant_name}}" height="48">{{/if}}
            <h1>Welcome, {{user_name}}!</h1>
        </div>
        <div class="content">
            <p>Thank you for creating an account with {{tenant_name}}.</p>
            <p>Your account has been successfully created with the email address: <strong>{{user_email}}</strong></p>
            {{#if action_url}}
            <p style="text-align: center;">
                <a href="{{action_url}}" class="button">Get Started</a>
            </p>
            {{/if}}
        </div>
        <div class="footer">
            <p>{{footer_text}}</p>
        </div>
    </div>
</body>
</html>"#,
            body_text: r#"Welcome to {{tenant_name}}, {{user_name}}!

Thank you for creating an account. Your account has been successfully created with the email address: {{user_email}}

{{#if action_url}}
Get started: {{action_url}}
{{/if}}

{{footer_text}}"#,
            variables: vec![
                TemplateVariable {
                    name: "user_name".to_string(),
                    description: "User's display name".to_string(),
                },
                TemplateVariable {
                    name: "user_email".to_string(),
                    description: "User's email address".to_string(),
                },
                TemplateVariable {
                    name: "tenant_name".to_string(),
                    description: "Tenant/organization name".to_string(),
                },
                TemplateVariable {
                    name: "logo_url".to_string(),
                    description: "URL to tenant logo (optional)".to_string(),
                },
                TemplateVariable {
                    name: "action_url".to_string(),
                    description: "URL to get started (optional)".to_string(),
                },
                TemplateVariable {
                    name: "footer_text".to_string(),
                    description: "Footer text from branding".to_string(),
                },
            ],
        },

        TemplateType::PasswordReset => DefaultTemplate {
            subject: "Reset your {{tenant_name}} password",
            body_html: r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { text-align: center; padding: 20px 0; }
        .content { padding: 20px 0; }
        .button { display: inline-block; padding: 12px 24px; background-color: #1a73e8; color: white; text-decoration: none; border-radius: 4px; }
        .footer { text-align: center; color: #666; font-size: 12px; padding-top: 20px; }
        .warning { color: #666; font-size: 14px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            {{#if logo_url}}<img src="{{logo_url}}" alt="{{tenant_name}}" height="48">{{/if}}
            <h1>Password Reset Request</h1>
        </div>
        <div class="content">
            <p>Hi {{user_name}},</p>
            <p>We received a request to reset the password for your {{tenant_name}} account.</p>
            <p style="text-align: center;">
                <a href="{{action_url}}" class="button">Reset Password</a>
            </p>
            <p class="warning">This link will expire in {{expiry_time}}.</p>
            <p class="warning">If you didn't request this password reset, you can safely ignore this email. Your password will remain unchanged.</p>
        </div>
        <div class="footer">
            <p>{{footer_text}}</p>
        </div>
    </div>
</body>
</html>"#,
            body_text: r#"Password Reset Request

Hi {{user_name}},

We received a request to reset the password for your {{tenant_name}} account.

Reset your password: {{action_url}}

This link will expire in {{expiry_time}}.

If you didn't request this password reset, you can safely ignore this email. Your password will remain unchanged.

{{footer_text}}"#,
            variables: vec![
                TemplateVariable {
                    name: "user_name".to_string(),
                    description: "User's display name".to_string(),
                },
                TemplateVariable {
                    name: "user_email".to_string(),
                    description: "User's email address".to_string(),
                },
                TemplateVariable {
                    name: "tenant_name".to_string(),
                    description: "Tenant/organization name".to_string(),
                },
                TemplateVariable {
                    name: "logo_url".to_string(),
                    description: "URL to tenant logo (optional)".to_string(),
                },
                TemplateVariable {
                    name: "action_url".to_string(),
                    description: "URL to reset password".to_string(),
                },
                TemplateVariable {
                    name: "expiry_time".to_string(),
                    description: "Time until link expires (e.g., '1 hour')".to_string(),
                },
                TemplateVariable {
                    name: "footer_text".to_string(),
                    description: "Footer text from branding".to_string(),
                },
            ],
        },

        TemplateType::EmailVerification => DefaultTemplate {
            subject: "Verify your email address for {{tenant_name}}",
            body_html: r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { text-align: center; padding: 20px 0; }
        .content { padding: 20px 0; }
        .button { display: inline-block; padding: 12px 24px; background-color: #1a73e8; color: white; text-decoration: none; border-radius: 4px; }
        .footer { text-align: center; color: #666; font-size: 12px; padding-top: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            {{#if logo_url}}<img src="{{logo_url}}" alt="{{tenant_name}}" height="48">{{/if}}
            <h1>Verify Your Email</h1>
        </div>
        <div class="content">
            <p>Hi {{user_name}},</p>
            <p>Please verify your email address to complete your {{tenant_name}} account setup.</p>
            <p style="text-align: center;">
                <a href="{{action_url}}" class="button">Verify Email</a>
            </p>
            <p style="color: #666; font-size: 14px;">This link will expire in {{expiry_time}}.</p>
        </div>
        <div class="footer">
            <p>{{footer_text}}</p>
        </div>
    </div>
</body>
</html>"#,
            body_text: r#"Verify Your Email

Hi {{user_name}},

Please verify your email address to complete your {{tenant_name}} account setup.

Verify your email: {{action_url}}

This link will expire in {{expiry_time}}.

{{footer_text}}"#,
            variables: vec![
                TemplateVariable {
                    name: "user_name".to_string(),
                    description: "User's display name".to_string(),
                },
                TemplateVariable {
                    name: "user_email".to_string(),
                    description: "User's email address".to_string(),
                },
                TemplateVariable {
                    name: "tenant_name".to_string(),
                    description: "Tenant/organization name".to_string(),
                },
                TemplateVariable {
                    name: "logo_url".to_string(),
                    description: "URL to tenant logo (optional)".to_string(),
                },
                TemplateVariable {
                    name: "action_url".to_string(),
                    description: "URL to verify email".to_string(),
                },
                TemplateVariable {
                    name: "expiry_time".to_string(),
                    description: "Time until link expires".to_string(),
                },
                TemplateVariable {
                    name: "footer_text".to_string(),
                    description: "Footer text from branding".to_string(),
                },
            ],
        },

        TemplateType::MfaSetup => DefaultTemplate {
            subject: "MFA has been enabled on your {{tenant_name}} account",
            body_html: r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { text-align: center; padding: 20px 0; }
        .content { padding: 20px 0; }
        .footer { text-align: center; color: #666; font-size: 12px; padding-top: 20px; }
        .alert { background-color: #e8f5e9; border-left: 4px solid #4caf50; padding: 12px; margin: 16px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            {{#if logo_url}}<img src="{{logo_url}}" alt="{{tenant_name}}" height="48">{{/if}}
            <h1>MFA Enabled</h1>
        </div>
        <div class="content">
            <p>Hi {{user_name}},</p>
            <div class="alert">
                <strong>Multi-factor authentication has been enabled</strong> on your {{tenant_name}} account.
            </div>
            <p>From now on, you'll need to enter a verification code from your authenticator app when signing in.</p>
            <p>If you didn't make this change, please contact support immediately.</p>
        </div>
        <div class="footer">
            <p>{{footer_text}}</p>
        </div>
    </div>
</body>
</html>"#,
            body_text: r#"MFA Enabled

Hi {{user_name}},

Multi-factor authentication has been enabled on your {{tenant_name}} account.

From now on, you'll need to enter a verification code from your authenticator app when signing in.

If you didn't make this change, please contact support immediately.

{{footer_text}}"#,
            variables: vec![
                TemplateVariable {
                    name: "user_name".to_string(),
                    description: "User's display name".to_string(),
                },
                TemplateVariable {
                    name: "user_email".to_string(),
                    description: "User's email address".to_string(),
                },
                TemplateVariable {
                    name: "tenant_name".to_string(),
                    description: "Tenant/organization name".to_string(),
                },
                TemplateVariable {
                    name: "logo_url".to_string(),
                    description: "URL to tenant logo (optional)".to_string(),
                },
                TemplateVariable {
                    name: "footer_text".to_string(),
                    description: "Footer text from branding".to_string(),
                },
            ],
        },

        TemplateType::SecurityAlert => DefaultTemplate {
            subject: "Security alert for your {{tenant_name}} account",
            body_html: r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { text-align: center; padding: 20px 0; }
        .content { padding: 20px 0; }
        .footer { text-align: center; color: #666; font-size: 12px; padding-top: 20px; }
        .alert { background-color: #fff3e0; border-left: 4px solid #ff9800; padding: 12px; margin: 16px 0; }
        .details { background-color: #f5f5f5; padding: 12px; margin: 16px 0; border-radius: 4px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            {{#if logo_url}}<img src="{{logo_url}}" alt="{{tenant_name}}" height="48">{{/if}}
            <h1>Security Alert</h1>
        </div>
        <div class="content">
            <p>Hi {{user_name}},</p>
            <div class="alert">
                <strong>{{alert_title}}</strong>
            </div>
            <p>{{alert_message}}</p>
            {{#if device_info}}
            <div class="details">
                <strong>Device Details:</strong><br>
                {{device_info}}
            </div>
            {{/if}}
            <p>If this was you, you can safely ignore this email. If you don't recognize this activity, please secure your account immediately.</p>
        </div>
        <div class="footer">
            <p>{{footer_text}}</p>
        </div>
    </div>
</body>
</html>"#,
            body_text: r#"Security Alert

Hi {{user_name}},

{{alert_title}}

{{alert_message}}

{{#if device_info}}
Device Details:
{{device_info}}
{{/if}}

If this was you, you can safely ignore this email. If you don't recognize this activity, please secure your account immediately.

{{footer_text}}"#,
            variables: vec![
                TemplateVariable {
                    name: "user_name".to_string(),
                    description: "User's display name".to_string(),
                },
                TemplateVariable {
                    name: "user_email".to_string(),
                    description: "User's email address".to_string(),
                },
                TemplateVariable {
                    name: "tenant_name".to_string(),
                    description: "Tenant/organization name".to_string(),
                },
                TemplateVariable {
                    name: "logo_url".to_string(),
                    description: "URL to tenant logo (optional)".to_string(),
                },
                TemplateVariable {
                    name: "alert_title".to_string(),
                    description: "Alert title/type".to_string(),
                },
                TemplateVariable {
                    name: "alert_message".to_string(),
                    description: "Detailed alert message".to_string(),
                },
                TemplateVariable {
                    name: "device_info".to_string(),
                    description: "Device/location info (optional)".to_string(),
                },
                TemplateVariable {
                    name: "footer_text".to_string(),
                    description: "Footer text from branding".to_string(),
                },
            ],
        },

        TemplateType::AccountLocked => DefaultTemplate {
            subject: "Your {{tenant_name}} account has been locked",
            body_html: r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { text-align: center; padding: 20px 0; }
        .content { padding: 20px 0; }
        .button { display: inline-block; padding: 12px 24px; background-color: #1a73e8; color: white; text-decoration: none; border-radius: 4px; }
        .footer { text-align: center; color: #666; font-size: 12px; padding-top: 20px; }
        .alert { background-color: #ffebee; border-left: 4px solid #f44336; padding: 12px; margin: 16px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            {{#if logo_url}}<img src="{{logo_url}}" alt="{{tenant_name}}" height="48">{{/if}}
            <h1>Account Locked</h1>
        </div>
        <div class="content">
            <p>Hi {{user_name}},</p>
            <div class="alert">
                <strong>Your account has been temporarily locked</strong> due to multiple failed login attempts.
            </div>
            <p>Your account will be automatically unlocked in {{unlock_time}}.</p>
            <p>If you've forgotten your password, you can reset it:</p>
            <p style="text-align: center;">
                <a href="{{action_url}}" class="button">Reset Password</a>
            </p>
            <p>If you didn't attempt to log in, please contact support immediately as someone may be trying to access your account.</p>
        </div>
        <div class="footer">
            <p>{{footer_text}}</p>
        </div>
    </div>
</body>
</html>"#,
            body_text: r#"Account Locked

Hi {{user_name}},

Your account has been temporarily locked due to multiple failed login attempts.

Your account will be automatically unlocked in {{unlock_time}}.

If you've forgotten your password, you can reset it here: {{action_url}}

If you didn't attempt to log in, please contact support immediately as someone may be trying to access your account.

{{footer_text}}"#,
            variables: vec![
                TemplateVariable {
                    name: "user_name".to_string(),
                    description: "User's display name".to_string(),
                },
                TemplateVariable {
                    name: "user_email".to_string(),
                    description: "User's email address".to_string(),
                },
                TemplateVariable {
                    name: "tenant_name".to_string(),
                    description: "Tenant/organization name".to_string(),
                },
                TemplateVariable {
                    name: "logo_url".to_string(),
                    description: "URL to tenant logo (optional)".to_string(),
                },
                TemplateVariable {
                    name: "action_url".to_string(),
                    description: "URL to reset password".to_string(),
                },
                TemplateVariable {
                    name: "unlock_time".to_string(),
                    description: "Time until account unlocks".to_string(),
                },
                TemplateVariable {
                    name: "footer_text".to_string(),
                    description: "Footer text from branding".to_string(),
                },
            ],
        },
    }
}

/// Get all template types.
pub fn get_all_template_types() -> Vec<TemplateType> {
    vec![
        TemplateType::Welcome,
        TemplateType::PasswordReset,
        TemplateType::EmailVerification,
        TemplateType::MfaSetup,
        TemplateType::SecurityAlert,
        TemplateType::AccountLocked,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_templates_have_required_fields() {
        for template_type in get_all_template_types() {
            let template = get_default_template(template_type);
            assert!(!template.subject.is_empty());
            assert!(!template.body_html.is_empty());
            assert!(!template.body_text.is_empty());
            assert!(!template.variables.is_empty());
        }
    }

    #[test]
    fn test_templates_have_common_variables() {
        for template_type in get_all_template_types() {
            let template = get_default_template(template_type);
            let var_names: Vec<&str> = template.variables.iter().map(|v| v.name.as_str()).collect();
            // All templates should have these common variables
            assert!(
                var_names.contains(&"user_name"),
                "Template {:?} missing user_name",
                template_type
            );
            assert!(
                var_names.contains(&"tenant_name"),
                "Template {:?} missing tenant_name",
                template_type
            );
        }
    }
}
