//! Email sender selection policy.
//!
//! Production must have SES or SMTP configured (fail closed). Development
//! may fall back to a mock sender that logs instead of delivering.

/// Selected outbound email transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmailSenderKind {
    /// AWS Simple Email Service.
    Ses,
    /// SMTP (including Mailpit in development).
    Smtp,
    /// In-process mock that does not deliver mail.
    Mock,
}

/// Choose an email transport from environment capability flags.
///
/// Priority is SES, then SMTP. Production with neither is an error.
pub fn select_email_sender_kind(
    is_production: bool,
    has_ses: bool,
    has_smtp: bool,
) -> Result<EmailSenderKind, String> {
    if has_ses {
        return Ok(EmailSenderKind::Ses);
    }
    if has_smtp {
        return Ok(EmailSenderKind::Smtp);
    }
    if is_production {
        return Err("No email provider configured in production. \
             Set EMAIL_SES_REGION for AWS SES, or EMAIL_SMTP_HOST for SMTP."
            .to_string());
    }
    Ok(EmailSenderKind::Mock)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_email_sender_kind_production_without_provider_fails() {
        let err = select_email_sender_kind(true, false, false).unwrap_err();
        assert!(
            err.contains("production"),
            "fail-closed message should mention production: {err}"
        );
    }

    #[test]
    fn select_email_sender_kind_development_without_provider_is_mock() {
        assert_eq!(
            select_email_sender_kind(false, false, false).unwrap(),
            EmailSenderKind::Mock
        );
    }

    #[test]
    fn select_email_sender_kind_production_smtp() {
        assert_eq!(
            select_email_sender_kind(true, false, true).unwrap(),
            EmailSenderKind::Smtp
        );
    }

    #[test]
    fn select_email_sender_kind_ses_preferred() {
        assert_eq!(
            select_email_sender_kind(true, true, true).unwrap(),
            EmailSenderKind::Ses
        );
        assert_eq!(
            select_email_sender_kind(false, true, false).unwrap(),
            EmailSenderKind::Ses
        );
    }

    #[test]
    fn select_email_sender_kind_development_smtp() {
        assert_eq!(
            select_email_sender_kind(false, false, true).unwrap(),
            EmailSenderKind::Smtp
        );
    }
}
