//! Structured security audit trail (F082-S8).
//!
//! Emits structured `tracing` events for security-relevant actions.
//! Events are logged with target "security" for SIEM filtering.

use serde::Serialize;
use uuid::Uuid;

/// Security event types for audit trail.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityEventType {
    LoginFailed,
    LoginSuccess,
    TokenRevoked,
    KeyRotated,
    KeyRevoked,
    CorsRejected,
    RateLimited,
    CsrfFailed,
}

impl std::fmt::Display for SecurityEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LoginFailed => write!(f, "login_failed"),
            Self::LoginSuccess => write!(f, "login_success"),
            Self::TokenRevoked => write!(f, "token_revoked"),
            Self::KeyRotated => write!(f, "key_rotated"),
            Self::KeyRevoked => write!(f, "key_revoked"),
            Self::CorsRejected => write!(f, "cors_rejected"),
            Self::RateLimited => write!(f, "rate_limited"),
            Self::CsrfFailed => write!(f, "csrf_failed"),
        }
    }
}

/// Structured security audit logger.
pub struct SecurityAudit;

impl SecurityAudit {
    /// Emit a structured security event.
    ///
    /// All fields are logged with target "security" for SIEM filtering.
    pub fn emit(
        event_type: SecurityEventType,
        tenant_id: Option<Uuid>,
        user_id: Option<Uuid>,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
        outcome: &str,
        detail: &str,
    ) {
        let tenant_str = tenant_id.map(|t| t.to_string()).unwrap_or_default();
        let user_str = user_id.map(|u| u.to_string()).unwrap_or_default();
        let ip = ip_address.unwrap_or("");
        let ua = user_agent.unwrap_or("");

        tracing::info!(
            target: "security",
            event_type = %event_type,
            tenant_id = %tenant_str,
            user_id = %user_str,
            ip_address = %ip,
            user_agent = %ua,
            outcome = %outcome,
            detail = %detail,
            "Security event: {event_type}"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_type_display() {
        assert_eq!(SecurityEventType::LoginFailed.to_string(), "login_failed");
        assert_eq!(SecurityEventType::LoginSuccess.to_string(), "login_success");
        assert_eq!(SecurityEventType::TokenRevoked.to_string(), "token_revoked");
        assert_eq!(SecurityEventType::KeyRotated.to_string(), "key_rotated");
        assert_eq!(SecurityEventType::KeyRevoked.to_string(), "key_revoked");
        assert_eq!(SecurityEventType::CorsRejected.to_string(), "cors_rejected");
        assert_eq!(SecurityEventType::RateLimited.to_string(), "rate_limited");
        assert_eq!(SecurityEventType::CsrfFailed.to_string(), "csrf_failed");
    }

    #[test]
    fn test_emit_does_not_panic() {
        // Just verify it doesn't panic with various inputs
        SecurityAudit::emit(
            SecurityEventType::LoginFailed,
            Some(Uuid::new_v4()),
            Some(Uuid::new_v4()),
            Some("192.168.1.1"),
            Some("Mozilla/5.0"),
            "failure",
            "Invalid password",
        );

        SecurityAudit::emit(
            SecurityEventType::LoginSuccess,
            None,
            None,
            None,
            None,
            "success",
            "",
        );
    }
}
