//! Authentication events.

use crate::event::Event;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Authentication method used for login.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    Password,
    Sso,
    Social,
    ApiKey,
    Refresh,
}

/// Reason for logout.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LogoutReason {
    User,
    Timeout,
    Forced,
    PasswordChange,
}

/// Published on successful authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthLogin {
    /// The authenticated user's ID.
    pub user_id: Uuid,
    /// Session identifier.
    pub session_id: Uuid,
    /// Authentication method used.
    pub method: AuthMethod,
    /// Client IP address (optional).
    pub ip_address: Option<String>,
    /// Client user agent string (optional).
    pub user_agent: Option<String>,
}

impl Event for AuthLogin {
    const TOPIC: &'static str = "xavyo.idp.auth.login";
    const EVENT_TYPE: &'static str = "xavyo.idp.auth.login";
}

/// Published when user logs out or session ends.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthLogout {
    /// The user's ID.
    pub user_id: Uuid,
    /// Session that was terminated.
    pub session_id: Uuid,
    /// Reason for logout (optional).
    pub reason: Option<LogoutReason>,
}

impl Event for AuthLogout {
    const TOPIC: &'static str = "xavyo.idp.auth.logout";
    const EVENT_TYPE: &'static str = "xavyo.idp.auth.logout";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_login_serialization() {
        let event = AuthLogin {
            user_id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            method: AuthMethod::Password,
            ip_address: Some("192.168.1.1".to_string()),
            user_agent: Some("Mozilla/5.0".to_string()),
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("password"));

        let restored: AuthLogin = serde_json::from_str(&json).unwrap();
        assert_eq!(event.method, restored.method);
    }

    #[test]
    fn test_auth_method_serialization() {
        assert_eq!(
            serde_json::to_string(&AuthMethod::Password).unwrap(),
            "\"password\""
        );
        assert_eq!(serde_json::to_string(&AuthMethod::Sso).unwrap(), "\"sso\"");
        assert_eq!(
            serde_json::to_string(&AuthMethod::Social).unwrap(),
            "\"social\""
        );
    }

    #[test]
    fn test_auth_logout_serialization() {
        let event = AuthLogout {
            user_id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            reason: Some(LogoutReason::User),
        };

        let json = serde_json::to_string(&event).unwrap();
        let restored: AuthLogout = serde_json::from_str(&json).unwrap();

        assert_eq!(event.reason, restored.reason);
    }

    #[test]
    fn test_auth_login_topic() {
        assert_eq!(AuthLogin::TOPIC, "xavyo.idp.auth.login");
        assert_eq!(AuthLogout::TOPIC, "xavyo.idp.auth.logout");
    }
}
