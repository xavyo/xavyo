//! Offline status detection and management

use serde::{Deserialize, Serialize};

/// Tracks current connectivity state
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum OfflineStatus {
    /// Network is available
    #[default]
    Online,
    /// Network is unavailable (detected via request failure)
    Offline,
    /// Forced offline mode via --offline flag
    ForcedOffline,
}

#[allow(dead_code)]
impl OfflineStatus {
    /// Check if we are currently in any offline mode
    pub fn is_offline(&self) -> bool {
        matches!(self, OfflineStatus::Offline | OfflineStatus::ForcedOffline)
    }

    /// Check if we are online
    pub fn is_online(&self) -> bool {
        matches!(self, OfflineStatus::Online)
    }

    /// Check if offline mode was forced by the user
    pub fn is_forced(&self) -> bool {
        matches!(self, OfflineStatus::ForcedOffline)
    }

    /// Get a human-readable status string
    pub fn status_str(&self) -> &'static str {
        match self {
            OfflineStatus::Online => "online",
            OfflineStatus::Offline => "offline",
            OfflineStatus::ForcedOffline => "offline (forced)",
        }
    }
}

impl std::fmt::Display for OfflineStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.status_str())
    }
}

/// Check if a reqwest error indicates network unavailability
#[allow(dead_code)]
pub fn is_network_error(err: &reqwest::Error) -> bool {
    err.is_connect() || err.is_timeout() || err.is_request()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_offline_status_is_offline() {
        assert!(!OfflineStatus::Online.is_offline());
        assert!(OfflineStatus::Offline.is_offline());
        assert!(OfflineStatus::ForcedOffline.is_offline());
    }

    #[test]
    fn test_offline_status_is_online() {
        assert!(OfflineStatus::Online.is_online());
        assert!(!OfflineStatus::Offline.is_online());
        assert!(!OfflineStatus::ForcedOffline.is_online());
    }

    #[test]
    fn test_offline_status_is_forced() {
        assert!(!OfflineStatus::Online.is_forced());
        assert!(!OfflineStatus::Offline.is_forced());
        assert!(OfflineStatus::ForcedOffline.is_forced());
    }

    #[test]
    fn test_offline_status_display() {
        assert_eq!(format!("{}", OfflineStatus::Online), "online");
        assert_eq!(format!("{}", OfflineStatus::Offline), "offline");
        assert_eq!(
            format!("{}", OfflineStatus::ForcedOffline),
            "offline (forced)"
        );
    }

    #[test]
    fn test_offline_status_default() {
        assert_eq!(OfflineStatus::default(), OfflineStatus::Online);
    }
}
