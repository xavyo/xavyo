//! Shell session state management
//!
//! Manages the active interactive shell session state including
//! authentication status, tenant context, and session lifecycle.

use crate::config::ConfigPaths;
use crate::credentials::get_credential_store;
use crate::error::CliResult;
use crate::models::Session;
use chrono::{DateTime, Utc};

/// Represents the active interactive shell session state
#[derive(Debug, Clone)]
pub struct ShellSession {
    /// Current tenant name from credentials
    pub tenant_name: Option<String>,
    /// Current user email from credentials
    pub user_email: Option<String>,
    /// Whether user has valid credentials
    pub is_authenticated: bool,
    /// Whether shell is in offline mode
    pub is_offline: bool,
    /// When session started (for session duration tracking)
    #[allow(dead_code)]
    pub start_time: DateTime<Utc>,
    /// Configuration paths
    paths: ConfigPaths,
}

impl ShellSession {
    /// Create a new shell session by loading credentials from storage
    pub fn new(paths: ConfigPaths) -> CliResult<Self> {
        let start_time = Utc::now();
        let mut session = Self {
            tenant_name: None,
            user_email: None,
            is_authenticated: false,
            is_offline: false,
            start_time,
            paths: paths.clone(),
        };

        // Try to load existing session and credentials
        session.reload_auth_state()?;

        Ok(session)
    }

    /// Reload authentication state from storage
    /// This is called when login/logout happens within the shell
    pub fn reload_auth_state(&mut self) -> CliResult<()> {
        // Load session info (user, tenant)
        if let Some(user_session) = Session::load(&self.paths)? {
            self.user_email = Some(user_session.email);
            self.tenant_name = user_session.tenant_name;
        } else {
            self.user_email = None;
            self.tenant_name = None;
        }

        // Check for valid credentials
        let store = get_credential_store(&self.paths);
        if let Ok(Some(creds)) = store.load() {
            self.is_authenticated = !creds.is_expired();
        } else {
            self.is_authenticated = false;
        }

        Ok(())
    }

    /// Check if the user has valid authentication
    pub fn is_authenticated(&self) -> bool {
        self.is_authenticated
    }

    /// Check if there is a tenant context
    #[allow(dead_code)]
    pub fn has_tenant(&self) -> bool {
        self.tenant_name.is_some()
    }

    /// Get the display name for the prompt
    /// Returns tenant name if available, "(not logged in)" otherwise
    pub fn prompt_context(&self) -> String {
        if let Some(ref tenant) = self.tenant_name {
            tenant.clone()
        } else if self.is_authenticated {
            "(no tenant)".to_string()
        } else {
            "(not logged in)".to_string()
        }
    }

    /// Get configuration paths
    #[allow(dead_code)]
    pub fn paths(&self) -> &ConfigPaths {
        &self.paths
    }

    /// Check if credentials are about to expire (within 5 minutes)
    pub fn credentials_expiring_soon(&self) -> bool {
        let store = get_credential_store(&self.paths);
        if let Ok(Some(creds)) = store.load() {
            let five_minutes = chrono::Duration::minutes(5);
            creds.expires_at <= Utc::now() + five_minutes
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_paths() -> (TempDir, ConfigPaths) {
        let temp_dir = TempDir::new().unwrap();
        let paths = ConfigPaths {
            config_dir: temp_dir.path().to_path_buf(),
            config_file: temp_dir.path().join("config.json"),
            session_file: temp_dir.path().join("session.json"),
            credentials_file: temp_dir.path().join("credentials.enc"),
            cache_dir: temp_dir.path().join("cache"),
            history_file: temp_dir.path().join("history"),
        };
        (temp_dir, paths)
    }

    #[test]
    fn test_shell_session_new_unauthenticated() {
        let (_temp_dir, paths) = create_test_paths();
        let session = ShellSession::new(paths).unwrap();

        assert!(!session.is_authenticated());
        assert!(!session.has_tenant());
        assert_eq!(session.prompt_context(), "(not logged in)");
    }

    #[test]
    fn test_shell_session_prompt_context() {
        let (_temp_dir, paths) = create_test_paths();
        let mut session = ShellSession::new(paths).unwrap();

        // Unauthenticated
        assert_eq!(session.prompt_context(), "(not logged in)");

        // Authenticated but no tenant
        session.is_authenticated = true;
        assert_eq!(session.prompt_context(), "(no tenant)");

        // Authenticated with tenant
        session.tenant_name = Some("my-tenant".to_string());
        assert_eq!(session.prompt_context(), "my-tenant");
    }

    #[test]
    fn test_shell_session_has_tenant() {
        let (_temp_dir, paths) = create_test_paths();
        let mut session = ShellSession::new(paths).unwrap();

        assert!(!session.has_tenant());
        session.tenant_name = Some("test-tenant".to_string());
        assert!(session.has_tenant());
    }

    #[test]
    fn test_shell_session_start_time() {
        let (_temp_dir, paths) = create_test_paths();
        let before = Utc::now();
        let session = ShellSession::new(paths).unwrap();
        let after = Utc::now();

        assert!(session.start_time >= before);
        assert!(session.start_time <= after);
    }
}
