//! Session model for storing user/tenant context

use crate::config::ConfigPaths;
use crate::error::{CliError, CliResult};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Current user and tenant session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// User ID
    pub user_id: Uuid,

    /// User email
    pub email: String,

    /// Current tenant ID (if any)
    pub tenant_id: Option<Uuid>,

    /// Current tenant name (if any)
    pub tenant_name: Option<String>,

    /// Current tenant slug (if any)
    pub tenant_slug: Option<String>,
}

impl Session {
    /// Create a new session from JWT claims
    pub fn from_jwt_claims(token: &str) -> CliResult<Self> {
        // Decode JWT without validation (server already validated)
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(CliError::AuthenticationFailed(
                "Invalid token format".to_string(),
            ));
        }

        // Decode the payload (second part)
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|e| {
                CliError::AuthenticationFailed(format!("Invalid token encoding: {}", e))
            })?;

        let claims: JwtClaims = serde_json::from_slice(&payload)
            .map_err(|e| CliError::AuthenticationFailed(format!("Invalid token claims: {}", e)))?;

        Ok(Self {
            user_id: claims.sub,
            email: claims.email,
            tenant_id: claims.tid,
            tenant_name: None,
            tenant_slug: None,
        })
    }

    /// Load session from file
    pub fn load(paths: &ConfigPaths) -> CliResult<Option<Self>> {
        if !paths.session_file.exists() {
            return Ok(None);
        }

        let content = std::fs::read_to_string(&paths.session_file)?;
        let session: Session = serde_json::from_str(&content)?;
        Ok(Some(session))
    }

    /// Save session to file
    pub fn save(&self, paths: &ConfigPaths) -> CliResult<()> {
        paths.ensure_dir_exists()?;
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(&paths.session_file, content)?;
        Ok(())
    }

    /// Delete session file
    pub fn delete(paths: &ConfigPaths) -> CliResult<()> {
        if paths.session_file.exists() {
            std::fs::remove_file(&paths.session_file)?;
        }
        Ok(())
    }

    /// Update tenant context
    pub fn set_tenant(&mut self, id: Uuid, name: String, slug: String) {
        self.tenant_id = Some(id);
        self.tenant_name = Some(name);
        self.tenant_slug = Some(slug);
    }

    /// Check if user has a tenant context
    pub fn has_tenant(&self) -> bool {
        self.tenant_id.is_some()
    }
}

/// JWT claims structure (subset we care about)
#[derive(Debug, Deserialize)]
struct JwtClaims {
    /// Subject (user ID)
    sub: Uuid,

    /// Email
    email: String,

    /// Tenant ID (optional)
    tid: Option<Uuid>,
}

use base64::Engine;

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_session() -> Session {
        Session {
            user_id: Uuid::new_v4(),
            email: "test@example.com".to_string(),
            tenant_id: None,
            tenant_name: None,
            tenant_slug: None,
        }
    }

    #[test]
    fn test_session_save_and_load() {
        let temp_dir = TempDir::new().unwrap();
        let paths = ConfigPaths {
            config_dir: temp_dir.path().to_path_buf(),
            config_file: temp_dir.path().join("config.json"),
            session_file: temp_dir.path().join("session.json"),
            credentials_file: temp_dir.path().join("credentials.enc"),
        };

        let session = create_test_session();
        session.save(&paths).unwrap();

        let loaded = Session::load(&paths).unwrap().unwrap();
        assert_eq!(loaded.user_id, session.user_id);
        assert_eq!(loaded.email, session.email);
    }

    #[test]
    fn test_session_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let paths = ConfigPaths {
            config_dir: temp_dir.path().to_path_buf(),
            config_file: temp_dir.path().join("config.json"),
            session_file: temp_dir.path().join("session.json"),
            credentials_file: temp_dir.path().join("credentials.enc"),
        };

        let result = Session::load(&paths).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_session_delete() {
        let temp_dir = TempDir::new().unwrap();
        let paths = ConfigPaths {
            config_dir: temp_dir.path().to_path_buf(),
            config_file: temp_dir.path().join("config.json"),
            session_file: temp_dir.path().join("session.json"),
            credentials_file: temp_dir.path().join("credentials.enc"),
        };

        let session = create_test_session();
        session.save(&paths).unwrap();
        assert!(paths.session_file.exists());

        Session::delete(&paths).unwrap();
        assert!(!paths.session_file.exists());
    }

    #[test]
    fn test_session_set_tenant() {
        let mut session = create_test_session();
        assert!(!session.has_tenant());

        session.set_tenant(
            Uuid::new_v4(),
            "Acme Corp".to_string(),
            "acme-corp".to_string(),
        );

        assert!(session.has_tenant());
        assert_eq!(session.tenant_name.as_deref(), Some("Acme Corp"));
        assert_eq!(session.tenant_slug.as_deref(), Some("acme-corp"));
    }
}
