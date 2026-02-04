//! Database Connector configuration
//!
//! Configuration types for database connections (`PostgreSQL`, `MySQL`, etc.).

use serde::{Deserialize, Serialize};
use xavyo_connector::config::{ConnectionSettings, ConnectorConfig, TlsConfig};
use xavyo_connector::error::{ConnectorError, ConnectorResult};
use xavyo_connector::types::ConnectorType;

/// Database driver type.
///
/// Per Constitution Principle XI (Single Technology Per Layer), only `PostgreSQL` is supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DatabaseDriver {
    /// `PostgreSQL` - the only supported database driver
    #[default]
    PostgreSQL,
}

impl DatabaseDriver {
    /// Get the default port for this driver.
    #[must_use] 
    pub fn default_port(&self) -> u16 {
        match self {
            DatabaseDriver::PostgreSQL => 5432,
        }
    }

    /// Get the driver identifier string.
    #[must_use] 
    pub fn as_str(&self) -> &'static str {
        match self {
            DatabaseDriver::PostgreSQL => "postgresql",
        }
    }
}

/// SSL mode for database connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SslMode {
    /// No SSL.
    #[default]
    Disable,
    /// Use SSL if available, but don't require it.
    Prefer,
    /// Require SSL.
    Require,
    /// Require SSL and verify CA certificate.
    VerifyCa,
    /// Require SSL and verify CA and hostname.
    VerifyFull,
}

impl SslMode {
    /// Get the string representation for connection strings.
    #[must_use] 
    pub fn as_str(&self) -> &'static str {
        match self {
            SslMode::Disable => "disable",
            SslMode::Prefer => "prefer",
            SslMode::Require => "require",
            SslMode::VerifyCa => "verify-ca",
            SslMode::VerifyFull => "verify-full",
        }
    }
}

/// Configuration for database connector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    /// Database driver type.
    pub driver: DatabaseDriver,

    /// Database server hostname or IP address.
    pub host: String,

    /// Database server port.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,

    /// Database name.
    pub database: String,

    /// Database schema (for `PostgreSQL`, defaults to "public").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,

    /// Username for authentication.
    pub username: String,

    /// Password for authentication (stored encrypted).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,

    /// SSL mode.
    #[serde(default)]
    pub ssl_mode: SslMode,

    /// TLS configuration (for custom certificates).
    #[serde(default)]
    pub tls: TlsConfig,

    /// Connection settings (timeouts, pool size).
    #[serde(default)]
    pub connection: ConnectionSettings,

    /// Table containing user records.
    #[serde(default = "default_users_table")]
    pub users_table: String,

    /// Table containing group records.
    #[serde(default = "default_groups_table")]
    pub groups_table: String,

    /// Column used as unique identifier for users.
    #[serde(default = "default_id_column")]
    pub user_id_column: String,

    /// Column used as unique identifier for groups.
    #[serde(default = "default_id_column")]
    pub group_id_column: String,

    /// Additional connection parameters.
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub extra_params: std::collections::HashMap<String, String>,
}

fn default_users_table() -> String {
    "users".to_string()
}

fn default_groups_table() -> String {
    "groups".to_string()
}

fn default_id_column() -> String {
    "id".to_string()
}

impl DatabaseConfig {
    /// Create a new database config with required fields.
    pub fn new(
        driver: DatabaseDriver,
        host: impl Into<String>,
        database: impl Into<String>,
        username: impl Into<String>,
    ) -> Self {
        Self {
            driver,
            host: host.into(),
            port: None,
            database: database.into(),
            schema: None,
            username: username.into(),
            password: None,
            ssl_mode: SslMode::default(),
            tls: TlsConfig::default(),
            connection: ConnectionSettings::default(),
            users_table: default_users_table(),
            groups_table: default_groups_table(),
            user_id_column: default_id_column(),
            group_id_column: default_id_column(),
            extra_params: std::collections::HashMap::new(),
        }
    }

    /// Set password.
    pub fn with_password(mut self, password: impl Into<String>) -> Self {
        self.password = Some(password.into());
        self
    }

    /// Set port.
    #[must_use] 
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    /// Set schema.
    pub fn with_schema(mut self, schema: impl Into<String>) -> Self {
        self.schema = Some(schema.into());
        self
    }

    /// Set SSL mode.
    #[must_use] 
    pub fn with_ssl_mode(mut self, mode: SslMode) -> Self {
        self.ssl_mode = mode;
        self
    }

    /// Set users table name.
    pub fn with_users_table(mut self, table: impl Into<String>) -> Self {
        self.users_table = table.into();
        self
    }

    /// Set groups table name.
    pub fn with_groups_table(mut self, table: impl Into<String>) -> Self {
        self.groups_table = table.into();
        self
    }

    /// Get the effective port (default if not specified).
    #[must_use] 
    pub fn effective_port(&self) -> u16 {
        self.port.unwrap_or_else(|| self.driver.default_port())
    }

    /// Get the effective schema (default if not specified).
    #[must_use] 
    pub fn effective_schema(&self) -> &str {
        self.schema.as_deref().unwrap_or("public")
    }

    /// Build a connection string for `PostgreSQL`.
    ///
    /// Note: This excludes the password for security. The password
    /// should be passed separately to the connection library.
    #[must_use] 
    pub fn connection_string(&self) -> String {
        // Only PostgreSQL is supported per Constitution Principle XI
        format!(
            "host={} port={} dbname={} user={} sslmode={}",
            self.host,
            self.effective_port(),
            self.database,
            self.username,
            self.ssl_mode.as_str()
        )
    }
}

impl ConnectorConfig for DatabaseConfig {
    fn connector_type() -> ConnectorType {
        ConnectorType::Database
    }

    fn validate(&self) -> ConnectorResult<()> {
        if self.host.is_empty() {
            return Err(ConnectorError::InvalidConfiguration {
                message: "host is required".to_string(),
            });
        }

        if self.database.is_empty() {
            return Err(ConnectorError::InvalidConfiguration {
                message: "database is required".to_string(),
            });
        }

        if self.username.is_empty() {
            return Err(ConnectorError::InvalidConfiguration {
                message: "username is required".to_string(),
            });
        }

        if self.users_table.is_empty() {
            return Err(ConnectorError::InvalidConfiguration {
                message: "users_table is required".to_string(),
            });
        }

        Ok(())
    }

    fn get_credentials(&self) -> Vec<(&'static str, String)> {
        match &self.password {
            Some(password) => vec![("password", password.clone())],
            None => vec![],
        }
    }

    fn redacted(&self) -> Self {
        let mut config = self.clone();
        if config.password.is_some() {
            config.password = Some("***REDACTED***".to_string());
        }
        config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_database_config_new() {
        let config = DatabaseConfig::new(
            DatabaseDriver::PostgreSQL,
            "db.example.com",
            "identity_db",
            "admin",
        )
        .with_password("secret");

        assert_eq!(config.host, "db.example.com");
        assert_eq!(config.database, "identity_db");
        assert_eq!(config.username, "admin");
        assert_eq!(config.password, Some("secret".to_string()));
    }

    #[test]
    fn test_database_driver_defaults() {
        // Only PostgreSQL is supported per Constitution Principle XI
        assert_eq!(DatabaseDriver::PostgreSQL.default_port(), 5432);
        assert_eq!(DatabaseDriver::PostgreSQL.as_str(), "postgresql");
    }

    #[test]
    fn test_database_config_effective_port() {
        let config = DatabaseConfig::new(
            DatabaseDriver::PostgreSQL,
            "db.example.com",
            "identity_db",
            "admin",
        );
        assert_eq!(config.effective_port(), 5432);

        let config = config.with_port(5433);
        assert_eq!(config.effective_port(), 5433);
    }

    #[test]
    fn test_database_config_validation() {
        let config = DatabaseConfig::new(
            DatabaseDriver::PostgreSQL,
            "db.example.com",
            "identity_db",
            "admin",
        );
        assert!(config.validate().is_ok());

        let empty_host =
            DatabaseConfig::new(DatabaseDriver::PostgreSQL, "", "identity_db", "admin");
        assert!(empty_host.validate().is_err());
    }

    #[test]
    fn test_database_config_connection_string() {
        let config = DatabaseConfig::new(
            DatabaseDriver::PostgreSQL,
            "db.example.com",
            "identity_db",
            "admin",
        )
        .with_ssl_mode(SslMode::Require);

        let conn_str = config.connection_string();
        assert!(conn_str.contains("host=db.example.com"));
        assert!(conn_str.contains("port=5432"));
        assert!(conn_str.contains("dbname=identity_db"));
        assert!(conn_str.contains("sslmode=require"));
    }

    #[test]
    fn test_database_config_redacted() {
        let config = DatabaseConfig::new(
            DatabaseDriver::PostgreSQL,
            "db.example.com",
            "identity_db",
            "admin",
        )
        .with_password("super-secret");

        let redacted = config.redacted();
        assert_eq!(redacted.password, Some("***REDACTED***".to_string()));
    }

    #[test]
    fn test_database_config_serialization() {
        let config = DatabaseConfig::new(
            DatabaseDriver::PostgreSQL,
            "db.example.com",
            "identity_db",
            "admin",
        )
        .with_password("secret")
        .with_schema("identity");

        let json = serde_json::to_string(&config).unwrap();
        let parsed: DatabaseConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.host, "db.example.com");
        assert_eq!(parsed.schema, Some("identity".to_string()));
    }
}
