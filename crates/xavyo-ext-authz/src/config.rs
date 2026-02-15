use std::net::SocketAddr;

/// Configuration for the ext_authz gRPC server.
#[derive(Debug, Clone)]
pub struct ExtAuthzConfig {
    /// Listen address for the gRPC server.
    pub listen_addr: SocketAddr,

    /// Database connection URL.
    pub database_url: String,

    /// Whether to allow requests when the service encounters internal errors.
    /// When false (default), internal errors result in DENY.
    pub fail_open: bool,

    /// Risk score threshold above which requests are denied (0-100).
    /// Default: 75 (deny critical risk).
    pub risk_score_deny_threshold: i32,

    /// NHI cache TTL in seconds.
    pub nhi_cache_ttl_secs: u64,

    /// Activity update flush interval in seconds.
    pub activity_flush_interval_secs: u64,

    /// Require JWT to come from trusted `metadata_context` (set by upstream JWT
    /// authn filter). When true (default), requests without `metadata_context` are
    /// rejected instead of falling back to base64 header decode (no signature
    /// verification). Set to false only in development/testing environments.
    pub require_metadata_context: bool,
}

impl ExtAuthzConfig {
    /// Load configuration from environment variables.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_reader(|key| std::env::var(key))
    }

    /// Load configuration from a custom variable reader.
    ///
    /// This allows tests to supply variables without mutating process-global
    /// environment state.
    pub fn from_reader<F>(reader: F) -> Result<Self, ConfigError>
    where
        F: Fn(&str) -> Result<String, std::env::VarError>,
    {
        let listen_addr = reader("EXT_AUTHZ_LISTEN_ADDR")
            .unwrap_or_else(|_| "0.0.0.0:50051".to_string())
            .parse::<SocketAddr>()
            .map_err(|e| {
                ConfigError::InvalidValue("EXT_AUTHZ_LISTEN_ADDR".into(), e.to_string())
            })?;

        let database_url =
            reader("DATABASE_URL").map_err(|_| ConfigError::MissingVar("DATABASE_URL".into()))?;

        let fail_open = reader("FAIL_OPEN")
            .unwrap_or_else(|_| "false".to_string())
            .parse::<bool>()
            .unwrap_or(false);

        let risk_score_deny_threshold = reader("RISK_SCORE_DENY_THRESHOLD")
            .unwrap_or_else(|_| "75".to_string())
            .parse::<i32>()
            .map_err(|e| {
                ConfigError::InvalidValue("RISK_SCORE_DENY_THRESHOLD".into(), e.to_string())
            })?;

        let nhi_cache_ttl_secs = reader("NHI_CACHE_TTL_SECS")
            .unwrap_or_else(|_| "60".to_string())
            .parse::<u64>()
            .unwrap_or(60);

        let activity_flush_interval_secs = reader("ACTIVITY_FLUSH_INTERVAL_SECS")
            .unwrap_or_else(|_| "30".to_string())
            .parse::<u64>()
            .unwrap_or(30);

        let require_metadata_context = reader("REQUIRE_METADATA_CONTEXT")
            .unwrap_or_else(|_| "true".to_string())
            .parse::<bool>()
            .unwrap_or(true);

        Ok(Self {
            listen_addr,
            database_url,
            fail_open,
            risk_score_deny_threshold,
            nhi_cache_ttl_secs,
            activity_flush_interval_secs,
            require_metadata_context,
        })
    }
}

/// Configuration errors.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("missing required environment variable: {0}")]
    MissingVar(String),

    #[error("invalid value for {0}: {1}")]
    InvalidValue(String, String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::env::VarError;

    /// Create a reader closure from a HashMap (no global env mutation).
    fn make_reader(vars: HashMap<&str, &str>) -> impl Fn(&str) -> Result<String, VarError> {
        let owned: HashMap<String, String> = vars
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |key: &str| owned.get(key).cloned().ok_or(VarError::NotPresent)
    }

    #[test]
    fn test_missing_database_url() {
        let reader = make_reader(HashMap::new());
        let result = ExtAuthzConfig::from_reader(reader);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ConfigError::MissingVar(_)));
        assert!(err.to_string().contains("DATABASE_URL"));
    }

    #[test]
    fn test_defaults() {
        let reader = make_reader(HashMap::from([(
            "DATABASE_URL",
            "postgres://test:test@localhost/test",
        )]));

        let config = ExtAuthzConfig::from_reader(reader).expect("should succeed with defaults");
        assert_eq!(config.listen_addr.to_string(), "0.0.0.0:50051");
        assert_eq!(config.database_url, "postgres://test:test@localhost/test");
        assert!(!config.fail_open);
        assert_eq!(config.risk_score_deny_threshold, 75);
        assert_eq!(config.nhi_cache_ttl_secs, 60);
        assert_eq!(config.activity_flush_interval_secs, 30);
        assert!(config.require_metadata_context);
    }

    #[test]
    fn test_custom_values() {
        let reader = make_reader(HashMap::from([
            ("DATABASE_URL", "postgres://prod@db/xavyo"),
            ("EXT_AUTHZ_LISTEN_ADDR", "127.0.0.1:9090"),
            ("FAIL_OPEN", "true"),
            ("RISK_SCORE_DENY_THRESHOLD", "50"),
            ("NHI_CACHE_TTL_SECS", "120"),
            ("ACTIVITY_FLUSH_INTERVAL_SECS", "10"),
            ("REQUIRE_METADATA_CONTEXT", "true"),
        ]));

        let config = ExtAuthzConfig::from_reader(reader).unwrap();
        assert_eq!(config.listen_addr.to_string(), "127.0.0.1:9090");
        assert_eq!(config.database_url, "postgres://prod@db/xavyo");
        assert!(config.fail_open);
        assert_eq!(config.risk_score_deny_threshold, 50);
        assert_eq!(config.nhi_cache_ttl_secs, 120);
        assert_eq!(config.activity_flush_interval_secs, 10);
        assert!(config.require_metadata_context);
    }

    #[test]
    fn test_invalid_listen_addr() {
        let reader = make_reader(HashMap::from([
            ("DATABASE_URL", "postgres://test@localhost/test"),
            ("EXT_AUTHZ_LISTEN_ADDR", "not-an-address"),
        ]));

        let result = ExtAuthzConfig::from_reader(reader);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(..)));
        assert!(err.to_string().contains("EXT_AUTHZ_LISTEN_ADDR"));
    }

    #[test]
    fn test_invalid_risk_threshold() {
        let reader = make_reader(HashMap::from([
            ("DATABASE_URL", "postgres://test@localhost/test"),
            ("RISK_SCORE_DENY_THRESHOLD", "not-a-number"),
        ]));

        let result = ExtAuthzConfig::from_reader(reader);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(..)));
        assert!(err.to_string().contains("RISK_SCORE_DENY_THRESHOLD"));
    }

    #[test]
    fn test_config_error_display() {
        let err = ConfigError::MissingVar("FOO".into());
        assert_eq!(
            err.to_string(),
            "missing required environment variable: FOO"
        );

        let err = ConfigError::InvalidValue("BAR".into(), "not a number".into());
        assert_eq!(err.to_string(), "invalid value for BAR: not a number");
    }
}
