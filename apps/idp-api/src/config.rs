//! Application configuration loaded from environment variables.
//!
//! This module provides fail-fast configuration loading with validation.
//! Required variables must be present and valid, or the application will
//! exit with a clear error message.
//!
//! Security hardening (F069): Includes production environment detection,
//! insecure default key validation, and multi-key JWT signing support.

use serde::Deserialize;
use std::env;
use std::sync::Arc;
use thiserror::Error;
use xavyo_secrets::SecretProvider;

// ── Insecure default constants (F069-S1) ──────────────────────────────────

/// Default SOCIAL_ENCRYPTION_KEY: base64-encoded 32 zero bytes.
pub const INSECURE_SOCIAL_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

/// Default SAML_ENCRYPTION_KEY: 64 hex '0' characters.
#[allow(dead_code)] // Reserved for insecure key detection
pub const INSECURE_SAML_KEY: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Default FEDERATION_ENCRYPTION_KEY: 64 hex '1' characters.
#[allow(dead_code)] // Reserved for insecure key detection
pub const INSECURE_FEDERATION_KEY: &str =
    "1111111111111111111111111111111111111111111111111111111111111111";

/// Default MFA_ENCRYPTION_KEY: 64 hex '2' characters.
#[allow(dead_code)] // Reserved for insecure key detection
pub const INSECURE_MFA_KEY: &str =
    "2222222222222222222222222222222222222222222222222222222222222222";

/// Default CONNECTOR_ENCRYPTION_KEY: 64 hex '3' characters.
#[allow(dead_code)] // Reserved for insecure key detection
pub const INSECURE_CONNECTOR_KEY: &str =
    "3333333333333333333333333333333333333333333333333333333333333333";

/// Default WEBHOOK_ENCRYPTION_KEY: 64 hex '4' characters.
#[allow(dead_code)] // Reserved for insecure key detection
pub const INSECURE_WEBHOOK_KEY: &str =
    "4444444444444444444444444444444444444444444444444444444444444444";

/// Default CSRF_SECRET: 64 hex '5' characters (insecure, for development only).
/// Note: This constant is for documentation; validation uses the parsed byte pattern [0x55u8; 32].
#[allow(dead_code)]
pub const INSECURE_CSRF_SECRET: &str =
    "5555555555555555555555555555555555555555555555555555555555555555";

/// Default SOCIAL_STATE_SECRET.
pub const INSECURE_SOCIAL_STATE_SECRET: &str =
    "development-social-state-secret-change-in-production";

// ── AppEnvironment (F069) ─────────────────────────────────────────────────

/// Application environment mode.
///
/// Controls security enforcement behavior:
/// - `Development`: Insecure defaults are allowed with WARN-level logging.
/// - `Production`: Insecure defaults cause the application to refuse startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppEnvironment {
    Development,
    Production,
}

impl AppEnvironment {
    /// Parse from the `APP_ENV` environment variable value.
    /// Defaults to `Development` if unset or unrecognized.
    pub fn from_env_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "production" | "prod" => Self::Production,
            "development" | "dev" => Self::Development,
            other => {
                tracing::warn!(
                    value = other,
                    "Unrecognized APP_ENV value, defaulting to Development"
                );
                Self::Development
            }
        }
    }

    /// Returns true if this is production mode.
    #[must_use]
    pub fn is_production(&self) -> bool {
        *self == Self::Production
    }
}

impl std::fmt::Display for AppEnvironment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Development => write!(f, "development"),
            Self::Production => write!(f, "production"),
        }
    }
}

// ── SigningKey (F069-S5) ──────────────────────────────────────────────────

/// A JWT signing key with key ID for multi-key rotation support.
#[derive(Debug, Clone)]
pub struct SigningKey {
    /// Key ID (kid) for JWKS identification.
    pub kid: String,

    /// PEM-encoded RSA private key.
    pub private_key_pem: String,

    /// PEM-encoded RSA public key.
    pub public_key_pem: String,

    /// Whether this is the active signing key (used for new tokens).
    pub is_active: bool,
}

/// JSON-deserialized signing key entry from `JWT_SIGNING_KEYS` env var.
#[derive(Debug, Deserialize)]
struct SigningKeyEntry {
    kid: String,
    private_key: String,
    public_key: String,
    #[serde(default)]
    active: bool,
}

/// Parse `JWT_SIGNING_KEYS` JSON array into `Vec<SigningKey>`.
///
/// Returns `None` if the env var is not set.
/// Returns `Err` if set but malformed.
fn parse_signing_keys() -> Result<Option<Vec<SigningKey>>, ConfigError> {
    let json_str = match env::var("JWT_SIGNING_KEYS") {
        Ok(s) if !s.is_empty() => s,
        _ => return Ok(None),
    };

    let entries: Vec<SigningKeyEntry> =
        serde_json::from_str(&json_str).map_err(|e| ConfigError::InvalidValue {
            var: "JWT_SIGNING_KEYS".to_string(),
            message: format!("Invalid JSON: {e}"),
        })?;

    if entries.is_empty() {
        return Err(ConfigError::InvalidValue {
            var: "JWT_SIGNING_KEYS".to_string(),
            message: "Array must contain at least one key".to_string(),
        });
    }

    let active_count = entries.iter().filter(|e| e.active).count();
    if active_count != 1 {
        return Err(ConfigError::InvalidValue {
            var: "JWT_SIGNING_KEYS".to_string(),
            message: format!("Exactly one key must be marked active, found {active_count}"),
        });
    }

    let keys: Vec<SigningKey> = entries
        .into_iter()
        .map(|e| SigningKey {
            kid: e.kid,
            private_key_pem: e.private_key,
            public_key_pem: e.public_key,
            is_active: e.active,
        })
        .collect();

    Ok(Some(keys))
}

/// Configuration errors that can occur during environment loading.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Missing required environment variable: {0}")]
    MissingVar(String),

    #[error("Invalid value for {var}: {message}")]
    InvalidValue { var: String, message: String },

    #[error("Failed to parse port: {0}")]
    InvalidPort(#[from] std::num::ParseIntError),
}

/// OpenTelemetry configuration (F072).
///
/// Controls distributed tracing, metrics export, and observability features.
/// When `otlp_endpoint` is None, no OTLP exporter is created and telemetry
/// is silently disabled (the system operates normally without a collector).
#[derive(Debug, Clone)]
pub struct OtelConfig {
    /// OTLP collector endpoint (e.g., "http://localhost:4317").
    /// When None, OTLP export is disabled.
    pub otlp_endpoint: Option<String>,

    /// Service name for traces and metrics (default: "xavyo").
    pub service_name: String,

    /// Trace sampling rate (0.0–1.0). Default: 1.0 (100%).
    pub sampling_rate: f64,

    /// Whether metrics collection is enabled. Default: true.
    pub metrics_enabled: bool,

    /// Application environment label (from APP_ENV).
    pub environment: String,
}

impl OtelConfig {
    /// Load OpenTelemetry configuration from environment variables.
    pub fn from_env(app_env: &AppEnvironment) -> Self {
        let otlp_endpoint = env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
            .ok()
            .filter(|s| !s.is_empty());

        let service_name =
            env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| "xavyo".to_string());

        let sampling_rate = env::var("OTEL_TRACES_SAMPLER_ARG")
            .ok()
            .and_then(|s| s.parse::<f64>().ok())
            .unwrap_or(1.0)
            .clamp(0.0, 1.0);

        let metrics_enabled = env::var("OTEL_METRICS_ENABLED")
            .map(|s| !matches!(s.to_lowercase().as_str(), "false" | "0" | "no"))
            .unwrap_or(true);

        let environment = app_env.to_string();

        Self {
            otlp_endpoint,
            service_name,
            sampling_rate,
            metrics_enabled,
            environment,
        }
    }

    /// Returns true if OTLP export is configured.
    #[must_use]
    pub fn is_export_enabled(&self) -> bool {
        self.otlp_endpoint.is_some()
    }
}

/// Rate limiting configuration (F082-US7).
///
/// Controls per-endpoint rate limits for authentication endpoints.
/// Loaded from environment variables with sensible defaults.
#[derive(Debug, Clone)]
pub struct RateLimitingConfig {
    /// Login endpoint: max attempts per minute per IP. Default: 5.
    pub login_per_ip: u32,
    /// Login endpoint: max attempts per minute per account. Default: 10.
    pub login_per_account: u32,
    /// Token endpoint: max requests per minute per client_id. Default: 30.
    pub token_per_client: u32,
    /// Registration endpoint: max registrations per hour per IP. Default: 3.
    pub registration_per_ip: u32,
}

impl RateLimitingConfig {
    /// Load rate limiting configuration from environment variables.
    pub fn from_env() -> Self {
        Self {
            login_per_ip: env::var("RATE_LIMIT_LOGIN_IP")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(5),
            login_per_account: env::var("RATE_LIMIT_LOGIN_ACCOUNT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(10),
            token_per_client: env::var("RATE_LIMIT_TOKEN")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(30),
            registration_per_ip: env::var("RATE_LIMIT_REGISTRATION")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(3),
        }
    }
}

/// Input validation hardening configuration (F082-US9).
///
/// Controls body size limits and request timeouts.
#[derive(Debug, Clone)]
pub struct InputValidationConfig {
    /// Maximum request body size in bytes. Default: 1MB (1_048_576).
    pub max_body_size: usize,
    /// Request timeout in seconds. Default: 30.
    pub request_timeout_secs: u64,
}

impl InputValidationConfig {
    /// Load input validation configuration from environment variables.
    pub fn from_env() -> Self {
        Self {
            max_body_size: env::var("MAX_BODY_SIZE")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(1_048_576), // 1MB default
            request_timeout_secs: env::var("REQUEST_TIMEOUT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(30),
        }
    }
}

/// Health check configuration (F074).
///
/// Controls timeouts for dependency health checks used by the readiness probe.
/// When a dependency check exceeds its timeout, the component is marked unhealthy
/// rather than blocking the probe indefinitely.
#[derive(Debug, Clone)]
pub struct HealthCheckConfig {
    /// Database health check timeout in seconds. Default: 2.
    pub db_timeout_secs: u64,

    /// Kafka health check timeout in seconds. Default: 3.
    pub kafka_timeout_secs: u64,
}

impl HealthCheckConfig {
    /// Load health check configuration from environment variables.
    ///
    /// - `HEALTH_DB_TIMEOUT_SECS` — default: 2 (minimum: 1)
    /// - `HEALTH_KAFKA_TIMEOUT_SECS` — default: 3 (minimum: 1)
    pub fn from_env() -> Self {
        let db_timeout_secs = env::var("HEALTH_DB_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(2)
            .max(1);

        let kafka_timeout_secs = env::var("HEALTH_KAFKA_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(3)
            .max(1);

        Self {
            db_timeout_secs,
            kafka_timeout_secs,
        }
    }
}

/// Kafka configuration for event consumers (optional).
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields are read indirectly in consumers.rs
pub struct KafkaConfig {
    /// Kafka bootstrap servers (e.g., "localhost:9092")
    pub bootstrap_servers: String,

    /// Kafka security protocol (PLAINTEXT, SSL, SASL_PLAINTEXT, SASL_SSL)
    pub security_protocol: String,

    /// SASL mechanism (PLAIN, SCRAM-SHA-256, SCRAM-SHA-512) - optional
    pub sasl_mechanism: Option<String>,

    /// SASL username - optional
    pub sasl_username: Option<String>,

    /// SASL password - optional
    pub sasl_password: Option<String>,

    /// Consumer group prefix for micro-certification consumers
    pub consumer_group_prefix: String,
}

/// Application configuration loaded from environment variables.
#[derive(Clone)]
#[allow(dead_code)] // Fields may be used in future handlers
pub struct Config {
    /// Application environment (development or production).
    pub app_env: AppEnvironment,

    /// PostgreSQL connection string
    pub database_url: String,

    /// RS256 private key in PEM format for signing JWTs (single-key fallback)
    pub jwt_private_key: String,

    /// RS256 public key in PEM format for verifying JWTs (single-key fallback)
    pub jwt_public_key: String,

    /// JWT Key ID for JWKS (single-key fallback)
    pub jwt_key_id: String,

    /// Multiple JWT signing keys for key rotation (F069-S5).
    /// If set, takes precedence over single jwt_private_key/jwt_public_key/jwt_key_id.
    pub signing_keys: Vec<SigningKey>,

    /// OAuth2/OIDC issuer URL (e.g., "https://idp.xavyo.com")
    pub issuer_url: String,

    /// Tracing filter directive (e.g., "info,xavyo=debug")
    pub rust_log: String,

    /// Allowed CORS origins (comma-separated URLs or "*" for development)
    pub cors_origins: Vec<String>,

    /// Server bind address
    pub host: String,

    /// Server listen port
    pub port: u16,

    /// Social login encryption key (32 bytes, base64-encoded) for storing OAuth tokens
    pub social_encryption_key: String,

    /// Social login state secret for signing OAuth state tokens
    pub social_state_secret: String,

    /// Frontend URL for social login redirects (e.g., "https://app.xavyo.com")
    pub frontend_url: String,

    /// SAML encryption key (32 bytes, hex-encoded) for encrypting IdP private keys
    pub saml_encryption_key: [u8; 32],

    /// OIDC Federation encryption key (32 bytes, hex-encoded) for encrypting client secrets
    pub federation_encryption_key: [u8; 32],

    /// MFA TOTP encryption key (32 bytes, hex-encoded) for encrypting TOTP secrets
    pub mfa_encryption_key: [u8; 32],

    /// MFA issuer name (shown in authenticator apps)
    pub mfa_issuer: String,

    /// WebAuthn Relying Party ID (usually the domain, e.g., "xavyo.net")
    pub webauthn_rp_id: String,

    /// WebAuthn Relying Party name (displayed to users)
    pub webauthn_rp_name: String,

    /// WebAuthn origin URL (must match the origin of the WebAuthn request)
    pub webauthn_origin: String,

    /// Connector encryption key (32 bytes, hex-encoded) for encrypting connector credentials
    pub connector_encryption_key: [u8; 32],

    /// Webhook encryption key (32 bytes, hex-encoded) for encrypting webhook subscription secrets
    pub webhook_encryption_key: [u8; 32],

    /// CSRF secret (32 bytes, hex-encoded) for OAuth consent form protection (F082-US6)
    /// SECURITY: This MUST be generated independently of the JWT signing key.
    pub csrf_secret: [u8; 32],

    /// Kafka configuration (optional - only if KAFKA_BOOTSTRAP_SERVERS is set)
    pub kafka: Option<KafkaConfig>,

    /// OpenTelemetry configuration (F072)
    pub otel: OtelConfig,

    /// Secret provider for external key management (F080).
    /// None when using the default env provider (backward compatibility).
    pub secret_provider: Option<Arc<dyn SecretProvider>>,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("app_env", &self.app_env)
            .field("database_url", &"[redacted]")
            .field("jwt_key_id", &self.jwt_key_id)
            .field("issuer_url", &self.issuer_url)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("cors_origins", &self.cors_origins)
            .field(
                "secret_provider",
                &self.secret_provider.as_ref().map(|p| p.provider_type()),
            )
            .finish_non_exhaustive()
    }
}

impl Config {
    /// Load configuration from environment variables.
    ///
    /// # Errors
    ///
    /// Returns `ConfigError` if:
    /// - Required variables are missing
    /// - Values are invalid (e.g., invalid port number)
    ///
    /// # Required Variables
    ///
    /// - `DATABASE_URL` - PostgreSQL connection string
    /// - `JWT_PRIVATE_KEY` - RS256 private key (PEM format)
    /// - `JWT_PUBLIC_KEY` - RS256 public key (PEM format)
    ///
    /// # Optional Variables
    ///
    /// - `RUST_LOG` - Log level filter (default: "info")
    /// - `CORS_ORIGINS` - Comma-separated allowed origins (default: "*")
    /// - `HOST` - Bind address (default: "0.0.0.0")
    /// - `PORT` - Listen port (default: 8080)
    pub fn from_env() -> Result<Self, ConfigError> {
        // Load .env file if present (development only)
        let _ = dotenvy::dotenv();

        // Application environment (F069)
        let app_env = AppEnvironment::from_env_str(
            &env::var("APP_ENV").unwrap_or_else(|_| "development".to_string()),
        );

        // Required variables
        let database_url = env::var("DATABASE_URL")
            .map_err(|_| ConfigError::MissingVar("DATABASE_URL".to_string()))?;

        let jwt_private_key = env::var("JWT_PRIVATE_KEY")
            .map_err(|_| ConfigError::MissingVar("JWT_PRIVATE_KEY".to_string()))?;

        let jwt_public_key = env::var("JWT_PUBLIC_KEY")
            .map_err(|_| ConfigError::MissingVar("JWT_PUBLIC_KEY".to_string()))?;

        // Validate PEM format (basic check)
        if !jwt_private_key.contains("-----BEGIN") {
            return Err(ConfigError::InvalidValue {
                var: "JWT_PRIVATE_KEY".to_string(),
                message: "Must be PEM format (should contain -----BEGIN)".to_string(),
            });
        }

        if !jwt_public_key.contains("-----BEGIN") {
            return Err(ConfigError::InvalidValue {
                var: "JWT_PUBLIC_KEY".to_string(),
                message: "Must be PEM format (should contain -----BEGIN)".to_string(),
            });
        }

        // JWT Key ID (optional, defaults to "primary")
        let jwt_key_id = env::var("JWT_KEY_ID").unwrap_or_else(|_| "primary".to_string());

        // OAuth2/OIDC issuer URL
        let issuer_url =
            env::var("ISSUER_URL").unwrap_or_else(|_| "http://localhost:8080".to_string());

        // Optional variables with defaults
        let rust_log = env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());

        let cors_origins = env::var("CORS_ORIGINS")
            .map(|s| s.split(',').map(|o| o.trim().to_string()).collect())
            .unwrap_or_else(|_| vec!["*".to_string()]);

        // F082-US3: Validate CORS origin URL formats at startup
        validate_cors_origins(&cors_origins, &app_env)?;

        let host = env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());

        let port: u16 = env::var("PORT")
            .unwrap_or_else(|_| "8080".to_string())
            .parse()?;

        // Validate port range
        if port == 0 {
            return Err(ConfigError::InvalidValue {
                var: "PORT".to_string(),
                message: "Port must be between 1 and 65535".to_string(),
            });
        }

        // Social login configuration
        let social_encryption_key = env::var("SOCIAL_ENCRYPTION_KEY").unwrap_or_else(|_| {
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0u8; 32])
        });
        let social_state_secret = env::var("SOCIAL_STATE_SECRET")
            .unwrap_or_else(|_| "development-social-state-secret-change-in-production".to_string());
        let frontend_url =
            env::var("FRONTEND_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());

        // SAML encryption key (hex-encoded 32 bytes)
        let saml_encryption_key = parse_hex_encryption_key(
            "SAML_ENCRYPTION_KEY",
            &env::var("SAML_ENCRYPTION_KEY").unwrap_or_else(|_| {
                // Default for development only - must be changed in production
                "0000000000000000000000000000000000000000000000000000000000000000".to_string()
            }),
        )?;

        // OIDC Federation encryption key (hex-encoded 32 bytes)
        let federation_encryption_key = parse_hex_encryption_key(
            "FEDERATION_ENCRYPTION_KEY",
            &env::var("FEDERATION_ENCRYPTION_KEY").unwrap_or_else(|_| {
                // Default for development only - must be changed in production
                "1111111111111111111111111111111111111111111111111111111111111111".to_string()
            }),
        )?;

        // MFA TOTP encryption key (hex-encoded 32 bytes)
        let mfa_encryption_key = parse_hex_encryption_key(
            "MFA_ENCRYPTION_KEY",
            &env::var("MFA_ENCRYPTION_KEY").unwrap_or_else(|_| {
                // Default for development only - must be changed in production
                "2222222222222222222222222222222222222222222222222222222222222222".to_string()
            }),
        )?;

        // MFA issuer name
        let mfa_issuer = env::var("MFA_ISSUER").unwrap_or_else(|_| "Xavyo".to_string());

        // WebAuthn configuration
        let webauthn_rp_id = env::var("WEBAUTHN_RP_ID").unwrap_or_else(|_| "localhost".to_string());
        let webauthn_rp_name =
            env::var("WEBAUTHN_RP_NAME").unwrap_or_else(|_| "xavyo".to_string());
        let webauthn_origin =
            env::var("WEBAUTHN_ORIGIN").unwrap_or_else(|_| "http://localhost:8080".to_string());

        // Connector encryption key (hex-encoded 32 bytes)
        let connector_encryption_key = parse_hex_encryption_key(
            "CONNECTOR_ENCRYPTION_KEY",
            &env::var("CONNECTOR_ENCRYPTION_KEY").unwrap_or_else(|_| {
                // Default for development only - must be changed in production
                "3333333333333333333333333333333333333333333333333333333333333333".to_string()
            }),
        )?;

        // Webhook encryption key (hex-encoded 32 bytes) for webhook subscription secrets (F085)
        let webhook_encryption_key = parse_hex_encryption_key(
            "WEBHOOK_ENCRYPTION_KEY",
            &env::var("WEBHOOK_ENCRYPTION_KEY").unwrap_or_else(|_| {
                // Default for development only - must be changed in production
                "4444444444444444444444444444444444444444444444444444444444444444".to_string()
            }),
        )?;

        // CSRF secret (hex-encoded 32 bytes) for OAuth consent form protection (F082-US6)
        // SECURITY: This MUST be independent of the JWT signing key to avoid key material reuse.
        let csrf_secret = parse_hex_encryption_key(
            "CSRF_SECRET",
            &env::var("CSRF_SECRET").unwrap_or_else(|_| {
                // Default for development only - must be changed in production
                "5555555555555555555555555555555555555555555555555555555555555555".to_string()
            }),
        )?;

        // Kafka configuration (optional - only enabled if KAFKA_BOOTSTRAP_SERVERS is set)
        let kafka = env::var("KAFKA_BOOTSTRAP_SERVERS")
            .ok()
            .map(|bootstrap_servers| KafkaConfig {
                bootstrap_servers,
                security_protocol: env::var("KAFKA_SECURITY_PROTOCOL")
                    .unwrap_or_else(|_| "PLAINTEXT".to_string()),
                sasl_mechanism: env::var("KAFKA_SASL_MECHANISM").ok(),
                sasl_username: env::var("KAFKA_SASL_USERNAME").ok(),
                sasl_password: env::var("KAFKA_SASL_PASSWORD").ok(),
                consumer_group_prefix: env::var("KAFKA_CONSUMER_GROUP_PREFIX")
                    .unwrap_or_else(|_| "xavyo".to_string()),
            });

        // JWT signing keys for rotation (F069-S5)
        // Falls back to single-key config if JWT_SIGNING_KEYS not set.
        let signing_keys = match parse_signing_keys()? {
            Some(keys) => keys,
            None => {
                // Backward compat: construct single key from existing vars
                vec![SigningKey {
                    kid: jwt_key_id.clone(),
                    private_key_pem: jwt_private_key.clone(),
                    public_key_pem: jwt_public_key.clone(),
                    is_active: true,
                }]
            }
        };

        // OpenTelemetry configuration (F072)
        let otel = OtelConfig::from_env(&app_env);

        Ok(Config {
            app_env,
            database_url,
            jwt_private_key,
            jwt_public_key,
            jwt_key_id,
            signing_keys,
            issuer_url,
            rust_log,
            cors_origins,
            host,
            port,
            social_encryption_key,
            social_state_secret,
            frontend_url,
            saml_encryption_key,
            federation_encryption_key,
            mfa_encryption_key,
            mfa_issuer,
            webauthn_rp_id,
            webauthn_rp_name,
            webauthn_origin,
            connector_encryption_key,
            webhook_encryption_key,
            csrf_secret,
            kafka,
            otel,
            secret_provider: None,
        })
    }

    /// Load configuration with external secret provider support (F080).
    ///
    /// If `SECRET_PROVIDER` is set to a non-env provider, this initializes the
    /// secret provider and resolves encryption keys from it. Otherwise, falls
    /// back to the standard `from_env()` path.
    pub async fn from_env_with_secrets() -> Result<Self, ConfigError> {
        // Check if a non-env secret provider is configured
        let provider_str = env::var("SECRET_PROVIDER").unwrap_or_else(|_| "env".to_string());

        if provider_str.to_lowercase() == "env" || provider_str.is_empty() {
            // Default path: use direct env var loading (backward compatible)
            return Self::from_env();
        }

        // External provider path: initialize the secret provider
        let secret_config = xavyo_secrets::SecretProviderConfig::from_env().map_err(|e| {
            ConfigError::InvalidValue {
                var: "SECRET_PROVIDER".to_string(),
                message: format!("Failed to parse secret provider config: {e}"),
            }
        })?;

        let provider = xavyo_secrets::build_provider(&secret_config)
            .await
            .map_err(|e| ConfigError::InvalidValue {
                var: "SECRET_PROVIDER".to_string(),
                message: format!("Failed to initialize secret provider: {e}"),
            })?;

        tracing::info!(
            provider = provider.provider_type(),
            "Secret provider initialized (F080)"
        );

        // Start with basic config from env (non-secret values)
        let mut config = Self::from_env()?;

        // Override encryption keys from the secret provider if mappings exist
        Self::load_secrets_from_provider(&provider, &mut config).await?;

        config.secret_provider = Some(provider);
        Ok(config)
    }

    /// Load encryption keys from the secret provider, overriding env var defaults.
    async fn load_secrets_from_provider(
        provider: &Arc<dyn SecretProvider>,
        config: &mut Config,
    ) -> Result<(), ConfigError> {
        // Try to load each named secret. If the provider has it, use it.
        // If not found (NotFound), fall back to the env var value already in config.

        // JWT signing keys
        if let Ok(secret) = provider.get_secret("jwt_signing_keys").await {
            let value = secret.as_str().map_err(|e| ConfigError::InvalidValue {
                var: "jwt_signing_keys (from secret provider)".to_string(),
                message: e.to_string(),
            })?;
            // Try to parse as JSON array of signing keys
            if let Ok(entries) = serde_json::from_str::<Vec<SigningKeyEntry>>(value) {
                if !entries.is_empty() {
                    let active_count = entries.iter().filter(|e| e.active).count();
                    if active_count != 1 {
                        return Err(ConfigError::InvalidValue {
                            var: "jwt_signing_keys (from secret provider)".to_string(),
                            message: format!(
                                "Exactly one key must be marked active, found {active_count}"
                            ),
                        });
                    }
                    config.signing_keys = entries
                        .into_iter()
                        .map(|e| SigningKey {
                            kid: e.kid,
                            private_key_pem: e.private_key,
                            public_key_pem: e.public_key,
                            is_active: e.active,
                        })
                        .collect();
                    // Extract active key fields without borrowing config simultaneously
                    if let Some(active_key) = config.active_signing_key() {
                        let active_kid = active_key.kid.clone();
                        let active_priv = active_key.private_key_pem.clone();
                        let active_pub = active_key.public_key_pem.clone();
                        config.jwt_private_key = active_priv;
                        config.jwt_public_key = active_pub;
                        config.jwt_key_id = active_kid;
                        tracing::info!("JWT signing keys loaded from secret provider");
                    } else {
                        return Err(ConfigError::InvalidValue {
                            var: "jwt_signing_keys".to_string(),
                            message: "No active signing key found in secret provider configuration"
                                .to_string(),
                        });
                    }
                }
            }
        }

        // SAML encryption key
        if let Ok(secret) = provider.get_secret("saml_encryption_key").await {
            config.saml_encryption_key =
                Self::parse_secret_as_hex_key("saml_encryption_key", &secret)?;
            tracing::info!("SAML encryption key loaded from secret provider");
        }

        // Federation encryption key
        if let Ok(secret) = provider.get_secret("federation_encryption_key").await {
            config.federation_encryption_key =
                Self::parse_secret_as_hex_key("federation_encryption_key", &secret)?;
            tracing::info!("Federation encryption key loaded from secret provider");
        }

        // MFA encryption key
        if let Ok(secret) = provider.get_secret("mfa_encryption_key").await {
            config.mfa_encryption_key =
                Self::parse_secret_as_hex_key("mfa_encryption_key", &secret)?;
            tracing::info!("MFA encryption key loaded from secret provider");
        }

        // Connector encryption key
        if let Ok(secret) = provider.get_secret("connector_encryption_key").await {
            config.connector_encryption_key =
                Self::parse_secret_as_hex_key("connector_encryption_key", &secret)?;
            tracing::info!("Connector encryption key loaded from secret provider");
        }

        // Webhook encryption key (F085)
        if let Ok(secret) = provider.get_secret("webhook_encryption_key").await {
            config.webhook_encryption_key =
                Self::parse_secret_as_hex_key("webhook_encryption_key", &secret)?;
            tracing::info!("Webhook encryption key loaded from secret provider");
        }

        Ok(())
    }

    /// Parse a secret value as a hex-encoded 32-byte key.
    fn parse_secret_as_hex_key(
        name: &str,
        secret: &xavyo_secrets::SecretValue,
    ) -> Result<[u8; 32], ConfigError> {
        let hex_str = secret.as_str().map_err(|e| ConfigError::InvalidValue {
            var: format!("{name} (from secret provider)"),
            message: e.to_string(),
        })?;
        parse_hex_encryption_key(name, hex_str.trim())
    }

    /// Get the server bind address as a socket address string.
    pub fn bind_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    /// Validate security configuration based on the application environment.
    ///
    /// In **production** mode: returns `Err(errors)` listing all insecure defaults found.
    /// In **development** mode: returns `Ok(warnings)` listing all insecure defaults found.
    ///
    /// This function checks:
    /// - SOCIAL_ENCRYPTION_KEY is not the zero-byte default
    /// - SAML_ENCRYPTION_KEY is not all zeros
    /// - FEDERATION_ENCRYPTION_KEY is not all ones
    /// - MFA_ENCRYPTION_KEY is not all twos
    /// - CONNECTOR_ENCRYPTION_KEY is not all threes
    /// - SOCIAL_STATE_SECRET is not the default string
    /// - CORS_ORIGINS is not wildcard ("*") in production
    pub fn validate_security_config(&self) -> Result<Vec<String>, Vec<String>> {
        let mut issues = Vec::new();

        // Check SOCIAL_ENCRYPTION_KEY
        let insecure_social =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0u8; 32]);
        if self.social_encryption_key == insecure_social
            || self.social_encryption_key == INSECURE_SOCIAL_KEY
        {
            issues.push("SOCIAL_ENCRYPTION_KEY is using the default insecure value".to_string());
        }

        // Check SAML_ENCRYPTION_KEY (all zeros)
        if self.saml_encryption_key == [0u8; 32] {
            issues.push(
                "SAML_ENCRYPTION_KEY is using the default insecure value (all zeros)".to_string(),
            );
        }

        // Check FEDERATION_ENCRYPTION_KEY (all ones = 0x11)
        if self.federation_encryption_key == [0x11u8; 32] {
            issues.push(
                "FEDERATION_ENCRYPTION_KEY is using the default insecure value (all 0x11)"
                    .to_string(),
            );
        }

        // Check MFA_ENCRYPTION_KEY (all twos = 0x22)
        if self.mfa_encryption_key == [0x22u8; 32] {
            issues.push(
                "MFA_ENCRYPTION_KEY is using the default insecure value (all 0x22)".to_string(),
            );
        }

        // Check CONNECTOR_ENCRYPTION_KEY (all threes = 0x33)
        if self.connector_encryption_key == [0x33u8; 32] {
            issues.push(
                "CONNECTOR_ENCRYPTION_KEY is using the default insecure value (all 0x33)"
                    .to_string(),
            );
        }

        // Check WEBHOOK_ENCRYPTION_KEY (all fours = 0x44) — F085
        if self.webhook_encryption_key == [0x44u8; 32] {
            issues.push(
                "WEBHOOK_ENCRYPTION_KEY is using the default insecure value (all 0x44)".to_string(),
            );
        }

        // Check CSRF_SECRET (all fives = 0x55) — F082-US6
        if self.csrf_secret == [0x55u8; 32] {
            issues.push("CSRF_SECRET is using the default insecure value (all 0x55)".to_string());
        }

        // Check SOCIAL_STATE_SECRET
        if self.social_state_secret == INSECURE_SOCIAL_STATE_SECRET {
            issues.push("SOCIAL_STATE_SECRET is using the default insecure value".to_string());
        }

        // Check CORS_ORIGINS wildcard
        if self.cors_origins.iter().any(|o| o == "*") {
            issues.push(
                "CORS_ORIGINS contains wildcard '*' which is not allowed in production".to_string(),
            );
        }

        if issues.is_empty() {
            return Ok(Vec::new());
        }

        if self.app_env.is_production() {
            Err(issues)
        } else {
            Ok(issues)
        }
    }

    /// Returns the active signing key, if one exists.
    ///
    /// Returns `None` if no active key is configured. Config validation
    /// should ensure at least one active key exists in production.
    #[must_use]
    pub fn active_signing_key(&self) -> Option<&SigningKey> {
        self.signing_keys.iter().find(|k| k.is_active)
    }

    /// Find a signing key by its kid.
    #[allow(dead_code)] // Reserved for key rotation support
    #[must_use]
    pub fn find_signing_key_by_kid(&self, kid: &str) -> Option<&SigningKey> {
        self.signing_keys.iter().find(|k| k.kid == kid)
    }
}

/// Validate CORS origin URL formats at startup (F082-US3).
///
/// In production mode, invalid URLs cause a startup error.
/// In development mode, invalid URLs produce a warning.
/// The wildcard "*" origin is allowed through (but rejected separately by `validate_security_config`).
fn validate_cors_origins(origins: &[String], app_env: &AppEnvironment) -> Result<(), ConfigError> {
    for origin in origins {
        // Wildcard is handled by security validation
        if origin == "*" {
            continue;
        }

        // Validate URL format: must have scheme and host
        let is_valid = origin.starts_with("http://") || origin.starts_with("https://");
        if !is_valid {
            let msg = format!(
                "CORS origin '{}' is not a valid URL (must start with http:// or https://)",
                origin
            );
            if app_env.is_production() {
                return Err(ConfigError::InvalidValue {
                    var: "CORS_ORIGINS".to_string(),
                    message: msg,
                });
            } else {
                tracing::warn!(target: "security", origin = %origin, "{}", msg);
            }
        }

        // Check for trailing slash (common mistake)
        if is_valid && origin.ends_with('/') {
            let msg = format!(
                "CORS origin '{}' has a trailing slash — origins should not end with '/'",
                origin
            );
            tracing::warn!(target: "security", origin = %origin, "{}", msg);
        }
    }
    Ok(())
}

/// Parse hex-encoded 32-byte encryption key
fn parse_hex_encryption_key(var_name: &str, hex_str: &str) -> Result<[u8; 32], ConfigError> {
    let bytes = hex::decode(hex_str).map_err(|_| ConfigError::InvalidValue {
        var: var_name.to_string(),
        message: "Must be 64 hex characters (32 bytes)".to_string(),
    })?;

    if bytes.len() != 32 {
        return Err(ConfigError::InvalidValue {
            var: var_name.to_string(),
            message: format!("Expected 32 bytes, got {}", bytes.len()),
        });
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a test Config with all insecure defaults (development mode).
    fn test_config_insecure_dev() -> Config {
        let insecure_social =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0u8; 32]);
        Config {
            app_env: AppEnvironment::Development,
            database_url: "postgres://localhost/test".to_string(),
            jwt_private_key: "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----"
                .to_string(),
            jwt_public_key: "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----"
                .to_string(),
            jwt_key_id: "primary".to_string(),
            signing_keys: vec![SigningKey {
                kid: "primary".to_string(),
                private_key_pem: "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----"
                    .to_string(),
                public_key_pem: "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----"
                    .to_string(),
                is_active: true,
            }],
            issuer_url: "http://localhost:8080".to_string(),
            rust_log: "info".to_string(),
            cors_origins: vec!["*".to_string()],
            host: "127.0.0.1".to_string(),
            port: 3000,
            social_encryption_key: insecure_social,
            social_state_secret: INSECURE_SOCIAL_STATE_SECRET.to_string(),
            frontend_url: "http://localhost:3000".to_string(),
            saml_encryption_key: [0u8; 32],
            federation_encryption_key: [0x11u8; 32],
            mfa_encryption_key: [0x22u8; 32],
            mfa_issuer: "Xavyo".to_string(),
            webauthn_rp_id: "localhost".to_string(),
            webauthn_rp_name: "xavyo".to_string(),
            webauthn_origin: "http://localhost:8080".to_string(),
            connector_encryption_key: [0x33u8; 32],
            webhook_encryption_key: [0x44u8; 32],
            csrf_secret: [0x55u8; 32],
            kafka: None,
            otel: OtelConfig {
                otlp_endpoint: None,
                service_name: "xavyo-test".to_string(),
                sampling_rate: 1.0,
                metrics_enabled: true,
                environment: "development".to_string(),
            },
            secret_provider: None,
        }
    }

    /// Helper: create a test Config with all secure (non-default) values.
    fn test_config_secure() -> Config {
        Config {
            app_env: AppEnvironment::Production,
            database_url: "postgres://localhost/test".to_string(),
            jwt_private_key: "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----"
                .to_string(),
            jwt_public_key: "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----"
                .to_string(),
            jwt_key_id: "key-2026-01".to_string(),
            signing_keys: vec![SigningKey {
                kid: "key-2026-01".to_string(),
                private_key_pem: "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----"
                    .to_string(),
                public_key_pem: "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----"
                    .to_string(),
                is_active: true,
            }],
            issuer_url: "https://idp.example.com".to_string(),
            rust_log: "info".to_string(),
            cors_origins: vec!["https://app.example.com".to_string()],
            host: "0.0.0.0".to_string(),
            port: 8080,
            social_encryption_key: "c2VjdXJlLXJhbmRvbS1rZXktdGhhdC1pcy1ub3QtZGVmYXVsdA=="
                .to_string(),
            social_state_secret: "secure-random-state-secret-not-default".to_string(),
            frontend_url: "https://app.example.com".to_string(),
            saml_encryption_key: [0xAAu8; 32],
            federation_encryption_key: [0xBBu8; 32],
            mfa_encryption_key: [0xCCu8; 32],
            mfa_issuer: "Xavyo".to_string(),
            webauthn_rp_id: "example.com".to_string(),
            webauthn_rp_name: "xavyo".to_string(),
            webauthn_origin: "https://idp.example.com".to_string(),
            connector_encryption_key: [0xDDu8; 32],
            webhook_encryption_key: [0xEEu8; 32],
            csrf_secret: [0xFFu8; 32],
            kafka: None,
            otel: OtelConfig {
                otlp_endpoint: None,
                service_name: "xavyo-test".to_string(),
                sampling_rate: 1.0,
                metrics_enabled: true,
                environment: "production".to_string(),
            },
            secret_provider: None,
        }
    }

    #[test]
    fn test_config_error_display() {
        let err = ConfigError::MissingVar("TEST_VAR".to_string());
        assert_eq!(
            err.to_string(),
            "Missing required environment variable: TEST_VAR"
        );

        let err = ConfigError::InvalidValue {
            var: "PORT".to_string(),
            message: "Must be a number".to_string(),
        };
        assert_eq!(err.to_string(), "Invalid value for PORT: Must be a number");
    }

    #[test]
    fn test_bind_addr() {
        let config = test_config_secure();
        let mut config = config;
        config.host = "127.0.0.1".to_string();
        config.port = 3000;
        assert_eq!(config.bind_addr(), "127.0.0.1:3000");
    }

    // ── AppEnvironment tests (T004, T016) ─────────────────────────────

    #[test]
    fn test_app_environment_parse_production() {
        assert_eq!(
            AppEnvironment::from_env_str("production"),
            AppEnvironment::Production
        );
        assert_eq!(
            AppEnvironment::from_env_str("prod"),
            AppEnvironment::Production
        );
        assert_eq!(
            AppEnvironment::from_env_str("PRODUCTION"),
            AppEnvironment::Production
        );
    }

    #[test]
    fn test_app_environment_parse_development() {
        assert_eq!(
            AppEnvironment::from_env_str("development"),
            AppEnvironment::Development
        );
        assert_eq!(
            AppEnvironment::from_env_str("dev"),
            AppEnvironment::Development
        );
    }

    // T016: Unrecognized APP_ENV defaults to Development
    #[test]
    fn test_app_environment_unrecognized_defaults_to_development() {
        assert_eq!(
            AppEnvironment::from_env_str("staging"),
            AppEnvironment::Development
        );
        assert_eq!(
            AppEnvironment::from_env_str(""),
            AppEnvironment::Development
        );
        assert_eq!(
            AppEnvironment::from_env_str("test"),
            AppEnvironment::Development
        );
    }

    #[test]
    fn test_app_environment_display() {
        assert_eq!(AppEnvironment::Development.to_string(), "development");
        assert_eq!(AppEnvironment::Production.to_string(), "production");
    }

    #[test]
    fn test_app_environment_is_production() {
        assert!(AppEnvironment::Production.is_production());
        assert!(!AppEnvironment::Development.is_production());
    }

    // ── Security validation tests (T007-T015) ────────────────────────

    // T007: production mode rejects default SOCIAL_ENCRYPTION_KEY
    #[test]
    fn test_production_rejects_default_social_encryption_key() {
        let mut config = test_config_secure();
        config.app_env = AppEnvironment::Production;
        let insecure_social =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0u8; 32]);
        config.social_encryption_key = insecure_social;

        let result = config.validate_security_config();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.contains("SOCIAL_ENCRYPTION_KEY")));
    }

    // T008: production mode rejects default SAML_ENCRYPTION_KEY
    #[test]
    fn test_production_rejects_default_saml_encryption_key() {
        let mut config = test_config_secure();
        config.app_env = AppEnvironment::Production;
        config.saml_encryption_key = [0u8; 32];

        let result = config.validate_security_config();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.contains("SAML_ENCRYPTION_KEY")));
    }

    // T009: production mode rejects default FEDERATION_ENCRYPTION_KEY
    #[test]
    fn test_production_rejects_default_federation_encryption_key() {
        let mut config = test_config_secure();
        config.app_env = AppEnvironment::Production;
        config.federation_encryption_key = [0x11u8; 32];

        let result = config.validate_security_config();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors
            .iter()
            .any(|e| e.contains("FEDERATION_ENCRYPTION_KEY")));
    }

    // T010: production mode rejects default MFA_ENCRYPTION_KEY
    #[test]
    fn test_production_rejects_default_mfa_encryption_key() {
        let mut config = test_config_secure();
        config.app_env = AppEnvironment::Production;
        config.mfa_encryption_key = [0x22u8; 32];

        let result = config.validate_security_config();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.contains("MFA_ENCRYPTION_KEY")));
    }

    // T011: production mode rejects default CONNECTOR_ENCRYPTION_KEY
    #[test]
    fn test_production_rejects_default_connector_encryption_key() {
        let mut config = test_config_secure();
        config.app_env = AppEnvironment::Production;
        config.connector_encryption_key = [0x33u8; 32];

        let result = config.validate_security_config();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors
            .iter()
            .any(|e| e.contains("CONNECTOR_ENCRYPTION_KEY")));
    }

    // T012: production mode rejects default SOCIAL_STATE_SECRET
    #[test]
    fn test_production_rejects_default_social_state_secret() {
        let mut config = test_config_secure();
        config.app_env = AppEnvironment::Production;
        config.social_state_secret = INSECURE_SOCIAL_STATE_SECRET.to_string();

        let result = config.validate_security_config();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.contains("SOCIAL_STATE_SECRET")));
    }

    // T012b: production mode rejects default CSRF_SECRET (F082-US6)
    #[test]
    fn test_production_rejects_default_csrf_secret() {
        let mut config = test_config_secure();
        config.app_env = AppEnvironment::Production;
        config.csrf_secret = [0x55u8; 32];

        let result = config.validate_security_config();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.contains("CSRF_SECRET")));
    }

    // T013: production mode rejects CORS_ORIGINS="*"
    #[test]
    fn test_production_rejects_cors_wildcard() {
        let mut config = test_config_secure();
        config.app_env = AppEnvironment::Production;
        config.cors_origins = vec!["*".to_string()];

        let result = config.validate_security_config();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.contains("CORS_ORIGINS")));
    }

    // T014: development mode allows default keys with warnings
    #[test]
    fn test_development_allows_default_keys_with_warnings() {
        let config = test_config_insecure_dev();

        let result = config.validate_security_config();
        assert!(result.is_ok());
        let warnings = result.unwrap();
        assert!(!warnings.is_empty());
        // Should have warnings for all 8 insecure defaults (including CSRF_SECRET)
        assert!(
            warnings.len() >= 8,
            "Expected at least 8 warnings, got {}",
            warnings.len()
        );
    }

    // T015: production mode passes when all keys are non-default
    #[test]
    fn test_production_passes_with_secure_config() {
        let config = test_config_secure();

        let result = config.validate_security_config();
        assert!(result.is_ok());
        let warnings = result.unwrap();
        assert!(warnings.is_empty());
    }

    // T015 supplement: production rejects ALL insecure defaults together
    #[test]
    fn test_production_rejects_all_insecure_defaults() {
        let mut config = test_config_insecure_dev();
        config.app_env = AppEnvironment::Production;

        let result = config.validate_security_config();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(
            errors.len() >= 8,
            "Expected at least 8 errors, got {}",
            errors.len()
        );
    }

    // ── SigningKey tests (T005, T055, T056) ───────────────────────────

    #[test]
    fn test_signing_key_active_lookup() {
        let config = test_config_secure();
        let active = config.active_signing_key().expect("Should have active key");
        assert!(active.is_active);
        assert_eq!(active.kid, "key-2026-01");
    }

    // ── HealthCheckConfig tests (F074) ─────────────────────────────
    // All env-var-dependent scenarios are consolidated into a single test
    // to avoid race conditions when Rust runs tests in parallel.

    #[test]
    fn test_health_check_config_from_env() {
        // Scenario 1: defaults (no env vars set)
        std::env::remove_var("HEALTH_DB_TIMEOUT_SECS");
        std::env::remove_var("HEALTH_KAFKA_TIMEOUT_SECS");
        let config = HealthCheckConfig::from_env();
        assert_eq!(config.db_timeout_secs, 2, "default db timeout should be 2");
        assert_eq!(
            config.kafka_timeout_secs, 3,
            "default kafka timeout should be 3"
        );

        // Scenario 2: custom values
        std::env::set_var("HEALTH_DB_TIMEOUT_SECS", "5");
        std::env::set_var("HEALTH_KAFKA_TIMEOUT_SECS", "10");
        let config = HealthCheckConfig::from_env();
        assert_eq!(config.db_timeout_secs, 5);
        assert_eq!(config.kafka_timeout_secs, 10);

        // Scenario 3: invalid values fall back to defaults
        std::env::set_var("HEALTH_DB_TIMEOUT_SECS", "not_a_number");
        std::env::set_var("HEALTH_KAFKA_TIMEOUT_SECS", "-1");
        let config = HealthCheckConfig::from_env();
        assert_eq!(config.db_timeout_secs, 2, "invalid should fall back to 2");
        assert_eq!(
            config.kafka_timeout_secs, 3,
            "invalid should fall back to 3"
        );

        // Scenario 4: zero is clamped to minimum of 1
        std::env::set_var("HEALTH_DB_TIMEOUT_SECS", "0");
        std::env::set_var("HEALTH_KAFKA_TIMEOUT_SECS", "0");
        let config = HealthCheckConfig::from_env();
        assert_eq!(config.db_timeout_secs, 1, "zero should be clamped to 1");
        assert_eq!(config.kafka_timeout_secs, 1, "zero should be clamped to 1");

        // Clean up
        std::env::remove_var("HEALTH_DB_TIMEOUT_SECS");
        std::env::remove_var("HEALTH_KAFKA_TIMEOUT_SECS");
    }

    #[test]
    fn test_signing_key_find_by_kid() {
        let mut config = test_config_secure();
        config.signing_keys.push(SigningKey {
            kid: "key-old".to_string(),
            private_key_pem: "-----BEGIN PRIVATE KEY-----\nold\n-----END PRIVATE KEY-----"
                .to_string(),
            public_key_pem: "-----BEGIN PUBLIC KEY-----\nold\n-----END PUBLIC KEY-----".to_string(),
            is_active: false,
        });

        assert!(config.find_signing_key_by_kid("key-2026-01").is_some());
        assert!(config.find_signing_key_by_kid("key-old").is_some());
        assert!(config.find_signing_key_by_kid("nonexistent").is_none());
    }

    // ── CORS origin validation tests (F082-US3) ─────────────────────

    #[test]
    fn test_cors_valid_origins_pass() {
        let origins = vec![
            "https://app.example.com".to_string(),
            "http://localhost:3000".to_string(),
        ];
        assert!(validate_cors_origins(&origins, &AppEnvironment::Production).is_ok());
    }

    #[test]
    fn test_cors_wildcard_passes_validation() {
        let origins = vec!["*".to_string()];
        assert!(validate_cors_origins(&origins, &AppEnvironment::Production).is_ok());
    }

    #[test]
    fn test_cors_invalid_origin_rejected_in_production() {
        let origins = vec!["not-a-url".to_string()];
        let result = validate_cors_origins(&origins, &AppEnvironment::Production);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("not a valid URL"));
    }

    #[test]
    fn test_cors_invalid_origin_warns_in_development() {
        let origins = vec!["not-a-url".to_string()];
        // Development mode should not error
        assert!(validate_cors_origins(&origins, &AppEnvironment::Development).is_ok());
    }
}
