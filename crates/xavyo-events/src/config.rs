//! Kafka configuration management.

use crate::error::EventError;
use std::env;
use std::str::FromStr;

/// Security protocol for Kafka connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityProtocol {
    /// Plaintext connection (no encryption or auth).
    Plaintext,
    /// SSL encryption without SASL auth.
    Ssl,
    /// SASL authentication without encryption.
    SaslPlaintext,
    /// SASL authentication with SSL encryption.
    SaslSsl,
}

impl FromStr for SecurityProtocol {
    type Err = EventError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "PLAINTEXT" => Ok(Self::Plaintext),
            "SSL" => Ok(Self::Ssl),
            "SASL_PLAINTEXT" => Ok(Self::SaslPlaintext),
            "SASL_SSL" => Ok(Self::SaslSsl),
            _ => Err(EventError::ConfigInvalid {
                var: "KAFKA_SECURITY_PROTOCOL".to_string(),
                reason: format!("Unknown protocol: {s}"),
            }),
        }
    }
}

impl SecurityProtocol {
    /// Convert to rdkafka string value.
    #[must_use] 
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Plaintext => "PLAINTEXT",
            Self::Ssl => "SSL",
            Self::SaslPlaintext => "SASL_PLAINTEXT",
            Self::SaslSsl => "SASL_SSL",
        }
    }
}

/// SASL mechanism for authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SaslMechanism {
    Plain,
    ScramSha256,
    ScramSha512,
}

impl FromStr for SaslMechanism {
    type Err = EventError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().replace('-', "_").as_str() {
            "PLAIN" => Ok(Self::Plain),
            "SCRAM_SHA_256" => Ok(Self::ScramSha256),
            "SCRAM_SHA_512" => Ok(Self::ScramSha512),
            _ => Err(EventError::ConfigInvalid {
                var: "KAFKA_SASL_MECHANISM".to_string(),
                reason: format!("Unknown mechanism: {s}"),
            }),
        }
    }
}

impl SaslMechanism {
    /// Convert to rdkafka string value.
    #[must_use] 
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Plain => "PLAIN",
            Self::ScramSha256 => "SCRAM-SHA-256",
            Self::ScramSha512 => "SCRAM-SHA-512",
        }
    }
}

/// SASL credentials for authentication.
#[derive(Debug, Clone)]
pub struct SaslCredentials {
    pub mechanism: SaslMechanism,
    pub username: String,
    pub password: String,
}

/// Kafka connection configuration.
#[derive(Debug, Clone)]
pub struct KafkaConfig {
    /// Comma-separated list of broker addresses.
    pub bootstrap_servers: String,
    /// Security protocol.
    pub security_protocol: SecurityProtocol,
    /// SASL credentials (required if using SASL).
    pub sasl: Option<SaslCredentials>,
    /// Client identifier.
    pub client_id: String,
}

impl KafkaConfig {
    /// Load configuration from environment variables.
    ///
    /// Required:
    /// - `KAFKA_BOOTSTRAP_SERVERS`: Comma-separated broker list
    ///
    /// Optional:
    /// - `KAFKA_SECURITY_PROTOCOL`: PLAINTEXT (default), SSL, `SASL_PLAINTEXT`, `SASL_SSL`
    /// - `KAFKA_CLIENT_ID`: Client identifier (default: "xavyo-events")
    /// - `KAFKA_SASL_MECHANISM`: PLAIN, SCRAM-SHA-256, SCRAM-SHA-512 (required if SASL)
    /// - `KAFKA_SASL_USERNAME`: SASL username (required if SASL)
    /// - `KAFKA_SASL_PASSWORD`: SASL password (required if SASL)
    pub fn from_env() -> Result<Self, EventError> {
        let bootstrap_servers =
            env::var("KAFKA_BOOTSTRAP_SERVERS").map_err(|_| EventError::ConfigMissing {
                var: "KAFKA_BOOTSTRAP_SERVERS".to_string(),
            })?;

        let security_protocol = match env::var("KAFKA_SECURITY_PROTOCOL") {
            Ok(v) => SecurityProtocol::from_str(&v)?,
            Err(_) => SecurityProtocol::Plaintext,
        };

        let client_id = env::var("KAFKA_CLIENT_ID").unwrap_or_else(|_| "xavyo-events".to_string());

        let sasl = if matches!(
            security_protocol,
            SecurityProtocol::SaslPlaintext | SecurityProtocol::SaslSsl
        ) {
            let mechanism_str =
                env::var("KAFKA_SASL_MECHANISM").map_err(|_| EventError::ConfigMissing {
                    var: "KAFKA_SASL_MECHANISM".to_string(),
                })?;

            let username =
                env::var("KAFKA_SASL_USERNAME").map_err(|_| EventError::ConfigMissing {
                    var: "KAFKA_SASL_USERNAME".to_string(),
                })?;

            let password =
                env::var("KAFKA_SASL_PASSWORD").map_err(|_| EventError::ConfigMissing {
                    var: "KAFKA_SASL_PASSWORD".to_string(),
                })?;

            Some(SaslCredentials {
                mechanism: SaslMechanism::from_str(&mechanism_str)?,
                username,
                password,
            })
        } else {
            None
        };

        Ok(Self {
            bootstrap_servers,
            security_protocol,
            sasl,
            client_id,
        })
    }

    /// Create a new configuration builder.
    #[must_use] 
    pub fn builder() -> KafkaConfigBuilder {
        KafkaConfigBuilder::new()
    }
}

/// Builder for `KafkaConfig`.
#[derive(Debug, Default)]
pub struct KafkaConfigBuilder {
    bootstrap_servers: Option<String>,
    security_protocol: Option<SecurityProtocol>,
    sasl: Option<SaslCredentials>,
    client_id: Option<String>,
}

impl KafkaConfigBuilder {
    /// Create a new builder.
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Set bootstrap servers.
    pub fn bootstrap_servers(mut self, servers: impl Into<String>) -> Self {
        self.bootstrap_servers = Some(servers.into());
        self
    }

    /// Set security protocol.
    #[must_use] 
    pub fn security_protocol(mut self, protocol: SecurityProtocol) -> Self {
        self.security_protocol = Some(protocol);
        self
    }

    /// Set SASL credentials.
    #[must_use] 
    pub fn sasl(mut self, mechanism: SaslMechanism, username: String, password: String) -> Self {
        self.sasl = Some(SaslCredentials {
            mechanism,
            username,
            password,
        });
        self
    }

    /// Set client ID.
    pub fn client_id(mut self, id: impl Into<String>) -> Self {
        self.client_id = Some(id.into());
        self
    }

    /// Build the configuration.
    pub fn build(self) -> Result<KafkaConfig, EventError> {
        let bootstrap_servers = self.bootstrap_servers.ok_or(EventError::ConfigMissing {
            var: "bootstrap_servers".to_string(),
        })?;

        let security_protocol = self
            .security_protocol
            .unwrap_or(SecurityProtocol::Plaintext);

        // Validate SASL is provided if required
        if matches!(
            security_protocol,
            SecurityProtocol::SaslPlaintext | SecurityProtocol::SaslSsl
        ) && self.sasl.is_none()
        {
            return Err(EventError::ConfigMissing {
                var: "sasl_credentials".to_string(),
            });
        }

        Ok(KafkaConfig {
            bootstrap_servers,
            security_protocol,
            sasl: self.sasl,
            client_id: self.client_id.unwrap_or_else(|| "xavyo-events".to_string()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_protocol_from_str() {
        assert_eq!(
            "PLAINTEXT".parse::<SecurityProtocol>().unwrap(),
            SecurityProtocol::Plaintext
        );
        assert_eq!(
            "sasl_ssl".parse::<SecurityProtocol>().unwrap(),
            SecurityProtocol::SaslSsl
        );
        assert!("INVALID".parse::<SecurityProtocol>().is_err());
    }

    #[test]
    fn test_sasl_mechanism_from_str() {
        assert_eq!(
            "PLAIN".parse::<SaslMechanism>().unwrap(),
            SaslMechanism::Plain
        );
        assert_eq!(
            "SCRAM-SHA-256".parse::<SaslMechanism>().unwrap(),
            SaslMechanism::ScramSha256
        );
        assert!("INVALID".parse::<SaslMechanism>().is_err());
    }

    #[test]
    fn test_builder_plaintext() {
        let config = KafkaConfig::builder()
            .bootstrap_servers("localhost:9092")
            .client_id("test-client")
            .build()
            .unwrap();

        assert_eq!(config.bootstrap_servers, "localhost:9092");
        assert_eq!(config.security_protocol, SecurityProtocol::Plaintext);
        assert_eq!(config.client_id, "test-client");
        assert!(config.sasl.is_none());
    }

    #[test]
    fn test_builder_sasl_ssl() {
        let config = KafkaConfig::builder()
            .bootstrap_servers("broker.example.com:9093")
            .security_protocol(SecurityProtocol::SaslSsl)
            .sasl(
                SaslMechanism::ScramSha256,
                "user".to_string(),
                "pass".to_string(),
            )
            .build()
            .unwrap();

        assert_eq!(config.security_protocol, SecurityProtocol::SaslSsl);
        assert!(config.sasl.is_some());
        let sasl = config.sasl.unwrap();
        assert_eq!(sasl.mechanism, SaslMechanism::ScramSha256);
        assert_eq!(sasl.username, "user");
    }

    #[test]
    fn test_builder_missing_servers() {
        let result = KafkaConfig::builder().build();
        assert!(result.is_err());
        if let Err(EventError::ConfigMissing { var }) = result {
            assert_eq!(var, "bootstrap_servers");
        } else {
            panic!("Expected ConfigMissing error");
        }
    }

    #[test]
    fn test_builder_sasl_without_credentials() {
        let result = KafkaConfig::builder()
            .bootstrap_servers("localhost:9092")
            .security_protocol(SecurityProtocol::SaslSsl)
            .build();

        assert!(result.is_err());
        if let Err(EventError::ConfigMissing { var }) = result {
            assert_eq!(var, "sasl_credentials");
        } else {
            panic!("Expected ConfigMissing error");
        }
    }

    #[test]
    fn test_from_env_missing_bootstrap() {
        // Clear the env var if set
        env::remove_var("KAFKA_BOOTSTRAP_SERVERS");
        let result = KafkaConfig::from_env();
        assert!(result.is_err());
    }
}
