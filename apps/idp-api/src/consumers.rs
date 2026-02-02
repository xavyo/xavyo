//! Kafka event consumer registration for F055 Micro-certification.
//!
//! This module is only compiled when the `kafka` feature is enabled.
//! It sets up consumers for governance events that trigger micro-certifications.

use std::sync::Arc;

use sqlx::PgPool;
use tracing::{error, info};

use crate::config::KafkaConfig;
use xavyo_api_governance::services::MicroCertificationService;
use xavyo_api_governance::{
    AssignmentCreatedConsumer, ManagerChangeConsumer, SodViolationConsumer,
};
use xavyo_events::config::{
    KafkaConfig as EventsKafkaConfig, SaslCredentials, SaslMechanism, SecurityProtocol,
};
use xavyo_events::consumer::EventConsumer;
use xavyo_events::events::{EntitlementAssignmentCreated, SodViolationDetected, UserUpdated};

/// Start micro-certification event consumers.
///
/// This spawns background tasks that listen for governance events
/// and automatically create micro-certifications based on trigger rules.
pub async fn start_micro_cert_consumers(pool: PgPool, config: KafkaConfig) {
    info!("Starting micro-certification event consumers");

    // Create the MicroCertificationService that will be shared across consumers
    let micro_cert_service = Arc::new(MicroCertificationService::new(pool.clone()));

    // Convert our config to xavyo-events config
    let events_config = convert_kafka_config(&config);

    // Start assignment created consumer
    let pool_clone = pool.clone();
    let config_clone = events_config.clone();
    let service_clone = micro_cert_service.clone();
    let consumer_group = format!("{}-assignment-created", config.consumer_group_prefix);
    tokio::spawn(async move {
        if let Err(e) =
            start_assignment_consumer(pool_clone, config_clone, consumer_group, service_clone).await
        {
            error!(error = %e, "Assignment created consumer failed");
        }
    });

    // Start SoD violation consumer
    let pool_clone = pool.clone();
    let config_clone = events_config.clone();
    let service_clone = micro_cert_service.clone();
    let consumer_group = format!("{}-sod-violation", config.consumer_group_prefix);
    tokio::spawn(async move {
        if let Err(e) =
            start_sod_consumer(pool_clone, config_clone, consumer_group, service_clone).await
        {
            error!(error = %e, "SoD violation consumer failed");
        }
    });

    // Start manager change consumer
    let pool_clone = pool.clone();
    let consumer_group = format!("{}-manager-change", config.consumer_group_prefix);
    tokio::spawn(async move {
        if let Err(e) = start_manager_change_consumer(
            pool_clone,
            events_config,
            consumer_group,
            micro_cert_service,
        )
        .await
        {
            error!(error = %e, "Manager change consumer failed");
        }
    });

    info!("Micro-certification event consumers started");
}

/// Convert our Kafka config to xavyo-events Kafka config.
fn convert_kafka_config(config: &KafkaConfig) -> EventsKafkaConfig {
    let security_protocol = match config.security_protocol.to_uppercase().as_str() {
        "SSL" => SecurityProtocol::Ssl,
        "SASL_PLAINTEXT" => SecurityProtocol::SaslPlaintext,
        "SASL_SSL" => SecurityProtocol::SaslSsl,
        _ => SecurityProtocol::Plaintext,
    };

    let sasl = match (
        &config.sasl_mechanism,
        &config.sasl_username,
        &config.sasl_password,
    ) {
        (Some(mechanism), Some(username), Some(password)) => {
            let mech = match mechanism.to_uppercase().as_str() {
                "SCRAM-SHA-256" => SaslMechanism::ScramSha256,
                "SCRAM-SHA-512" => SaslMechanism::ScramSha512,
                _ => SaslMechanism::Plain,
            };
            Some(SaslCredentials {
                mechanism: mech,
                username: username.clone(),
                password: password.clone(),
            })
        }
        _ => None,
    };

    EventsKafkaConfig {
        bootstrap_servers: config.bootstrap_servers.clone(),
        client_id: "xavyo-micro-cert".to_string(),
        security_protocol,
        sasl,
    }
}

/// Start the assignment created consumer.
async fn start_assignment_consumer(
    pool: PgPool,
    config: EventsKafkaConfig,
    consumer_group: String,
    service: Arc<MicroCertificationService>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!(consumer_group = %consumer_group, "Starting assignment created consumer");

    let consumer = EventConsumer::new(config, pool.clone(), consumer_group)?;
    let handler = AssignmentCreatedConsumer::new(pool, service);

    let typed_consumer = consumer
        .subscribe::<EntitlementAssignmentCreated, _>(handler)
        .await?;
    typed_consumer.run().await?;

    Ok(())
}

/// Start the SoD violation consumer.
async fn start_sod_consumer(
    pool: PgPool,
    config: EventsKafkaConfig,
    consumer_group: String,
    service: Arc<MicroCertificationService>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!(consumer_group = %consumer_group, "Starting SoD violation consumer");

    let consumer = EventConsumer::new(config, pool.clone(), consumer_group)?;
    let handler = SodViolationConsumer::new(pool, service);

    let typed_consumer = consumer
        .subscribe::<SodViolationDetected, _>(handler)
        .await?;
    typed_consumer.run().await?;

    Ok(())
}

/// Start the manager change consumer.
async fn start_manager_change_consumer(
    pool: PgPool,
    config: EventsKafkaConfig,
    consumer_group: String,
    service: Arc<MicroCertificationService>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!(consumer_group = %consumer_group, "Starting manager change consumer");

    let consumer = EventConsumer::new(config, pool.clone(), consumer_group)?;
    let handler = ManagerChangeConsumer::new(pool, service);

    let typed_consumer = consumer.subscribe::<UserUpdated, _>(handler).await?;
    typed_consumer.run().await?;

    Ok(())
}
