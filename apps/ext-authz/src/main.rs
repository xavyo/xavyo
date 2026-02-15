use std::sync::Arc;

use sqlx::postgres::PgPoolOptions;
use tonic::transport::Server;
use tracing_subscriber::EnvFilter;

use xavyo_authorization::cache::{MappingCache, PolicyCache};
use xavyo_ext_authz::config::ExtAuthzConfig;
use xavyo_ext_authz::proto::authorization_server::AuthorizationServer;
use xavyo_ext_authz::server::ExtAuthzService;

#[tokio::main]
async fn main() {
    // Load .env if present
    let _ = dotenvy::dotenv();

    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,xavyo_ext_authz=debug")),
        )
        .init();

    // Load configuration
    let config = ExtAuthzConfig::from_env().unwrap_or_else(|e| {
        eprintln!("Configuration error: {e}");
        std::process::exit(1);
    });

    tracing::info!(
        listen_addr = %config.listen_addr,
        fail_open = config.fail_open,
        risk_threshold = config.risk_score_deny_threshold,
        "starting ext-authz server"
    );

    // Create database pool
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&config.database_url)
        .await
        .unwrap_or_else(|e| {
            eprintln!("Database connection error: {e}");
            std::process::exit(1);
        });

    let pool = Arc::new(pool);

    // Initialize caches
    let policy_cache = Arc::new(PolicyCache::new());
    let mapping_cache = Arc::new(MappingCache::new());

    // Create the ext_authz service
    let service = ExtAuthzService::new(Arc::clone(&pool), &config, policy_cache, mapping_cache);

    // Create gRPC health service
    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_serving::<AuthorizationServer<ExtAuthzService>>()
        .await;

    let listen_addr = config.listen_addr;

    tracing::info!(%listen_addr, "ext-authz gRPC server listening");

    // Start gRPC server with health check
    Server::builder()
        .add_service(health_service)
        .add_service(AuthorizationServer::new(service))
        .serve(listen_addr)
        .await
        .unwrap_or_else(|e| {
            eprintln!("Server error: {e}");
            std::process::exit(1);
        });
}
