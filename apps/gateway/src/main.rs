//! Xavyo API Gateway - Unified routing, authentication, and rate limiting.

use axum::Router;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::{error, info};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

mod config;
mod error;
mod middleware;
mod proxy;
mod routes;

use config::GatewayConfig;
use middleware::{AuthLayer, RateLimitLayer, RequestIdLayer, TenantLayer};
use proxy::{BackendRouter, ProxyClient};
use routes::{
    docs::{docs_routes, init_docs, DocsState},
    health::{health_routes, HealthState},
    metrics::{metrics_routes, MetricsState},
    proxy::{proxy_handler, ProxyState},
};

/// Application version.
const VERSION: &str = env!("CARGO_PKG_VERSION");

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    init_logging();

    info!("Starting Xavyo API Gateway v{}", VERSION);

    // Load configuration
    let config_path = GatewayConfig::config_path();
    info!(path = %config_path, "Loading configuration");

    let mut config = GatewayConfig::from_file(&config_path)?;
    config.apply_env_overrides();

    let config = Arc::new(config);
    let start_time = Instant::now();

    // Create shared components
    let client = ProxyClient::new()?;
    let router = BackendRouter::new(config.clone());

    // Create state objects
    let proxy_state = Arc::new(ProxyState {
        router: router.clone(),
        client: client.clone(),
    });

    let health_state = Arc::new(HealthState {
        router: router.clone(),
        client: client.clone(),
        start_time,
        version: VERSION.to_string(),
    });

    let docs_state = Arc::new(DocsState::new(config.clone(), client.clone()));

    // Initialize docs (fetch OpenAPI specs)
    init_docs(docs_state.clone()).await;

    // Initialize metrics
    let metrics_state = Arc::new(MetricsState::new()?);

    // Build CORS layer
    let cors = build_cors_layer(&config);

    // Build the router
    let app = build_router(
        config.clone(),
        proxy_state,
        health_state,
        docs_state,
        metrics_state,
        cors,
    );

    // Start server
    let addr: SocketAddr = match format!("{}:{}", config.server.host, config.server.port).parse() {
        Ok(a) => a,
        Err(e) => {
            error!(
                host = %config.server.host,
                port = %config.server.port,
                error = %e,
                "Invalid server address"
            );
            return Err(e.into());
        }
    };

    info!(address = %addr, "Gateway listening");

    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// Initialize structured logging.
fn init_logging() {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,tower_http=debug"));

    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt::layer().json())
        .init();
}

/// Build CORS layer from configuration.
fn build_cors_layer(config: &GatewayConfig) -> CorsLayer {
    let mut cors = CorsLayer::new();

    // Origins
    if config.cors.allowed_origins.contains(&"*".to_string()) {
        cors = cors.allow_origin(Any);
    } else {
        let origins: Vec<_> = config
            .cors
            .allowed_origins
            .iter()
            .filter_map(|o| o.parse().ok())
            .collect();
        cors = cors.allow_origin(origins);
    }

    // Methods
    let methods: Vec<_> = config
        .cors
        .allowed_methods
        .iter()
        .filter_map(|m| m.parse().ok())
        .collect();
    cors = cors.allow_methods(methods);

    // Headers
    let headers: Vec<_> = config
        .cors
        .allowed_headers
        .iter()
        .filter_map(|h| h.parse().ok())
        .collect();
    cors = cors.allow_headers(headers);

    // Max age
    cors = cors.max_age(std::time::Duration::from_secs(config.cors.max_age_secs));

    cors
}

/// Build the main router with all routes and middleware.
fn build_router(
    config: Arc<GatewayConfig>,
    proxy_state: Arc<ProxyState>,
    health_state: Arc<HealthState>,
    docs_state: Arc<DocsState>,
    metrics_state: Arc<MetricsState>,
    cors: CorsLayer,
) -> Router {
    // Public routes (no auth required)
    let public_routes = Router::new()
        .merge(health_routes(health_state))
        .merge(metrics_routes(metrics_state))
        .merge(docs_routes(docs_state));

    // Protected routes with middleware stack
    let protected_routes = Router::new()
        .fallback(proxy_handler)
        .with_state(proxy_state)
        .layer(
            ServiceBuilder::new()
                .layer(RateLimitLayer::new(config.clone()))
                .layer(TenantLayer::new(config.clone()))
                .layer(AuthLayer::new(config.clone())),
        );

    // Combine all routes with global middleware
    // Note: We apply CORS and tracing at the top level
    Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .layer(RequestIdLayer::new())
}
