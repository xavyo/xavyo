//! Xavyo Identity Provider API
//!
//! A Rust-based identity provider service built with Axum.
//! Provides authentication endpoints, health checks, and API documentation.

mod bootstrap;
mod config;
#[cfg(feature = "kafka")]
mod consumers;
mod health;
mod logging;
mod metrics;
mod middleware;
mod openapi;
mod state;
mod telemetry;

use axum::{routing::get, Router};
use config::{Config, HealthCheckConfig, InputValidationConfig, RateLimitingConfig};
use health::{health_handler, healthz_handler, livez_handler, readyz_handler, startupz_handler};
use middleware::request_id_layer;
use openapi::swagger_routes;
use sqlx::postgres::PgPoolOptions;
use state::AppState;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::signal;
use tower_http::cors::{Any, CorsLayer};
use tracing::info;
use xavyo_api_agents::{a2a_router, discovery_router, mcp_router, AgentsState};
use xavyo_api_auth::{
    admin_invite_public_router, admin_invite_router, admin_router as auth_admin_router,
    alerts_router, api_key_auth_middleware, audit_router, auth_router, branding_router,
    delegation_router, devices_router, jwt_auth_middleware, key_management_router, me_router,
    mfa_router, passwordless_admin_router, passwordless_router, public_router, revocation_router,
    users_router as auth_users_router, AuditService, AuthService, AuthState, EmailRateLimiter,
    JwtPublicKey, JwtPublicKeys, KeyService, LockoutService, MfaService, MockEmailSender,
    RateLimitConfig, RateLimiter, RevocationCache, SessionService, TokenConfig, TokenService,
    TotpEncryption,
};
use xavyo_api_authorization::authorization_router;
use xavyo_api_connectors::{
    connector_routes_full, reconciliation_global_routes, scim_target_routes, ConnectorService,
    ConnectorState, MappingService, ReconciliationService, ReconciliationState, ScimTargetService,
    ScimTargetState, SyncService, SyncState,
};
use xavyo_api_governance::governance_router;
use xavyo_api_import::{import_router, ImportState};
use xavyo_api_nhi::router as nhi_router;
use xavyo_api_oauth::router::{
    admin_oauth_router, device_router, oauth_router, well_known_router, OAuthState,
};
use xavyo_api_oidc_federation::{create_federation_router, FederationConfig};
use xavyo_api_saml::{create_saml_state, saml_admin_router, saml_public_router};
use xavyo_api_scim::{scim_router, ScimConfig};
use xavyo_api_social::{admin_social_router, public_social_router, SocialConfig, SocialState};
use xavyo_api_tenants::{
    api_keys_router, oauth_clients_router, suspension_check_middleware, system_admin_router,
    tenant_router,
};
use xavyo_api_users::{
    attribute_definitions_router, bulk_operations_router, groups_router, users_router, UsersState,
};
use xavyo_connector::crypto::CredentialEncryption;
use xavyo_connector::registry::ConnectorRegistry;
use xavyo_tenant::TenantLayer;
use xavyo_webhooks::services::delivery_service::DeliveryService;
use xavyo_webhooks::{webhooks_router, EventPublisher, WebhookWorker, WebhooksState};

#[tokio::main]
async fn main() {
    // Load configuration (fail-fast on missing required values)
    // F080: Use from_env_with_secrets() to support external secret providers.
    // Falls back to from_env() when SECRET_PROVIDER=env or unset (backward compatible).
    let config = match Config::from_env_with_secrets().await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    };

    // Initialize OpenTelemetry telemetry (F072)
    let (telemetry_guard, otel_layer) = telemetry::init_telemetry(&config.otel);

    // Initialize logging (with optional OpenTelemetry layer)
    logging::init_logging(&config.rust_log, otel_layer);

    info!(
        version = env!("CARGO_PKG_VERSION"),
        host = %config.host,
        port = config.port,
        env = %config.app_env,
        otel_enabled = config.otel.is_export_enabled(),
        "Starting xavyo API"
    );

    // Validate security configuration (F069-S1)
    match config.validate_security_config() {
        Ok(warnings) => {
            for warning in &warnings {
                tracing::warn!(target: "security", "{}", warning);
            }
            if !warnings.is_empty() {
                tracing::warn!(
                    target: "security",
                    count = warnings.len(),
                    "Insecure default values detected (allowed in {} mode)",
                    config.app_env
                );
            }
        }
        Err(errors) => {
            for error in &errors {
                tracing::error!(target: "security", "{}", error);
            }
            eprintln!(
                "FATAL: {} insecure default(s) detected in production mode. \
                 Set proper encryption keys or use APP_ENV=development.",
                errors.len()
            );
            std::process::exit(1);
        }
    }

    // Create database connection pool
    let pool = match PgPoolOptions::new()
        .max_connections(10)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&config.database_url)
        .await
    {
        Ok(pool) => {
            info!("Database connection established");
            pool
        }
        Err(e) => {
            eprintln!("Failed to connect to database: {e}");
            std::process::exit(1);
        }
    };

    // F095: Bootstrap system tenant and CLI OAuth client
    // This must happen after DB connection but before any services that depend on tenants
    match bootstrap::bootstrap_system(&pool).await {
        Ok(result) => {
            info!(
                tenant_created = result.tenant_created,
                oauth_client_created = result.oauth_client_created,
                "System tenant bootstrap completed"
            );
        }
        Err(e) => {
            eprintln!("FATAL: System tenant bootstrap failed: {e}");
            eprintln!("The application cannot start without the system tenant.");
            std::process::exit(1);
        }
    }

    // F082-US4: Create revocation cache (moka LRU, 10K entries, 30s TTL)
    let revocation_cache = RevocationCache::new(pool.clone());

    // F082-US5: Create key service for DB-backed signing key management
    let key_service = KeyService::new(pool.clone());

    // F082-US7: Create per-endpoint rate limiters
    let rate_limiting_config = RateLimitingConfig::from_env();
    let endpoint_rate_limiters =
        middleware::EndpointRateLimiters::from_config(&rate_limiting_config);

    // F082-US9: Input validation config (body size limit, timeout)
    let input_validation_config = InputValidationConfig::from_env();

    // Create authentication services
    let auth_service = AuthService::new(pool.clone());

    let token_config = TokenConfig {
        private_key: config.jwt_private_key.as_bytes().to_vec(),
        issuer: "xavyo".to_string(),
        audience: "xavyo".to_string(),
    };
    let token_service = TokenService::new(token_config.clone(), pool.clone());

    let rate_limiter = RateLimiter::new(RateLimitConfig {
        max_attempts: 5,
        window: Duration::from_secs(60),
    });

    let email_rate_limiter = EmailRateLimiter::new();

    // Use MockEmailSender for now (replace with SmtpEmailSender in production)
    let email_sender = Arc::new(MockEmailSender::new());

    // Create MFA service for TOTP authentication
    let totp_encryption = match TotpEncryption::from_key(&config.mfa_encryption_key) {
        Ok(e) => e,
        Err(e) => {
            tracing::error!("Failed to create TOTP encryption: {e}");
            std::process::exit(1);
        }
    };
    let mfa_service = MfaService::new(
        pool.clone(),
        totp_encryption.clone(),
        config.mfa_issuer.clone(),
    );

    // Create session service for session management
    let session_service = SessionService::new(pool.clone());
    // F112: Clone session service for device routes (will be wrapped in Arc)
    let session_service_for_device = Arc::new(session_service.clone());

    // F112: Create services for device login routes
    let auth_service_for_device = Arc::new(AuthService::new(pool.clone()));
    let lockout_service_for_device = Arc::new(LockoutService::new(pool.clone()));
    let mfa_service_for_device = Arc::new(MfaService::new(
        pool.clone(),
        totp_encryption.clone(),
        config.mfa_issuer.clone(),
    ));
    let audit_service_for_device = Arc::new(AuditService::new(pool.clone()));

    let auth_state = match AuthState::new(
        pool.clone(),
        auth_service,
        token_service.clone(),
        rate_limiter,
        email_rate_limiter,
        email_sender,
        mfa_service,
        session_service,
        token_config.clone(),
    ) {
        Ok(state) => state,
        Err(e) => {
            tracing::error!("Failed to create auth state: {e}");
            std::process::exit(1);
        }
    };

    // Create metrics registry (F072 — US2)
    let metrics_registry = Arc::new(metrics::MetricsRegistry::new());

    // Health check configuration (F074)
    let health_config = HealthCheckConfig::from_env();

    // Create application state
    let app_state = AppState::new(
        pool.clone(),
        auth_state.clone(),
        metrics_registry.clone(),
        health_config,
        // TODO(F074): Wire Kafka health callback once xavyo-events exposes a health check method.
        // Currently the rdkafka consumer does not provide a connection health API.
        None,
    )
    // F080: Wire secret provider for health check integration
    .with_secret_provider(config.secret_provider.clone());

    // Clone shutdown/startup flags before app_state is moved into the router (F074)
    let shutting_down = app_state.shutting_down.clone();

    // Mark startup as complete — DB pool established, config validated (F074 — FR-003)
    app_state.mark_startup_complete();
    info!("Startup complete — startup probe will return 200");

    // Build CORS layer
    // F082-US3: Auto-allow localhost in development mode when no origins configured
    let effective_cors_origins = if config.app_env == config::AppEnvironment::Development
        && (config.cors_origins.is_empty()
            || (config.cors_origins.len() == 1 && config.cors_origins[0] == "*"))
    {
        tracing::info!(
            target: "security",
            "Development mode: auto-allowing localhost CORS origins"
        );
        vec![
            "http://localhost:3000".to_string(),
            "http://localhost:8080".to_string(),
            "http://127.0.0.1:3000".to_string(),
            "http://127.0.0.1:8080".to_string(),
        ]
    } else {
        config.cors_origins.clone()
    };
    let cors = build_cors_layer(&effective_cors_origins);

    // Build JWT public keys map for kid-based lookup (F069-S5)
    let jwt_public_keys = {
        let mut keys_map = std::collections::HashMap::new();
        for key in &config.signing_keys {
            keys_map.insert(key.kid.clone(), key.public_key_pem.clone());
        }
        // Always include the default key
        if !keys_map.contains_key(&config.jwt_key_id) {
            keys_map.insert(config.jwt_key_id.clone(), config.jwt_public_key.clone());
        }
        JwtPublicKeys(keys_map)
    };

    // Build auth routes with tenant middleware
    // The auth_router returns Router<()> as it uses Extension for state
    // Tenant is required for all auth operations (login, register, etc.)
    let auth_routes = auth_router(auth_state.clone())
        // F082-US7: Rate limit login/register endpoints
        .layer(axum::middleware::from_fn(
            middleware::login_rate_limit_middleware,
        ))
        .layer(axum::Extension(endpoint_rate_limiters.clone()))
        .layer(TenantLayer::with_config(
            xavyo_tenant::TenantConfig::builder()
                .require_tenant(true) // Tenant header required for multi-tenant auth
                .build(),
        ));

    // Build MFA routes with JWT authentication (F022)
    let mfa_routes = mfa_router(auth_state.clone())
        .layer(axum::middleware::from_fn(jwt_auth_middleware))
        .layer(axum::Extension(JwtPublicKey(config.jwt_public_key.clone())))
        .layer(TenantLayer::with_config(
            xavyo_tenant::TenantConfig::builder()
                .require_tenant(true)
                .build(),
        ));

    // Build auth session routes (for /users/me/sessions)
    let auth_session_routes = auth_users_router(auth_state.clone())
        .layer(axum::middleware::from_fn(jwt_auth_middleware))
        .layer(axum::Extension(JwtPublicKey(config.jwt_public_key.clone())))
        .layer(TenantLayer::with_config(
            xavyo_tenant::TenantConfig::builder()
                .require_tenant(true)
                .build(),
        ));

    // Build auth admin routes (for /admin/tenants/:id/session-policy)
    let auth_admin_routes = auth_admin_router(auth_state.clone())
        .layer(axum::middleware::from_fn(jwt_auth_middleware))
        .layer(axum::Extension(JwtPublicKey(config.jwt_public_key.clone())))
        .layer(TenantLayer::with_config(
            xavyo_tenant::TenantConfig::builder()
                .require_tenant(true)
                .build(),
        ));

    // Build devices routes (F026)
    let devices_routes = devices_router(auth_state.clone())
        .layer(axum::middleware::from_fn(jwt_auth_middleware))
        .layer(axum::Extension(JwtPublicKey(config.jwt_public_key.clone())))
        .layer(TenantLayer::with_config(
            xavyo_tenant::TenantConfig::builder()
                .require_tenant(true)
                .build(),
        ));

    // Build audit routes (F025)
    let audit_routes = audit_router(auth_state.clone())
        .layer(axum::middleware::from_fn(jwt_auth_middleware))
        .layer(axum::Extension(JwtPublicKey(config.jwt_public_key.clone())))
        .layer(TenantLayer::with_config(
            xavyo_tenant::TenantConfig::builder()
                .require_tenant(true)
                .build(),
        ));

    // Build alerts routes (F025)
    let alerts_routes = alerts_router(auth_state.clone())
        .layer(axum::middleware::from_fn(jwt_auth_middleware))
        .layer(axum::Extension(JwtPublicKey(config.jwt_public_key.clone())))
        .layer(TenantLayer::with_config(
            xavyo_tenant::TenantConfig::builder()
                .require_tenant(true)
                .build(),
        ));

    // Build self-service profile routes (F027)
    // Note: These routes require JWT authentication
    let me_routes = me_router(auth_state.clone())
        .layer(axum::middleware::from_fn(jwt_auth_middleware))
        .layer(axum::Extension(JwtPublicKey(config.jwt_public_key.clone())))
        .layer(TenantLayer::with_config(
            xavyo_tenant::TenantConfig::builder()
                .require_tenant(true)
                .build(),
        ));

    // Build delegation routes (F029)
    let delegation_routes = delegation_router(auth_state.clone())
        .layer(axum::middleware::from_fn(jwt_auth_middleware))
        .layer(axum::Extension(JwtPublicKey(config.jwt_public_key.clone())))
        .layer(TenantLayer::with_config(
            xavyo_tenant::TenantConfig::builder()
                .require_tenant(true)
                .build(),
        ));

    // Build branding routes (F030)
    let branding_routes = branding_router(auth_state.clone())
        .layer(axum::middleware::from_fn(jwt_auth_middleware))
        .layer(axum::Extension(JwtPublicKey(config.jwt_public_key.clone())))
        .layer(TenantLayer::with_config(
            xavyo_tenant::TenantConfig::builder()
                .require_tenant(true)
                .build(),
        ));

    // Build public branding routes (F030 - no auth)
    let public_branding_routes = public_router(auth_state.clone());

    // Build passwordless authentication routes (F079 - public, tenant from header)
    // F082-US7: Rate limit registration/passwordless endpoints
    let passwordless_routes = passwordless_router(auth_state.clone())
        .layer(axum::middleware::from_fn(
            middleware::registration_rate_limit_middleware,
        ))
        .layer(axum::Extension(endpoint_rate_limiters.clone()))
        .layer(TenantLayer::with_config(
            xavyo_tenant::TenantConfig::builder()
                .require_tenant(true)
                .build(),
        ));

    // Build passwordless admin routes (F079 - requires JWT + admin role)
    let passwordless_admin_routes = passwordless_admin_router(auth_state.clone())
        .layer(axum::middleware::from_fn(jwt_auth_middleware))
        .layer(axum::Extension(JwtPublicKey(config.jwt_public_key.clone())))
        .layer(TenantLayer::with_config(
            xavyo_tenant::TenantConfig::builder()
                .require_tenant(true)
                .build(),
        ));

    // Build admin invitation routes (F-ADMIN-INVITE)
    // Authenticated routes for admin operations
    let admin_invite_routes = admin_invite_router(auth_state.clone())
        .layer(axum::middleware::from_fn(jwt_auth_middleware))
        .layer(axum::Extension(JwtPublicKey(config.jwt_public_key.clone())))
        .layer(TenantLayer::with_config(
            xavyo_tenant::TenantConfig::builder()
                .require_tenant(true)
                .build(),
        ));

    // Public invitation accept route (F-ADMIN-INVITE)
    // Invitees don't have accounts yet, so this must be unauthenticated
    let admin_invite_public_routes =
        admin_invite_public_router(auth_state.clone()).layer(TenantLayer::with_config(
            xavyo_tenant::TenantConfig::builder()
                .require_tenant(true)
                .build(),
        ));

    // Build token revocation routes (F069-S4)
    let revocation_routes = revocation_router()
        .layer(axum::middleware::from_fn(jwt_auth_middleware))
        .layer(axum::Extension(JwtPublicKey(config.jwt_public_key.clone())))
        .layer(axum::Extension(pool.clone()))
        .layer(TenantLayer::with_config(
            xavyo_tenant::TenantConfig::builder()
                .require_tenant(true)
                .build(),
        ));

    // Build users routes with tenant middleware
    // The users_router requires JWT authentication with admin role
    let users_state = UsersState::new(pool.clone());
    let users_routes = users_router(users_state.clone())
        .layer(axum::middleware::from_fn(jwt_auth_middleware))
        .layer(axum::Extension(JwtPublicKey(config.jwt_public_key.clone())))
        .layer(TenantLayer::with_config(
            xavyo_tenant::TenantConfig::builder()
                .require_tenant(true) // Tenant is required for user management
                .build(),
        ));

    // Build attribute definitions routes (F070 - Custom User Attributes)
    let attribute_def_routes = attribute_definitions_router(users_state.clone())
        .layer(axum::middleware::from_fn(jwt_auth_middleware))
        .layer(axum::Extension(JwtPublicKey(config.jwt_public_key.clone())))
        .layer(TenantLayer::with_config(
            xavyo_tenant::TenantConfig::builder()
                .require_tenant(true)
                .build(),
        ));

    // Build bulk operations routes (F070 - US4 Bulk Updates)
    let bulk_ops_routes = bulk_operations_router(users_state.clone())
        .layer(axum::middleware::from_fn(jwt_auth_middleware))
        .layer(axum::Extension(JwtPublicKey(config.jwt_public_key.clone())))
        .layer(TenantLayer::with_config(
            xavyo_tenant::TenantConfig::builder()
                .require_tenant(true)
                .build(),
        ));

    // Build group hierarchy routes (F071 - Organization Hierarchy)
    let groups_routes = groups_router(users_state)
        .layer(axum::middleware::from_fn(jwt_auth_middleware))
        .layer(axum::Extension(JwtPublicKey(config.jwt_public_key.clone())))
        .layer(TenantLayer::with_config(
            xavyo_tenant::TenantConfig::builder()
                .require_tenant(true)
                .build(),
        ));

    // Build OAuth2/OIDC routes (F069-S5: multi-key support)
    let oauth_signing_keys: Vec<xavyo_api_oauth::OAuthSigningKey> =
        if config.signing_keys.is_empty() {
            vec![xavyo_api_oauth::OAuthSigningKey {
                kid: config.jwt_key_id.clone(),
                private_key_pem: config.jwt_private_key.clone(),
                public_key_pem: config.jwt_public_key.clone(),
                is_active: true,
            }]
        } else {
            config
                .signing_keys
                .iter()
                .map(|k| xavyo_api_oauth::OAuthSigningKey {
                    kid: k.kid.clone(),
                    private_key_pem: k.private_key_pem.clone(),
                    public_key_pem: k.public_key_pem.clone(),
                    is_active: k.is_active,
                })
                .collect()
        };

    let oauth_state = OAuthState::with_signing_keys(
        pool.clone(),
        config.issuer_url.clone(),
        config.jwt_private_key.as_bytes().to_vec(),
        config.jwt_public_key.as_bytes().to_vec(),
        config.jwt_key_id.clone(),
        oauth_signing_keys,
        // F082-US6: CSRF secret MUST be independent of JWT signing key
        config.csrf_secret.to_vec(),
    )
    // F084: Share RevocationCache with OAuth2 revocation/introspection handlers
    .with_revocation_cache(revocation_cache.clone());

    // OAuth routes (token endpoint, authorize, userinfo)
    // F082-US7: Rate limit token endpoint
    let oauth_routes = oauth_router(oauth_state.clone())
        .layer(axum::middleware::from_fn(
            middleware::token_rate_limit_middleware,
        ))
        .layer(axum::Extension(endpoint_rate_limiters.clone()));

    // Well-known routes (OIDC discovery, JWKS)
    let well_known_routes = well_known_router(oauth_state.clone());

    // Device code verification routes (F096 - RFC 8628)
    // These render HTML pages for the device authorization flow
    // F112: Device routes need all auth services for login flow
    let device_routes = device_router(oauth_state.clone())
        .layer(axum::Extension(session_service_for_device.clone()))
        .layer(axum::Extension(auth_service_for_device.clone()))
        .layer(axum::Extension(lockout_service_for_device.clone()))
        .layer(axum::Extension(mfa_service_for_device.clone()))
        .layer(axum::Extension(audit_service_for_device.clone()))
        .layer(TenantLayer::with_config(
            xavyo_tenant::TenantConfig::builder()
                .require_tenant(true)
                .build(),
        ));

    // OAuth admin routes (client management - requires admin role)
    let oauth_admin_routes = admin_oauth_router(oauth_state)
        .layer(axum::middleware::from_fn(jwt_auth_middleware))
        .layer(axum::Extension(JwtPublicKey(config.jwt_public_key.clone())))
        .layer(TenantLayer::with_config(
            xavyo_tenant::TenantConfig::builder()
                .require_tenant(true)
                .build(),
        ));

    // Build social login state
    let social_auth_adapter = Arc::new(SocialAuthAdapter::new(
        pool.clone(),
        config.jwt_private_key.clone(),
    ));
    let social_config = SocialConfig {
        pool: pool.clone(),
        base_url: config.issuer_url.clone(),
        frontend_url: config.frontend_url.clone(),
        encryption_key: config.social_encryption_key.clone(),
        state_secret: config.social_state_secret.clone(),
    };
    let social_state = match SocialState::new(social_config, social_auth_adapter) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to create social state: {e}");
            std::process::exit(1);
        }
    };

    // Social login public routes (no auth required, tenant from header)
    let social_public_routes = public_social_router().with_state(social_state.clone());

    // Social login admin routes (requires admin role and tenant)
    let social_admin_routes = admin_social_router()
        .with_state(social_state)
        .layer(axum::middleware::from_fn(jwt_auth_middleware))
        .layer(axum::Extension(JwtPublicKey(config.jwt_public_key.clone())))
        .layer(TenantLayer::with_config(
            xavyo_tenant::TenantConfig::builder()
                .require_tenant(true)
                .build(),
        ));

    // SAML IdP routes
    let saml_state = create_saml_state(
        pool.clone(),
        config.issuer_url.clone(),
        config.saml_encryption_key,
    );
    // SAML public routes (metadata, SSO) - require tenant but not auth
    // Provide default Extension<Option<User>> = None for unauthenticated requests
    // The SSO handler expects this extension to check if user is authenticated
    let saml_public_routes = saml_public_router(saml_state.clone())
        .layer(axum::Extension(None::<xavyo_db::models::User>))
        .layer(TenantLayer::with_config(
            xavyo_tenant::TenantConfig::builder()
                .require_tenant(true)
                .build(),
        ));
    // SAML admin routes (SP/cert management) - require tenant and JWT auth
    let saml_admin_routes = saml_admin_router(saml_state)
        .layer(axum::middleware::from_fn(jwt_auth_middleware))
        .layer(axum::Extension(JwtPublicKey(config.jwt_public_key.clone())))
        .layer(TenantLayer::with_config(
            xavyo_tenant::TenantConfig::builder()
                .require_tenant(true)
                .build(),
        ));

    // OIDC Federation routes (external IdP integration)
    // Tenant ID is extracted per-request via TenantLayer middleware.
    let federation_config = FederationConfig {
        pool: pool.clone(),
        master_key: config.federation_encryption_key,
        callback_base_url: config.issuer_url.clone(),
    };
    let federation_routes =
        create_federation_router(federation_config).layer(TenantLayer::with_config(
            xavyo_tenant::TenantConfig::builder()
                .require_tenant(true)
                .build(),
        ));

    // SCIM 2.0 provisioning routes
    let scim_config = ScimConfig::new(pool.clone(), config.issuer_url.clone());
    let scim_routes = scim_router(scim_config);

    // Governance routes (F033 - IGA Entitlement Management)
    // F113: Support both API key and JWT authentication for programmatic access
    let governance_routes = governance_router(pool.clone())
        .layer(axum::middleware::from_fn(jwt_auth_middleware))
        .layer(axum::middleware::from_fn(api_key_auth_middleware))
        .layer(axum::Extension(JwtPublicKey(config.jwt_public_key.clone())))
        .layer(axum::Extension(pool.clone()))
        .layer(TenantLayer::with_config(
            xavyo_tenant::TenantConfig::builder()
                .require_tenant(true)
                .build(),
        ));

    // Authorization engine routes (F083 - Fine-Grained Authorization)
    // F113: Support both API key and JWT authentication for programmatic access
    let authorization_routes = authorization_router(pool.clone(), "all".to_string())
        .layer(axum::middleware::from_fn(jwt_auth_middleware))
        .layer(axum::middleware::from_fn(api_key_auth_middleware))
        .layer(axum::Extension(JwtPublicKey(config.jwt_public_key.clone())))
        .layer(axum::Extension(pool.clone()))
        .layer(TenantLayer::with_config(
            xavyo_tenant::TenantConfig::builder()
                .require_tenant(true)
                .build(),
        ));

    // Connector routes (F045 - Connector Framework)
    let connector_encryption = Arc::new(CredentialEncryption::new(config.connector_encryption_key));
    let connector_registry = Arc::new(ConnectorRegistry::new());
    let connector_service = Arc::new(ConnectorService::new(
        pool.clone(),
        connector_encryption.clone(),
        connector_registry.clone(),
    ));
    let schema_service = Arc::new(xavyo_api_connectors::SchemaService::new(
        pool.clone(),
        connector_encryption.clone(),
        connector_registry,
    ));
    let mapping_service = Arc::new(MappingService::new(pool.clone()));
    let schedule_service = Arc::new(xavyo_api_connectors::ScheduleService::new(pool.clone()));
    let connector_state = ConnectorState::new(
        connector_service,
        schema_service,
        mapping_service,
        schedule_service.clone(),
    );

    // Sync service (F048 - Live Synchronization)
    let sync_service = Arc::new(SyncService::new(pool.clone()));
    let sync_state = SyncState::new(sync_service);

    // Reconciliation service (F049 - Reconciliation Engine)
    // Service is stateless with respect to tenant - all methods accept tenant_id as parameter
    let reconciliation_service = Arc::new(ReconciliationService::new(pool.clone()));
    let reconciliation_state = ReconciliationState::new(reconciliation_service);

    // Combined connector routes with sync and reconciliation
    // F113: Support both API key and JWT authentication for programmatic access
    let connector_routes =
        connector_routes_full(connector_state, sync_state, reconciliation_state.clone())
            .layer(axum::middleware::from_fn(jwt_auth_middleware))
            .layer(axum::middleware::from_fn(api_key_auth_middleware))
            .layer(axum::Extension(JwtPublicKey(config.jwt_public_key.clone())))
            .layer(axum::Extension(pool.clone()))
            .layer(TenantLayer::with_config(
                xavyo_tenant::TenantConfig::builder()
                    .require_tenant(true)
                    .build(),
            ));

    // Global reconciliation routes (F049 - not under /connectors)
    // F113: Support both API key and JWT authentication for programmatic access
    let reconciliation_global = reconciliation_global_routes(reconciliation_state)
        .layer(axum::middleware::from_fn(jwt_auth_middleware))
        .layer(axum::middleware::from_fn(api_key_auth_middleware))
        .layer(axum::Extension(JwtPublicKey(config.jwt_public_key.clone())))
        .layer(axum::Extension(pool.clone()))
        .layer(TenantLayer::with_config(
            xavyo_tenant::TenantConfig::builder()
                .require_tenant(true)
                .build(),
        ));

    // SCIM Outbound Provisioning Target routes (F087)
    let scim_target_service = Arc::new(ScimTargetService::new(
        pool.clone(),
        connector_encryption.clone(),
    ));
    let scim_target_state = ScimTargetState {
        scim_target_service,
    };
    // F113: Support both API key and JWT authentication for programmatic access
    let scim_target_routes = scim_target_routes(scim_target_state)
        .layer(axum::middleware::from_fn(jwt_auth_middleware))
        .layer(axum::middleware::from_fn(api_key_auth_middleware))
        .layer(axum::Extension(JwtPublicKey(config.jwt_public_key.clone())))
        .layer(axum::Extension(pool.clone()))
        .layer(TenantLayer::with_config(
            xavyo_tenant::TenantConfig::builder()
                .require_tenant(true)
                .build(),
        ));

    // Webhook event publishing & delivery (F085)
    let (event_publisher, event_rx) = EventPublisher::new(1024);
    let webhook_delivery_service =
        match DeliveryService::new(pool.clone(), config.webhook_encryption_key.to_vec()) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("Failed to create webhook delivery service: {e}");
                std::process::exit(1);
            }
        };
    let webhooks_state = WebhooksState::new(pool.clone(), config.webhook_encryption_key.to_vec());
    // F113: Support both API key and JWT authentication for programmatic access
    let webhooks_routes = webhooks_router(webhooks_state)
        .layer(axum::middleware::from_fn(jwt_auth_middleware))
        .layer(axum::middleware::from_fn(api_key_auth_middleware))
        .layer(axum::Extension(JwtPublicKey(config.jwt_public_key.clone())))
        .layer(axum::Extension(pool.clone()))
        .layer(TenantLayer::with_config(
            xavyo_tenant::TenantConfig::builder()
                .require_tenant(true)
                .build(),
        ));

    // Bulk user import routes (F086 - Import & Invitation)
    // F113: Support both API key and JWT authentication for programmatic access
    let import_state = ImportState::new(pool.clone(), auth_state.email_sender.clone());
    let import_routes = import_router(import_state)
        .layer(axum::middleware::from_fn(jwt_auth_middleware))
        .layer(axum::middleware::from_fn(api_key_auth_middleware))
        .layer(axum::Extension(JwtPublicKey(config.jwt_public_key.clone())))
        .layer(axum::Extension(pool.clone()))
        .layer(TenantLayer::with_config(
            xavyo_tenant::TenantConfig::builder()
                .require_tenant(true)
                .build(),
        ));

    // AI Agent state for MCP/A2A/Discovery routes
    // NOTE: Agent CRUD routes (/agents/*, /tools/*, /approvals/*) are now under /nhi/*
    // via F109 - NHI API Consolidation. The agents_state is still needed for protocol routes.
    let agents_state = match AgentsState::new(pool.clone()) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to create agents state: {e}");
            std::process::exit(1);
        }
    };

    // MCP routes (F091 - Model Context Protocol)
    // F113: Support both API key and JWT authentication for programmatic access
    let mcp_routes = mcp_router(agents_state.clone())
        .layer(axum::middleware::from_fn(jwt_auth_middleware))
        .layer(axum::middleware::from_fn(api_key_auth_middleware))
        .layer(axum::Extension(JwtPublicKey(config.jwt_public_key.clone())))
        .layer(axum::Extension(pool.clone()))
        .layer(TenantLayer::with_config(
            xavyo_tenant::TenantConfig::builder()
                .require_tenant(true)
                .build(),
        ));

    // A2A routes (F091 - Agent-to-Agent Protocol)
    // F113: Support both API key and JWT authentication for programmatic access
    let a2a_routes = a2a_router(agents_state.clone())
        .layer(axum::middleware::from_fn(jwt_auth_middleware))
        .layer(axum::middleware::from_fn(api_key_auth_middleware))
        .layer(axum::Extension(JwtPublicKey(config.jwt_public_key.clone())))
        .layer(axum::Extension(pool.clone()))
        .layer(TenantLayer::with_config(
            xavyo_tenant::TenantConfig::builder()
                .require_tenant(true)
                .build(),
        ));

    // A2A AgentCard discovery routes (public, no auth required)
    let agents_discovery_routes = discovery_router(agents_state);

    // Unified NHI routes (F108 - Unified Non-Human Identity Architecture)
    // F113: Support both API key and JWT authentication for programmatic access
    let nhi_routes = match nhi_router(pool.clone()) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Failed to create NHI router: {e}");
            std::process::exit(1);
        }
    }
    .layer(axum::middleware::from_fn(jwt_auth_middleware))
    // F113: API key middleware runs before JWT - if API key, validates; if not, passes through
    .layer(axum::middleware::from_fn(api_key_auth_middleware))
    .layer(axum::Extension(JwtPublicKey(config.jwt_public_key.clone())))
    // F113: PgPool required for API key validation lookups
    .layer(axum::Extension(pool.clone()))
    .layer(TenantLayer::with_config(
        xavyo_tenant::TenantConfig::builder()
            .require_tenant(true)
            .build(),
    ));

    // Tenant provisioning routes (F097 - Self-service tenant creation)
    // Requires JWT authentication against the system tenant
    // F113: Support both API key and JWT authentication for programmatic access
    // F-IDEMPOTENCY: Support Idempotency-Key header for safe retries
    let idempotency_state = middleware::IdempotencyState { pool: pool.clone() };
    let tenant_routes = tenant_router(pool.clone())
        // F-IDEMPOTENCY: Idempotency middleware must run after JWT auth to access claims
        .layer(axum::middleware::from_fn_with_state(
            idempotency_state,
            middleware::idempotency_middleware_jwt,
        ))
        .layer(axum::middleware::from_fn(jwt_auth_middleware))
        // F113: API key middleware runs before JWT - if API key, validates; if not, passes through
        .layer(axum::middleware::from_fn(api_key_auth_middleware))
        .layer(axum::Extension(JwtPublicKey(config.jwt_public_key.clone())))
        // F113: PgPool required for API key validation lookups
        .layer(axum::Extension(pool.clone()));
    // Note: No TenantLayer - provisioning is done before the user has a tenant

    // System administration routes (F-SUSPEND, F-DELETE, F-USAGE-TRACK, F-PLAN-MGMT, F-SETTINGS-API)
    // Requires JWT authentication against the system tenant
    let system_admin_routes = system_admin_router(pool.clone())
        .layer(axum::middleware::from_fn(jwt_auth_middleware))
        .layer(axum::middleware::from_fn(api_key_auth_middleware))
        .layer(axum::Extension(JwtPublicKey(config.jwt_public_key.clone())))
        .layer(axum::Extension(pool.clone()));

    // API key management routes (F-KEY-ROTATE)
    // Requires JWT authentication
    let api_keys_routes = api_keys_router(pool.clone())
        .layer(axum::middleware::from_fn(jwt_auth_middleware))
        .layer(axum::middleware::from_fn(api_key_auth_middleware))
        .layer(axum::Extension(JwtPublicKey(config.jwt_public_key.clone())))
        .layer(axum::Extension(pool.clone()));

    // OAuth client management routes (F-SECRET-ROTATE)
    // Requires JWT authentication
    let oauth_clients_routes = oauth_clients_router(pool.clone())
        .layer(axum::middleware::from_fn(jwt_auth_middleware))
        .layer(axum::middleware::from_fn(api_key_auth_middleware))
        .layer(axum::Extension(JwtPublicKey(config.jwt_public_key.clone())))
        .layer(axum::Extension(pool.clone()));

    // Build the router
    // We first create routes that need AppState, then merge the auth routes
    let app = Router::new()
        // Health check endpoint (no auth required)
        .route("/health", get(health_handler))
        // Kubernetes health probes (no auth required, F072 — US3, F074)
        .route("/livez", get(livez_handler))
        .route("/readyz", get(readyz_handler))
        .route("/healthz", get(healthz_handler))
        .route("/startupz", get(startupz_handler))
        // Prometheus metrics endpoint (no auth required, F072 — US2)
        .route("/metrics", get(metrics::metrics_handler))
        // Swagger UI and OpenAPI spec
        .merge(swagger_routes())
        .with_state(app_state)
        // Auth routes (uses Extension, not State, so nest_service works)
        .nest_service("/auth", auth_routes)
        // MFA routes (F022 - requires JWT authentication)
        .nest("/auth/mfa", mfa_routes)
        // Users routes - separate nesting to avoid route conflicts
        // auth_session_routes handles: /users/me/* (session management for self)
        .nest("/users", auth_session_routes)
        // users_routes handles: /admin/users/* (admin endpoints for user management)
        .nest("/admin/users", users_routes)
        // Attribute definition routes (F070 - Custom User Attributes)
        .nest("/admin/attribute-definitions", attribute_def_routes)
        // Bulk operations routes (F070 - US4 Bulk Updates)
        .nest("/admin/custom-attributes", bulk_ops_routes)
        // Group hierarchy routes (F071 - Organization Hierarchy)
        .nest("/admin/groups", groups_routes)
        // Auth admin routes (for session policy endpoints)
        .nest_service("/admin", auth_admin_routes)
        // OAuth2/OIDC routes
        .nest("/oauth", oauth_routes)
        // Well-known routes (at root level)
        .nest("/.well-known", well_known_routes)
        // Device code verification routes (F096 - RFC 8628)
        .nest("/device", device_routes)
        // OAuth admin routes (requires admin role)
        .nest("/admin/oauth", oauth_admin_routes)
        // Social login routes (public, with tenant from header)
        .nest("/auth/social", social_public_routes)
        // Social login admin routes (requires admin role)
        .nest("/admin/social-providers", social_admin_routes)
        // SAML IdP public routes (metadata, SSO)
        .merge(saml_public_routes)
        // SAML admin routes (SP/cert management)
        .nest("/admin/saml", saml_admin_routes)
        // OIDC Federation routes (external IdP integration)
        .merge(federation_routes)
        // SCIM 2.0 provisioning routes
        .merge(scim_routes)
        // Devices routes (F026)
        .nest("/devices", devices_routes)
        // Audit routes (F025)
        .nest("/audit", audit_routes)
        // Security alerts routes (F025)
        .nest("/security-alerts", alerts_routes)
        // Self-service profile routes (F027)
        .nest("/me", me_routes)
        // Delegation admin routes (F029)
        .nest("/admin/delegation", delegation_routes)
        // Admin invitation routes (F-ADMIN-INVITE - authenticated)
        .nest("/admin", admin_invite_routes)
        // Admin invitation accept route (F-ADMIN-INVITE - public, no auth)
        .nest("/admin", admin_invite_public_routes)
        // Branding admin routes (F030)
        .nest("/admin/branding", branding_routes)
        // Public branding routes (F030)
        .nest("/public", public_branding_routes)
        // Passwordless authentication routes (F079 - public, no JWT)
        .nest("/auth/passwordless", passwordless_routes)
        // Passwordless admin routes (F079 - requires JWT + admin role)
        .nest("/auth/passwordless", passwordless_admin_routes)
        // Token revocation routes (F069-S4)
        .nest("/auth/tokens", revocation_routes)
        // Key management admin routes (F082-US5)
        // F113: Support both API key and JWT authentication for programmatic access
        .nest(
            "/admin/keys",
            key_management_router()
                .layer(axum::middleware::from_fn(jwt_auth_middleware))
                .layer(axum::middleware::from_fn(api_key_auth_middleware))
                .layer(axum::Extension(JwtPublicKey(config.jwt_public_key.clone())))
                .layer(axum::Extension(pool.clone()))
                .layer(axum::Extension(key_service.clone()))
                .layer(TenantLayer::with_config(
                    xavyo_tenant::TenantConfig::builder()
                        .require_tenant(true)
                        .build(),
                )),
        )
        // Governance routes (F033 - IGA Entitlement Management)
        .nest("/governance", governance_routes)
        // Connector routes (F045 - Connector Framework)
        .nest("/connectors", connector_routes)
        // Global reconciliation routes (F049 - at root level)
        .merge(reconciliation_global)
        // SCIM Outbound Provisioning Target routes (F087)
        .nest("/admin/scim-targets", scim_target_routes)
        // Authorization engine routes (F083 - Fine-Grained Authorization)
        .merge(authorization_routes)
        // Webhooks routes (F085 - Webhooks & Event Subscriptions)
        .merge(webhooks_routes)
        // Bulk user import routes (F086 - Import & Invitation)
        .merge(import_routes)
        // NOTE: AI Agent Security routes (/agents/*, /tools/*, /approvals/*) have been
        // consolidated under /nhi/* by F109 - NHI API Consolidation
        // MCP routes (F091 - Model Context Protocol)
        .nest("/mcp", mcp_routes)
        // A2A routes (F091 - Agent-to-Agent Protocol)
        .nest("/a2a", a2a_routes)
        // A2A AgentCard discovery routes (public, no auth required)
        .merge(agents_discovery_routes)
        // Unified NHI routes (F108 - Unified Non-Human Identity Architecture)
        .nest("/nhi", nhi_routes)
        // Tenant provisioning routes (F097 - Self-service tenant creation)
        .nest("/tenants", tenant_routes)
        // System administration routes (F-SUSPEND, F-DELETE, F-USAGE-TRACK, F-PLAN-MGMT, F-SETTINGS-API)
        .nest("/system", system_admin_routes)
        // API key management routes (F-KEY-ROTATE)
        .merge(api_keys_routes)
        // OAuth client management routes (F-SECRET-ROTATE)
        .merge(oauth_clients_routes)
        // Apply middleware to all routes
        .layer(axum::middleware::from_fn(
            middleware::security_headers_middleware,
        ))
        // F082-US9: Content-Type validation for POST/PUT/PATCH requests
        .layer(axum::middleware::from_fn(
            middleware::content_type_validation_middleware,
        ))
        // F082-US9: Error sanitization in production mode
        .layer(axum::middleware::from_fn(
            middleware::error_sanitization_middleware,
        ))
        // F082-US9: Request timeout (default 30s)
        .layer(axum::middleware::from_fn(
            middleware::request_timeout_middleware,
        ))
        .layer(axum::Extension(middleware::RequestTimeoutSecs(
            input_validation_config.request_timeout_secs,
        )))
        // F082-US9: Body size limit (default 1MB)
        .layer(tower_http::limit::RequestBodyLimitLayer::new(
            input_validation_config.max_body_size,
        ))
        .layer(request_id_layer())
        // Distributed tracing middleware (F072 — US1): creates a span per request
        // with HTTP attributes and W3C Trace Context propagation.
        .layer(axum::middleware::from_fn(middleware::otel_trace_middleware))
        // HTTP metrics middleware (F072 — US2): records request count and duration.
        .layer(axum::middleware::from_fn_with_state(
            metrics_registry,
            metrics::metrics_middleware,
        ))
        .layer(cors)
        // F-SUSPEND: Check tenant suspension/deletion status for JWT-authenticated requests
        // This middleware blocks requests from suspended or deleted tenants with RFC 7807 errors.
        // Must be applied after JWT auth middleware adds claims to Extensions.
        .layer(axum::middleware::from_fn_with_state(
            pool.clone(),
            suspension_check_middleware,
        ))
        // JWT public keys for kid-based key rotation (F069-S5)
        .layer(axum::Extension(jwt_public_keys))
        // F082-US4: Revocation cache for fast JTI lookups
        .layer(axum::Extension(revocation_cache))
        // F085: Webhook event publisher for identity lifecycle events
        .layer(axum::Extension(event_publisher));

    // Start Kafka consumers if configured (F055 - Micro-certification)
    #[cfg(feature = "kafka")]
    if let Some(kafka_config) = config.kafka.clone() {
        consumers::start_micro_cert_consumers(pool.clone(), kafka_config.clone()).await;

        // F087: SCIM outbound provisioning consumers
        xavyo_scim_client::consumer::start_scim_provisioning_consumers(
            pool.clone(),
            kafka_config,
            "scim-provisioning",
            connector_encryption.clone(),
        )
        .await;
    }

    // Start webhook delivery worker (F085)
    {
        let worker_token = tokio_util::sync::CancellationToken::new();
        let worker = WebhookWorker::new(webhook_delivery_service, event_rx, worker_token);
        tokio::spawn(async move {
            worker.run().await;
        });
        info!("Webhook delivery worker started");
    }

    // TODO(F078): Start SIEM event consumer for real-time audit log export.
    // When Kafka is enabled, this spawns a SiemEventConsumer that fans out
    // identity events to all configured SIEM destinations per tenant.
    // Requires: XAVYO_SIEM_ENCRYPTION_KEY env var for auth_config decryption.
    // #[cfg(feature = "kafka")]
    // if let Some(_kafka_config) = config.kafka.as_ref() {
    //     use xavyo_siem::pipeline::consumer::SiemEventConsumer;
    //     // Load active destinations from DB and build consumer
    //     tracing::info!("SIEM event consumer initialization pending");
    // }

    // Spawn background cleanup task for expired revoked tokens (F069-S4)
    {
        let cleanup_pool = pool.clone();
        tokio::spawn(async move {
            let interval = Duration::from_secs(15 * 60); // 15 minutes
            loop {
                tokio::time::sleep(interval).await;
                match xavyo_db::models::RevokedToken::delete_expired(&cleanup_pool).await {
                    Ok(count) if count > 0 => {
                        tracing::info!(
                            target: "security",
                            deleted = count,
                            "Cleaned up expired revoked token records"
                        );
                    }
                    Ok(_) => {} // Nothing to clean
                    Err(e) => {
                        tracing::warn!(
                            target: "security",
                            error = %e,
                            "Failed to clean up expired revoked tokens"
                        );
                    }
                }
            }
        });
    }

    // Spawn background cleanup task for expired passwordless tokens (F079)
    {
        let cleanup_pool = pool.clone();
        tokio::spawn(async move {
            let interval = Duration::from_secs(30 * 60); // 30 minutes
            loop {
                tokio::time::sleep(interval).await;
                match xavyo_db::models::PasswordlessToken::delete_expired(&cleanup_pool).await {
                    Ok(count) if count > 0 => {
                        tracing::info!(
                            target: "passwordless",
                            deleted = count,
                            "Cleaned up expired passwordless token records"
                        );
                    }
                    Ok(_) => {} // Nothing to clean
                    Err(e) => {
                        tracing::warn!(
                            target: "passwordless",
                            error = %e,
                            "Failed to clean up expired passwordless tokens"
                        );
                    }
                }
            }
        });
    }

    // Spawn background cleanup task for expired approval requests (F092)
    {
        let cleanup_pool = pool.clone();
        tokio::spawn(async move {
            let interval = Duration::from_secs(30); // Check every 30 seconds
            loop {
                tokio::time::sleep(interval).await;
                match xavyo_db::models::AiAgentApprovalRequest::expire_pending(&cleanup_pool).await
                {
                    Ok(count) if count > 0 => {
                        tracing::info!(
                            target: "agents",
                            expired = count,
                            "Expired pending approval requests"
                        );
                    }
                    Ok(_) => {} // Nothing to expire
                    Err(e) => {
                        tracing::warn!(
                            target: "agents",
                            error = %e,
                            "Failed to expire pending approval requests"
                        );
                    }
                }
            }
        });
    }

    // Spawn background cleanup task for expired device codes (F096)
    {
        let cleanup_pool = pool.clone();
        tokio::spawn(async move {
            let interval = Duration::from_secs(5 * 60); // Check every 5 minutes
            loop {
                tokio::time::sleep(interval).await;
                match xavyo_db::models::DeviceCode::cleanup_expired(&cleanup_pool).await {
                    Ok(count) if count > 0 => {
                        tracing::info!(
                            target: "oauth",
                            deleted = count,
                            "Cleaned up expired device codes"
                        );
                    }
                    Ok(_) => {} // Nothing to clean
                    Err(e) => {
                        tracing::warn!(
                            target: "oauth",
                            error = %e,
                            "Failed to clean up expired device codes"
                        );
                    }
                }
            }
        });
    }

    // Bind and serve
    let addr: SocketAddr = match config.bind_addr().parse() {
        Ok(a) => a,
        Err(e) => {
            tracing::error!("Invalid bind address '{}': {e}", config.bind_addr());
            std::process::exit(1);
        }
    };

    info!(%addr, "Server listening");

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("Failed to bind to address {addr}: {e}");
            std::process::exit(1);
        }
    };

    if let Err(e) = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal(shutting_down))
    .await
    {
        tracing::error!("Server error: {e}");
        std::process::exit(1);
    }

    // Flush pending telemetry data (FR-014)
    info!("Flushing telemetry...");
    telemetry_guard.shutdown();
    info!("Server shutdown complete");
}

/// Build CORS layer from configured origins.
///
/// When explicit origins are configured (non-wildcard), enables
/// `allow_credentials(true)` for cookie/auth header support.
///
/// F082-US3/T010: When a non-wildcard origin list is used, rejected origins
/// are logged as structured security audit events.
fn build_cors_layer(origins: &[String]) -> CorsLayer {
    use tower_http::cors::AllowOrigin;

    let is_wildcard = origins.len() == 1 && origins[0] == "*";

    let allow_origin = if is_wildcard {
        AllowOrigin::any()
    } else {
        // F082-US3/T010: Use a predicate that logs CORS rejections
        let allowed: Vec<axum::http::HeaderValue> =
            origins.iter().filter_map(|o| o.parse().ok()).collect();
        AllowOrigin::predicate(
            move |origin: &axum::http::HeaderValue, _req: &axum::http::request::Parts| {
                // SECURITY NOTE: Constant-time comparison is NOT required for CORS origin checks.
                // The CORS response (Access-Control-Allow-Origin header) directly reveals whether
                // the origin is allowed, so timing attacks cannot extract any additional information.
                let is_allowed = allowed.contains(origin);
                if !is_allowed {
                    let origin_str = origin.to_str().unwrap_or("<non-utf8>");
                    tracing::warn!(
                        target: "security",
                        event_type = "cors_rejected",
                        origin = %origin_str,
                        outcome = "rejected",
                        "CORS origin rejected"
                    );
                }
                is_allowed
            },
        )
    };

    let mut layer = CorsLayer::new()
        .allow_origin(allow_origin)
        .max_age(Duration::from_secs(3600));

    // Only enable credentials for non-wildcard origins (browser requirement)
    // When credentials are enabled, we cannot use `Any` for headers or methods per CORS spec.
    // Instead, explicitly list commonly needed headers and methods.
    if is_wildcard {
        layer = layer.allow_methods(Any).allow_headers(Any);
    } else {
        use axum::http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, COOKIE, ORIGIN};
        use axum::http::Method;
        layer = layer
            .allow_methods([
                Method::GET,
                Method::POST,
                Method::PUT,
                Method::PATCH,
                Method::DELETE,
                Method::OPTIONS,
            ])
            .allow_headers([
                AUTHORIZATION,
                CONTENT_TYPE,
                ACCEPT,
                ORIGIN,
                COOKIE,
                axum::http::HeaderName::from_static("x-requested-with"),
                axum::http::HeaderName::from_static("x-tenant-id"),
                axum::http::HeaderName::from_static("x-request-id"),
            ])
            .allow_credentials(true);
    }

    layer
}

/// Adapter to connect xavyo-api-social to xavyo-auth.
struct SocialAuthAdapter {
    pool: sqlx::PgPool,
    jwt_private_key: String,
}

impl SocialAuthAdapter {
    fn new(pool: sqlx::PgPool, jwt_private_key: String) -> Self {
        Self {
            pool,
            jwt_private_key,
        }
    }
}

#[async_trait::async_trait]
impl xavyo_api_social::AuthService for SocialAuthAdapter {
    async fn issue_tokens(
        &self,
        user_id: uuid::Uuid,
        tenant_id: uuid::Uuid,
    ) -> Result<xavyo_api_social::handlers::JwtTokens, xavyo_api_social::SocialError> {
        // Use xavyo-auth to issue tokens
        let token_config = TokenConfig {
            private_key: self.jwt_private_key.as_bytes().to_vec(),
            issuer: "xavyo".to_string(),
            audience: "xavyo".to_string(),
        };
        let token_service = TokenService::new(token_config, self.pool.clone());

        // Convert to typed IDs
        let typed_user_id = xavyo_core::UserId::from_uuid(user_id);
        let typed_tenant_id = xavyo_core::TenantId::from_uuid(tenant_id);

        // Fetch user email for JWT claims
        let email = xavyo_db::User::get_email_by_id(&self.pool, user_id)
            .await
            .ok()
            .flatten();

        // Issue tokens with 15 minute access token, 7 day refresh token
        match token_service
            .create_tokens(
                typed_user_id,
                typed_tenant_id,
                vec!["user".to_string()],
                email,
                None,
                None,
            )
            .await
        {
            Ok((access_token, refresh_token, expires_in)) => {
                Ok(xavyo_api_social::handlers::JwtTokens {
                    access_token,
                    refresh_token,
                    expires_in,
                })
            }
            Err(e) => Err(xavyo_api_social::SocialError::InternalError {
                message: format!("Failed to issue tokens: {}", e),
            }),
        }
    }

    async fn create_social_user(
        &self,
        tenant_id: uuid::Uuid,
        email: Option<&str>,
        display_name: &str,
        email_verified: bool,
    ) -> Result<uuid::Uuid, xavyo_api_social::SocialError> {
        let user_id = uuid::Uuid::new_v4();

        // F116: Create user with provider's email_verified status (not always true)
        sqlx::query(
            r#"
            INSERT INTO users (id, tenant_id, email, display_name, email_verified, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
            "#,
        )
        .bind(user_id)
        .bind(tenant_id)
        .bind(email)
        .bind(display_name)
        .bind(email_verified)
        .execute(&self.pool)
        .await
        .map_err(xavyo_api_social::SocialError::from)?;

        Ok(user_id)
    }
}

/// Graceful shutdown signal handler.
///
/// Sets the `shutting_down` flag before returning so the readiness probe
/// returns 503 to drain traffic before Axum stops accepting connections (F074).
async fn shutdown_signal(shutting_down: std::sync::Arc<std::sync::atomic::AtomicBool>) {
    let ctrl_c = async {
        match signal::ctrl_c().await {
            Ok(()) => {}
            Err(e) => {
                tracing::error!("Failed to install Ctrl+C handler: {e}");
                // Fall through - we still want to wait for terminate signal
            }
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(e) => {
                tracing::error!("Failed to install SIGTERM handler: {e}");
                // Wait forever if we can't install the handler
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            info!("Received Ctrl+C, initiating graceful shutdown");
        }
        _ = terminate => {
            info!("Received SIGTERM, initiating graceful shutdown");
        }
    }

    // Set shutting_down flag BEFORE Axum starts draining connections (F074 — FR-012).
    // The readiness probe will now return 503, telling Kubernetes to stop routing traffic.
    shutting_down.store(true, std::sync::atomic::Ordering::Release);
    info!("Readiness probe set to unhealthy — draining traffic");
}
