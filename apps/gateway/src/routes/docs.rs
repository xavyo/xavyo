//! OpenAPI documentation aggregation and Swagger UI.

use axum::{
    extract::State,
    response::{Html, IntoResponse},
    routing::get,
    Json, Router,
};
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::config::GatewayConfig;
use crate::proxy::ProxyClient;

/// State for documentation routes.
#[derive(Clone)]
pub struct DocsState {
    pub config: Arc<GatewayConfig>,
    pub client: ProxyClient,
    pub merged_spec: Arc<RwLock<Option<Value>>>,
}

impl DocsState {
    /// Create new docs state.
    pub fn new(config: Arc<GatewayConfig>, client: ProxyClient) -> Self {
        Self {
            config,
            client,
            merged_spec: Arc::new(RwLock::new(None)),
        }
    }

    /// Fetch and merge OpenAPI specs from all backends.
    pub async fn refresh_specs(&self) {
        info!("Refreshing OpenAPI specs from backends");

        let mut merged = serde_json::json!({
            "openapi": "3.1.0",
            "info": {
                "title": "xavyo API Gateway",
                "description": "Unified API Gateway for xavyo",
                "version": "1.0.0"
            },
            "servers": [
                {"url": "/", "description": "Gateway"}
            ],
            "paths": {},
            "components": {
                "schemas": {},
                "securitySchemes": {
                    "bearerAuth": {
                        "type": "http",
                        "scheme": "bearer",
                        "bearerFormat": "JWT"
                    }
                }
            }
        });

        for backend in &self.config.backends {
            match self.client.fetch_openapi(backend).await {
                Ok(spec_text) => {
                    match serde_json::from_str::<Value>(&spec_text) {
                        Ok(spec) => {
                            // Merge paths with prefix
                            if let Some(paths) = spec.get("paths").and_then(|p| p.as_object()) {
                                // SAFETY: merged is initialized above with "paths" as an object
                                if let Some(merged_paths) =
                                    merged.get_mut("paths").and_then(|p| p.as_object_mut())
                                {
                                    for (path, operations) in paths {
                                        let prefixed_path =
                                            format!("{}{}", backend.path_prefix, path);
                                        merged_paths.insert(prefixed_path, operations.clone());
                                    }
                                }
                            }

                            // Merge schemas
                            if let Some(components) = spec.get("components") {
                                if let Some(schemas) =
                                    components.get("schemas").and_then(|s| s.as_object())
                                {
                                    // SAFETY: merged is initialized above with "components.schemas" as an object
                                    if let Some(merged_schemas) = merged
                                        .get_mut("components")
                                        .and_then(|c| c.as_object_mut())
                                        .and_then(|c| c.get_mut("schemas"))
                                        .and_then(|s| s.as_object_mut())
                                    {
                                        for (name, schema) in schemas {
                                            // Prefix schema names to avoid conflicts
                                            let prefixed_name = format!(
                                                "{}_{}",
                                                backend.name.replace('-', "_"),
                                                name
                                            );
                                            merged_schemas.insert(prefixed_name, schema.clone());
                                        }
                                    }
                                }
                            }

                            info!(backend = %backend.name, "Merged OpenAPI spec");
                        }
                        Err(e) => {
                            warn!(backend = %backend.name, error = %e, "Failed to parse OpenAPI spec");
                        }
                    }
                }
                Err(e) => {
                    warn!(backend = %backend.name, error = %e, "Failed to fetch OpenAPI spec");
                }
            }
        }

        // Store merged spec
        let mut spec_lock = self.merged_spec.write().await;
        *spec_lock = Some(merged);
    }
}

/// Create documentation routes.
pub fn docs_routes(state: Arc<DocsState>) -> Router {
    Router::new()
        .route("/docs", get(swagger_ui))
        .route("/docs/", get(swagger_ui))
        .route("/docs/openapi.json", get(openapi_spec))
        .with_state(state)
}

/// Serve Swagger UI.
async fn swagger_ui() -> impl IntoResponse {
    let html = r#"<!DOCTYPE html>
<html>
<head>
    <title>xavyo API Gateway - Documentation</title>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <script>
        window.onload = function() {
            SwaggerUIBundle({
                url: "/docs/openapi.json",
                dom_id: '#swagger-ui',
                deepLinking: true,
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIBundle.SwaggerUIStandalonePreset
                ],
                layout: "StandaloneLayout"
            });
        };
    </script>
</body>
</html>"#;

    Html(html)
}

/// Serve merged OpenAPI spec.
async fn openapi_spec(State(state): State<Arc<DocsState>>) -> impl IntoResponse {
    let spec = state.merged_spec.read().await;

    match spec.as_ref() {
        Some(spec) => Json(spec.clone()).into_response(),
        None => {
            // Return a minimal spec if not yet loaded
            let empty_spec = serde_json::json!({
                "openapi": "3.1.0",
                "info": {
                    "title": "xavyo API Gateway",
                    "description": "Loading specifications...",
                    "version": "1.0.0"
                },
                "paths": {}
            });
            Json(empty_spec).into_response()
        }
    }
}

/// Initialize docs state and start background refresh.
pub async fn init_docs(state: Arc<DocsState>) {
    // Initial refresh
    state.refresh_specs().await;

    // Start background refresh task (every 5 minutes)
    let state_clone = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
        loop {
            interval.tick().await;
            state_clone.refresh_specs().await;
        }
    });
}
