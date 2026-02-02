//! HTTP handlers for connector management.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use chrono::Utc;
use uuid::Uuid;

use xavyo_auth::JwtClaims;
use xavyo_db::models::{
    ConnectorFilter, CreateConnectorConfiguration, UpdateConnectorConfiguration,
};

use crate::error::{ConnectorApiError, Result};
use crate::models::{
    ConnectionTestResponse, ConnectorHealthResponse, ConnectorListResponse, ConnectorResponse,
    CreateConnectorRequest, ListConnectorsQuery, UpdateConnectorRequest,
};
use crate::router::ConnectorState;
use xavyo_webhooks::{EventPublisher, WebhookEvent};

/// List connectors with optional filtering and pagination.
#[utoipa::path(
    get,
    path = "/connectors",
    tag = "Connectors",
    params(ListConnectorsQuery),
    responses(
        (status = 200, description = "List of connectors", body = ConnectorListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_connectors(
    State(state): State<ConnectorState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListConnectorsQuery>,
) -> Result<Json<ConnectorListResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;

    let filter = ConnectorFilter {
        connector_type: query.connector_type,
        status: query.status,
        name_contains: query.name_contains,
    };

    let (connectors, total) = state
        .connector_service
        .list_connectors(tenant_id, filter, query.limit, query.offset)
        .await?;

    Ok(Json(ConnectorListResponse {
        items: connectors.into_iter().map(Into::into).collect(),
        total,
        limit: query.limit,
        offset: query.offset,
    }))
}

/// Get a connector by ID.
#[utoipa::path(
    get,
    path = "/connectors/{id}",
    tag = "Connectors",
    params(
        ("id" = Uuid, Path, description = "Connector ID")
    ),
    responses(
        (status = 200, description = "Connector details", body = ConnectorResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Connector not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_connector(
    State(state): State<ConnectorState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> Result<Json<ConnectorResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;

    let connector = state.connector_service.get_connector(tenant_id, id).await?;

    Ok(Json(connector.into()))
}

/// Create a new connector.
#[utoipa::path(
    post,
    path = "/connectors",
    tag = "Connectors",
    request_body = CreateConnectorRequest,
    responses(
        (status = 201, description = "Connector created", body = ConnectorResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 409, description = "Connector name already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_connector(
    State(state): State<ConnectorState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateConnectorRequest>,
) -> Result<(StatusCode, Json<ConnectorResponse>)> {
    let tenant_id = extract_tenant_id(&claims)?;

    let input = CreateConnectorConfiguration {
        name: request.name,
        connector_type: request.connector_type,
        description: request.description,
        config: request.config,
        credentials: request.credentials,
    };

    let connector = state
        .connector_service
        .create_connector(tenant_id, input)
        .await?;

    Ok((StatusCode::CREATED, Json(connector.into())))
}

/// Update a connector.
#[utoipa::path(
    put,
    path = "/connectors/{id}",
    tag = "Connectors",
    params(
        ("id" = Uuid, Path, description = "Connector ID")
    ),
    request_body = UpdateConnectorRequest,
    responses(
        (status = 200, description = "Connector updated", body = ConnectorResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Connector not found"),
        (status = 409, description = "Connector name already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_connector(
    State(state): State<ConnectorState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateConnectorRequest>,
) -> Result<Json<ConnectorResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;

    let input = UpdateConnectorConfiguration {
        name: request.name,
        description: request.description,
        config: request.config,
        credentials: request.credentials,
        status: None, // Status changes via activate/deactivate endpoints
    };

    let connector = state
        .connector_service
        .update_connector(tenant_id, id, input)
        .await?;

    Ok(Json(connector.into()))
}

/// Delete a connector.
#[utoipa::path(
    delete,
    path = "/connectors/{id}",
    tag = "Connectors",
    params(
        ("id" = Uuid, Path, description = "Connector ID")
    ),
    responses(
        (status = 204, description = "Connector deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Connector not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_connector(
    State(state): State<ConnectorState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode> {
    let tenant_id = extract_tenant_id(&claims)?;

    state
        .connector_service
        .delete_connector(tenant_id, id)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Test a connector's connection.
#[utoipa::path(
    post,
    path = "/connectors/{id}/test",
    tag = "Connectors",
    params(
        ("id" = Uuid, Path, description = "Connector ID")
    ),
    responses(
        (status = 200, description = "Connection test result", body = ConnectionTestResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Connector not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn test_connector(
    State(state): State<ConnectorState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> Result<Json<ConnectionTestResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;

    let result = state.connector_service.test_connector(tenant_id, id).await;

    let response = match result {
        Ok(()) => ConnectionTestResponse {
            success: true,
            error: None,
            tested_at: Utc::now(),
        },
        Err(ConnectorApiError::ConnectionTestFailed(msg)) => ConnectionTestResponse {
            success: false,
            error: Some(msg),
            tested_at: Utc::now(),
        },
        Err(e) => return Err(e),
    };

    Ok(Json(response))
}

/// Activate a connector.
#[utoipa::path(
    post,
    path = "/connectors/{id}/activate",
    tag = "Connectors",
    params(
        ("id" = Uuid, Path, description = "Connector ID")
    ),
    responses(
        (status = 200, description = "Connector activated", body = ConnectorResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Connector not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn activate_connector(
    State(state): State<ConnectorState>,
    Extension(claims): Extension<JwtClaims>,
    publisher: Option<Extension<EventPublisher>>,
    Path(id): Path<Uuid>,
) -> Result<Json<ConnectorResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;
    let actor_id = Uuid::parse_str(&claims.sub).ok();

    state
        .connector_service
        .activate_connector(tenant_id, id)
        .await?;

    let connector = state.connector_service.get_connector(tenant_id, id).await?;

    // F085: Publish connector.status.changed webhook event
    if let Some(Extension(publisher)) = publisher {
        publisher.publish(WebhookEvent {
            event_id: Uuid::new_v4(),
            event_type: "connector.status.changed".to_string(),
            tenant_id,
            actor_id,
            timestamp: Utc::now(),
            data: serde_json::json!({
                "connector_id": id,
                "new_status": "active",
            }),
        });
    }

    Ok(Json(connector.into()))
}

/// Deactivate a connector.
#[utoipa::path(
    post,
    path = "/connectors/{id}/deactivate",
    tag = "Connectors",
    params(
        ("id" = Uuid, Path, description = "Connector ID")
    ),
    responses(
        (status = 200, description = "Connector deactivated", body = ConnectorResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Connector not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn deactivate_connector(
    State(state): State<ConnectorState>,
    Extension(claims): Extension<JwtClaims>,
    publisher: Option<Extension<EventPublisher>>,
    Path(id): Path<Uuid>,
) -> Result<Json<ConnectorResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;
    let actor_id = Uuid::parse_str(&claims.sub).ok();

    state
        .connector_service
        .deactivate_connector(tenant_id, id)
        .await?;

    let connector = state.connector_service.get_connector(tenant_id, id).await?;

    // F085: Publish connector.status.changed webhook event
    if let Some(Extension(publisher)) = publisher {
        publisher.publish(WebhookEvent {
            event_id: Uuid::new_v4(),
            event_type: "connector.status.changed".to_string(),
            tenant_id,
            actor_id,
            timestamp: Utc::now(),
            data: serde_json::json!({
                "connector_id": id,
                "new_status": "inactive",
            }),
        });
    }

    Ok(Json(connector.into()))
}

/// Get connector health status.
#[utoipa::path(
    get,
    path = "/connectors/{id}/health",
    tag = "Connectors",
    params(
        ("id" = Uuid, Path, description = "Connector ID")
    ),
    responses(
        (status = 200, description = "Connector health status", body = ConnectorHealthResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Connector not found"),
        (status = 501, description = "Health service not configured"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_connector_health(
    State(state): State<ConnectorState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> Result<Json<ConnectorHealthResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;

    // Ensure health service is configured
    let health_service = state.health_service.as_ref().ok_or_else(|| {
        ConnectorApiError::Validation("Health service not configured".to_string())
    })?;

    // Verify connector exists
    let _connector = state.connector_service.get_connector(tenant_id, id).await?;

    // Get health info
    let health_info = health_service
        .get_health(tenant_id, id)
        .await
        .map_err(|e| ConnectorApiError::HealthError(e.to_string()))?;

    let response = match health_info {
        Some(info) => ConnectorHealthResponse {
            connector_id: info.connector_id,
            is_online: info.is_online,
            consecutive_failures: info.consecutive_failures,
            offline_since: info.offline_since,
            last_success_at: info.last_success_at,
            last_error: info.last_error,
            last_check_at: info.last_check_at,
        },
        None => {
            // No health record yet - connector is assumed online
            ConnectorHealthResponse {
                connector_id: id,
                is_online: true,
                consecutive_failures: 0,
                offline_since: None,
                last_success_at: None,
                last_error: None,
                last_check_at: Utc::now(),
            }
        }
    };

    Ok(Json(response))
}

/// Extract tenant ID from JWT claims.
fn extract_tenant_id(claims: &JwtClaims) -> Result<Uuid> {
    claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(ConnectorApiError::Validation(
            "Missing tenant_id in claims".to_string(),
        ))
}
