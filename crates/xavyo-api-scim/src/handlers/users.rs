//! SCIM User resource handlers.

use axum::{
    extract::{Path, Query},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde::Deserialize;
use std::net::IpAddr;
use std::sync::Arc;
use uuid::Uuid;

use xavyo_db::models::{ScimOperation, ScimResourceType};

use crate::error::ScimError;
use crate::middleware::auth::ScimAuthContext;
use crate::models::{
    CreateScimUserRequest, ReplaceScimUserRequest, ScimPagination, ScimPatchRequest,
};
use crate::services::{AuditService, UserService};
use xavyo_webhooks::{EventPublisher, WebhookEvent};

/// Query parameters for list users.
#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct ListUsersQuery {
    filter: Option<String>,
    #[serde(default = "default_start_index")]
    start_index: i64,
    #[serde(default = "default_count")]
    count: i64,
    sort_by: Option<String>,
    sort_order: Option<String>,
}

fn default_start_index() -> i64 {
    1
}

fn default_count() -> i64 {
    25
}

/// SCIM content type header.
const SCIM_CONTENT_TYPE: &str = "application/scim+json";

/// Wrap response with SCIM content type.
fn scim_response<T: serde::Serialize>(status: StatusCode, body: T) -> Response {
    let json = Json(body);
    let mut response = (status, json).into_response();
    // SECURITY: Use from_static for compile-time validated header value (no unwrap needed)
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(SCIM_CONTENT_TYPE),
    );
    response
}

/// Extract client IP from request (for audit logging).
fn extract_client_ip(headers: &axum::http::HeaderMap) -> IpAddr {
    // Check X-Forwarded-For header
    if let Some(xff) = headers.get("x-forwarded-for") {
        if let Ok(xff_str) = xff.to_str() {
            if let Some(first_ip) = xff_str.split(',').next() {
                if let Ok(ip) = first_ip.trim().parse() {
                    return ip;
                }
            }
        }
    }

    // Default to localhost
    "127.0.0.1".parse().unwrap()
}

/// Extract user agent from request.
fn extract_user_agent(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

/// List users with optional filtering.
#[utoipa::path(
    get,
    path = "/scim/v2/Users",
    params(ListUsersQuery),
    responses(
        (status = 200, description = "List of SCIM users"),
        (status = 401, description = "Not authenticated"),
    ),
    security(("bearerAuth" = [])),
    tag = "SCIM"
)]
pub async fn list_users(
    Extension(auth): Extension<ScimAuthContext>,
    Extension(user_service): Extension<Arc<UserService>>,
    Extension(audit_service): Extension<Arc<AuditService>>,
    headers: axum::http::HeaderMap,
    Query(query): Query<ListUsersQuery>,
) -> Result<Response, ScimError> {
    let pagination = ScimPagination::from_query(
        Some(query.start_index),
        Some(query.count),
        query.sort_by,
        query.sort_order,
    );

    let result = user_service
        .list_users(auth.tenant_id, query.filter.as_deref(), pagination)
        .await;

    // Log the operation
    let source_ip = extract_client_ip(&headers);
    let user_agent = extract_user_agent(&headers);

    match &result {
        Ok(_) => {
            audit_service
                .log_user_success(
                    auth.tenant_id,
                    auth.token.id,
                    ScimOperation::List,
                    None,
                    source_ip,
                    user_agent,
                )
                .await;
        }
        Err(e) => {
            audit_service
                .log_error(
                    auth.tenant_id,
                    Some(auth.token.id),
                    ScimOperation::List,
                    ScimResourceType::User,
                    None,
                    source_ip,
                    user_agent,
                    e.status_code().as_u16() as i32,
                    e.to_string(),
                )
                .await;
        }
    }

    let response = result?;
    Ok(scim_response(StatusCode::OK, response))
}

/// Create a new user.
#[utoipa::path(
    post,
    path = "/scim/v2/Users",
    request_body = CreateScimUserRequest,
    responses(
        (status = 201, description = "User created", body = ScimUser),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Not authenticated"),
        (status = 409, description = "User already exists"),
    ),
    security(("bearerAuth" = [])),
    tag = "SCIM"
)]
pub async fn create_user(
    Extension(auth): Extension<ScimAuthContext>,
    Extension(user_service): Extension<Arc<UserService>>,
    Extension(audit_service): Extension<Arc<AuditService>>,
    publisher: Option<Extension<EventPublisher>>,
    headers: axum::http::HeaderMap,
    Json(request): Json<CreateScimUserRequest>,
) -> Result<Response, ScimError> {
    let source_ip = extract_client_ip(&headers);
    let user_agent = extract_user_agent(&headers);

    let result = user_service.create_user(auth.tenant_id, request).await;

    match &result {
        Ok(user) => {
            audit_service
                .log_user_success(
                    auth.tenant_id,
                    auth.token.id,
                    ScimOperation::Create,
                    user.id,
                    source_ip,
                    user_agent,
                )
                .await;
        }
        Err(e) => {
            audit_service
                .log_error(
                    auth.tenant_id,
                    Some(auth.token.id),
                    ScimOperation::Create,
                    ScimResourceType::User,
                    None,
                    source_ip,
                    user_agent,
                    e.status_code().as_u16() as i32,
                    e.to_string(),
                )
                .await;
        }
    }

    let user = result?;

    // F085: Publish user.created webhook event
    if let Some(Extension(publisher)) = publisher {
        publisher.publish(WebhookEvent {
            event_id: Uuid::new_v4(),
            event_type: "user.created".to_string(),
            tenant_id: auth.tenant_id,
            actor_id: None,
            timestamp: chrono::Utc::now(),
            data: serde_json::json!({
                "user_id": user.id,
                "display_name": user.display_name,
            }),
        });
    }

    Ok(scim_response(StatusCode::CREATED, user))
}

/// Get a user by ID.
#[utoipa::path(
    get,
    path = "/scim/v2/Users/{id}",
    params(
        ("id" = Uuid, Path, description = "User ID"),
    ),
    responses(
        (status = 200, description = "User found", body = ScimUser),
        (status = 401, description = "Not authenticated"),
        (status = 404, description = "User not found"),
    ),
    security(("bearerAuth" = [])),
    tag = "SCIM"
)]
pub async fn get_user(
    Extension(auth): Extension<ScimAuthContext>,
    Extension(user_service): Extension<Arc<UserService>>,
    Extension(audit_service): Extension<Arc<AuditService>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Response, ScimError> {
    let source_ip = extract_client_ip(&headers);
    let user_agent = extract_user_agent(&headers);

    let result = user_service.get_user(auth.tenant_id, id).await;

    match &result {
        Ok(_) => {
            audit_service
                .log_user_success(
                    auth.tenant_id,
                    auth.token.id,
                    ScimOperation::Read,
                    Some(id),
                    source_ip,
                    user_agent,
                )
                .await;
        }
        Err(e) => {
            audit_service
                .log_error(
                    auth.tenant_id,
                    Some(auth.token.id),
                    ScimOperation::Read,
                    ScimResourceType::User,
                    Some(id),
                    source_ip,
                    user_agent,
                    e.status_code().as_u16() as i32,
                    e.to_string(),
                )
                .await;
        }
    }

    let user = result?;
    Ok(scim_response(StatusCode::OK, user))
}

/// Replace a user (full update).
#[utoipa::path(
    put,
    path = "/scim/v2/Users/{id}",
    params(
        ("id" = Uuid, Path, description = "User ID"),
    ),
    request_body = CreateScimUserRequest,  // ReplaceScimUserRequest is an alias for CreateScimUserRequest
    responses(
        (status = 200, description = "User replaced", body = ScimUser),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Not authenticated"),
        (status = 404, description = "User not found"),
    ),
    security(("bearerAuth" = [])),
    tag = "SCIM"
)]
pub async fn replace_user(
    Extension(auth): Extension<ScimAuthContext>,
    Extension(user_service): Extension<Arc<UserService>>,
    Extension(audit_service): Extension<Arc<AuditService>>,
    publisher: Option<Extension<EventPublisher>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
    Json(request): Json<ReplaceScimUserRequest>,
) -> Result<Response, ScimError> {
    let source_ip = extract_client_ip(&headers);
    let user_agent = extract_user_agent(&headers);

    let result = user_service.replace_user(auth.tenant_id, id, request).await;

    match &result {
        Ok(_) => {
            audit_service
                .log_user_success(
                    auth.tenant_id,
                    auth.token.id,
                    ScimOperation::Update,
                    Some(id),
                    source_ip,
                    user_agent,
                )
                .await;
        }
        Err(e) => {
            audit_service
                .log_error(
                    auth.tenant_id,
                    Some(auth.token.id),
                    ScimOperation::Update,
                    ScimResourceType::User,
                    Some(id),
                    source_ip,
                    user_agent,
                    e.status_code().as_u16() as i32,
                    e.to_string(),
                )
                .await;
        }
    }

    let user = result?;

    // F085: Publish user.updated webhook event
    if let Some(Extension(publisher)) = publisher {
        publisher.publish(WebhookEvent {
            event_id: Uuid::new_v4(),
            event_type: "user.updated".to_string(),
            tenant_id: auth.tenant_id,
            actor_id: None,
            timestamp: chrono::Utc::now(),
            data: serde_json::json!({
                "user_id": user.id,
                "display_name": user.display_name,
            }),
        });
    }

    Ok(scim_response(StatusCode::OK, user))
}

/// Patch a user (partial update).
#[utoipa::path(
    patch,
    path = "/scim/v2/Users/{id}",
    params(
        ("id" = Uuid, Path, description = "User ID"),
    ),
    request_body = ScimPatchRequest,
    responses(
        (status = 200, description = "User updated", body = ScimUser),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Not authenticated"),
        (status = 404, description = "User not found"),
    ),
    security(("bearerAuth" = [])),
    tag = "SCIM"
)]
pub async fn update_user(
    Extension(auth): Extension<ScimAuthContext>,
    Extension(user_service): Extension<Arc<UserService>>,
    Extension(audit_service): Extension<Arc<AuditService>>,
    publisher: Option<Extension<EventPublisher>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
    Json(request): Json<ScimPatchRequest>,
) -> Result<Response, ScimError> {
    let source_ip = extract_client_ip(&headers);
    let user_agent = extract_user_agent(&headers);

    let result = user_service.patch_user(auth.tenant_id, id, request).await;

    match &result {
        Ok(_) => {
            audit_service
                .log_user_success(
                    auth.tenant_id,
                    auth.token.id,
                    ScimOperation::Update,
                    Some(id),
                    source_ip,
                    user_agent,
                )
                .await;
        }
        Err(e) => {
            audit_service
                .log_error(
                    auth.tenant_id,
                    Some(auth.token.id),
                    ScimOperation::Update,
                    ScimResourceType::User,
                    Some(id),
                    source_ip,
                    user_agent,
                    e.status_code().as_u16() as i32,
                    e.to_string(),
                )
                .await;
        }
    }

    let user = result?;

    // F085: Publish user.updated webhook event
    if let Some(Extension(publisher)) = publisher {
        publisher.publish(WebhookEvent {
            event_id: Uuid::new_v4(),
            event_type: "user.updated".to_string(),
            tenant_id: auth.tenant_id,
            actor_id: None,
            timestamp: chrono::Utc::now(),
            data: serde_json::json!({
                "user_id": user.id,
                "display_name": user.display_name,
            }),
        });
    }

    Ok(scim_response(StatusCode::OK, user))
}

/// Delete (deactivate) a user.
#[utoipa::path(
    delete,
    path = "/scim/v2/Users/{id}",
    params(
        ("id" = Uuid, Path, description = "User ID"),
    ),
    responses(
        (status = 204, description = "User deleted"),
        (status = 401, description = "Not authenticated"),
        (status = 404, description = "User not found"),
    ),
    security(("bearerAuth" = [])),
    tag = "SCIM"
)]
pub async fn delete_user(
    Extension(auth): Extension<ScimAuthContext>,
    Extension(user_service): Extension<Arc<UserService>>,
    Extension(audit_service): Extension<Arc<AuditService>>,
    publisher: Option<Extension<EventPublisher>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Response, ScimError> {
    let source_ip = extract_client_ip(&headers);
    let user_agent = extract_user_agent(&headers);

    let result = user_service.delete_user(auth.tenant_id, id).await;

    match &result {
        Ok(_) => {
            audit_service
                .log_user_success(
                    auth.tenant_id,
                    auth.token.id,
                    ScimOperation::Delete,
                    Some(id),
                    source_ip,
                    user_agent,
                )
                .await;
        }
        Err(e) => {
            audit_service
                .log_error(
                    auth.tenant_id,
                    Some(auth.token.id),
                    ScimOperation::Delete,
                    ScimResourceType::User,
                    Some(id),
                    source_ip,
                    user_agent,
                    e.status_code().as_u16() as i32,
                    e.to_string(),
                )
                .await;
        }
    }

    result?;

    // F085: Publish user.deleted webhook event
    if let Some(Extension(publisher)) = publisher {
        publisher.publish(WebhookEvent {
            event_id: Uuid::new_v4(),
            event_type: "user.deleted".to_string(),
            tenant_id: auth.tenant_id,
            actor_id: None,
            timestamp: chrono::Utc::now(),
            data: serde_json::json!({
                "user_id": id,
            }),
        });
    }

    // Return 204 No Content
    Ok(StatusCode::NO_CONTENT.into_response())
}
