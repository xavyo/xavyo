//! SCIM Group resource handlers.

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
    CreateScimGroupRequest, ReplaceScimGroupRequest, ScimPagination, ScimPatchRequest,
};
use crate::services::{AuditService, GroupService};
use xavyo_webhooks::{EventPublisher, WebhookEvent};

/// Query parameters for list groups.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListGroupsQuery {
    filter: Option<String>,
    #[serde(default = "default_start_index")]
    start_index: i64,
    #[serde(default = "default_count")]
    count: i64,
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

/// Extract client IP from request.
fn extract_client_ip(headers: &axum::http::HeaderMap) -> IpAddr {
    if let Some(xff) = headers.get("x-forwarded-for") {
        if let Ok(xff_str) = xff.to_str() {
            if let Some(first_ip) = xff_str.split(',').next() {
                if let Ok(ip) = first_ip.trim().parse() {
                    return ip;
                }
            }
        }
    }
    "127.0.0.1".parse().unwrap()
}

/// Extract user agent from request.
fn extract_user_agent(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(std::string::ToString::to_string)
}

/// List groups with optional filtering.
///
/// GET /scim/v2/Groups
pub async fn list_groups(
    Extension(auth): Extension<ScimAuthContext>,
    Extension(group_service): Extension<Arc<GroupService>>,
    Extension(audit_service): Extension<Arc<AuditService>>,
    headers: axum::http::HeaderMap,
    Query(query): Query<ListGroupsQuery>,
) -> Result<Response, ScimError> {
    let pagination =
        ScimPagination::from_query(Some(query.start_index), Some(query.count), None, None);

    let result = group_service
        .list_groups(auth.tenant_id, query.filter.as_deref(), pagination)
        .await;

    let source_ip = extract_client_ip(&headers);
    let user_agent = extract_user_agent(&headers);

    match &result {
        Ok(_) => {
            let _ = audit_service
                .log(
                    auth.tenant_id,
                    Some(auth.token.id),
                    ScimOperation::List,
                    ScimResourceType::Group,
                    None,
                    source_ip,
                    user_agent,
                    None,
                    200,
                    None,
                )
                .await;
        }
        Err(e) => {
            audit_service
                .log_error(
                    auth.tenant_id,
                    Some(auth.token.id),
                    ScimOperation::List,
                    ScimResourceType::Group,
                    None,
                    source_ip,
                    user_agent,
                    i32::from(e.status_code().as_u16()),
                    e.to_string(),
                )
                .await;
        }
    }

    let response = result?;
    Ok(scim_response(StatusCode::OK, response))
}

/// Create a new group.
///
/// POST /scim/v2/Groups
pub async fn create_group(
    Extension(auth): Extension<ScimAuthContext>,
    Extension(group_service): Extension<Arc<GroupService>>,
    Extension(audit_service): Extension<Arc<AuditService>>,
    publisher: Option<Extension<EventPublisher>>,
    headers: axum::http::HeaderMap,
    Json(request): Json<CreateScimGroupRequest>,
) -> Result<Response, ScimError> {
    let source_ip = extract_client_ip(&headers);
    let user_agent = extract_user_agent(&headers);

    let result = group_service.create_group(auth.tenant_id, request).await;

    match &result {
        Ok(group) => {
            let _ = audit_service
                .log(
                    auth.tenant_id,
                    Some(auth.token.id),
                    ScimOperation::Create,
                    ScimResourceType::Group,
                    group.id,
                    source_ip,
                    user_agent,
                    None,
                    201,
                    None,
                )
                .await;
        }
        Err(e) => {
            audit_service
                .log_error(
                    auth.tenant_id,
                    Some(auth.token.id),
                    ScimOperation::Create,
                    ScimResourceType::Group,
                    None,
                    source_ip,
                    user_agent,
                    i32::from(e.status_code().as_u16()),
                    e.to_string(),
                )
                .await;
        }
    }

    let group = result?;

    // F085: Publish group.created webhook event
    if let Some(Extension(publisher)) = publisher {
        publisher.publish(WebhookEvent {
            event_id: Uuid::new_v4(),
            event_type: "group.created".to_string(),
            tenant_id: auth.tenant_id,
            actor_id: None,
            timestamp: chrono::Utc::now(),
            data: serde_json::json!({
                "group_id": group.id,
                "display_name": group.display_name,
            }),
        });
    }

    Ok(scim_response(StatusCode::CREATED, group))
}

/// Get a group by ID.
///
/// GET /scim/v2/Groups/{id}
pub async fn get_group(
    Extension(auth): Extension<ScimAuthContext>,
    Extension(group_service): Extension<Arc<GroupService>>,
    Extension(audit_service): Extension<Arc<AuditService>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Response, ScimError> {
    let source_ip = extract_client_ip(&headers);
    let user_agent = extract_user_agent(&headers);

    let result = group_service.get_group(auth.tenant_id, id).await;

    match &result {
        Ok(_) => {
            let _ = audit_service
                .log(
                    auth.tenant_id,
                    Some(auth.token.id),
                    ScimOperation::Read,
                    ScimResourceType::Group,
                    Some(id),
                    source_ip,
                    user_agent,
                    None,
                    200,
                    None,
                )
                .await;
        }
        Err(e) => {
            audit_service
                .log_error(
                    auth.tenant_id,
                    Some(auth.token.id),
                    ScimOperation::Read,
                    ScimResourceType::Group,
                    Some(id),
                    source_ip,
                    user_agent,
                    i32::from(e.status_code().as_u16()),
                    e.to_string(),
                )
                .await;
        }
    }

    let group = result?;
    Ok(scim_response(StatusCode::OK, group))
}

/// Replace a group (full update).
///
/// PUT /scim/v2/Groups/{id}
pub async fn replace_group(
    Extension(auth): Extension<ScimAuthContext>,
    Extension(group_service): Extension<Arc<GroupService>>,
    Extension(audit_service): Extension<Arc<AuditService>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
    Json(request): Json<ReplaceScimGroupRequest>,
) -> Result<Response, ScimError> {
    let source_ip = extract_client_ip(&headers);
    let user_agent = extract_user_agent(&headers);

    let result = group_service
        .replace_group(auth.tenant_id, id, request)
        .await;

    match &result {
        Ok(_) => {
            let _ = audit_service
                .log(
                    auth.tenant_id,
                    Some(auth.token.id),
                    ScimOperation::Update,
                    ScimResourceType::Group,
                    Some(id),
                    source_ip,
                    user_agent,
                    None,
                    200,
                    None,
                )
                .await;
        }
        Err(e) => {
            audit_service
                .log_error(
                    auth.tenant_id,
                    Some(auth.token.id),
                    ScimOperation::Update,
                    ScimResourceType::Group,
                    Some(id),
                    source_ip,
                    user_agent,
                    i32::from(e.status_code().as_u16()),
                    e.to_string(),
                )
                .await;
        }
    }

    let group = result?;
    Ok(scim_response(StatusCode::OK, group))
}

/// Patch a group (partial update).
///
/// PATCH /scim/v2/Groups/{id}
pub async fn update_group(
    Extension(auth): Extension<ScimAuthContext>,
    Extension(group_service): Extension<Arc<GroupService>>,
    Extension(audit_service): Extension<Arc<AuditService>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
    Json(request): Json<ScimPatchRequest>,
) -> Result<Response, ScimError> {
    let source_ip = extract_client_ip(&headers);
    let user_agent = extract_user_agent(&headers);

    let result = group_service.patch_group(auth.tenant_id, id, request).await;

    match &result {
        Ok(_) => {
            let _ = audit_service
                .log(
                    auth.tenant_id,
                    Some(auth.token.id),
                    ScimOperation::Update,
                    ScimResourceType::Group,
                    Some(id),
                    source_ip,
                    user_agent,
                    None,
                    200,
                    None,
                )
                .await;
        }
        Err(e) => {
            audit_service
                .log_error(
                    auth.tenant_id,
                    Some(auth.token.id),
                    ScimOperation::Update,
                    ScimResourceType::Group,
                    Some(id),
                    source_ip,
                    user_agent,
                    i32::from(e.status_code().as_u16()),
                    e.to_string(),
                )
                .await;
        }
    }

    let group = result?;
    Ok(scim_response(StatusCode::OK, group))
}

/// Delete a group.
///
/// DELETE /scim/v2/Groups/{id}
pub async fn delete_group(
    Extension(auth): Extension<ScimAuthContext>,
    Extension(group_service): Extension<Arc<GroupService>>,
    Extension(audit_service): Extension<Arc<AuditService>>,
    publisher: Option<Extension<EventPublisher>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Response, ScimError> {
    let source_ip = extract_client_ip(&headers);
    let user_agent = extract_user_agent(&headers);

    let result = group_service.delete_group(auth.tenant_id, id).await;

    match &result {
        Ok(()) => {
            let _ = audit_service
                .log(
                    auth.tenant_id,
                    Some(auth.token.id),
                    ScimOperation::Delete,
                    ScimResourceType::Group,
                    Some(id),
                    source_ip,
                    user_agent,
                    None,
                    204,
                    None,
                )
                .await;
        }
        Err(e) => {
            audit_service
                .log_error(
                    auth.tenant_id,
                    Some(auth.token.id),
                    ScimOperation::Delete,
                    ScimResourceType::Group,
                    Some(id),
                    source_ip,
                    user_agent,
                    i32::from(e.status_code().as_u16()),
                    e.to_string(),
                )
                .await;
        }
    }

    result?;

    // F085: Publish group.deleted webhook event
    if let Some(Extension(publisher)) = publisher {
        publisher.publish(WebhookEvent {
            event_id: Uuid::new_v4(),
            event_type: "group.deleted".to_string(),
            tenant_id: auth.tenant_id,
            actor_id: None,
            timestamp: chrono::Utc::now(),
            data: serde_json::json!({
                "group_id": id,
            }),
        });
    }

    Ok(StatusCode::NO_CONTENT.into_response())
}
