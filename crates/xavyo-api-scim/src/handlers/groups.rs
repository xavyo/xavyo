//! SCIM Group resource handlers.

use axum::{
    extract::{Path, Query},
    http::StatusCode,
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

use xavyo_db::models::{ScimOperation, ScimResourceType};

use crate::error::ScimError;
use crate::handlers::common::{extract_client_ip, extract_user_agent, scim_response};
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
    sort_by: Option<String>,
    sort_order: Option<String>,
}

fn default_start_index() -> i64 {
    1
}

fn default_count() -> i64 {
    25
}

/// List groups with optional filtering.
///
/// GET /scim/v2/Groups
#[utoipa::path(
    get,
    path = "/scim/v2/Groups",
    responses(
        (status = 200, description = "List of SCIM groups"),
        (status = 401, description = "Not authenticated"),
    ),
    tag = "SCIM Groups"
)]
pub async fn list_groups(
    Extension(auth): Extension<ScimAuthContext>,
    Extension(group_service): Extension<Arc<GroupService>>,
    Extension(audit_service): Extension<Arc<AuditService>>,
    headers: axum::http::HeaderMap,
    Query(query): Query<ListGroupsQuery>,
) -> Result<Response, ScimError> {
    // Cap sortBy/sortOrder length to prevent oversized query parameters.
    if query.sort_by.as_ref().is_some_and(|s| s.len() > 64) {
        return Err(ScimError::BadRequest(
            "sortBy exceeds maximum length".to_string(),
        ));
    }
    if query.sort_order.as_ref().is_some_and(|s| s.len() > 64) {
        return Err(ScimError::BadRequest(
            "sortOrder exceeds maximum length".to_string(),
        ));
    }

    let pagination = ScimPagination::from_query(
        Some(query.start_index),
        Some(query.count),
        query.sort_by,
        query.sort_order,
    );

    let result = group_service
        .list_groups(auth.tenant_id, query.filter.as_deref(), pagination)
        .await;

    let source_ip = extract_client_ip(&headers);
    let user_agent = extract_user_agent(&headers);

    match &result {
        Ok(_) => {
            if let Err(e) = audit_service
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
                .await
            {
                tracing::warn!(error = %e, "Failed to write SCIM group audit log");
            }
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
#[utoipa::path(
    post,
    path = "/scim/v2/Groups",
    request_body = CreateScimGroupRequest,
    responses(
        (status = 201, description = "Group created", body = ScimGroup),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Not authenticated"),
        (status = 409, description = "Group already exists"),
    ),
    tag = "SCIM Groups"
)]
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
            if let Err(e) = audit_service
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
                .await
            {
                tracing::warn!(error = %e, "Failed to write SCIM group audit log");
            }
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
#[utoipa::path(
    get,
    path = "/scim/v2/Groups/{id}",
    params(
        ("id" = Uuid, Path, description = "Group ID"),
    ),
    responses(
        (status = 200, description = "Group details", body = ScimGroup),
        (status = 401, description = "Not authenticated"),
        (status = 404, description = "Group not found"),
    ),
    tag = "SCIM Groups"
)]
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
            if let Err(e) = audit_service
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
                .await
            {
                tracing::warn!(error = %e, "Failed to write SCIM group audit log");
            }
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
#[utoipa::path(
    put,
    path = "/scim/v2/Groups/{id}",
    params(
        ("id" = Uuid, Path, description = "Group ID"),
    ),
    request_body = ReplaceScimGroupRequest,
    responses(
        (status = 200, description = "Group replaced", body = ScimGroup),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Not authenticated"),
        (status = 404, description = "Group not found"),
    ),
    tag = "SCIM Groups"
)]
pub async fn replace_group(
    Extension(auth): Extension<ScimAuthContext>,
    Extension(group_service): Extension<Arc<GroupService>>,
    Extension(audit_service): Extension<Arc<AuditService>>,
    publisher: Option<Extension<EventPublisher>>,
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
            if let Err(e) = audit_service
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
                .await
            {
                tracing::warn!(error = %e, "Failed to write SCIM group audit log");
            }
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

    // F085: Publish group.updated webhook event
    if let Some(Extension(publisher)) = publisher {
        publisher.publish(WebhookEvent {
            event_id: Uuid::new_v4(),
            event_type: "group.updated".to_string(),
            tenant_id: auth.tenant_id,
            actor_id: None,
            timestamp: chrono::Utc::now(),
            data: serde_json::json!({
                "group_id": group.id,
                "display_name": group.display_name,
            }),
        });
    }

    Ok(scim_response(StatusCode::OK, group))
}

/// Patch a group (partial update).
///
/// PATCH /scim/v2/Groups/{id}
#[utoipa::path(
    patch,
    path = "/scim/v2/Groups/{id}",
    params(
        ("id" = Uuid, Path, description = "Group ID"),
    ),
    request_body = ScimPatchRequest,
    responses(
        (status = 200, description = "Group patched", body = ScimGroup),
        (status = 400, description = "Invalid patch operations"),
        (status = 401, description = "Not authenticated"),
        (status = 404, description = "Group not found"),
    ),
    tag = "SCIM Groups"
)]
pub async fn update_group(
    Extension(auth): Extension<ScimAuthContext>,
    Extension(group_service): Extension<Arc<GroupService>>,
    Extension(audit_service): Extension<Arc<AuditService>>,
    publisher: Option<Extension<EventPublisher>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
    Json(request): Json<ScimPatchRequest>,
) -> Result<Response, ScimError> {
    let source_ip = extract_client_ip(&headers);
    let user_agent = extract_user_agent(&headers);

    let result = group_service.patch_group(auth.tenant_id, id, request).await;

    match &result {
        Ok(_) => {
            if let Err(e) = audit_service
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
                .await
            {
                tracing::warn!(error = %e, "Failed to write SCIM group audit log");
            }
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

    // F085: Publish group.updated webhook event
    if let Some(Extension(publisher)) = publisher {
        publisher.publish(WebhookEvent {
            event_id: Uuid::new_v4(),
            event_type: "group.updated".to_string(),
            tenant_id: auth.tenant_id,
            actor_id: None,
            timestamp: chrono::Utc::now(),
            data: serde_json::json!({
                "group_id": group.id,
                "display_name": group.display_name,
            }),
        });
    }

    Ok(scim_response(StatusCode::OK, group))
}

/// Delete a group.
///
/// DELETE /scim/v2/Groups/{id}
#[utoipa::path(
    delete,
    path = "/scim/v2/Groups/{id}",
    params(
        ("id" = Uuid, Path, description = "Group ID"),
    ),
    responses(
        (status = 204, description = "Group deleted"),
        (status = 401, description = "Not authenticated"),
        (status = 404, description = "Group not found"),
    ),
    tag = "SCIM Groups"
)]
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
            if let Err(e) = audit_service
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
                .await
            {
                tracing::warn!(error = %e, "Failed to write SCIM group audit log");
            }
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
