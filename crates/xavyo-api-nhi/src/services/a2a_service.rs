//! A2A (Agent-to-Agent) Protocol service using NHI tables.
//!
//! Provides A2A task creation, retrieval, listing, and cancellation
//! backed by the unified NHI data model. Validates agents via
//! `nhi_identities` and enforces NHI-to-NHI call permissions.
//! Migrated from xavyo-api-agents as part of Feature 205 protocol migration.
//!
//! All functions are stateless and take `&PgPool` as their first argument.

use chrono::Utc;
use sqlx::PgPool;
use tracing::{info, warn};
use url::Url;
use uuid::Uuid;

use xavyo_db::models::{A2aTask, A2aTaskFilter, CreateA2aTask, NhiIdentity, NhiNhiPermission};
use xavyo_nhi::NhiLifecycleState;

use crate::error::NhiApiError;
use crate::models::{
    A2aTaskListResponse, A2aTaskResponse, A2aTaskWebhookPayload, CancelA2aTaskResponse,
    CreateA2aTaskRequest, CreateA2aTaskResponse, ListA2aTasksQuery,
};

/// Create a new A2A task.
///
/// Validates that the source agent is active, the target agent exists
/// and is active, checks NHI-to-NHI call permission, validates the
/// callback URL if provided, and creates the task record.
pub async fn create_task(
    pool: &PgPool,
    tenant_id: Uuid,
    source_nhi_id: Uuid,
    request: CreateA2aTaskRequest,
) -> Result<CreateA2aTaskResponse, NhiApiError> {
    // 1. Validate source agent exists and is active
    let source = NhiIdentity::find_by_id(pool, tenant_id, source_nhi_id)
        .await?
        .ok_or(NhiApiError::NotFound)?;

    if source.lifecycle_state != NhiLifecycleState::Active {
        return Err(NhiApiError::BadRequest(format!(
            "Source agent is in {} state; must be active to create tasks",
            source.lifecycle_state
        )));
    }

    // 2. Validate target agent exists and is active
    let target = NhiIdentity::find_by_id(pool, tenant_id, request.target_agent_id)
        .await?
        .ok_or(NhiApiError::NotFound)?;

    if target.lifecycle_state != NhiLifecycleState::Active {
        return Err(NhiApiError::BadRequest(format!(
            "Target agent is in {} state; must be active to receive tasks",
            target.lifecycle_state
        )));
    }

    // 3. Check NHI-to-NHI call permission
    let has_permission =
        NhiNhiPermission::check_permission(pool, tenant_id, source_nhi_id, request.target_agent_id)
            .await?;

    if !has_permission {
        return Err(NhiApiError::Forbidden);
    }

    // 4. Validate callback URL if provided
    if let Some(ref url) = request.callback_url {
        validate_callback_url(url)?;
    }

    // 5. Create the task
    let create_req = CreateA2aTask {
        target_nhi_id: Some(request.target_agent_id),
        task_type: request.task_type,
        input: request.input,
        callback_url: request.callback_url,
    };

    let task = A2aTask::create(pool, tenant_id, Some(source_nhi_id), create_req).await?;

    info!(
        task_id = %task.id,
        source_nhi_id = %source_nhi_id,
        target_nhi_id = %request.target_agent_id,
        task_type = %task.task_type,
        "A2A task created"
    );

    Ok(CreateA2aTaskResponse {
        task_id: task.id,
        status: task.state.clone(),
        created_at: task.created_at,
    })
}

/// Get a task by ID with tenant isolation and ownership check.
///
/// The requester must be either the source or target agent of the task,
/// or an admin/super_admin user.
pub async fn get_task(
    pool: &PgPool,
    tenant_id: Uuid,
    requester_nhi_id: Uuid,
    is_admin: bool,
    task_id: Uuid,
) -> Result<A2aTaskResponse, NhiApiError> {
    let task = A2aTask::get_by_id(pool, tenant_id, task_id)
        .await?
        .ok_or(NhiApiError::NotFound)?;

    // Admins can view any task; non-admins must be a participant
    if !is_admin {
        let is_source = task.source_nhi_id == Some(requester_nhi_id);
        let is_target = task.target_nhi_id == Some(requester_nhi_id);
        if !is_source && !is_target {
            return Err(NhiApiError::NotFound);
        }
    }

    Ok(task_to_response(&task))
}

/// List tasks with optional filters.
///
/// Admin users see all tasks for the tenant. Non-admin agents see only
/// tasks where they are the source. Supports optional query parameters
/// (state, target agent, pagination).
pub async fn list_tasks(
    pool: &PgPool,
    tenant_id: Uuid,
    source_nhi_id: Uuid,
    is_admin: bool,
    query: ListA2aTasksQuery,
) -> Result<A2aTaskListResponse, NhiApiError> {
    let limit = query.limit.unwrap_or(100).min(1000);
    let offset = query.offset.unwrap_or(0);

    // Admins see all tasks; non-admins see only their own
    let source_filter = if is_admin { None } else { Some(source_nhi_id) };

    let filter = A2aTaskFilter {
        state: query.state.clone(),
        target_nhi_id: query.target_agent_id,
        source_nhi_id: source_filter,
        limit: Some(limit),
        offset: Some(offset),
    };

    let tasks = A2aTask::list(pool, tenant_id, source_filter, filter.clone()).await?;
    let total = A2aTask::count(pool, tenant_id, source_filter, &filter).await?;

    let task_responses: Vec<A2aTaskResponse> = tasks.iter().map(task_to_response).collect();

    Ok(A2aTaskListResponse {
        tasks: task_responses,
        total,
        limit,
        offset,
    })
}

/// Cancel a task.
///
/// Only tasks in `pending` or `running` state can be cancelled.
/// Tasks in terminal states (`completed`, `failed`, `cancelled`) are rejected.
/// The requester must be either the source or target agent of the task,
/// or an admin/super_admin user.
pub async fn cancel_task(
    pool: &PgPool,
    tenant_id: Uuid,
    requester_nhi_id: Uuid,
    is_admin: bool,
    task_id: Uuid,
) -> Result<CancelA2aTaskResponse, NhiApiError> {
    // First fetch the task to check its current state
    let existing = A2aTask::get_by_id(pool, tenant_id, task_id)
        .await?
        .ok_or(NhiApiError::NotFound)?;

    // Admins can cancel any task; non-admins must be a participant
    if !is_admin {
        let is_source = existing.source_nhi_id == Some(requester_nhi_id);
        let is_target = existing.target_nhi_id == Some(requester_nhi_id);
        if !is_source && !is_target {
            return Err(NhiApiError::NotFound);
        }
    }

    // Validate the task is in a cancellable state
    if existing.is_terminal() {
        return Err(NhiApiError::InvalidTransition(format!(
            "Task cannot be cancelled: already in '{}' state",
            existing.state
        )));
    }

    // Perform the cancellation
    let cancelled = A2aTask::cancel(pool, tenant_id, task_id)
        .await?
        .ok_or_else(|| {
            NhiApiError::InvalidTransition(
                "Task could not be cancelled (concurrent state change)".to_string(),
            )
        })?;

    info!(
        task_id = %task_id,
        previous_state = %existing.state,
        "A2A task cancelled"
    );

    // Deliver webhook notification if callback URL is configured
    if let Some(ref callback_url) = cancelled.callback_url {
        let payload = A2aTaskWebhookPayload {
            task_id: cancelled.id,
            state: "cancelled".to_string(),
            result: None,
            error_code: None,
            error_message: None,
            completed_at: cancelled.completed_at.unwrap_or_else(Utc::now),
        };
        deliver_webhook(callback_url, &payload).await;
    }

    Ok(CancelA2aTaskResponse {
        task_id: cancelled.id,
        state: "cancelled".to_string(),
        cancelled_at: cancelled.completed_at.unwrap_or_else(Utc::now),
    })
}

/// Convert a database task model to an API response.
///
/// Maps `source_nhi_id`/`target_nhi_id` to `source_agent_id`/`target_agent_id`
/// for backward compatibility with the legacy API contract.
fn task_to_response(task: &A2aTask) -> A2aTaskResponse {
    A2aTaskResponse {
        id: task.id,
        source_agent_id: task.source_nhi_id,
        target_agent_id: task.target_nhi_id,
        task_type: task.task_type.clone(),
        state: task.state.clone(),
        result: task.result.clone(),
        error_code: task.error_code.clone(),
        error_message: task.error_message.clone(),
        created_at: task.created_at,
        started_at: task.started_at,
        completed_at: task.completed_at,
    }
}

/// Validate a callback URL.
///
/// Only HTTP and HTTPS schemes are allowed. Other schemes (e.g., `ftp://`,
/// `file://`) are rejected to prevent SSRF.
fn validate_callback_url(url: &str) -> Result<(), NhiApiError> {
    let parsed = Url::parse(url)
        .map_err(|_| NhiApiError::BadRequest("Invalid callback URL format".to_string()))?;

    match parsed.scheme() {
        "http" | "https" => Ok(()),
        scheme => Err(NhiApiError::BadRequest(format!(
            "Callback URL scheme '{}' is not allowed; only http and https are supported",
            scheme
        ))),
    }
}

/// Deliver a webhook notification to the callback URL.
///
/// Performs a best-effort POST request. Errors are logged but do not
/// cause the parent operation to fail.
async fn deliver_webhook(callback_url: &str, payload: &A2aTaskWebhookPayload) {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build();

    let client = match client {
        Ok(c) => c,
        Err(e) => {
            warn!(
                callback_url = %callback_url,
                error = %e,
                "Failed to build HTTP client for webhook delivery"
            );
            return;
        }
    };

    match client.post(callback_url).json(payload).send().await {
        Ok(response) => {
            if response.status().is_success() {
                info!(
                    callback_url = %callback_url,
                    task_id = %payload.task_id,
                    status = %response.status(),
                    "Webhook delivered successfully"
                );
            } else {
                warn!(
                    callback_url = %callback_url,
                    task_id = %payload.task_id,
                    status = %response.status(),
                    "Webhook delivery received non-success response"
                );
            }
        }
        Err(e) => {
            warn!(
                callback_url = %callback_url,
                task_id = %payload.task_id,
                error = %e,
                "Webhook delivery failed"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_validate_callback_url_https() {
        assert!(validate_callback_url("https://example.com/webhook").is_ok());
    }

    #[test]
    fn test_validate_callback_url_http() {
        assert!(validate_callback_url("http://localhost:8080/hook").is_ok());
    }

    #[test]
    fn test_validate_callback_url_invalid_scheme() {
        let err = validate_callback_url("ftp://example.com/hook").unwrap_err();
        match err {
            NhiApiError::BadRequest(msg) => {
                assert!(msg.contains("ftp"));
            }
            _ => panic!("Expected BadRequest error"),
        }
    }

    #[test]
    fn test_validate_callback_url_invalid_format() {
        let err = validate_callback_url("not a url at all").unwrap_err();
        match err {
            NhiApiError::BadRequest(msg) => {
                assert!(msg.contains("Invalid callback URL format"));
            }
            _ => panic!("Expected BadRequest error"),
        }
    }

    #[test]
    fn test_task_to_response_maps_nhi_ids() {
        let source_id = Uuid::new_v4();
        let target_id = Uuid::new_v4();
        let now = Utc::now();

        let task = A2aTask {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            source_nhi_id: Some(source_id),
            target_nhi_id: Some(target_id),
            task_type: "process".to_string(),
            input: serde_json::json!({}),
            state: "pending".to_string(),
            result: None,
            error_code: None,
            error_message: None,
            callback_url: None,
            callback_status: None,
            callback_attempts: 0,
            created_at: now,
            updated_at: now,
            started_at: None,
            completed_at: None,
        };

        let response = task_to_response(&task);

        assert_eq!(response.source_agent_id, Some(source_id));
        assert_eq!(response.target_agent_id, Some(target_id));
        assert_eq!(response.state, "pending");
        assert!(response.result.is_none());
    }

    #[test]
    fn test_task_to_response_with_completed_task() {
        let now = Utc::now();

        let task = A2aTask {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            source_nhi_id: Some(Uuid::new_v4()),
            target_nhi_id: Some(Uuid::new_v4()),
            task_type: "analyze".to_string(),
            input: serde_json::json!({"url": "https://example.com"}),
            state: "completed".to_string(),
            result: Some(serde_json::json!({"score": 95})),
            error_code: None,
            error_message: None,
            callback_url: Some("https://example.com/webhook".to_string()),
            callback_status: Some("delivered".to_string()),
            callback_attempts: 1,
            created_at: now,
            updated_at: now,
            started_at: Some(now),
            completed_at: Some(now),
        };

        let response = task_to_response(&task);

        assert_eq!(response.state, "completed");
        assert!(response.result.is_some());
        assert!(response.started_at.is_some());
        assert!(response.completed_at.is_some());
    }

    #[test]
    fn test_validate_callback_url_file_scheme_rejected() {
        let err = validate_callback_url("file:///etc/passwd").unwrap_err();
        match err {
            NhiApiError::BadRequest(msg) => {
                assert!(msg.contains("file"));
            }
            _ => panic!("Expected BadRequest error"),
        }
    }
}
