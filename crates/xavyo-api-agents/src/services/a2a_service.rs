//! A2A (Agent-to-Agent) service for asynchronous task management.
//!
//! This service implements the A2A protocol for creating, tracking, and
//! cancelling tasks between AI agents.

use crate::error::ApiAgentsError;
use crate::models::{
    A2aTaskListResponse, A2aTaskResponse, CancelA2aTaskResponse, CreateA2aTaskRequest,
    CreateA2aTaskResponse, ListA2aTasksQuery,
};
use crate::services::WebhookService;
use chrono::Utc;
use sqlx::PgPool;
use std::sync::Arc;
use tracing::{info, warn};
use url::Url;
use uuid::Uuid;
use xavyo_db::models::{A2aTask, A2aTaskFilter, AiAgent, CreateA2aTask};

/// A2A service for task operations.
#[derive(Clone)]
pub struct A2aService {
    pool: PgPool,
    webhook_service: Arc<WebhookService>,
}

impl A2aService {
    /// Create a new A2A service.
    #[must_use] 
    pub fn new(pool: PgPool, webhook_service: Arc<WebhookService>) -> Self {
        Self {
            pool,
            webhook_service,
        }
    }

    /// Create a new A2A task.
    pub async fn create_task(
        &self,
        tenant_id: Uuid,
        source_agent_id: Uuid,
        request: CreateA2aTaskRequest,
    ) -> Result<CreateA2aTaskResponse, ApiAgentsError> {
        // Validate target agent exists and is active
        self.validate_target_agent(tenant_id, request.target_agent_id)
            .await?;

        // Validate callback URL if provided
        if let Some(ref url) = request.callback_url {
            Self::validate_callback_url(url)?;
        }

        // Create the task
        let create_req = CreateA2aTask {
            target_agent_id: request.target_agent_id,
            task_type: request.task_type,
            input: request.input,
            callback_url: request.callback_url,
        };

        let task = A2aTask::create(&self.pool, tenant_id, source_agent_id, create_req).await?;

        info!(
            tenant_id = %tenant_id,
            task_id = %task.id,
            source_agent_id = %source_agent_id,
            target_agent_id = %task.target_agent_id,
            task_type = %task.task_type,
            "A2A task created"
        );

        Ok(CreateA2aTaskResponse {
            task_id: task.id,
            status: task.state,
            created_at: task.created_at,
        })
    }

    /// Validate that the target agent exists and is active.
    pub async fn validate_target_agent(
        &self,
        tenant_id: Uuid,
        target_agent_id: Uuid,
    ) -> Result<(), ApiAgentsError> {
        let agent = AiAgent::find_by_id(&self.pool, tenant_id, target_agent_id).await?;

        match agent {
            None => Err(ApiAgentsError::NotFound(format!(
                "Target agent {target_agent_id} not found"
            ))),
            Some(a) if a.status != "active" => Err(ApiAgentsError::BadRequest(format!(
                "Target agent {target_agent_id} is not active"
            ))),
            Some(_) => Ok(()),
        }
    }

    /// Validate callback URL format.
    fn validate_callback_url(url: &str) -> Result<(), ApiAgentsError> {
        let parsed = Url::parse(url)
            .map_err(|_| ApiAgentsError::BadRequest("Invalid callback URL format".to_string()))?;

        // Only allow HTTPS in production (allow HTTP for local testing)
        if parsed.scheme() != "https" && parsed.scheme() != "http" {
            return Err(ApiAgentsError::BadRequest(
                "Callback URL must use HTTPS or HTTP scheme".to_string(),
            ));
        }

        Ok(())
    }

    /// Get a task by ID with tenant isolation.
    pub async fn get_task(
        &self,
        tenant_id: Uuid,
        task_id: Uuid,
    ) -> Result<A2aTaskResponse, ApiAgentsError> {
        let task = A2aTask::get_by_id(&self.pool, tenant_id, task_id)
            .await?
            .ok_or_else(|| ApiAgentsError::NotFound(format!("Task {task_id} not found")))?;

        Ok(self.task_to_response(&task))
    }

    /// List tasks for an agent with filters.
    pub async fn list_tasks(
        &self,
        tenant_id: Uuid,
        source_agent_id: Uuid,
        query: ListA2aTasksQuery,
    ) -> Result<A2aTaskListResponse, ApiAgentsError> {
        let filter = A2aTaskFilter {
            state: query.state.clone(),
            target_agent_id: query.target_agent_id,
            limit: query.limit,
            offset: query.offset,
            ..Default::default()
        };

        let tasks = A2aTask::list(&self.pool, tenant_id, source_agent_id, filter.clone()).await?;
        let total = A2aTask::count(&self.pool, tenant_id, source_agent_id, &filter).await?;

        let limit = query.limit.unwrap_or(100).min(1000);
        let offset = query.offset.unwrap_or(0);

        Ok(A2aTaskListResponse {
            tasks: tasks.iter().map(|t| self.task_to_response(t)).collect(),
            total,
            limit,
            offset,
        })
    }

    /// Cancel a task.
    pub async fn cancel_task(
        &self,
        tenant_id: Uuid,
        task_id: Uuid,
    ) -> Result<CancelA2aTaskResponse, ApiAgentsError> {
        // Get current task state
        let task = A2aTask::get_by_id(&self.pool, tenant_id, task_id)
            .await?
            .ok_or_else(|| ApiAgentsError::NotFound(format!("Task {task_id} not found")))?;

        // Check if already cancelled (idempotent)
        if task.state == "cancelled" {
            return Ok(CancelA2aTaskResponse {
                task_id: task.id,
                state: "cancelled".to_string(),
                cancelled_at: task.completed_at.unwrap_or_else(Utc::now),
            });
        }

        // Check if in terminal state
        if let Some(state) = task.get_state() {
            if state.is_terminal() {
                return Err(ApiAgentsError::InvalidStateTransition(format!(
                    "Task cannot be cancelled: already in '{}' state",
                    task.state
                )));
            }
        }

        // Cancel the task
        let cancelled = A2aTask::cancel(&self.pool, tenant_id, task_id)
            .await?
            .ok_or_else(|| {
                ApiAgentsError::InvalidStateTransition(
                    "Task state changed during cancellation".to_string(),
                )
            })?;

        info!(
            tenant_id = %tenant_id,
            task_id = %task_id,
            "A2A task cancelled"
        );

        // Trigger webhook if configured
        if cancelled.callback_url.is_some() {
            self.trigger_webhook(&cancelled).await;
        }

        Ok(CancelA2aTaskResponse {
            task_id: cancelled.id,
            state: "cancelled".to_string(),
            cancelled_at: cancelled.completed_at.unwrap_or_else(Utc::now),
        })
    }

    /// Trigger webhook for task completion.
    async fn trigger_webhook(&self, task: &A2aTask) {
        if let Some(ref url) = task.callback_url {
            if let Err(e) = self
                .webhook_service
                .deliver_task_webhook(
                    task.tenant_id,
                    task.id,
                    url,
                    &task.state,
                    task.result.clone(),
                    task.error_code.clone(),
                    task.error_message.clone(),
                )
                .await
            {
                warn!(
                    task_id = %task.id,
                    error = %e,
                    "Failed to trigger webhook for task completion"
                );
            }
        }
    }

    /// Convert database task to API response.
    fn task_to_response(&self, task: &A2aTask) -> A2aTaskResponse {
        A2aTaskResponse {
            id: task.id,
            source_agent_id: task.source_agent_id,
            target_agent_id: task.target_agent_id,
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_callback_url() {
        assert!(A2aService::validate_callback_url("https://example.com/webhook").is_ok());
        assert!(A2aService::validate_callback_url("http://localhost:3000/webhook").is_ok());
        assert!(A2aService::validate_callback_url("ftp://example.com").is_err());
        assert!(A2aService::validate_callback_url("not-a-url").is_err());
    }
}
