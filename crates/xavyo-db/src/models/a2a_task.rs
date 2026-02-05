//! A2A Task model for Agent-to-Agent asynchronous task management.
//!
//! This module provides the database model for A2A tasks, which enable
//! asynchronous task delegation between AI agents following the A2A protocol.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

/// A2A task state enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "varchar", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum A2aTaskState {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

impl A2aTaskState {
    /// Returns the string representation of the state.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    /// Check if this is a terminal state.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }

    /// Parse a state from string.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(Self::Pending),
            "running" => Some(Self::Running),
            "completed" => Some(Self::Completed),
            "failed" => Some(Self::Failed),
            "cancelled" => Some(Self::Cancelled),
            _ => None,
        }
    }
}

impl std::fmt::Display for A2aTaskState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Callback delivery status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "varchar", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum CallbackStatus {
    Pending,
    Delivered,
    Failed,
}

impl CallbackStatus {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Delivered => "delivered",
            Self::Failed => "failed",
        }
    }
}

/// A2A Task database model.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct A2aTask {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub source_agent_id: Uuid,
    pub target_agent_id: Uuid,
    pub task_type: String,
    pub input: serde_json::Value,
    pub state: String,
    pub result: Option<serde_json::Value>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub callback_url: Option<String>,
    pub callback_status: Option<String>,
    pub callback_attempts: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
}

impl A2aTask {
    /// Get the parsed task state.
    #[must_use]
    pub fn get_state(&self) -> Option<A2aTaskState> {
        A2aTaskState::parse(&self.state)
    }

    /// Check if the task is in a terminal state.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        self.get_state().is_some_and(|s| s.is_terminal())
    }
}

/// Request to create a new A2A task.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateA2aTask {
    pub target_agent_id: Uuid,
    pub task_type: String,
    pub input: serde_json::Value,
    pub callback_url: Option<String>,
}

/// Filter for listing A2A tasks.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct A2aTaskFilter {
    pub state: Option<String>,
    pub target_agent_id: Option<Uuid>,
    pub source_agent_id: Option<Uuid>,
    pub limit: Option<i32>,
    pub offset: Option<i32>,
}

impl A2aTask {
    /// Create a new A2A task.
    pub async fn create(
        pool: &PgPool,
        tenant_id: Uuid,
        source_agent_id: Uuid,
        req: CreateA2aTask,
    ) -> Result<Self, sqlx::Error> {
        let task = sqlx::query_as::<_, Self>(
            r"
            INSERT INTO a2a_tasks (
                tenant_id, source_agent_id, target_agent_id, task_type, input, callback_url
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(source_agent_id)
        .bind(req.target_agent_id)
        .bind(&req.task_type)
        .bind(&req.input)
        .bind(&req.callback_url)
        .fetch_one(pool)
        .await?;

        Ok(task)
    }

    /// Get a task by ID with tenant isolation.
    pub async fn get_by_id(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        let task = sqlx::query_as::<_, Self>(
            r"
            SELECT * FROM a2a_tasks
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(pool)
        .await?;

        Ok(task)
    }

    /// List tasks with filters.
    pub async fn list(
        pool: &PgPool,
        tenant_id: Uuid,
        source_agent_id: Uuid,
        filter: A2aTaskFilter,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let limit = filter.limit.unwrap_or(100).min(1000);
        let offset = filter.offset.unwrap_or(0);

        let tasks = sqlx::query_as::<_, Self>(
            r"
            SELECT * FROM a2a_tasks
            WHERE tenant_id = $1
              AND source_agent_id = $2
              AND ($3::varchar IS NULL OR state = $3)
              AND ($4::uuid IS NULL OR target_agent_id = $4)
            ORDER BY created_at DESC
            LIMIT $5 OFFSET $6
            ",
        )
        .bind(tenant_id)
        .bind(source_agent_id)
        .bind(&filter.state)
        .bind(filter.target_agent_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?;

        Ok(tasks)
    }

    /// Count tasks matching filter.
    pub async fn count(
        pool: &PgPool,
        tenant_id: Uuid,
        source_agent_id: Uuid,
        filter: &A2aTaskFilter,
    ) -> Result<i64, sqlx::Error> {
        let row: (i64,) = sqlx::query_as(
            r"
            SELECT COUNT(*) FROM a2a_tasks
            WHERE tenant_id = $1
              AND source_agent_id = $2
              AND ($3::varchar IS NULL OR state = $3)
              AND ($4::uuid IS NULL OR target_agent_id = $4)
            ",
        )
        .bind(tenant_id)
        .bind(source_agent_id)
        .bind(&filter.state)
        .bind(filter.target_agent_id)
        .fetch_one(pool)
        .await?;

        Ok(row.0)
    }

    /// Update task state with optional result/error.
    pub async fn update_state(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
        new_state: A2aTaskState,
        result: Option<serde_json::Value>,
        error_code: Option<String>,
        error_message: Option<String>,
    ) -> Result<Option<Self>, sqlx::Error> {
        let now = Utc::now();
        let started_at = if new_state == A2aTaskState::Running {
            Some(now)
        } else {
            None
        };
        let completed_at = if new_state.is_terminal() {
            Some(now)
        } else {
            None
        };

        let task = sqlx::query_as::<_, Self>(
            r"
            UPDATE a2a_tasks
            SET state = $3,
                result = COALESCE($4, result),
                error_code = COALESCE($5, error_code),
                error_message = COALESCE($6, error_message),
                started_at = COALESCE($7, started_at),
                completed_at = COALESCE($8, completed_at),
                updated_at = NOW()
            WHERE tenant_id = $1 AND id = $2
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .bind(new_state.as_str())
        .bind(result)
        .bind(error_code)
        .bind(error_message)
        .bind(started_at)
        .bind(completed_at)
        .fetch_optional(pool)
        .await?;

        Ok(task)
    }

    /// Cancel a task (only if pending or running).
    pub async fn cancel(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        let task = sqlx::query_as::<_, Self>(
            r"
            UPDATE a2a_tasks
            SET state = 'cancelled',
                completed_at = NOW(),
                updated_at = NOW()
            WHERE tenant_id = $1 AND id = $2
              AND state IN ('pending', 'running')
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(pool)
        .await?;

        Ok(task)
    }

    /// Update callback status and increment attempts.
    pub async fn update_callback_status(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
        status: CallbackStatus,
    ) -> Result<Option<Self>, sqlx::Error> {
        let task = sqlx::query_as::<_, Self>(
            r"
            UPDATE a2a_tasks
            SET callback_status = $3,
                callback_attempts = callback_attempts + 1,
                updated_at = NOW()
            WHERE tenant_id = $1 AND id = $2
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .bind(status.as_str())
        .fetch_optional(pool)
        .await?;

        Ok(task)
    }

    /// Get tasks with pending callbacks for retry.
    pub async fn get_pending_callbacks(
        pool: &PgPool,
        tenant_id: Uuid,
        max_attempts: i32,
        limit: i32,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let tasks = sqlx::query_as::<_, Self>(
            r"
            SELECT * FROM a2a_tasks
            WHERE tenant_id = $1
              AND callback_url IS NOT NULL
              AND state IN ('completed', 'failed', 'cancelled')
              AND (callback_status IS NULL OR callback_status = 'pending')
              AND callback_attempts < $2
            ORDER BY completed_at ASC
            LIMIT $3
            ",
        )
        .bind(tenant_id)
        .bind(max_attempts)
        .bind(limit)
        .fetch_all(pool)
        .await?;

        Ok(tasks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_parsing() {
        assert_eq!(A2aTaskState::parse("pending"), Some(A2aTaskState::Pending));
        assert_eq!(A2aTaskState::parse("running"), Some(A2aTaskState::Running));
        assert_eq!(
            A2aTaskState::parse("completed"),
            Some(A2aTaskState::Completed)
        );
        assert_eq!(A2aTaskState::parse("failed"), Some(A2aTaskState::Failed));
        assert_eq!(
            A2aTaskState::parse("cancelled"),
            Some(A2aTaskState::Cancelled)
        );
        assert_eq!(A2aTaskState::parse("invalid"), None);
    }

    #[test]
    fn test_terminal_states() {
        assert!(!A2aTaskState::Pending.is_terminal());
        assert!(!A2aTaskState::Running.is_terminal());
        assert!(A2aTaskState::Completed.is_terminal());
        assert!(A2aTaskState::Failed.is_terminal());
        assert!(A2aTaskState::Cancelled.is_terminal());
    }

    #[test]
    fn test_state_display() {
        assert_eq!(A2aTaskState::Pending.to_string(), "pending");
        assert_eq!(A2aTaskState::Running.to_string(), "running");
        assert_eq!(A2aTaskState::Completed.to_string(), "completed");
    }
}
