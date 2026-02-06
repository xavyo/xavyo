//! Reconciliation Action model for F049 Reconciliation Engine.
//!
//! Audit log of remediation actions executed to resolve discrepancies.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sqlx::PgPool;
use std::fmt;
use uuid::Uuid;

use super::reconciliation_discrepancy::ReconciliationActionType;

/// Result of a remediation action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "varchar", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum ReconciliationActionResult {
    /// Action succeeded.
    Success,
    /// Action failed.
    Failure,
}

impl fmt::Display for ReconciliationActionResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Success => write!(f, "success"),
            Self::Failure => write!(f, "failure"),
        }
    }
}

impl std::str::FromStr for ReconciliationActionResult {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "success" => Ok(Self::Success),
            "failure" => Ok(Self::Failure),
            _ => Err(format!("Unknown action result: {s}")),
        }
    }
}

/// A reconciliation action record (audit log entry).
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ReconciliationAction {
    pub id: Uuid,
    pub discrepancy_id: Uuid,
    pub tenant_id: Uuid,
    pub action_type: String,
    pub executed_by: Uuid,
    pub result: String,
    pub error_message: Option<String>,
    pub before_state: Option<JsonValue>,
    pub after_state: Option<JsonValue>,
    pub dry_run: bool,
    pub executed_at: DateTime<Utc>,
}

impl ReconciliationAction {
    /// Get action type enum.
    #[must_use]
    pub fn action_type(&self) -> ReconciliationActionType {
        self.action_type
            .parse()
            .unwrap_or(ReconciliationActionType::Update)
    }

    /// Get result enum.
    #[must_use]
    pub fn result(&self) -> ReconciliationActionResult {
        self.result
            .parse()
            .unwrap_or(ReconciliationActionResult::Failure)
    }

    /// Check if action succeeded.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.result().eq(&ReconciliationActionResult::Success)
    }

    /// Create a new action record.
    pub async fn create(
        pool: &PgPool,
        tenant_id: Uuid,
        input: &CreateReconciliationAction,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO gov_reconciliation_actions (
                discrepancy_id, tenant_id, action_type, executed_by,
                result, error_message, before_state, after_state, dry_run
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING *
            ",
        )
        .bind(input.discrepancy_id)
        .bind(tenant_id)
        .bind(input.action_type.to_string())
        .bind(input.executed_by)
        .bind(input.result.to_string())
        .bind(&input.error_message)
        .bind(&input.before_state)
        .bind(&input.after_state)
        .bind(input.dry_run)
        .fetch_one(pool)
        .await
    }

    /// Find action by ID.
    pub async fn find_by_id(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_reconciliation_actions
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List actions for a discrepancy.
    pub async fn list_by_discrepancy(
        pool: &PgPool,
        tenant_id: Uuid,
        discrepancy_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_reconciliation_actions
            WHERE tenant_id = $1 AND discrepancy_id = $2
            ORDER BY executed_at DESC
            ",
        )
        .bind(tenant_id)
        .bind(discrepancy_id)
        .fetch_all(pool)
        .await
    }

    /// List actions with filtering.
    pub async fn list(
        pool: &PgPool,
        tenant_id: Uuid,
        filter: &ReconciliationActionFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query =
            String::from(r"SELECT * FROM gov_reconciliation_actions WHERE tenant_id = $1");
        let mut param_idx = 2;

        if filter.discrepancy_id.is_some() {
            query.push_str(&format!(" AND discrepancy_id = ${param_idx}"));
            param_idx += 1;
        }
        if filter.action_type.is_some() {
            query.push_str(&format!(" AND action_type = ${param_idx}"));
            param_idx += 1;
        }
        if filter.result.is_some() {
            query.push_str(&format!(" AND result = ${param_idx}"));
            param_idx += 1;
        }
        if filter.executed_by.is_some() {
            query.push_str(&format!(" AND executed_by = ${param_idx}"));
            param_idx += 1;
        }
        if filter.dry_run.is_some() {
            query.push_str(&format!(" AND dry_run = ${param_idx}"));
            param_idx += 1;
        }
        if filter.since.is_some() {
            query.push_str(&format!(" AND executed_at >= ${param_idx}"));
            param_idx += 1;
        }

        query.push_str(&format!(
            " ORDER BY executed_at DESC LIMIT ${} OFFSET ${}",
            param_idx,
            param_idx + 1
        ));

        let mut q = sqlx::query_as::<_, Self>(&query).bind(tenant_id);

        if let Some(discrepancy_id) = filter.discrepancy_id {
            q = q.bind(discrepancy_id);
        }
        if let Some(ref action_type) = filter.action_type {
            q = q.bind(action_type.to_string());
        }
        if let Some(ref result) = filter.result {
            q = q.bind(result.to_string());
        }
        if let Some(executed_by) = filter.executed_by {
            q = q.bind(executed_by);
        }
        if let Some(dry_run) = filter.dry_run {
            q = q.bind(dry_run);
        }
        if let Some(since) = filter.since {
            q = q.bind(since);
        }

        q = q.bind(limit).bind(offset);
        q.fetch_all(pool).await
    }

    /// Count actions.
    pub async fn count(
        pool: &PgPool,
        tenant_id: Uuid,
        filter: &ReconciliationActionFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query =
            String::from(r"SELECT COUNT(*) FROM gov_reconciliation_actions WHERE tenant_id = $1");
        let mut param_idx = 2;

        if filter.discrepancy_id.is_some() {
            query.push_str(&format!(" AND discrepancy_id = ${param_idx}"));
            param_idx += 1;
        }
        if filter.action_type.is_some() {
            query.push_str(&format!(" AND action_type = ${param_idx}"));
            param_idx += 1;
        }
        if filter.result.is_some() {
            query.push_str(&format!(" AND result = ${param_idx}"));
            param_idx += 1;
        }
        if filter.executed_by.is_some() {
            query.push_str(&format!(" AND executed_by = ${param_idx}"));
            param_idx += 1;
        }
        if filter.dry_run.is_some() {
            query.push_str(&format!(" AND dry_run = ${param_idx}"));
            param_idx += 1;
        }
        if filter.since.is_some() {
            query.push_str(&format!(" AND executed_at >= ${param_idx}"));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(discrepancy_id) = filter.discrepancy_id {
            q = q.bind(discrepancy_id);
        }
        if let Some(ref action_type) = filter.action_type {
            q = q.bind(action_type.to_string());
        }
        if let Some(ref result) = filter.result {
            q = q.bind(result.to_string());
        }
        if let Some(executed_by) = filter.executed_by {
            q = q.bind(executed_by);
        }
        if let Some(dry_run) = filter.dry_run {
            q = q.bind(dry_run);
        }
        if let Some(since) = filter.since {
            q = q.bind(since);
        }

        q.fetch_one(pool).await
    }

    /// Count actions by type for statistics.
    pub async fn count_by_type(
        pool: &PgPool,
        tenant_id: Uuid,
        since: Option<DateTime<Utc>>,
    ) -> Result<Vec<(String, i64)>, sqlx::Error> {
        if let Some(since) = since {
            sqlx::query_as(
                r"
                SELECT action_type, COUNT(*) as count
                FROM gov_reconciliation_actions
                WHERE tenant_id = $1 AND executed_at >= $2
                GROUP BY action_type
                ",
            )
            .bind(tenant_id)
            .bind(since)
            .fetch_all(pool)
            .await
        } else {
            sqlx::query_as(
                r"
                SELECT action_type, COUNT(*) as count
                FROM gov_reconciliation_actions
                WHERE tenant_id = $1
                GROUP BY action_type
                ",
            )
            .bind(tenant_id)
            .fetch_all(pool)
            .await
        }
    }

    /// Count actions by result for statistics.
    pub async fn count_by_result(
        pool: &PgPool,
        tenant_id: Uuid,
        since: Option<DateTime<Utc>>,
    ) -> Result<Vec<(String, i64)>, sqlx::Error> {
        if let Some(since) = since {
            sqlx::query_as(
                r"
                SELECT result, COUNT(*) as count
                FROM gov_reconciliation_actions
                WHERE tenant_id = $1 AND executed_at >= $2
                GROUP BY result
                ",
            )
            .bind(tenant_id)
            .bind(since)
            .fetch_all(pool)
            .await
        } else {
            sqlx::query_as(
                r"
                SELECT result, COUNT(*) as count
                FROM gov_reconciliation_actions
                WHERE tenant_id = $1
                GROUP BY result
                ",
            )
            .bind(tenant_id)
            .fetch_all(pool)
            .await
        }
    }
}

/// Input for creating an action record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateReconciliationAction {
    pub discrepancy_id: Uuid,
    pub action_type: ReconciliationActionType,
    pub executed_by: Uuid,
    pub result: ReconciliationActionResult,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before_state: Option<JsonValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after_state: Option<JsonValue>,
    #[serde(default)]
    pub dry_run: bool,
}

impl CreateReconciliationAction {
    /// Create a success action record.
    #[must_use]
    pub fn success(
        discrepancy_id: Uuid,
        action_type: ReconciliationActionType,
        executed_by: Uuid,
        dry_run: bool,
    ) -> Self {
        Self {
            discrepancy_id,
            action_type,
            executed_by,
            result: ReconciliationActionResult::Success,
            error_message: None,
            before_state: None,
            after_state: None,
            dry_run,
        }
    }

    /// Create a failure action record.
    #[must_use]
    pub fn failure(
        discrepancy_id: Uuid,
        action_type: ReconciliationActionType,
        executed_by: Uuid,
        error: String,
        dry_run: bool,
    ) -> Self {
        Self {
            discrepancy_id,
            action_type,
            executed_by,
            result: ReconciliationActionResult::Failure,
            error_message: Some(error),
            before_state: None,
            after_state: None,
            dry_run,
        }
    }

    /// Add before state.
    #[must_use]
    pub fn with_before_state(mut self, state: JsonValue) -> Self {
        self.before_state = Some(state);
        self
    }

    /// Add after state.
    #[must_use]
    pub fn with_after_state(mut self, state: JsonValue) -> Self {
        self.after_state = Some(state);
        self
    }
}

/// Filter for listing actions.
#[derive(Debug, Clone, Default)]
pub struct ReconciliationActionFilter {
    pub discrepancy_id: Option<Uuid>,
    pub action_type: Option<ReconciliationActionType>,
    pub result: Option<ReconciliationActionResult>,
    pub executed_by: Option<Uuid>,
    pub dry_run: Option<bool>,
    pub since: Option<DateTime<Utc>>,
}

impl ReconciliationActionFilter {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn for_discrepancy(mut self, discrepancy_id: Uuid) -> Self {
        self.discrepancy_id = Some(discrepancy_id);
        self
    }

    #[must_use]
    pub fn with_type(mut self, action_type: ReconciliationActionType) -> Self {
        self.action_type = Some(action_type);
        self
    }

    #[must_use]
    pub fn successful_only(mut self) -> Self {
        self.result = Some(ReconciliationActionResult::Success);
        self
    }

    #[must_use]
    pub fn exclude_dry_run(mut self) -> Self {
        self.dry_run = Some(false);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_result_roundtrip() {
        for result in [
            ReconciliationActionResult::Success,
            ReconciliationActionResult::Failure,
        ] {
            let s = result.to_string();
            let parsed: ReconciliationActionResult = s.parse().unwrap();
            assert_eq!(result, parsed);
        }
    }

    #[test]
    fn test_create_success() {
        let action = CreateReconciliationAction::success(
            Uuid::new_v4(),
            ReconciliationActionType::Create,
            Uuid::new_v4(),
            false,
        );

        assert_eq!(action.result, ReconciliationActionResult::Success);
        assert!(action.error_message.is_none());
        assert!(!action.dry_run);
    }

    #[test]
    fn test_create_failure() {
        let action = CreateReconciliationAction::failure(
            Uuid::new_v4(),
            ReconciliationActionType::Delete,
            Uuid::new_v4(),
            "Connection refused".to_string(),
            false,
        );

        assert_eq!(action.result, ReconciliationActionResult::Failure);
        assert_eq!(action.error_message, Some("Connection refused".to_string()));
    }

    #[test]
    fn test_with_states() {
        let before = serde_json::json!({"email": "old@example.com"});
        let after = serde_json::json!({"email": "new@example.com"});

        let action = CreateReconciliationAction::success(
            Uuid::new_v4(),
            ReconciliationActionType::Update,
            Uuid::new_v4(),
            false,
        )
        .with_before_state(before.clone())
        .with_after_state(after.clone());

        assert_eq!(action.before_state, Some(before));
        assert_eq!(action.after_state, Some(after));
    }
}
