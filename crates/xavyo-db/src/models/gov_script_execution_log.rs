//! Script Execution Log model (F066).
//! Records every script execution for troubleshooting and analytics.

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use super::gov_script_types::{ExecutionStatus, GovHookPhase, ScriptOperationType};

/// A record of a single script execution during provisioning.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovScriptExecutionLog {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant this log entry belongs to.
    pub tenant_id: Uuid,

    /// The script that was executed (nullable - SET NULL on script delete).
    pub script_id: Option<Uuid>,

    /// The binding that triggered the execution (nullable - SET NULL on binding delete).
    pub binding_id: Option<Uuid>,

    /// The connector the script ran against.
    pub connector_id: Uuid,

    /// Version of the script that was executed.
    pub script_version: i32,

    /// Hook phase (before or after the provisioning operation).
    pub hook_phase: GovHookPhase,

    /// Type of provisioning operation that triggered execution.
    pub operation_type: ScriptOperationType,

    /// Outcome of the execution.
    pub execution_status: ExecutionStatus,

    /// Input context provided to the script.
    pub input_context: Option<serde_json::Value>,

    /// Output result from the script.
    pub output_result: Option<serde_json::Value>,

    /// Error message if execution failed.
    pub error_message: Option<String>,

    /// Execution duration in milliseconds.
    pub duration_ms: i64,

    /// Whether this was a dry run (no side effects).
    pub dry_run: bool,

    /// When the execution occurred.
    pub executed_at: DateTime<Utc>,
}

/// Request to create a new execution log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateExecutionLog {
    pub tenant_id: Uuid,
    pub script_id: Option<Uuid>,
    pub binding_id: Option<Uuid>,
    pub connector_id: Uuid,
    pub script_version: i32,
    pub hook_phase: GovHookPhase,
    pub operation_type: ScriptOperationType,
    pub execution_status: ExecutionStatus,
    pub input_context: Option<serde_json::Value>,
    pub output_result: Option<serde_json::Value>,
    pub error_message: Option<String>,
    pub duration_ms: i64,
    pub dry_run: bool,
}

/// Filter options for listing execution logs.
#[derive(Debug, Clone, Default)]
pub struct ExecutionLogFilter {
    pub script_id: Option<Uuid>,
    pub connector_id: Option<Uuid>,
    pub binding_id: Option<Uuid>,
    pub execution_status: Option<ExecutionStatus>,
    pub dry_run: Option<bool>,
    pub from_date: Option<DateTime<Utc>>,
    pub to_date: Option<DateTime<Utc>>,
}

/// Aggregate dashboard statistics for script executions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardStats {
    pub total_executions: i64,
    pub success_count: i64,
    pub failure_count: i64,
    pub timeout_count: i64,
    pub avg_duration_ms: f64,
}

/// Raw row for dashboard stats query.
#[derive(Debug, FromRow)]
struct DashboardStatsRow {
    total_executions: Option<i64>,
    success_count: Option<i64>,
    failure_count: Option<i64>,
    timeout_count: Option<i64>,
    avg_duration_ms: Option<f64>,
}

/// Per-script aggregate statistics.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct ScriptStats {
    pub script_id: Option<Uuid>,
    pub total_executions: i64,
    pub success_count: i64,
    pub failure_count: i64,
    pub avg_duration_ms: f64,
}

/// Raw row for per-script stats query.
#[derive(Debug, FromRow)]
struct ScriptStatsRow {
    script_id: Option<Uuid>,
    total_executions: Option<i64>,
    success_count: Option<i64>,
    failure_count: Option<i64>,
    avg_duration_ms: Option<f64>,
}

/// Daily trend data point for a script.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DailyTrendRow {
    pub date: NaiveDate,
    pub executions: i64,
    pub successes: i64,
    pub failures: i64,
    pub avg_duration_ms: f64,
}

/// Raw row for daily trends query.
#[derive(Debug, FromRow)]
struct DailyTrendRawRow {
    date: Option<NaiveDate>,
    executions: Option<i64>,
    successes: Option<i64>,
    failures: Option<i64>,
    avg_duration_ms: Option<f64>,
}

impl GovScriptExecutionLog {
    /// Create a new execution log entry.
    pub async fn create(
        pool: &sqlx::PgPool,
        params: CreateExecutionLog,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r#"
            INSERT INTO gov_script_execution_logs (
                tenant_id, script_id, binding_id, connector_id,
                script_version, hook_phase, operation_type, execution_status,
                input_context, output_result, error_message,
                duration_ms, dry_run
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            RETURNING *
            "#,
        )
        .bind(params.tenant_id)
        .bind(params.script_id)
        .bind(params.binding_id)
        .bind(params.connector_id)
        .bind(params.script_version)
        .bind(params.hook_phase)
        .bind(params.operation_type)
        .bind(params.execution_status)
        .bind(&params.input_context)
        .bind(&params.output_result)
        .bind(&params.error_message)
        .bind(params.duration_ms)
        .bind(params.dry_run)
        .fetch_one(pool)
        .await
    }

    /// Find by ID within a tenant.
    pub async fn get_by_id(
        pool: &sqlx::PgPool,
        id: Uuid,
        tenant_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_script_execution_logs
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List execution logs for a tenant with dynamic filtering, ordered by executed_at DESC.
    ///
    /// Returns a tuple of (rows, total_count) for pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &ExecutionLogFilter,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<Self>, i64), sqlx::Error> {
        let mut where_clause = String::from("WHERE tenant_id = $1");
        let mut param_count = 1;

        if filter.script_id.is_some() {
            param_count += 1;
            where_clause.push_str(&format!(" AND script_id = ${}", param_count));
        }
        if filter.connector_id.is_some() {
            param_count += 1;
            where_clause.push_str(&format!(" AND connector_id = ${}", param_count));
        }
        if filter.binding_id.is_some() {
            param_count += 1;
            where_clause.push_str(&format!(" AND binding_id = ${}", param_count));
        }
        if filter.execution_status.is_some() {
            param_count += 1;
            where_clause.push_str(&format!(" AND execution_status = ${}", param_count));
        }
        if filter.dry_run.is_some() {
            param_count += 1;
            where_clause.push_str(&format!(" AND dry_run = ${}", param_count));
        }
        if filter.from_date.is_some() {
            param_count += 1;
            where_clause.push_str(&format!(" AND executed_at >= ${}", param_count));
        }
        if filter.to_date.is_some() {
            param_count += 1;
            where_clause.push_str(&format!(" AND executed_at <= ${}", param_count));
        }

        // Count query
        let count_query = format!(
            "SELECT COUNT(*) FROM gov_script_execution_logs {}",
            where_clause
        );

        let mut count_q = sqlx::query_scalar::<_, i64>(&count_query).bind(tenant_id);

        if let Some(script_id) = filter.script_id {
            count_q = count_q.bind(script_id);
        }
        if let Some(connector_id) = filter.connector_id {
            count_q = count_q.bind(connector_id);
        }
        if let Some(binding_id) = filter.binding_id {
            count_q = count_q.bind(binding_id);
        }
        if let Some(execution_status) = filter.execution_status {
            count_q = count_q.bind(execution_status);
        }
        if let Some(dry_run) = filter.dry_run {
            count_q = count_q.bind(dry_run);
        }
        if let Some(from_date) = filter.from_date {
            count_q = count_q.bind(from_date);
        }
        if let Some(to_date) = filter.to_date {
            count_q = count_q.bind(to_date);
        }

        let total = count_q.fetch_one(pool).await?;

        // Data query
        let data_query = format!(
            "SELECT * FROM gov_script_execution_logs {} ORDER BY executed_at DESC LIMIT ${} OFFSET ${}",
            where_clause,
            param_count + 1,
            param_count + 2
        );

        let mut data_q = sqlx::query_as::<_, Self>(&data_query).bind(tenant_id);

        if let Some(script_id) = filter.script_id {
            data_q = data_q.bind(script_id);
        }
        if let Some(connector_id) = filter.connector_id {
            data_q = data_q.bind(connector_id);
        }
        if let Some(binding_id) = filter.binding_id {
            data_q = data_q.bind(binding_id);
        }
        if let Some(execution_status) = filter.execution_status {
            data_q = data_q.bind(execution_status);
        }
        if let Some(dry_run) = filter.dry_run {
            data_q = data_q.bind(dry_run);
        }
        if let Some(from_date) = filter.from_date {
            data_q = data_q.bind(from_date);
        }
        if let Some(to_date) = filter.to_date {
            data_q = data_q.bind(to_date);
        }

        let rows = data_q.bind(limit).bind(offset).fetch_all(pool).await?;

        Ok((rows, total))
    }

    /// List execution logs for a specific script, ordered by executed_at DESC.
    ///
    /// Returns a tuple of (rows, total_count) for pagination.
    pub async fn list_by_script(
        pool: &sqlx::PgPool,
        script_id: Uuid,
        tenant_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<Self>, i64), sqlx::Error> {
        let total: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM gov_script_execution_logs
            WHERE script_id = $1 AND tenant_id = $2
            "#,
        )
        .bind(script_id)
        .bind(tenant_id)
        .fetch_one(pool)
        .await?;

        let rows = sqlx::query_as(
            r#"
            SELECT * FROM gov_script_execution_logs
            WHERE script_id = $1 AND tenant_id = $2
            ORDER BY executed_at DESC
            LIMIT $3 OFFSET $4
            "#,
        )
        .bind(script_id)
        .bind(tenant_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?;

        Ok((rows, total))
    }

    /// Get aggregate dashboard statistics for a tenant since the given timestamp.
    pub async fn get_dashboard_stats(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        since: DateTime<Utc>,
    ) -> Result<DashboardStats, sqlx::Error> {
        let row = sqlx::query_as::<_, DashboardStatsRow>(
            r#"
            SELECT
                COUNT(*) AS total_executions,
                COUNT(*) FILTER (WHERE execution_status = 'success') AS success_count,
                COUNT(*) FILTER (WHERE execution_status = 'failure') AS failure_count,
                COUNT(*) FILTER (WHERE execution_status = 'timeout') AS timeout_count,
                AVG(duration_ms)::float8 AS avg_duration_ms
            FROM gov_script_execution_logs
            WHERE tenant_id = $1 AND executed_at >= $2
            "#,
        )
        .bind(tenant_id)
        .bind(since)
        .fetch_one(pool)
        .await?;

        Ok(DashboardStats {
            total_executions: row.total_executions.unwrap_or(0),
            success_count: row.success_count.unwrap_or(0),
            failure_count: row.failure_count.unwrap_or(0),
            timeout_count: row.timeout_count.unwrap_or(0),
            avg_duration_ms: row.avg_duration_ms.unwrap_or(0.0),
        })
    }

    /// Get per-script aggregate statistics for a tenant since the given timestamp.
    pub async fn get_per_script_stats(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        since: DateTime<Utc>,
    ) -> Result<Vec<ScriptStats>, sqlx::Error> {
        let rows = sqlx::query_as::<_, ScriptStatsRow>(
            r#"
            SELECT
                script_id,
                COUNT(*) AS total_executions,
                COUNT(*) FILTER (WHERE execution_status = 'success') AS success_count,
                COUNT(*) FILTER (WHERE execution_status = 'failure') AS failure_count,
                AVG(duration_ms)::float8 AS avg_duration_ms
            FROM gov_script_execution_logs
            WHERE tenant_id = $1 AND executed_at >= $2
            GROUP BY script_id
            ORDER BY total_executions DESC
            "#,
        )
        .bind(tenant_id)
        .bind(since)
        .fetch_all(pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| ScriptStats {
                script_id: r.script_id,
                total_executions: r.total_executions.unwrap_or(0),
                success_count: r.success_count.unwrap_or(0),
                failure_count: r.failure_count.unwrap_or(0),
                avg_duration_ms: r.avg_duration_ms.unwrap_or(0.0),
            })
            .collect())
    }

    /// Get daily trend aggregates for a specific script over a given number of days.
    pub async fn get_daily_trends(
        pool: &sqlx::PgPool,
        script_id: Uuid,
        tenant_id: Uuid,
        days: i32,
    ) -> Result<Vec<DailyTrendRow>, sqlx::Error> {
        let rows = sqlx::query_as::<_, DailyTrendRawRow>(
            r#"
            SELECT
                DATE(executed_at) AS date,
                COUNT(*) AS executions,
                COUNT(*) FILTER (WHERE execution_status = 'success') AS successes,
                COUNT(*) FILTER (WHERE execution_status = 'failure') AS failures,
                AVG(duration_ms)::float8 AS avg_duration_ms
            FROM gov_script_execution_logs
            WHERE script_id = $1
              AND tenant_id = $2
              AND executed_at >= NOW() - ($3 || ' days')::interval
            GROUP BY DATE(executed_at)
            ORDER BY date ASC
            "#,
        )
        .bind(script_id)
        .bind(tenant_id)
        .bind(days)
        .fetch_all(pool)
        .await?;

        Ok(rows
            .into_iter()
            .filter_map(|r| {
                r.date.map(|d| DailyTrendRow {
                    date: d,
                    executions: r.executions.unwrap_or(0),
                    successes: r.successes.unwrap_or(0),
                    failures: r.failures.unwrap_or(0),
                    avg_duration_ms: r.avg_duration_ms.unwrap_or(0.0),
                })
            })
            .collect())
    }

    /// Get the error rate for a specific script since the given timestamp.
    ///
    /// Returns a value between 0.0 and 1.0, or 0.0 if there are no executions.
    pub async fn get_error_rate(
        pool: &sqlx::PgPool,
        script_id: Uuid,
        tenant_id: Uuid,
        since: DateTime<Utc>,
    ) -> Result<f64, sqlx::Error> {
        let rate: Option<f64> = sqlx::query_scalar(
            r#"
            SELECT
                CASE
                    WHEN COUNT(*) = 0 THEN 0.0
                    ELSE COUNT(*) FILTER (WHERE execution_status IN ('failure', 'timeout'))::float8 / COUNT(*)::float8
                END AS error_rate
            FROM gov_script_execution_logs
            WHERE script_id = $1
              AND tenant_id = $2
              AND executed_at >= $3
            "#,
        )
        .bind(script_id)
        .bind(tenant_id)
        .bind(since)
        .fetch_one(pool)
        .await?;

        Ok(rate.unwrap_or(0.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_execution_log_input() {
        let input = CreateExecutionLog {
            tenant_id: Uuid::new_v4(),
            script_id: Some(Uuid::new_v4()),
            binding_id: Some(Uuid::new_v4()),
            connector_id: Uuid::new_v4(),
            script_version: 1,
            hook_phase: GovHookPhase::Before,
            operation_type: ScriptOperationType::Create,
            execution_status: ExecutionStatus::Success,
            input_context: Some(serde_json::json!({"user": "test"})),
            output_result: Some(serde_json::json!({"transformed": true})),
            error_message: None,
            duration_ms: 42,
            dry_run: false,
        };

        assert_eq!(input.script_version, 1);
        assert_eq!(input.execution_status, ExecutionStatus::Success);
        assert_eq!(input.duration_ms, 42);
        assert!(!input.dry_run);
    }

    #[test]
    fn test_create_execution_log_nullable_fields() {
        let input = CreateExecutionLog {
            tenant_id: Uuid::new_v4(),
            script_id: None,
            binding_id: None,
            connector_id: Uuid::new_v4(),
            script_version: 2,
            hook_phase: GovHookPhase::After,
            operation_type: ScriptOperationType::Delete,
            execution_status: ExecutionStatus::Failure,
            input_context: None,
            output_result: None,
            error_message: Some("runtime error".to_string()),
            duration_ms: 100,
            dry_run: true,
        };

        assert!(input.script_id.is_none());
        assert!(input.binding_id.is_none());
        assert_eq!(input.error_message.as_deref(), Some("runtime error"));
        assert!(input.dry_run);
    }

    #[test]
    fn test_execution_log_filter_default() {
        let filter = ExecutionLogFilter::default();

        assert!(filter.script_id.is_none());
        assert!(filter.connector_id.is_none());
        assert!(filter.binding_id.is_none());
        assert!(filter.execution_status.is_none());
        assert!(filter.dry_run.is_none());
        assert!(filter.from_date.is_none());
        assert!(filter.to_date.is_none());
    }

    #[test]
    fn test_dashboard_stats() {
        let stats = DashboardStats {
            total_executions: 100,
            success_count: 85,
            failure_count: 10,
            timeout_count: 5,
            avg_duration_ms: 45.5,
        };

        assert_eq!(stats.total_executions, 100);
        assert_eq!(stats.success_count, 85);
        assert_eq!(stats.failure_count, 10);
        assert_eq!(stats.timeout_count, 5);
        assert!((stats.avg_duration_ms - 45.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_script_stats() {
        let stats = ScriptStats {
            script_id: Some(Uuid::new_v4()),
            total_executions: 50,
            success_count: 45,
            failure_count: 5,
            avg_duration_ms: 30.0,
        };

        assert!(stats.script_id.is_some());
        assert_eq!(stats.total_executions, 50);
    }

    #[test]
    fn test_daily_trend_row() {
        let trend = DailyTrendRow {
            date: NaiveDate::from_ymd_opt(2026, 1, 27).unwrap(),
            executions: 20,
            successes: 18,
            failures: 2,
            avg_duration_ms: 55.0,
        };

        assert_eq!(trend.date.to_string(), "2026-01-27");
        assert_eq!(trend.executions, 20);
        assert_eq!(trend.successes, 18);
        assert_eq!(trend.failures, 2);
    }
}
