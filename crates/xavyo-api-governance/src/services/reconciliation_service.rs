//! Reconciliation service for orphan account detection.
//!
//! Provides reconciliation run management and orphan detection logic.

use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::{
    CreateGovOrphanDetection, CreateGovReconciliationRun, DetectionReason, GovDetectionRule,
    GovLifecycleEvent, GovOrphanDetection, GovReconciliationRun, GovServiceAccount,
    LifecycleEventFilter, LifecycleEventType, LoginAttempt, OrphanDetectionFilter, OrphanStatus,
    ReconciliationRunFilter, ReconciliationStatus,
};
use xavyo_governance::error::{GovernanceError, Result};

use crate::models::{
    ListReconciliationRunsQuery, ReconciliationRunListResponse, ReconciliationRunResponse,
    ReconciliationScheduleResponse, ScheduleFrequency, UpsertScheduleRequest,
};

/// Default batch size for processing users.
const DEFAULT_BATCH_SIZE: i64 = 500;

/// Minimal user info needed for detection.
#[derive(Debug, Clone, sqlx::FromRow)]
struct UserInfo {
    id: Uuid,
    manager_id: Option<Uuid>,
    #[allow(dead_code)]
    created_at: chrono::DateTime<Utc>,
}

/// Service for reconciliation operations.
pub struct ReconciliationService {
    pool: PgPool,
    batch_size: i64,
}

impl ReconciliationService {
    /// Create a new reconciliation service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            batch_size: DEFAULT_BATCH_SIZE,
        }
    }

    /// Create with custom batch size.
    #[must_use]
    pub fn with_batch_size(pool: PgPool, batch_size: i64) -> Self {
        Self { pool, batch_size }
    }

    /// Trigger a new reconciliation run.
    ///
    /// Returns an error if a reconciliation is already running.
    pub async fn trigger_reconciliation(
        &self,
        tenant_id: Uuid,
        triggered_by: Option<Uuid>,
    ) -> Result<ReconciliationRunResponse> {
        // Check if there's already a running reconciliation
        if let Some(running) = GovReconciliationRun::find_running(&self.pool, tenant_id)
            .await
            .map_err(GovernanceError::Database)?
        {
            // A reconciliation is already running
            tracing::warn!(
                tenant_id = %tenant_id,
                run_id = %running.id,
                "Reconciliation already running"
            );
            return Err(GovernanceError::ReconciliationAlreadyRunning);
        }

        // Create the run record
        let run = GovReconciliationRun::create(
            &self.pool,
            tenant_id,
            CreateGovReconciliationRun { triggered_by },
        )
        .await
        .map_err(GovernanceError::Database)?;

        tracing::info!(
            tenant_id = %tenant_id,
            run_id = %run.id,
            triggered_by = ?triggered_by,
            "Started reconciliation run"
        );

        // Spawn the detection task
        let pool = self.pool.clone();
        let batch_size = self.batch_size;
        let run_id = run.id;

        tokio::spawn(async move {
            if let Err(e) = Self::execute_detection(pool, tenant_id, run_id, batch_size).await {
                tracing::error!(
                    tenant_id = %tenant_id,
                    run_id = %run_id,
                    error = %e,
                    "Reconciliation run failed"
                );
            }
        });

        Ok(ReconciliationRunResponse::from(run))
    }

    /// Execute the detection process.
    async fn execute_detection(
        pool: PgPool,
        tenant_id: Uuid,
        run_id: Uuid,
        batch_size: i64,
    ) -> Result<()> {
        let mut total_accounts = 0i32;
        let mut orphans_found = 0i32;
        let mut new_orphans = 0i32;
        let mut offset = 0i64;

        // Get enabled detection rules
        let rules = GovDetectionRule::list_enabled(&pool, tenant_id)
            .await
            .map_err(GovernanceError::Database)?;

        // Get service account user IDs for exclusion
        let service_account_ids = GovServiceAccount::get_all_user_ids(&pool, tenant_id)
            .await
            .map_err(GovernanceError::Database)?;

        // Process users in batches
        loop {
            let users: Vec<UserInfo> = sqlx::query_as(
                r"
                SELECT id, manager_id, created_at
                FROM users
                WHERE tenant_id = $1
                ORDER BY id
                LIMIT $2 OFFSET $3
                ",
            )
            .bind(tenant_id)
            .bind(batch_size)
            .bind(offset)
            .fetch_all(&pool)
            .await
            .map_err(GovernanceError::Database)?;

            if users.is_empty() {
                break;
            }

            let batch_count = users.len() as i32;
            total_accounts += batch_count;

            for user in users {
                // Skip service accounts
                if service_account_ids.contains(&user.id) {
                    continue;
                }

                // Check each rule
                for rule in &rules {
                    if let Some(reason) = Self::check_rule(&pool, tenant_id, &user, rule).await? {
                        // Check if there's already an active detection for this user
                        let existing =
                            GovOrphanDetection::find_active_for_user(&pool, tenant_id, user.id)
                                .await
                                .map_err(GovernanceError::Database)?;

                        if existing.is_none() {
                            // Create new detection
                            let days_inactive = if reason == DetectionReason::Inactive {
                                Self::calculate_days_inactive(&pool, tenant_id, user.id)
                                    .await
                                    .ok()
                            } else {
                                None
                            };

                            let last_activity = Self::get_last_activity(&pool, tenant_id, user.id)
                                .await
                                .ok();

                            GovOrphanDetection::create(
                                &pool,
                                tenant_id,
                                CreateGovOrphanDetection {
                                    user_id: user.id,
                                    run_id,
                                    detection_reason: reason,
                                    last_activity_at: last_activity,
                                    days_inactive: days_inactive.map(|d| d as i32),
                                },
                            )
                            .await
                            .map_err(GovernanceError::Database)?;

                            new_orphans += 1;
                        }
                        orphans_found += 1;
                        break; // Only count once per user
                    }
                }
            }

            // Update progress
            let progress = ((offset + i64::from(batch_count)) * 100 / (offset + batch_size).max(1))
                .min(99) as i32;

            GovReconciliationRun::update_progress(
                &pool,
                tenant_id,
                run_id,
                progress,
                total_accounts,
                orphans_found,
            )
            .await
            .map_err(GovernanceError::Database)?;

            offset += batch_size;
        }

        // Check for resolved orphans (previously detected but no longer orphan)
        let resolved_orphans = Self::check_resolved_orphans(&pool, tenant_id, run_id).await? as i32;

        // Mark run as completed
        GovReconciliationRun::mark_completed(
            &pool,
            tenant_id,
            run_id,
            total_accounts,
            orphans_found,
            new_orphans,
            resolved_orphans,
        )
        .await
        .map_err(GovernanceError::Database)?;

        tracing::info!(
            tenant_id = %tenant_id,
            run_id = %run_id,
            total_accounts = total_accounts,
            orphans_found = orphans_found,
            new_orphans = new_orphans,
            resolved_orphans = resolved_orphans,
            "Reconciliation run completed"
        );

        Ok(())
    }

    /// Check a single rule against a user.
    async fn check_rule(
        pool: &PgPool,
        tenant_id: Uuid,
        user: &UserInfo,
        rule: &GovDetectionRule,
    ) -> Result<Option<DetectionReason>> {
        match rule.rule_type {
            xavyo_db::DetectionRuleType::NoManager => Self::check_no_manager_rule(user).await,
            xavyo_db::DetectionRuleType::Terminated => {
                Self::check_terminated_rule(pool, tenant_id, user).await
            }
            xavyo_db::DetectionRuleType::Inactive => {
                let days_threshold = rule
                    .parameters
                    .get("days_threshold")
                    .and_then(serde_json::Value::as_i64)
                    .unwrap_or(90) as i32;
                Self::check_inactive_rule(pool, tenant_id, user, days_threshold).await
            }
            xavyo_db::DetectionRuleType::Custom => {
                // Custom rules not implemented yet
                Ok(None)
            }
        }
    }

    /// Check if user has no manager assigned.
    async fn check_no_manager_rule(user: &UserInfo) -> Result<Option<DetectionReason>> {
        if user.manager_id.is_none() {
            Ok(Some(DetectionReason::NoManager))
        } else {
            Ok(None)
        }
    }

    /// Check if user is marked as terminated in HR/lifecycle events.
    async fn check_terminated_rule(
        pool: &PgPool,
        tenant_id: Uuid,
        user: &UserInfo,
    ) -> Result<Option<DetectionReason>> {
        // Check for a 'leave' lifecycle event that is processed
        let filter = LifecycleEventFilter {
            user_id: Some(user.id),
            event_type: Some(LifecycleEventType::Leaver),
            processed: Some(true),
            ..Default::default()
        };

        let events = GovLifecycleEvent::list_by_tenant(pool, tenant_id, &filter, 1, 0)
            .await
            .map_err(GovernanceError::Database)?;

        if events.is_empty() {
            Ok(None)
        } else {
            Ok(Some(DetectionReason::TerminatedEmployee))
        }
    }

    /// Check if user has been inactive for more than threshold days.
    async fn check_inactive_rule(
        pool: &PgPool,
        tenant_id: Uuid,
        user: &UserInfo,
        days_threshold: i32,
    ) -> Result<Option<DetectionReason>> {
        let days_inactive = Self::calculate_days_inactive(pool, tenant_id, user.id).await?;

        if days_inactive >= i64::from(days_threshold) {
            Ok(Some(DetectionReason::Inactive))
        } else {
            Ok(None)
        }
    }

    /// Calculate days since last activity for a user.
    async fn calculate_days_inactive(pool: &PgPool, tenant_id: Uuid, user_id: Uuid) -> Result<i64> {
        // Get the most recent successful login attempt
        let last_logins = LoginAttempt::get_user_history_filtered(
            pool,
            tenant_id,
            user_id,
            Some(true), // success = true
            None,       // start_date
            None,       // end_date
            None,       // cursor
            1,          // limit - just need the most recent
        )
        .await
        .map_err(GovernanceError::Database)?;

        let last_activity = last_logins
            .first()
            .map(|l| l.created_at)
            .unwrap_or_else(|| {
                // If no login history, use user creation date
                Utc::now() - chrono::Duration::days(365) // Default to 365 days ago if unknown
            });

        let days = Utc::now().signed_duration_since(last_activity).num_days();

        Ok(days)
    }

    /// Get the last activity timestamp for a user.
    async fn get_last_activity(
        pool: &PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<chrono::DateTime<Utc>> {
        let last_logins = LoginAttempt::get_user_history_filtered(
            pool,
            tenant_id,
            user_id,
            Some(true), // success = true
            None,       // start_date
            None,       // end_date
            None,       // cursor
            1,          // limit
        )
        .await
        .map_err(GovernanceError::Database)?;

        Ok(last_logins.first().map_or_else(Utc::now, |l| l.created_at))
    }

    /// Check for orphans that have been resolved.
    async fn check_resolved_orphans(
        pool: &PgPool,
        tenant_id: Uuid,
        current_run_id: Uuid,
    ) -> Result<u64> {
        // Get all active orphan detections from previous runs
        let filter = OrphanDetectionFilter {
            status: Some(OrphanStatus::Pending),
            ..Default::default()
        };

        let active_detections = GovOrphanDetection::list(pool, tenant_id, &filter, 10000, 0)
            .await
            .map_err(GovernanceError::Database)?;

        let mut resolved_count = 0u64;

        for detection in active_detections {
            // Skip if from current run
            if detection.run_id == current_run_id {
                continue;
            }

            // Re-check if user is still an orphan - fetch user info directly
            let user: Option<UserInfo> = sqlx::query_as(
                r"
                SELECT id, manager_id, created_at
                FROM users
                WHERE tenant_id = $1 AND id = $2
                ",
            )
            .bind(tenant_id)
            .bind(detection.user_id)
            .fetch_optional(pool)
            .await
            .map_err(GovernanceError::Database)?;

            if let Some(user) = user {
                let rules = GovDetectionRule::list_enabled(pool, tenant_id)
                    .await
                    .map_err(GovernanceError::Database)?;

                let mut still_orphan = false;
                for rule in &rules {
                    if Self::check_rule(pool, tenant_id, &user, rule)
                        .await?
                        .is_some()
                    {
                        still_orphan = true;
                        break;
                    }
                }

                if !still_orphan {
                    // Mark as resolved
                    let count = GovOrphanDetection::mark_resolved_for_user(
                        pool,
                        tenant_id,
                        detection.user_id,
                        current_run_id,
                    )
                    .await
                    .map_err(GovernanceError::Database)?;
                    resolved_count += count;
                }
            }
        }

        Ok(resolved_count)
    }

    /// Get a reconciliation run by ID.
    pub async fn get_run(
        &self,
        tenant_id: Uuid,
        run_id: Uuid,
    ) -> Result<ReconciliationRunResponse> {
        let run = GovReconciliationRun::find_by_id(&self.pool, tenant_id, run_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::ReconciliationRunNotFound(run_id))?;

        Ok(ReconciliationRunResponse::from(run))
    }

    /// List reconciliation runs with filtering.
    pub async fn list_runs(
        &self,
        tenant_id: Uuid,
        query: &ListReconciliationRunsQuery,
    ) -> Result<ReconciliationRunListResponse> {
        let filter = ReconciliationRunFilter {
            status: query.status,
            triggered_by: query.triggered_by,
            since: query.since,
        };

        let limit = query.limit.unwrap_or(20);
        let offset = query.offset.unwrap_or(0);

        let runs = GovReconciliationRun::list(&self.pool, tenant_id, &filter, limit, offset)
            .await
            .map_err(GovernanceError::Database)?;

        let total = GovReconciliationRun::count(&self.pool, tenant_id, &filter)
            .await
            .map_err(GovernanceError::Database)?;

        Ok(ReconciliationRunListResponse {
            items: runs
                .into_iter()
                .map(ReconciliationRunResponse::from)
                .collect(),
            total,
            limit,
            offset,
        })
    }

    /// Cancel a running reconciliation.
    pub async fn cancel_run(
        &self,
        tenant_id: Uuid,
        run_id: Uuid,
    ) -> Result<ReconciliationRunResponse> {
        let run = GovReconciliationRun::find_by_id(&self.pool, tenant_id, run_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::ReconciliationRunNotFound(run_id))?;

        if run.status != ReconciliationStatus::Running {
            return Err(GovernanceError::CannotCancelNonRunningReconciliation);
        }

        let cancelled = GovReconciliationRun::cancel(&self.pool, tenant_id, run_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::ReconciliationRunNotFound(run_id))?;

        tracing::info!(
            tenant_id = %tenant_id,
            run_id = %run_id,
            "Reconciliation run cancelled"
        );

        Ok(ReconciliationRunResponse::from(cancelled))
    }

    // =========================================================================
    // Schedule Management
    // =========================================================================

    /// Get the current reconciliation schedule for a tenant.
    pub async fn get_schedule(
        &self,
        tenant_id: Uuid,
    ) -> Result<Option<ReconciliationScheduleResponse>> {
        #[derive(sqlx::FromRow)]
        struct ScheduleRow {
            id: Uuid,
            frequency: String,
            day_of_week: Option<i32>,
            day_of_month: Option<i32>,
            hour_of_day: i32,
            is_enabled: bool,
            last_run_at: Option<chrono::DateTime<Utc>>,
            next_run_at: Option<chrono::DateTime<Utc>>,
            created_at: chrono::DateTime<Utc>,
            updated_at: chrono::DateTime<Utc>,
        }

        let row: Option<ScheduleRow> = sqlx::query_as(
            r"
            SELECT id, frequency, day_of_week, day_of_month, hour_of_day,
                   is_enabled, last_run_at, next_run_at, created_at, updated_at
            FROM gov_reconciliation_schedules
            WHERE tenant_id = $1
            ",
        )
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        Ok(row.map(|r| ReconciliationScheduleResponse {
            id: r.id,
            frequency: r.frequency,
            day_of_week: r.day_of_week,
            day_of_month: r.day_of_month,
            hour_of_day: r.hour_of_day,
            is_enabled: r.is_enabled,
            last_run_at: r.last_run_at,
            next_run_at: r.next_run_at,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }))
    }

    /// Create or update the reconciliation schedule for a tenant.
    pub async fn upsert_schedule(
        &self,
        tenant_id: Uuid,
        request: UpsertScheduleRequest,
    ) -> Result<ReconciliationScheduleResponse> {
        // Validate schedule parameters
        self.validate_schedule(&request)?;

        let frequency_str = match request.frequency {
            ScheduleFrequency::Daily => "daily",
            ScheduleFrequency::Weekly => "weekly",
            ScheduleFrequency::Monthly => "monthly",
        };

        // Calculate next run time
        let next_run_at = if request.is_enabled {
            Some(self.calculate_next_run(
                request.frequency,
                request.day_of_week,
                request.day_of_month,
                request.hour_of_day,
            ))
        } else {
            None
        };

        #[derive(sqlx::FromRow)]
        struct ScheduleRow {
            id: Uuid,
            frequency: String,
            day_of_week: Option<i32>,
            day_of_month: Option<i32>,
            hour_of_day: i32,
            is_enabled: bool,
            last_run_at: Option<chrono::DateTime<Utc>>,
            next_run_at: Option<chrono::DateTime<Utc>>,
            created_at: chrono::DateTime<Utc>,
            updated_at: chrono::DateTime<Utc>,
        }

        let row: ScheduleRow = sqlx::query_as(
            r"
            INSERT INTO gov_reconciliation_schedules (
                tenant_id, frequency, day_of_week, day_of_month, hour_of_day, is_enabled, next_run_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (tenant_id) DO UPDATE SET
                frequency = EXCLUDED.frequency,
                day_of_week = EXCLUDED.day_of_week,
                day_of_month = EXCLUDED.day_of_month,
                hour_of_day = EXCLUDED.hour_of_day,
                is_enabled = EXCLUDED.is_enabled,
                next_run_at = EXCLUDED.next_run_at,
                updated_at = NOW()
            RETURNING id, frequency, day_of_week, day_of_month, hour_of_day,
                      is_enabled, last_run_at, next_run_at, created_at, updated_at
            ",
        )
        .bind(tenant_id)
        .bind(frequency_str)
        .bind(request.day_of_week)
        .bind(request.day_of_month)
        .bind(request.hour_of_day)
        .bind(request.is_enabled)
        .bind(next_run_at)
        .fetch_one(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        tracing::info!(
            tenant_id = %tenant_id,
            frequency = frequency_str,
            is_enabled = request.is_enabled,
            "Reconciliation schedule updated"
        );

        Ok(ReconciliationScheduleResponse {
            id: row.id,
            frequency: row.frequency,
            day_of_week: row.day_of_week,
            day_of_month: row.day_of_month,
            hour_of_day: row.hour_of_day,
            is_enabled: row.is_enabled,
            last_run_at: row.last_run_at,
            next_run_at: row.next_run_at,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }

    /// Delete the reconciliation schedule for a tenant.
    pub async fn delete_schedule(&self, tenant_id: Uuid) -> Result<bool> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_reconciliation_schedules
            WHERE tenant_id = $1
            ",
        )
        .bind(tenant_id)
        .execute(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        let deleted = result.rows_affected() > 0;

        if deleted {
            tracing::info!(
                tenant_id = %tenant_id,
                "Reconciliation schedule deleted"
            );
        }

        Ok(deleted)
    }

    /// Trigger scheduled reconciliation runs (called by external scheduler).
    ///
    /// Returns the number of reconciliations triggered.
    pub async fn trigger_scheduled_runs(&self) -> Result<Vec<(Uuid, Uuid)>> {
        // Get all enabled schedules that are due
        #[derive(sqlx::FromRow)]
        struct DueSchedule {
            tenant_id: Uuid,
        }

        let due: Vec<DueSchedule> = sqlx::query_as(
            r"
            SELECT tenant_id
            FROM gov_reconciliation_schedules
            WHERE is_enabled = true
                AND (next_run_at IS NULL OR next_run_at <= NOW())
            ",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        let mut triggered = Vec::new();

        for schedule in due {
            // Try to trigger reconciliation
            match self.trigger_reconciliation(schedule.tenant_id, None).await {
                Ok(run) => {
                    // Update last_run_at and calculate next_run_at
                    self.update_schedule_after_run(schedule.tenant_id)
                        .await
                        .ok();
                    triggered.push((schedule.tenant_id, run.id));
                }
                Err(GovernanceError::ReconciliationAlreadyRunning) => {
                    // Skip if already running
                    tracing::debug!(
                        tenant_id = %schedule.tenant_id,
                        "Skipping scheduled run - already running"
                    );
                }
                Err(e) => {
                    tracing::error!(
                        tenant_id = %schedule.tenant_id,
                        error = %e,
                        "Failed to trigger scheduled reconciliation"
                    );
                }
            }
        }

        Ok(triggered)
    }

    /// Validate schedule parameters.
    fn validate_schedule(&self, request: &UpsertScheduleRequest) -> Result<()> {
        // Validate hour
        if request.hour_of_day < 0 || request.hour_of_day > 23 {
            return Err(GovernanceError::Validation(
                "hour_of_day must be between 0 and 23".to_string(),
            ));
        }

        // Validate day_of_week for weekly schedule
        if request.frequency == ScheduleFrequency::Weekly {
            if let Some(dow) = request.day_of_week {
                if !(0..=6).contains(&dow) {
                    return Err(GovernanceError::Validation(
                        "day_of_week must be between 0 (Sunday) and 6 (Saturday)".to_string(),
                    ));
                }
            }
        }

        // Validate day_of_month for monthly schedule
        if request.frequency == ScheduleFrequency::Monthly {
            if let Some(dom) = request.day_of_month {
                if !(1..=28).contains(&dom) {
                    return Err(GovernanceError::Validation(
                        "day_of_month must be between 1 and 28".to_string(),
                    ));
                }
            }
        }

        Ok(())
    }

    /// Calculate the next run time based on schedule.
    fn calculate_next_run(
        &self,
        frequency: ScheduleFrequency,
        day_of_week: Option<i32>,
        day_of_month: Option<i32>,
        hour_of_day: i32,
    ) -> chrono::DateTime<Utc> {
        use chrono::{Datelike, Duration, Timelike};

        let now = Utc::now();
        let target_hour = hour_of_day as u32;

        match frequency {
            ScheduleFrequency::Daily => {
                let mut next = now
                    .with_hour(target_hour)
                    .unwrap()
                    .with_minute(0)
                    .unwrap()
                    .with_second(0)
                    .unwrap();

                if next <= now {
                    next += Duration::days(1);
                }

                next
            }
            ScheduleFrequency::Weekly => {
                let target_dow = day_of_week.unwrap_or(0) as u32; // Sunday = 0
                let current_dow = now.weekday().num_days_from_sunday();

                let days_until = if target_dow > current_dow {
                    target_dow - current_dow
                } else if target_dow < current_dow {
                    7 - (current_dow - target_dow)
                } else {
                    // Same day - check if we've passed the time
                    let target_time = now
                        .with_hour(target_hour)
                        .unwrap()
                        .with_minute(0)
                        .unwrap()
                        .with_second(0)
                        .unwrap();

                    if now < target_time {
                        0
                    } else {
                        7
                    }
                };

                (now + Duration::days(i64::from(days_until)))
                    .with_hour(target_hour)
                    .unwrap()
                    .with_minute(0)
                    .unwrap()
                    .with_second(0)
                    .unwrap()
            }
            ScheduleFrequency::Monthly => {
                let target_day = day_of_month.unwrap_or(1) as u32;

                let mut next_month = now.month();
                let mut next_year = now.year();

                // Check if we can run this month
                if now.day() > target_day || (now.day() == target_day && now.hour() >= target_hour)
                {
                    // Move to next month
                    if next_month == 12 {
                        next_month = 1;
                        next_year += 1;
                    } else {
                        next_month += 1;
                    }
                }

                now.with_year(next_year)
                    .unwrap()
                    .with_month(next_month)
                    .unwrap()
                    .with_day(target_day)
                    .unwrap()
                    .with_hour(target_hour)
                    .unwrap()
                    .with_minute(0)
                    .unwrap()
                    .with_second(0)
                    .unwrap()
            }
        }
    }

    /// Update schedule after a run completes.
    async fn update_schedule_after_run(&self, tenant_id: Uuid) -> Result<()> {
        // First get the schedule to calculate next run
        if let Some(schedule) = self.get_schedule(tenant_id).await? {
            let frequency = match schedule.frequency.as_str() {
                "daily" => ScheduleFrequency::Daily,
                "weekly" => ScheduleFrequency::Weekly,
                "monthly" => ScheduleFrequency::Monthly,
                _ => ScheduleFrequency::Weekly,
            };

            let next_run_at = self.calculate_next_run(
                frequency,
                schedule.day_of_week,
                schedule.day_of_month,
                schedule.hour_of_day,
            );

            sqlx::query(
                r"
                UPDATE gov_reconciliation_schedules
                SET last_run_at = NOW(), next_run_at = $2
                WHERE tenant_id = $1
                ",
            )
            .bind(tenant_id)
            .bind(next_run_at)
            .execute(&self.pool)
            .await
            .map_err(GovernanceError::Database)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_batch_size() {
        assert_eq!(DEFAULT_BATCH_SIZE, 500);
    }

    // =========================================================================
    // Schedule Validation Tests
    // =========================================================================

    /// Helper to create a test UpsertScheduleRequest
    fn make_schedule_request(
        frequency: ScheduleFrequency,
        day_of_week: Option<i32>,
        day_of_month: Option<i32>,
        hour_of_day: i32,
    ) -> UpsertScheduleRequest {
        UpsertScheduleRequest {
            frequency,
            day_of_week,
            day_of_month,
            hour_of_day,
            is_enabled: true,
        }
    }

    /// Helper struct to test validate_schedule without needing a pool
    struct TestableScheduleValidator;

    impl TestableScheduleValidator {
        fn validate_schedule(request: &UpsertScheduleRequest) -> Result<()> {
            // Validate hour
            if request.hour_of_day < 0 || request.hour_of_day > 23 {
                return Err(GovernanceError::Validation(
                    "hour_of_day must be between 0 and 23".to_string(),
                ));
            }

            // Validate day_of_week for weekly schedule
            if request.frequency == ScheduleFrequency::Weekly {
                if let Some(dow) = request.day_of_week {
                    if !(0..=6).contains(&dow) {
                        return Err(GovernanceError::Validation(
                            "day_of_week must be between 0 (Sunday) and 6 (Saturday)".to_string(),
                        ));
                    }
                }
            }

            // Validate day_of_month for monthly schedule
            if request.frequency == ScheduleFrequency::Monthly {
                if let Some(dom) = request.day_of_month {
                    if !(1..=28).contains(&dom) {
                        return Err(GovernanceError::Validation(
                            "day_of_month must be between 1 and 28".to_string(),
                        ));
                    }
                }
            }

            Ok(())
        }
    }

    #[test]
    fn test_validate_schedule_daily_valid() {
        let request = make_schedule_request(ScheduleFrequency::Daily, None, None, 9);
        assert!(TestableScheduleValidator::validate_schedule(&request).is_ok());
    }

    #[test]
    fn test_validate_schedule_hour_min() {
        let request = make_schedule_request(ScheduleFrequency::Daily, None, None, 0);
        assert!(TestableScheduleValidator::validate_schedule(&request).is_ok());
    }

    #[test]
    fn test_validate_schedule_hour_max() {
        let request = make_schedule_request(ScheduleFrequency::Daily, None, None, 23);
        assert!(TestableScheduleValidator::validate_schedule(&request).is_ok());
    }

    #[test]
    fn test_validate_schedule_hour_too_low() {
        let request = make_schedule_request(ScheduleFrequency::Daily, None, None, -1);
        assert!(TestableScheduleValidator::validate_schedule(&request).is_err());
    }

    #[test]
    fn test_validate_schedule_hour_too_high() {
        let request = make_schedule_request(ScheduleFrequency::Daily, None, None, 24);
        assert!(TestableScheduleValidator::validate_schedule(&request).is_err());
    }

    #[test]
    fn test_validate_schedule_weekly_valid() {
        let request = make_schedule_request(ScheduleFrequency::Weekly, Some(1), None, 9);
        assert!(TestableScheduleValidator::validate_schedule(&request).is_ok());
    }

    #[test]
    fn test_validate_schedule_weekly_sunday() {
        let request = make_schedule_request(ScheduleFrequency::Weekly, Some(0), None, 9);
        assert!(TestableScheduleValidator::validate_schedule(&request).is_ok());
    }

    #[test]
    fn test_validate_schedule_weekly_saturday() {
        let request = make_schedule_request(ScheduleFrequency::Weekly, Some(6), None, 9);
        assert!(TestableScheduleValidator::validate_schedule(&request).is_ok());
    }

    #[test]
    fn test_validate_schedule_weekly_invalid_day() {
        let request = make_schedule_request(ScheduleFrequency::Weekly, Some(7), None, 9);
        assert!(TestableScheduleValidator::validate_schedule(&request).is_err());
    }

    #[test]
    fn test_validate_schedule_weekly_negative_day() {
        let request = make_schedule_request(ScheduleFrequency::Weekly, Some(-1), None, 9);
        assert!(TestableScheduleValidator::validate_schedule(&request).is_err());
    }

    #[test]
    fn test_validate_schedule_monthly_valid() {
        let request = make_schedule_request(ScheduleFrequency::Monthly, None, Some(15), 9);
        assert!(TestableScheduleValidator::validate_schedule(&request).is_ok());
    }

    #[test]
    fn test_validate_schedule_monthly_first_day() {
        let request = make_schedule_request(ScheduleFrequency::Monthly, None, Some(1), 9);
        assert!(TestableScheduleValidator::validate_schedule(&request).is_ok());
    }

    #[test]
    fn test_validate_schedule_monthly_day_28() {
        let request = make_schedule_request(ScheduleFrequency::Monthly, None, Some(28), 9);
        assert!(TestableScheduleValidator::validate_schedule(&request).is_ok());
    }

    #[test]
    fn test_validate_schedule_monthly_day_too_high() {
        let request = make_schedule_request(ScheduleFrequency::Monthly, None, Some(29), 9);
        assert!(TestableScheduleValidator::validate_schedule(&request).is_err());
    }

    #[test]
    fn test_validate_schedule_monthly_day_zero() {
        let request = make_schedule_request(ScheduleFrequency::Monthly, None, Some(0), 9);
        assert!(TestableScheduleValidator::validate_schedule(&request).is_err());
    }
}
