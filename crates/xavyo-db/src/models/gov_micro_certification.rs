//! Governance Micro-certification model (F055).
//!
//! Represents a single micro-certification item for just-in-time access review.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use super::{MicroCertDecision, MicroCertStatus};

/// A micro-certification item.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovMicroCertification {
    /// Unique identifier for the certification.
    pub id: Uuid,

    /// The tenant this certification belongs to.
    pub tenant_id: Uuid,

    /// Rule that created this certification.
    pub trigger_rule_id: Uuid,

    /// Source assignment (NULL if deleted).
    pub assignment_id: Option<Uuid>,

    /// User whose access is being certified.
    pub user_id: Uuid,

    /// Entitlement being certified.
    pub entitlement_id: Uuid,

    /// Primary reviewer.
    pub reviewer_id: Uuid,

    /// Backup reviewer for escalation.
    pub backup_reviewer_id: Option<Uuid>,

    /// Current status.
    pub status: MicroCertStatus,

    /// Kafka event type that triggered.
    pub triggering_event_type: String,

    /// Event ID for traceability.
    pub triggering_event_id: Uuid,

    /// Snapshot of event payload.
    pub triggering_event_data: Option<serde_json::Value>,

    /// When certification must be completed.
    pub deadline: DateTime<Utc>,

    /// When to escalate to backup reviewer.
    pub escalation_deadline: Option<DateTime<Utc>>,

    /// Whether reminder was sent.
    pub reminder_sent: bool,

    /// Whether escalated to backup.
    pub escalated: bool,

    /// Final decision (NULL while pending).
    pub decision: Option<MicroCertDecision>,

    /// Reviewer's comment.
    pub decision_comment: Option<String>,

    /// Who made the decision.
    pub decided_by: Option<Uuid>,

    /// When decision was made.
    pub decided_at: Option<DateTime<Utc>>,

    /// Which assignment was revoked (for `SoD`).
    pub revoked_assignment_id: Option<Uuid>,

    /// User who delegated to current reviewer (for Delegate decision chain).
    pub delegated_by_id: Option<Uuid>,

    /// Original reviewer before any delegation.
    pub original_reviewer_id: Option<Uuid>,

    /// Comment from delegator explaining why delegated.
    pub delegation_comment: Option<String>,

    /// When the certification was created.
    pub created_at: DateTime<Utc>,

    /// When the certification was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Request to create a new micro-certification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateMicroCertification {
    pub trigger_rule_id: Uuid,
    pub assignment_id: Option<Uuid>,
    pub user_id: Uuid,
    pub entitlement_id: Uuid,
    pub reviewer_id: Uuid,
    pub backup_reviewer_id: Option<Uuid>,
    pub triggering_event_type: String,
    pub triggering_event_id: Uuid,
    pub triggering_event_data: Option<serde_json::Value>,
    pub deadline: DateTime<Utc>,
    pub escalation_deadline: Option<DateTime<Utc>>,
}

/// Request to decide on a micro-certification.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DecideMicroCertification {
    pub decision: MicroCertDecision,
    pub comment: Option<String>,
}

/// Filter options for listing micro-certifications.
#[derive(Debug, Clone, Default)]
pub struct MicroCertificationFilter {
    pub status: Option<MicroCertStatus>,
    pub reviewer_id: Option<Uuid>,
    pub user_id: Option<Uuid>,
    pub entitlement_id: Option<Uuid>,
    pub assignment_id: Option<Uuid>,
    pub trigger_rule_id: Option<Uuid>,
    pub from_date: Option<DateTime<Utc>>,
    pub to_date: Option<DateTime<Utc>>,
    pub escalated: Option<bool>,
    pub past_deadline: Option<bool>,
}

/// Summary statistics for micro-certifications.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MicroCertificationStats {
    pub total: i64,
    pub pending: i64,
    pub approved: i64,
    pub revoked: i64,
    pub auto_revoked: i64,
    pub flagged_for_review: i64,
    pub expired: i64,
    pub skipped: i64,
    pub escalated: i64,
    pub past_deadline: i64,
}

impl GovMicroCertification {
    /// Find a certification by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_micro_certifications
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find a pending certification for an assignment and trigger rule.
    pub async fn find_pending_for_assignment(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        assignment_id: Uuid,
        trigger_rule_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_micro_certifications
            WHERE tenant_id = $1 AND assignment_id = $2 AND trigger_rule_id = $3
              AND status = 'pending'
            ",
        )
        .bind(tenant_id)
        .bind(assignment_id)
        .bind(trigger_rule_id)
        .fetch_optional(pool)
        .await
    }

    /// Find all pending certifications for a reviewer.
    pub async fn find_pending_by_reviewer(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        reviewer_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_micro_certifications
            WHERE tenant_id = $1 AND reviewer_id = $2 AND status = 'pending'
            ORDER BY deadline ASC
            LIMIT $3 OFFSET $4
            ",
        )
        .bind(tenant_id)
        .bind(reviewer_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

    /// Find all pending certifications for a backup reviewer (escalated only).
    pub async fn find_pending_by_backup_reviewer(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        backup_reviewer_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_micro_certifications
            WHERE tenant_id = $1 AND backup_reviewer_id = $2
              AND status = 'pending' AND escalated = true
            ORDER BY deadline ASC
            LIMIT $3 OFFSET $4
            ",
        )
        .bind(tenant_id)
        .bind(backup_reviewer_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

    /// Find certifications past deadline (for expiration job).
    pub async fn find_past_deadline(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        limit: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_micro_certifications
            WHERE tenant_id = $1 AND status = 'pending' AND deadline < NOW()
            ORDER BY deadline ASC
            LIMIT $2
            ",
        )
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(pool)
        .await
    }

    /// Find certifications needing escalation.
    pub async fn find_needing_escalation(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        limit: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_micro_certifications
            WHERE tenant_id = $1 AND status = 'pending'
              AND escalated = false
              AND backup_reviewer_id IS NOT NULL
              AND escalation_deadline IS NOT NULL
              AND escalation_deadline < NOW()
            ORDER BY escalation_deadline ASC
            LIMIT $2
            ",
        )
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(pool)
        .await
    }

    /// Find certifications needing reminder.
    pub async fn find_needing_reminder(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        reminder_time: DateTime<Utc>,
        limit: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_micro_certifications
            WHERE tenant_id = $1 AND status = 'pending'
              AND reminder_sent = false
              AND deadline <= $2
            ORDER BY deadline ASC
            LIMIT $3
            ",
        )
        .bind(tenant_id)
        .bind(reminder_time)
        .bind(limit)
        .fetch_all(pool)
        .await
    }

    /// List certifications with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &MicroCertificationFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from("SELECT * FROM gov_micro_certifications WHERE tenant_id = $1");
        let mut param_count = 1;

        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${param_count}"));
        }
        if filter.reviewer_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND reviewer_id = ${param_count}"));
        }
        if filter.user_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND user_id = ${param_count}"));
        }
        if filter.entitlement_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND entitlement_id = ${param_count}"));
        }
        if filter.assignment_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND assignment_id = ${param_count}"));
        }
        if filter.trigger_rule_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND trigger_rule_id = ${param_count}"));
        }
        if filter.from_date.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_at >= ${param_count}"));
        }
        if filter.to_date.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_at <= ${param_count}"));
        }
        if filter.escalated.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND escalated = ${param_count}"));
        }
        if filter.past_deadline == Some(true) {
            query.push_str(" AND status = 'pending' AND deadline < NOW()");
        }

        query.push_str(&format!(
            " ORDER BY created_at DESC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, Self>(&query).bind(tenant_id);

        if let Some(status) = filter.status {
            q = q.bind(status);
        }
        if let Some(reviewer_id) = filter.reviewer_id {
            q = q.bind(reviewer_id);
        }
        if let Some(user_id) = filter.user_id {
            q = q.bind(user_id);
        }
        if let Some(entitlement_id) = filter.entitlement_id {
            q = q.bind(entitlement_id);
        }
        if let Some(assignment_id) = filter.assignment_id {
            q = q.bind(assignment_id);
        }
        if let Some(trigger_rule_id) = filter.trigger_rule_id {
            q = q.bind(trigger_rule_id);
        }
        if let Some(from_date) = filter.from_date {
            q = q.bind(from_date);
        }
        if let Some(to_date) = filter.to_date {
            q = q.bind(to_date);
        }
        if let Some(escalated) = filter.escalated {
            q = q.bind(escalated);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count certifications with filtering.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &MicroCertificationFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query =
            String::from("SELECT COUNT(*) FROM gov_micro_certifications WHERE tenant_id = $1");
        let mut param_count = 1;

        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${param_count}"));
        }
        if filter.reviewer_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND reviewer_id = ${param_count}"));
        }
        if filter.user_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND user_id = ${param_count}"));
        }
        if filter.entitlement_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND entitlement_id = ${param_count}"));
        }
        if filter.assignment_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND assignment_id = ${param_count}"));
        }
        if filter.trigger_rule_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND trigger_rule_id = ${param_count}"));
        }
        if filter.from_date.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_at >= ${param_count}"));
        }
        if filter.to_date.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_at <= ${param_count}"));
        }
        if filter.escalated.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND escalated = ${param_count}"));
        }
        if filter.past_deadline == Some(true) {
            query.push_str(" AND status = 'pending' AND deadline < NOW()");
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(status) = filter.status {
            q = q.bind(status);
        }
        if let Some(reviewer_id) = filter.reviewer_id {
            q = q.bind(reviewer_id);
        }
        if let Some(user_id) = filter.user_id {
            q = q.bind(user_id);
        }
        if let Some(entitlement_id) = filter.entitlement_id {
            q = q.bind(entitlement_id);
        }
        if let Some(assignment_id) = filter.assignment_id {
            q = q.bind(assignment_id);
        }
        if let Some(trigger_rule_id) = filter.trigger_rule_id {
            q = q.bind(trigger_rule_id);
        }
        if let Some(from_date) = filter.from_date {
            q = q.bind(from_date);
        }
        if let Some(to_date) = filter.to_date {
            q = q.bind(to_date);
        }
        if let Some(escalated) = filter.escalated {
            q = q.bind(escalated);
        }

        q.fetch_one(pool).await
    }

    /// Get statistics for a tenant.
    pub async fn get_stats(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
    ) -> Result<MicroCertificationStats, sqlx::Error> {
        let row: (i64, i64, i64, i64, i64, i64, i64, i64, i64, i64) = sqlx::query_as(
            r"
            SELECT
                COUNT(*) as total,
                COUNT(*) FILTER (WHERE status = 'pending') as pending,
                COUNT(*) FILTER (WHERE status = 'approved') as approved,
                COUNT(*) FILTER (WHERE status = 'revoked') as revoked,
                COUNT(*) FILTER (WHERE status = 'auto_revoked') as auto_revoked,
                COUNT(*) FILTER (WHERE status = 'flagged_for_review') as flagged_for_review,
                COUNT(*) FILTER (WHERE status = 'expired') as expired,
                COUNT(*) FILTER (WHERE status = 'skipped') as skipped,
                COUNT(*) FILTER (WHERE escalated = true) as escalated,
                COUNT(*) FILTER (WHERE status = 'pending' AND deadline < NOW()) as past_deadline
            FROM gov_micro_certifications
            WHERE tenant_id = $1
            ",
        )
        .bind(tenant_id)
        .fetch_one(pool)
        .await?;

        Ok(MicroCertificationStats {
            total: row.0,
            pending: row.1,
            approved: row.2,
            revoked: row.3,
            auto_revoked: row.4,
            flagged_for_review: row.5,
            expired: row.6,
            skipped: row.7,
            escalated: row.8,
            past_deadline: row.9,
        })
    }

    /// Create a new micro-certification.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateMicroCertification,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO gov_micro_certifications (
                tenant_id, trigger_rule_id, assignment_id, user_id, entitlement_id,
                reviewer_id, backup_reviewer_id, triggering_event_type,
                triggering_event_id, triggering_event_data, deadline, escalation_deadline
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(input.trigger_rule_id)
        .bind(input.assignment_id)
        .bind(input.user_id)
        .bind(input.entitlement_id)
        .bind(input.reviewer_id)
        .bind(input.backup_reviewer_id)
        .bind(&input.triggering_event_type)
        .bind(input.triggering_event_id)
        .bind(&input.triggering_event_data)
        .bind(input.deadline)
        .bind(input.escalation_deadline)
        .fetch_one(pool)
        .await
    }

    /// Record a decision on the certification.
    pub async fn decide(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        decided_by: Uuid,
        input: DecideMicroCertification,
    ) -> Result<Option<Self>, sqlx::Error> {
        let status = input.decision.to_status();
        sqlx::query_as(
            r"
            UPDATE gov_micro_certifications
            SET status = $3,
                decision = $4,
                decision_comment = $5,
                decided_by = $6,
                decided_at = NOW(),
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status = 'pending'
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(status)
        .bind(input.decision)
        .bind(&input.comment)
        .bind(decided_by)
        .fetch_optional(pool)
        .await
    }

    /// Mark certification as expired (timeout without auto-revoke).
    pub async fn mark_expired(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_micro_certifications
            SET status = 'expired', updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status = 'pending'
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Mark certification as auto-revoked (timeout with auto-revoke).
    pub async fn mark_auto_revoked(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        revoked_assignment_id: Option<Uuid>,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_micro_certifications
            SET status = 'revoked',
                decision = 'revoke',
                revoked_assignment_id = $3,
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status = 'pending'
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(revoked_assignment_id)
        .fetch_optional(pool)
        .await
    }

    /// Mark certification as skipped (assignment deleted).
    pub async fn mark_skipped(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_micro_certifications
            SET status = 'skipped', updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status = 'pending'
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Mark certification as escalated.
    pub async fn mark_escalated(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_micro_certifications
            SET escalated = true, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status = 'pending'
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Mark reminder as sent.
    pub async fn mark_reminder_sent(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE gov_micro_certifications
            SET reminder_sent = true, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status = 'pending'
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Set the revoked assignment ID.
    pub async fn set_revoked_assignment(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        revoked_assignment_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE gov_micro_certifications
            SET revoked_assignment_id = $3, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(revoked_assignment_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Delegate a certification to a new reviewer.
    ///
    /// Updates the reviewer while preserving the original reviewer for audit trail.
    pub async fn delegate(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        new_reviewer_id: Uuid,
        delegated_by_id: Uuid,
        original_reviewer_id: Uuid,
        delegation_comment: Option<String>,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_micro_certifications
            SET reviewer_id = $3,
                delegated_by_id = $4,
                original_reviewer_id = $5,
                delegation_comment = $6,
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status = 'pending'
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(new_reviewer_id)
        .bind(delegated_by_id)
        .bind(original_reviewer_id)
        .bind(delegation_comment)
        .fetch_optional(pool)
        .await
    }

    /// Skip all pending certifications for an assignment (assignment deleted).
    pub async fn skip_by_assignment(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        assignment_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE gov_micro_certifications
            SET status = 'skipped', updated_at = NOW()
            WHERE tenant_id = $1 AND assignment_id = $2 AND status = 'pending'
            ",
        )
        .bind(tenant_id)
        .bind(assignment_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    // =========================================================================
    // Cross-tenant query methods for background jobs (F055)
    // =========================================================================

    /// Find all certifications past deadline across all tenants (for expiration job).
    ///
    /// Uses `FOR UPDATE SKIP LOCKED` to prevent race conditions when multiple
    /// workers process expirations concurrently.
    pub async fn find_all_past_deadline(
        pool: &sqlx::PgPool,
        now: DateTime<Utc>,
        limit: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_micro_certifications
            WHERE status = 'pending' AND deadline < $1
            ORDER BY deadline ASC
            LIMIT $2
            FOR UPDATE SKIP LOCKED
            ",
        )
        .bind(now)
        .bind(limit)
        .fetch_all(pool)
        .await
    }

    /// Find all certifications needing escalation across all tenants (for expiration job).
    ///
    /// Uses `FOR UPDATE SKIP LOCKED` to prevent race conditions.
    pub async fn find_all_needing_escalation(
        pool: &sqlx::PgPool,
        now: DateTime<Utc>,
        limit: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_micro_certifications
            WHERE status = 'pending'
              AND escalated = false
              AND backup_reviewer_id IS NOT NULL
              AND escalation_deadline IS NOT NULL
              AND escalation_deadline < $1
            ORDER BY escalation_deadline ASC
            LIMIT $2
            FOR UPDATE SKIP LOCKED
            ",
        )
        .bind(now)
        .bind(limit)
        .fetch_all(pool)
        .await
    }

    /// Find all certifications needing reminder across all tenants (for expiration job).
    ///
    /// Uses `FOR UPDATE SKIP LOCKED` to prevent race conditions.
    pub async fn find_all_needing_reminder(
        pool: &sqlx::PgPool,
        now: DateTime<Utc>,
        limit: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        // Certifications where reminder not yet sent and deadline is within 6 hours
        let reminder_threshold = now + chrono::Duration::hours(6);
        sqlx::query_as(
            r"
            SELECT * FROM gov_micro_certifications
            WHERE status = 'pending'
              AND reminder_sent = false
              AND deadline <= $1
              AND deadline > $2
            ORDER BY deadline ASC
            LIMIT $3
            FOR UPDATE SKIP LOCKED
            ",
        )
        .bind(reminder_threshold)
        .bind(now)
        .bind(limit)
        .fetch_all(pool)
        .await
    }

    /// Check if the user can decide on this certification.
    #[must_use]
    pub fn can_decide(&self, user_id: Uuid) -> bool {
        if self.status != MicroCertStatus::Pending {
            return false;
        }

        // Primary reviewer can always decide
        if self.reviewer_id == user_id {
            return true;
        }

        // Backup reviewer can decide only after escalation
        if self.escalated {
            if let Some(backup_id) = self.backup_reviewer_id {
                if backup_id == user_id {
                    return true;
                }
            }
        }

        false
    }

    /// Check if past deadline.
    #[must_use]
    pub fn is_past_deadline(&self) -> bool {
        self.status == MicroCertStatus::Pending && Utc::now() > self.deadline
    }

    /// Check if needing escalation.
    #[must_use]
    pub fn needs_escalation(&self) -> bool {
        if self.status != MicroCertStatus::Pending || self.escalated {
            return false;
        }
        if self.backup_reviewer_id.is_none() {
            return false;
        }
        if let Some(escalation_deadline) = self.escalation_deadline {
            return Utc::now() > escalation_deadline;
        }
        false
    }

    /// Get remaining time until deadline.
    #[must_use]
    pub fn time_until_deadline(&self) -> chrono::Duration {
        self.deadline - Utc::now()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_micro_certification() {
        let input = CreateMicroCertification {
            trigger_rule_id: Uuid::new_v4(),
            assignment_id: Some(Uuid::new_v4()),
            user_id: Uuid::new_v4(),
            entitlement_id: Uuid::new_v4(),
            reviewer_id: Uuid::new_v4(),
            backup_reviewer_id: None,
            triggering_event_type: "xavyo.governance.entitlement.assigned".to_string(),
            triggering_event_id: Uuid::new_v4(),
            triggering_event_data: None,
            deadline: Utc::now() + chrono::Duration::hours(24),
            escalation_deadline: None,
        };

        assert_eq!(
            input.triggering_event_type,
            "xavyo.governance.entitlement.assigned"
        );
    }

    #[test]
    fn test_can_decide_primary_reviewer() {
        let reviewer_id = Uuid::new_v4();
        let cert = GovMicroCertification {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            trigger_rule_id: Uuid::new_v4(),
            assignment_id: Some(Uuid::new_v4()),
            user_id: Uuid::new_v4(),
            entitlement_id: Uuid::new_v4(),
            reviewer_id,
            backup_reviewer_id: Some(Uuid::new_v4()),
            status: MicroCertStatus::Pending,
            triggering_event_type: "test".to_string(),
            triggering_event_id: Uuid::new_v4(),
            triggering_event_data: None,
            deadline: Utc::now() + chrono::Duration::hours(24),
            escalation_deadline: None,
            reminder_sent: false,
            escalated: false,
            decision: None,
            decision_comment: None,
            decided_by: None,
            decided_at: None,
            revoked_assignment_id: None,
            delegated_by_id: None,
            original_reviewer_id: None,
            delegation_comment: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        assert!(cert.can_decide(reviewer_id));
        assert!(!cert.can_decide(Uuid::new_v4())); // Random user cannot decide
    }

    #[test]
    fn test_can_decide_backup_reviewer_after_escalation() {
        let reviewer_id = Uuid::new_v4();
        let backup_id = Uuid::new_v4();

        let mut cert = GovMicroCertification {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            trigger_rule_id: Uuid::new_v4(),
            assignment_id: Some(Uuid::new_v4()),
            user_id: Uuid::new_v4(),
            entitlement_id: Uuid::new_v4(),
            reviewer_id,
            backup_reviewer_id: Some(backup_id),
            status: MicroCertStatus::Pending,
            triggering_event_type: "test".to_string(),
            triggering_event_id: Uuid::new_v4(),
            triggering_event_data: None,
            deadline: Utc::now() + chrono::Duration::hours(24),
            escalation_deadline: None,
            reminder_sent: false,
            escalated: false,
            decision: None,
            decision_comment: None,
            decided_by: None,
            decided_at: None,
            revoked_assignment_id: None,
            delegated_by_id: None,
            original_reviewer_id: None,
            delegation_comment: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        // Backup cannot decide before escalation
        assert!(!cert.can_decide(backup_id));

        // After escalation
        cert.escalated = true;
        assert!(cert.can_decide(backup_id));
    }

    #[test]
    fn test_cannot_decide_on_non_pending() {
        let reviewer_id = Uuid::new_v4();
        let cert = GovMicroCertification {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            trigger_rule_id: Uuid::new_v4(),
            assignment_id: Some(Uuid::new_v4()),
            user_id: Uuid::new_v4(),
            entitlement_id: Uuid::new_v4(),
            reviewer_id,
            backup_reviewer_id: None,
            status: MicroCertStatus::Approved, // Already decided
            triggering_event_type: "test".to_string(),
            triggering_event_id: Uuid::new_v4(),
            triggering_event_data: None,
            deadline: Utc::now() + chrono::Duration::hours(24),
            escalation_deadline: None,
            reminder_sent: false,
            escalated: false,
            decision: Some(MicroCertDecision::Approve),
            decision_comment: None,
            decided_by: Some(reviewer_id),
            decided_at: Some(Utc::now()),
            revoked_assignment_id: None,
            delegated_by_id: None,
            original_reviewer_id: None,
            delegation_comment: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        assert!(!cert.can_decide(reviewer_id));
    }

    #[test]
    fn test_needs_escalation() {
        let backup_id = Uuid::new_v4();
        let mut cert = GovMicroCertification {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            trigger_rule_id: Uuid::new_v4(),
            assignment_id: Some(Uuid::new_v4()),
            user_id: Uuid::new_v4(),
            entitlement_id: Uuid::new_v4(),
            reviewer_id: Uuid::new_v4(),
            backup_reviewer_id: Some(backup_id),
            status: MicroCertStatus::Pending,
            triggering_event_type: "test".to_string(),
            triggering_event_id: Uuid::new_v4(),
            triggering_event_data: None,
            deadline: Utc::now() + chrono::Duration::hours(24),
            escalation_deadline: Some(Utc::now() - chrono::Duration::hours(1)), // Past
            reminder_sent: false,
            escalated: false,
            decision: None,
            decision_comment: None,
            decided_by: None,
            decided_at: None,
            revoked_assignment_id: None,
            delegated_by_id: None,
            original_reviewer_id: None,
            delegation_comment: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        assert!(cert.needs_escalation());

        // After escalation, no longer needs it
        cert.escalated = true;
        assert!(!cert.needs_escalation());
    }

    #[test]
    fn test_filter_default() {
        let filter = MicroCertificationFilter::default();
        assert!(filter.status.is_none());
        assert!(filter.reviewer_id.is_none());
    }
}
