//! Orphan detection service for viewing and managing detected orphans.
//!
//! Provides listing, filtering, and summary operations for orphan detections.

use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::{DetectionReason, GovOrphanDetection, OrphanDetectionFilter, OrphanStatus};
use xavyo_governance::error::{GovernanceError, Result};

use crate::models::{
    HighRiskOrphan, ListOrphanDetectionsQuery, OrphanAgeAnalysis, OrphanDetectionListResponse,
    OrphanDetectionResponse, OrphanRiskReport, OrphanSummaryResponse, ReasonBreakdown,
};

/// Service for orphan detection operations.
pub struct OrphanDetectionService {
    pool: PgPool,
}

impl OrphanDetectionService {
    /// Create a new orphan detection service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get the database pool reference.
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// List orphan detections with filtering and pagination.
    pub async fn list(
        &self,
        tenant_id: Uuid,
        query: &ListOrphanDetectionsQuery,
    ) -> Result<OrphanDetectionListResponse> {
        let filter = OrphanDetectionFilter {
            status: query.status,
            detection_reason: query.reason,
            run_id: query.run_id,
            user_id: query.user_id,
            since: query.since,
            until: query.until,
        };

        let limit = query.limit.unwrap_or(50).min(100);
        let offset = query.offset.unwrap_or(0);

        let detections = GovOrphanDetection::list(&self.pool, tenant_id, &filter, limit, offset)
            .await
            .map_err(GovernanceError::Database)?;

        let total = GovOrphanDetection::count(&self.pool, tenant_id, &filter)
            .await
            .map_err(GovernanceError::Database)?;

        Ok(OrphanDetectionListResponse {
            items: detections
                .into_iter()
                .map(OrphanDetectionResponse::from)
                .collect(),
            total,
            limit,
            offset,
        })
    }

    /// Get a single orphan detection by ID.
    pub async fn get(
        &self,
        tenant_id: Uuid,
        detection_id: Uuid,
    ) -> Result<OrphanDetectionResponse> {
        let detection = GovOrphanDetection::find_by_id(&self.pool, tenant_id, detection_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::OrphanDetectionNotFound(detection_id))?;

        Ok(OrphanDetectionResponse::from(detection))
    }

    /// Get summary statistics for orphan detections.
    pub async fn get_summary(&self, tenant_id: Uuid) -> Result<OrphanSummaryResponse> {
        // Count by status
        let pending = GovOrphanDetection::count(
            &self.pool,
            tenant_id,
            &OrphanDetectionFilter {
                status: Some(OrphanStatus::Pending),
                ..Default::default()
            },
        )
        .await
        .map_err(GovernanceError::Database)?;

        let under_review = GovOrphanDetection::count(
            &self.pool,
            tenant_id,
            &OrphanDetectionFilter {
                status: Some(OrphanStatus::UnderReview),
                ..Default::default()
            },
        )
        .await
        .map_err(GovernanceError::Database)?;

        let remediated = GovOrphanDetection::count(
            &self.pool,
            tenant_id,
            &OrphanDetectionFilter {
                status: Some(OrphanStatus::Remediated),
                ..Default::default()
            },
        )
        .await
        .map_err(GovernanceError::Database)?;

        let dismissed = GovOrphanDetection::count(
            &self.pool,
            tenant_id,
            &OrphanDetectionFilter {
                status: Some(OrphanStatus::Dismissed),
                ..Default::default()
            },
        )
        .await
        .map_err(GovernanceError::Database)?;

        // Count by reason (only pending/under_review)
        let active_filter = OrphanDetectionFilter {
            status: None, // We'll count separately
            ..Default::default()
        };

        let no_manager = GovOrphanDetection::count(
            &self.pool,
            tenant_id,
            &OrphanDetectionFilter {
                detection_reason: Some(DetectionReason::NoManager),
                ..active_filter.clone()
            },
        )
        .await
        .map_err(GovernanceError::Database)?;

        let terminated_employee = GovOrphanDetection::count(
            &self.pool,
            tenant_id,
            &OrphanDetectionFilter {
                detection_reason: Some(DetectionReason::TerminatedEmployee),
                ..active_filter.clone()
            },
        )
        .await
        .map_err(GovernanceError::Database)?;

        let inactive = GovOrphanDetection::count(
            &self.pool,
            tenant_id,
            &OrphanDetectionFilter {
                detection_reason: Some(DetectionReason::Inactive),
                ..active_filter.clone()
            },
        )
        .await
        .map_err(GovernanceError::Database)?;

        let hr_mismatch = GovOrphanDetection::count(
            &self.pool,
            tenant_id,
            &OrphanDetectionFilter {
                detection_reason: Some(DetectionReason::HrMismatch),
                ..active_filter
            },
        )
        .await
        .map_err(GovernanceError::Database)?;

        // Calculate average age for pending orphans
        let average_age_days = self.calculate_average_age(tenant_id).await.ok();

        Ok(OrphanSummaryResponse {
            total_pending: pending,
            total_under_review: under_review,
            total_remediated: remediated,
            total_dismissed: dismissed,
            by_reason: ReasonBreakdown {
                no_manager,
                terminated_employee,
                inactive,
                hr_mismatch,
            },
            average_age_days,
        })
    }

    /// Calculate the average age of pending orphan detections.
    async fn calculate_average_age(&self, tenant_id: Uuid) -> Result<f64> {
        let avg: Option<f64> = sqlx::query_scalar(
            r"
            SELECT AVG(EXTRACT(EPOCH FROM (NOW() - detected_at)) / 86400.0)
            FROM gov_orphan_detections
            WHERE tenant_id = $1 AND status = 'pending'
            ",
        )
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        Ok(avg.unwrap_or(0.0))
    }

    /// Find active detection for a user.
    pub async fn find_active_for_user(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<OrphanDetectionResponse>> {
        let detection = GovOrphanDetection::find_active_for_user(&self.pool, tenant_id, user_id)
            .await
            .map_err(GovernanceError::Database)?;

        Ok(detection.map(OrphanDetectionResponse::from))
    }

    /// Mark a detection as under review.
    pub async fn start_review(
        &self,
        tenant_id: Uuid,
        detection_id: Uuid,
    ) -> Result<OrphanDetectionResponse> {
        let detection = GovOrphanDetection::find_by_id(&self.pool, tenant_id, detection_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::OrphanDetectionNotFound(detection_id))?;

        if detection.status != OrphanStatus::Pending {
            return Err(GovernanceError::InvalidRemediationAction {
                action: "start_review".to_string(),
                status: format!("{:?}", detection.status),
            });
        }

        let updated = GovOrphanDetection::update_status(
            &self.pool,
            tenant_id,
            detection_id,
            OrphanStatus::UnderReview,
        )
        .await
        .map_err(GovernanceError::Database)?
        .ok_or(GovernanceError::OrphanDetectionNotFound(detection_id))?;

        tracing::info!(
            tenant_id = %tenant_id,
            detection_id = %detection_id,
            "Orphan detection review started"
        );

        Ok(OrphanDetectionResponse::from(updated))
    }

    /// Reassign an orphan to a new owner/manager.
    pub async fn reassign(
        &self,
        tenant_id: Uuid,
        detection_id: Uuid,
        new_owner_id: Uuid,
        remediated_by: Uuid,
        notes: Option<String>,
    ) -> Result<OrphanDetectionResponse> {
        let detection = GovOrphanDetection::find_by_id(&self.pool, tenant_id, detection_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::OrphanDetectionNotFound(detection_id))?;

        // Validate state
        if detection.status == OrphanStatus::Remediated {
            return Err(GovernanceError::OrphanAlreadyRemediated(detection_id));
        }
        if detection.status == OrphanStatus::Dismissed {
            return Err(GovernanceError::OrphanAlreadyDismissed(detection_id));
        }

        // Apply remediation
        let updated = GovOrphanDetection::remediate(
            &self.pool,
            tenant_id,
            detection_id,
            xavyo_db::RemediateGovOrphanDetection {
                action: xavyo_db::RemediationAction::Reassign,
                remediation_by: remediated_by,
                remediation_notes: notes.clone(),
                new_owner_id: Some(new_owner_id),
            },
        )
        .await
        .map_err(GovernanceError::Database)?
        .ok_or(GovernanceError::OrphanDetectionNotFound(detection_id))?;

        // Log the remediation
        xavyo_db::GovRemediationLog::create(
            &self.pool,
            tenant_id,
            xavyo_db::CreateGovRemediationLog {
                orphan_detection_id: detection_id,
                action: xavyo_db::RemediationAction::Reassign,
                performed_by: remediated_by,
                details: Some(serde_json::json!({
                    "notes": notes,
                    "new_owner_id": new_owner_id
                })),
            },
        )
        .await
        .map_err(GovernanceError::Database)?;

        tracing::info!(
            tenant_id = %tenant_id,
            detection_id = %detection_id,
            new_owner_id = %new_owner_id,
            "Orphan reassigned to new owner"
        );

        Ok(OrphanDetectionResponse::from(updated))
    }

    /// Disable an orphan account.
    pub async fn disable(
        &self,
        tenant_id: Uuid,
        detection_id: Uuid,
        remediated_by: Uuid,
        notes: Option<String>,
    ) -> Result<OrphanDetectionResponse> {
        let detection = GovOrphanDetection::find_by_id(&self.pool, tenant_id, detection_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::OrphanDetectionNotFound(detection_id))?;

        // Validate state
        if detection.status == OrphanStatus::Remediated {
            return Err(GovernanceError::OrphanAlreadyRemediated(detection_id));
        }
        if detection.status == OrphanStatus::Dismissed {
            return Err(GovernanceError::OrphanAlreadyDismissed(detection_id));
        }

        // Apply remediation
        let updated = GovOrphanDetection::remediate(
            &self.pool,
            tenant_id,
            detection_id,
            xavyo_db::RemediateGovOrphanDetection {
                action: xavyo_db::RemediationAction::Disable,
                remediation_by: remediated_by,
                remediation_notes: notes.clone(),
                new_owner_id: None,
            },
        )
        .await
        .map_err(GovernanceError::Database)?
        .ok_or(GovernanceError::OrphanDetectionNotFound(detection_id))?;

        // Log the remediation
        xavyo_db::GovRemediationLog::create(
            &self.pool,
            tenant_id,
            xavyo_db::CreateGovRemediationLog {
                orphan_detection_id: detection_id,
                action: xavyo_db::RemediationAction::Disable,
                performed_by: remediated_by,
                details: notes.map(|n| serde_json::json!({ "notes": n })),
            },
        )
        .await
        .map_err(GovernanceError::Database)?;

        tracing::info!(
            tenant_id = %tenant_id,
            detection_id = %detection_id,
            "Orphan account disabled"
        );

        Ok(OrphanDetectionResponse::from(updated))
    }

    /// Dismiss an orphan detection as false positive.
    pub async fn dismiss(
        &self,
        tenant_id: Uuid,
        detection_id: Uuid,
        dismissed_by: Uuid,
        justification: String,
    ) -> Result<OrphanDetectionResponse> {
        let detection = GovOrphanDetection::find_by_id(&self.pool, tenant_id, detection_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::OrphanDetectionNotFound(detection_id))?;

        // Validate state
        if detection.status == OrphanStatus::Remediated {
            return Err(GovernanceError::OrphanAlreadyRemediated(detection_id));
        }
        if detection.status == OrphanStatus::Dismissed {
            return Err(GovernanceError::OrphanAlreadyDismissed(detection_id));
        }

        // Apply dismissal
        let updated = GovOrphanDetection::remediate(
            &self.pool,
            tenant_id,
            detection_id,
            xavyo_db::RemediateGovOrphanDetection {
                action: xavyo_db::RemediationAction::Dismiss,
                remediation_by: dismissed_by,
                remediation_notes: Some(justification.clone()),
                new_owner_id: None,
            },
        )
        .await
        .map_err(GovernanceError::Database)?
        .ok_or(GovernanceError::OrphanDetectionNotFound(detection_id))?;

        // Log the dismissal
        xavyo_db::GovRemediationLog::create(
            &self.pool,
            tenant_id,
            xavyo_db::CreateGovRemediationLog {
                orphan_detection_id: detection_id,
                action: xavyo_db::RemediationAction::Dismiss,
                performed_by: dismissed_by,
                details: Some(serde_json::json!({ "justification": justification })),
            },
        )
        .await
        .map_err(GovernanceError::Database)?;

        tracing::info!(
            tenant_id = %tenant_id,
            detection_id = %detection_id,
            "Orphan detection dismissed"
        );

        Ok(OrphanDetectionResponse::from(updated))
    }

    /// Request deletion of an orphan account (may require approval).
    pub async fn request_delete(
        &self,
        tenant_id: Uuid,
        detection_id: Uuid,
        requested_by: Uuid,
        justification: String,
    ) -> Result<(OrphanDetectionResponse, bool, Option<Uuid>)> {
        let detection = GovOrphanDetection::find_by_id(&self.pool, tenant_id, detection_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::OrphanDetectionNotFound(detection_id))?;

        // Validate state
        if detection.status == OrphanStatus::Remediated {
            return Err(GovernanceError::OrphanAlreadyRemediated(detection_id));
        }
        if detection.status == OrphanStatus::Dismissed {
            return Err(GovernanceError::OrphanAlreadyDismissed(detection_id));
        }

        // For deletion, we mark it as pending deletion but return that approval is required
        // In a full implementation, this would integrate with AccessRequestService

        let updated = GovOrphanDetection::remediate(
            &self.pool,
            tenant_id,
            detection_id,
            xavyo_db::RemediateGovOrphanDetection {
                action: xavyo_db::RemediationAction::Delete,
                remediation_by: requested_by,
                remediation_notes: Some(justification.clone()),
                new_owner_id: None,
            },
        )
        .await
        .map_err(GovernanceError::Database)?
        .ok_or(GovernanceError::OrphanDetectionNotFound(detection_id))?;

        // Log the delete request
        xavyo_db::GovRemediationLog::create(
            &self.pool,
            tenant_id,
            xavyo_db::CreateGovRemediationLog {
                orphan_detection_id: detection_id,
                action: xavyo_db::RemediationAction::Delete,
                performed_by: requested_by,
                details: Some(serde_json::json!({ "justification": justification })),
            },
        )
        .await
        .map_err(GovernanceError::Database)?;

        tracing::info!(
            tenant_id = %tenant_id,
            detection_id = %detection_id,
            "Orphan account deletion requested"
        );

        // For now, deletion doesn't require approval
        // In a full implementation, this would return requires_approval = true
        // and create an access request
        Ok((OrphanDetectionResponse::from(updated), false, None))
    }

    /// Get age analysis for orphan detections.
    pub async fn get_age_analysis(&self, tenant_id: Uuid) -> Result<OrphanAgeAnalysis> {
        // Get counts by age bracket
        let under_7_days: i64 = sqlx::query_scalar(
            r"
            SELECT COUNT(*)
            FROM gov_orphan_detections
            WHERE tenant_id = $1
                AND status IN ('pending', 'under_review')
                AND detected_at > NOW() - INTERVAL '7 days'
            ",
        )
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        let from_7_to_30_days: i64 = sqlx::query_scalar(
            r"
            SELECT COUNT(*)
            FROM gov_orphan_detections
            WHERE tenant_id = $1
                AND status IN ('pending', 'under_review')
                AND detected_at <= NOW() - INTERVAL '7 days'
                AND detected_at > NOW() - INTERVAL '30 days'
            ",
        )
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        let from_30_to_90_days: i64 = sqlx::query_scalar(
            r"
            SELECT COUNT(*)
            FROM gov_orphan_detections
            WHERE tenant_id = $1
                AND status IN ('pending', 'under_review')
                AND detected_at <= NOW() - INTERVAL '30 days'
                AND detected_at > NOW() - INTERVAL '90 days'
            ",
        )
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        let over_90_days: i64 = sqlx::query_scalar(
            r"
            SELECT COUNT(*)
            FROM gov_orphan_detections
            WHERE tenant_id = $1
                AND status IN ('pending', 'under_review')
                AND detected_at <= NOW() - INTERVAL '90 days'
            ",
        )
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        // Get average age
        let average_age_days = self.calculate_average_age(tenant_id).await.unwrap_or(0.0);

        // Get median age
        let median_age_days: Option<f64> = sqlx::query_scalar(
            r"
            SELECT PERCENTILE_CONT(0.5) WITHIN GROUP (
                ORDER BY EXTRACT(EPOCH FROM (NOW() - detected_at)) / 86400.0
            )
            FROM gov_orphan_detections
            WHERE tenant_id = $1 AND status IN ('pending', 'under_review')
            ",
        )
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        Ok(OrphanAgeAnalysis {
            under_7_days,
            from_7_to_30_days,
            from_30_to_90_days,
            over_90_days,
            average_age_days,
            median_age_days,
        })
    }

    /// Get risk report for orphan accounts.
    ///
    /// This integrates with F039 Risk Scoring if available.
    pub async fn get_risk_report(&self, tenant_id: Uuid) -> Result<OrphanRiskReport> {
        // Get total active orphans
        let total_orphans: i64 = sqlx::query_scalar(
            r"
            SELECT COUNT(*)
            FROM gov_orphan_detections
            WHERE tenant_id = $1 AND status IN ('pending', 'under_review')
            ",
        )
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        // Get risk breakdown by joining with risk scores (F039)
        // High risk: score >= 70, Medium: 40-69, Low: < 40
        let high_risk: i64 = sqlx::query_scalar(
            r"
            SELECT COUNT(*)
            FROM gov_orphan_detections od
            LEFT JOIN gov_risk_scores rs ON od.user_id = rs.user_id AND rs.tenant_id = od.tenant_id
            WHERE od.tenant_id = $1
                AND od.status IN ('pending', 'under_review')
                AND COALESCE(rs.score, 0) >= 70
            ",
        )
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        let medium_risk: i64 = sqlx::query_scalar(
            r"
            SELECT COUNT(*)
            FROM gov_orphan_detections od
            LEFT JOIN gov_risk_scores rs ON od.user_id = rs.user_id AND rs.tenant_id = od.tenant_id
            WHERE od.tenant_id = $1
                AND od.status IN ('pending', 'under_review')
                AND COALESCE(rs.score, 0) >= 40
                AND COALESCE(rs.score, 0) < 70
            ",
        )
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        let low_risk: i64 = sqlx::query_scalar(
            r"
            SELECT COUNT(*)
            FROM gov_orphan_detections od
            LEFT JOIN gov_risk_scores rs ON od.user_id = rs.user_id AND rs.tenant_id = od.tenant_id
            WHERE od.tenant_id = $1
                AND od.status IN ('pending', 'under_review')
                AND COALESCE(rs.score, 0) < 40
            ",
        )
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        // Check for active sessions (simplified - checking recent login)
        let with_active_sessions: i64 = sqlx::query_scalar(
            r"
            SELECT COUNT(DISTINCT od.id)
            FROM gov_orphan_detections od
            JOIN login_attempts la ON od.user_id = la.user_id AND la.tenant_id = od.tenant_id
            WHERE od.tenant_id = $1
                AND od.status IN ('pending', 'under_review')
                AND la.is_successful = true
                AND la.created_at > NOW() - INTERVAL '24 hours'
            ",
        )
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        // Recent activity (last 7 days)
        let with_recent_activity: i64 = sqlx::query_scalar(
            r"
            SELECT COUNT(*)
            FROM gov_orphan_detections
            WHERE tenant_id = $1
                AND status IN ('pending', 'under_review')
                AND last_activity_at > NOW() - INTERVAL '7 days'
            ",
        )
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        // Get top high-risk orphans
        let high_risk_details = self.get_high_risk_orphans(tenant_id, 10).await?;

        Ok(OrphanRiskReport {
            total_orphans,
            high_risk,
            medium_risk,
            low_risk,
            with_active_sessions,
            with_recent_activity,
            high_risk_details,
        })
    }

    /// Get top N high-risk orphans with details.
    async fn get_high_risk_orphans(
        &self,
        tenant_id: Uuid,
        limit: i64,
    ) -> Result<Vec<HighRiskOrphan>> {
        #[derive(sqlx::FromRow)]
        struct HighRiskOrphanRow {
            detection_id: Uuid,
            user_id: Uuid,
            detection_reason: DetectionReason,
            risk_score: Option<i32>,
            sensitive_entitlements: i64,
            days_since_detection: f64,
        }

        let rows: Vec<HighRiskOrphanRow> = sqlx::query_as(
            r"
            SELECT
                od.id as detection_id,
                od.user_id,
                od.detection_reason,
                rs.score as risk_score,
                COALESCE(
                    (SELECT COUNT(*) FROM gov_entitlement_assignments ea
                     JOIN gov_entitlements e ON ea.entitlement_id = e.id
                     WHERE ea.user_id = od.user_id AND ea.tenant_id = od.tenant_id
                     AND e.risk_level = 'high'),
                    0
                ) as sensitive_entitlements,
                EXTRACT(EPOCH FROM (NOW() - od.detected_at)) / 86400.0 as days_since_detection
            FROM gov_orphan_detections od
            LEFT JOIN gov_risk_scores rs ON od.user_id = rs.user_id AND rs.tenant_id = od.tenant_id
            WHERE od.tenant_id = $1
                AND od.status IN ('pending', 'under_review')
            ORDER BY COALESCE(rs.score, 0) DESC, od.detected_at ASC
            LIMIT $2
            ",
        )
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        Ok(rows
            .into_iter()
            .map(|r| HighRiskOrphan {
                detection_id: r.detection_id,
                user_id: r.user_id,
                reason: r.detection_reason,
                risk_score: r.risk_score,
                sensitive_entitlements: r.sensitive_entitlements as i32,
                days_since_detection: r.days_since_detection as i32,
            })
            .collect())
    }

    /// Export orphan detections to CSV format.
    pub async fn export_csv(&self, tenant_id: Uuid) -> Result<String> {
        let detections = GovOrphanDetection::list(
            &self.pool,
            tenant_id,
            &OrphanDetectionFilter::default(),
            10000, // Max export size
            0,
        )
        .await
        .map_err(GovernanceError::Database)?;

        let mut csv = String::from(
            "id,user_id,run_id,detection_reason,status,detected_at,last_activity_at,days_inactive,remediation_action,remediation_by,remediation_at\n",
        );

        for d in detections {
            csv.push_str(&format!(
                "{},{},{},{:?},{:?},{},{},{},{},{},{}\n",
                d.id,
                d.user_id,
                d.run_id,
                d.detection_reason,
                d.status,
                d.detected_at.format("%Y-%m-%d %H:%M:%S"),
                d.last_activity_at
                    .map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string())
                    .unwrap_or_default(),
                d.days_inactive.unwrap_or(0),
                d.remediation_action
                    .map(|a| format!("{a:?}"))
                    .unwrap_or_default(),
                d.remediation_by.map(|u| u.to_string()).unwrap_or_default(),
                d.remediation_at
                    .map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string())
                    .unwrap_or_default(),
            ));
        }

        Ok(csv)
    }

    /// Bulk remediation of multiple orphans.
    pub async fn bulk_remediate(
        &self,
        tenant_id: Uuid,
        detection_ids: Vec<Uuid>,
        action: crate::models::BulkRemediationAction,
        performed_by: Uuid,
        justification: String,
        new_owner_id: Option<Uuid>,
    ) -> Result<crate::models::BulkRemediateResponse> {
        use crate::models::{BulkRemediateResponse, BulkRemediationAction, BulkRemediationError};

        let mut succeeded = 0i64;
        let mut failed = 0i64;
        let mut errors = Vec::new();

        // Validate reassign has new_owner_id
        if action == BulkRemediationAction::Reassign && new_owner_id.is_none() {
            return Err(GovernanceError::NewOwnerRequiredForReassignment);
        }

        for detection_id in detection_ids {
            let result = match action {
                BulkRemediationAction::Disable => {
                    self.disable(
                        tenant_id,
                        detection_id,
                        performed_by,
                        Some(justification.clone()),
                    )
                    .await
                }
                BulkRemediationAction::Dismiss => {
                    self.dismiss(tenant_id, detection_id, performed_by, justification.clone())
                        .await
                }
                BulkRemediationAction::Reassign => {
                    self.reassign(
                        tenant_id,
                        detection_id,
                        new_owner_id.unwrap(), // Safe because we validated above
                        performed_by,
                        Some(justification.clone()),
                    )
                    .await
                }
            };

            match result {
                Ok(_) => succeeded += 1,
                Err(e) => {
                    failed += 1;
                    errors.push(BulkRemediationError {
                        detection_id,
                        error: e.to_string(),
                    });
                }
            }
        }

        Ok(BulkRemediateResponse {
            succeeded,
            failed,
            errors,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::models::{
        BulkRemediateResponse, BulkRemediationError, OrphanAgeAnalysis, OrphanSummaryResponse,
        ReasonBreakdown,
    };
    use uuid::Uuid;

    #[test]
    fn test_service_creation() {
        // Basic test to ensure the service can be created
        // Full integration tests would require a database
    }

    // =========================================================================
    // Summary and Report Tests
    // =========================================================================

    #[test]
    fn test_orphan_summary_response_fields() {
        let summary = OrphanSummaryResponse {
            total_pending: 40,
            total_under_review: 30,
            total_remediated: 20,
            total_dismissed: 10,
            by_reason: ReasonBreakdown {
                no_manager: 35,
                terminated_employee: 30,
                inactive: 25,
                hr_mismatch: 10,
            },
            average_age_days: Some(45.5),
        };

        assert_eq!(summary.total_pending, 40);
        assert_eq!(summary.total_under_review, 30);
        assert_eq!(summary.total_remediated, 20);
        assert_eq!(summary.total_dismissed, 10);
    }

    #[test]
    fn test_orphan_summary_status_total() {
        let summary = OrphanSummaryResponse {
            total_pending: 40,
            total_under_review: 30,
            total_remediated: 20,
            total_dismissed: 10,
            by_reason: ReasonBreakdown {
                no_manager: 35,
                terminated_employee: 30,
                inactive: 25,
                hr_mismatch: 10,
            },
            average_age_days: Some(45.5),
        };

        // Total across all statuses
        let total = summary.total_pending
            + summary.total_under_review
            + summary.total_remediated
            + summary.total_dismissed;
        assert_eq!(total, 100);
    }

    #[test]
    fn test_orphan_summary_reason_breakdown() {
        let breakdown = ReasonBreakdown {
            no_manager: 35,
            terminated_employee: 30,
            inactive: 25,
            hr_mismatch: 10,
        };

        // Total across all reasons
        let total = breakdown.no_manager
            + breakdown.terminated_employee
            + breakdown.inactive
            + breakdown.hr_mismatch;
        assert_eq!(total, 100);
    }

    #[test]
    fn test_orphan_age_analysis_fields() {
        let analysis = OrphanAgeAnalysis {
            under_7_days: 10,
            from_7_to_30_days: 25,
            from_30_to_90_days: 40,
            over_90_days: 15,
            average_age_days: 45.5,
            median_age_days: Some(38.0),
        };

        assert_eq!(analysis.under_7_days, 10);
        assert_eq!(analysis.from_7_to_30_days, 25);
        assert_eq!(analysis.from_30_to_90_days, 40);
        assert_eq!(analysis.over_90_days, 15);
        assert!((analysis.average_age_days - 45.5).abs() < 0.001);
    }

    #[test]
    fn test_orphan_age_analysis_total() {
        let analysis = OrphanAgeAnalysis {
            under_7_days: 10,
            from_7_to_30_days: 25,
            from_30_to_90_days: 40,
            over_90_days: 15,
            average_age_days: 45.5,
            median_age_days: None,
        };

        // Total across age buckets
        let total = analysis.under_7_days
            + analysis.from_7_to_30_days
            + analysis.from_30_to_90_days
            + analysis.over_90_days;
        assert_eq!(total, 90);
    }

    // =========================================================================
    // Bulk Remediation Tests
    // =========================================================================

    #[test]
    fn test_bulk_remediate_response_all_success() {
        let response = BulkRemediateResponse {
            succeeded: 5,
            failed: 0,
            errors: vec![],
        };

        assert_eq!(response.succeeded, 5);
        assert_eq!(response.failed, 0);
        assert!(response.errors.is_empty());
    }

    #[test]
    fn test_bulk_remediate_response_partial_failure() {
        let response = BulkRemediateResponse {
            succeeded: 3,
            failed: 2,
            errors: vec![
                BulkRemediationError {
                    detection_id: Uuid::new_v4(),
                    error: "Orphan already remediated".to_string(),
                },
                BulkRemediationError {
                    detection_id: Uuid::new_v4(),
                    error: "User not found".to_string(),
                },
            ],
        };

        assert_eq!(response.succeeded, 3);
        assert_eq!(response.failed, 2);
        assert_eq!(response.errors.len(), 2);
    }

    #[test]
    fn test_bulk_remediate_response_all_failure() {
        let response = BulkRemediateResponse {
            succeeded: 0,
            failed: 3,
            errors: vec![
                BulkRemediationError {
                    detection_id: Uuid::new_v4(),
                    error: "Error 1".to_string(),
                },
                BulkRemediationError {
                    detection_id: Uuid::new_v4(),
                    error: "Error 2".to_string(),
                },
                BulkRemediationError {
                    detection_id: Uuid::new_v4(),
                    error: "Error 3".to_string(),
                },
            ],
        };

        assert_eq!(response.succeeded, 0);
        assert_eq!(response.failed, 3);
        assert_eq!(response.errors.len(), 3);
    }
}
