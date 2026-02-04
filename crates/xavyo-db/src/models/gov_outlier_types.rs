//! Outlier detection shared types and enums.

use serde::{Deserialize, Serialize};

/// Status of an outlier analysis run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "outlier_analysis_status", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum OutlierAnalysisStatus {
    /// Analysis is queued but not started.
    Pending,
    /// Analysis is currently running.
    Running,
    /// Analysis completed successfully.
    Completed,
    /// Analysis failed with an error.
    Failed,
}

impl OutlierAnalysisStatus {
    /// Check if the analysis can be started.
    #[must_use] 
    pub fn can_start(&self) -> bool {
        matches!(self, Self::Pending)
    }

    /// Check if the analysis can be cancelled.
    #[must_use] 
    pub fn can_cancel(&self) -> bool {
        matches!(self, Self::Running)
    }

    /// Check if the analysis is in a terminal state.
    #[must_use] 
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed | Self::Failed)
    }
}

/// How the analysis was triggered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "outlier_trigger_type", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum OutlierTriggerType {
    /// Triggered by scheduled job.
    Scheduled,
    /// Triggered manually by user.
    Manual,
    /// Triggered via API call.
    Api,
}

/// Classification of a user based on outlier analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "outlier_classification", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum OutlierClassification {
    /// User is within normal range for their peer group(s).
    Normal,
    /// User deviates significantly from their peer group(s).
    Outlier,
    /// User cannot be classified (no valid peer groups).
    Unclassifiable,
}

/// Status of an analyst's disposition for an outlier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "outlier_disposition_status", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum OutlierDispositionStatus {
    /// Newly detected, not yet reviewed.
    New,
    /// Reviewed and determined to be acceptable.
    Legitimate,
    /// Analyst determined remediation is needed.
    RequiresRemediation,
    /// Currently being investigated.
    UnderInvestigation,
    /// Issue has been resolved.
    Remediated,
}

impl OutlierDispositionStatus {
    /// Check if a transition from this status to another is valid.
    #[must_use] 
    pub fn can_transition_to(&self, target: &Self) -> bool {
        match (self, target) {
            // From New, can go to any review state
            (Self::New,
Self::Legitimate | Self::RequiresRemediation | Self::UnderInvestigation) => true,

            // From Investigation, can conclude in any direction
            (Self::UnderInvestigation,
Self::Legitimate | Self::RequiresRemediation | Self::Remediated) => true,

            // From RequiresRemediation, can investigate or remediate
            (Self::RequiresRemediation, Self::UnderInvestigation | Self::Remediated) => true,

            // Legitimate can be re-flagged (system sets back to New)
            (Self::Legitimate, Self::New) => true,

            // Same status is always valid (no-op)
            (a, b) if a == b => true,

            _ => false,
        }
    }

    /// Check if this is a terminal state (no further action needed).
    #[must_use] 
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Legitimate | Self::Remediated)
    }

    /// Check if this status requires analyst attention.
    #[must_use] 
    pub fn requires_attention(&self) -> bool {
        matches!(
            self,
            Self::New | Self::RequiresRemediation | Self::UnderInvestigation
        )
    }
}

/// Type of outlier alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "outlier_alert_type", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum OutlierAlertType {
    /// User flagged as outlier for the first time.
    NewOutlier,
    /// User's score increased significantly.
    ScoreIncrease,
    /// User flagged again after being marked legitimate.
    RepeatedOutlier,
}

/// Severity level for outlier alerts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "outlier_alert_severity", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum OutlierAlertSeverity {
    /// Low severity (score 0-40).
    Low,
    /// Medium severity (score 40-60).
    Medium,
    /// High severity (score 60-80).
    High,
    /// Critical severity (score 80-100).
    Critical,
}

impl OutlierAlertSeverity {
    /// Determine severity based on outlier score.
    #[must_use] 
    pub fn from_score(score: f64) -> Self {
        if score >= 80.0 {
            Self::Critical
        } else if score >= 60.0 {
            Self::High
        } else if score >= 40.0 {
            Self::Medium
        } else {
            Self::Low
        }
    }
}

/// Scoring weights for outlier detection factors.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub struct ScoringWeights {
    /// Weight for role frequency factor.
    pub role_frequency: f64,
    /// Weight for entitlement count factor.
    pub entitlement_count: f64,
    /// Weight for assignment pattern factor.
    pub assignment_pattern: f64,
    /// Weight for peer group coverage factor.
    pub peer_group_coverage: f64,
    /// Weight for historical deviation factor.
    pub historical_deviation: f64,
}

impl Default for ScoringWeights {
    fn default() -> Self {
        Self {
            role_frequency: 0.30,
            entitlement_count: 0.25,
            assignment_pattern: 0.20,
            peer_group_coverage: 0.15,
            historical_deviation: 0.10,
        }
    }
}

impl ScoringWeights {
    /// Validate that weights sum to approximately 1.0.
    pub fn validate(&self) -> Result<(), String> {
        let sum = self.role_frequency
            + self.entitlement_count
            + self.assignment_pattern
            + self.peer_group_coverage
            + self.historical_deviation;

        if (sum - 1.0).abs() > 0.01 {
            return Err(format!("Scoring weights must sum to 1.0, got {sum}"));
        }

        // Validate individual weights are non-negative
        if self.role_frequency < 0.0
            || self.entitlement_count < 0.0
            || self.assignment_pattern < 0.0
            || self.peer_group_coverage < 0.0
            || self.historical_deviation < 0.0
        {
            return Err("All scoring weights must be non-negative".to_string());
        }

        Ok(())
    }

    /// Normalize weights to sum to 1.0.
    pub fn normalize(&mut self) {
        let sum = self.role_frequency
            + self.entitlement_count
            + self.assignment_pattern
            + self.peer_group_coverage
            + self.historical_deviation;

        if sum > 0.0 {
            self.role_frequency /= sum;
            self.entitlement_count /= sum;
            self.assignment_pattern /= sum;
            self.peer_group_coverage /= sum;
            self.historical_deviation /= sum;
        }
    }
}

/// Score for a single peer group comparison.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct PeerGroupScore {
    /// Peer group identifier.
    pub peer_group_id: uuid::Uuid,
    /// Peer group name.
    pub peer_group_name: String,
    /// Z-score (deviation from mean in standard deviations).
    pub z_score: f64,
    /// Deviation factor (0-100 normalized).
    pub deviation_factor: f64,
    /// Whether this constitutes an outlier for this group.
    pub is_outlier: bool,
}

/// Breakdown of a single scoring factor.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct FactorScore {
    /// Raw value before normalization.
    pub raw_value: f64,
    /// Weight applied to this factor.
    pub weight: f64,
    /// Contribution to overall score (`raw_value` * weight, normalized).
    pub contribution: f64,
    /// Human-readable explanation.
    pub details: String,
}

/// Complete factor breakdown for a user's outlier score.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct FactorBreakdown {
    /// Role frequency factor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role_frequency: Option<FactorScore>,
    /// Entitlement count factor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entitlement_count: Option<FactorScore>,
    /// Assignment pattern factor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assignment_pattern: Option<FactorScore>,
    /// Peer group coverage factor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_group_coverage: Option<FactorScore>,
    /// Historical deviation factor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub historical_deviation: Option<FactorScore>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analysis_status_can_start() {
        assert!(OutlierAnalysisStatus::Pending.can_start());
        assert!(!OutlierAnalysisStatus::Running.can_start());
        assert!(!OutlierAnalysisStatus::Completed.can_start());
        assert!(!OutlierAnalysisStatus::Failed.can_start());
    }

    #[test]
    fn test_analysis_status_can_cancel() {
        assert!(!OutlierAnalysisStatus::Pending.can_cancel());
        assert!(OutlierAnalysisStatus::Running.can_cancel());
        assert!(!OutlierAnalysisStatus::Completed.can_cancel());
        assert!(!OutlierAnalysisStatus::Failed.can_cancel());
    }

    #[test]
    fn test_disposition_status_transitions() {
        // From New
        assert!(
            OutlierDispositionStatus::New.can_transition_to(&OutlierDispositionStatus::Legitimate)
        );
        assert!(OutlierDispositionStatus::New
            .can_transition_to(&OutlierDispositionStatus::RequiresRemediation));
        assert!(OutlierDispositionStatus::New
            .can_transition_to(&OutlierDispositionStatus::UnderInvestigation));
        assert!(
            !OutlierDispositionStatus::New.can_transition_to(&OutlierDispositionStatus::Remediated)
        );

        // From UnderInvestigation
        assert!(OutlierDispositionStatus::UnderInvestigation
            .can_transition_to(&OutlierDispositionStatus::Legitimate));
        assert!(OutlierDispositionStatus::UnderInvestigation
            .can_transition_to(&OutlierDispositionStatus::Remediated));

        // From RequiresRemediation
        assert!(OutlierDispositionStatus::RequiresRemediation
            .can_transition_to(&OutlierDispositionStatus::Remediated));
        assert!(!OutlierDispositionStatus::RequiresRemediation
            .can_transition_to(&OutlierDispositionStatus::Legitimate));

        // Re-flagging
        assert!(
            OutlierDispositionStatus::Legitimate.can_transition_to(&OutlierDispositionStatus::New)
        );
    }

    #[test]
    fn test_alert_severity_from_score() {
        assert_eq!(
            OutlierAlertSeverity::from_score(10.0),
            OutlierAlertSeverity::Low
        );
        assert_eq!(
            OutlierAlertSeverity::from_score(39.9),
            OutlierAlertSeverity::Low
        );
        assert_eq!(
            OutlierAlertSeverity::from_score(40.0),
            OutlierAlertSeverity::Medium
        );
        assert_eq!(
            OutlierAlertSeverity::from_score(59.9),
            OutlierAlertSeverity::Medium
        );
        assert_eq!(
            OutlierAlertSeverity::from_score(60.0),
            OutlierAlertSeverity::High
        );
        assert_eq!(
            OutlierAlertSeverity::from_score(79.9),
            OutlierAlertSeverity::High
        );
        assert_eq!(
            OutlierAlertSeverity::from_score(80.0),
            OutlierAlertSeverity::Critical
        );
        assert_eq!(
            OutlierAlertSeverity::from_score(100.0),
            OutlierAlertSeverity::Critical
        );
    }

    #[test]
    fn test_scoring_weights_default() {
        let weights = ScoringWeights::default();
        assert!(weights.validate().is_ok());
    }

    #[test]
    fn test_scoring_weights_validation() {
        let mut weights = ScoringWeights::default();
        weights.role_frequency = 0.5;
        assert!(weights.validate().is_err());

        weights.normalize();
        assert!(weights.validate().is_ok());
    }

    #[test]
    fn test_scoring_weights_negative_validation() {
        let weights = ScoringWeights {
            role_frequency: -0.1,
            entitlement_count: 0.5,
            assignment_pattern: 0.3,
            peer_group_coverage: 0.2,
            historical_deviation: 0.1,
        };
        assert!(weights.validate().is_err());
    }
}
