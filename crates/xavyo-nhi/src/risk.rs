//! Risk score calculation and normalization utilities.

use crate::types::NhiRiskLevel;

/// Factors that contribute to the risk score calculation.
#[derive(Debug, Clone, Default)]
pub struct RiskFactors {
    /// Staleness factor: days since last activity (max 40 points)
    pub staleness_days: Option<i64>,
    /// Credential age factor: days since last rotation (max 30 points)
    pub credential_age_days: Option<i64>,
    /// Access scope factor: number of entitlements/permissions (max 30 points)
    pub scope_count: Option<u32>,
}

/// Risk factor weights for service accounts.
pub mod weights {
    /// Maximum points for staleness factor
    pub const STALENESS_MAX: u32 = 40;
    /// Maximum points for credential age factor
    pub const CREDENTIAL_AGE_MAX: u32 = 30;
    /// Maximum points for access scope factor
    pub const SCOPE_MAX: u32 = 30;

    /// Days of inactivity for maximum staleness score
    pub const STALENESS_CRITICAL_DAYS: i64 = 90;
    /// Days of inactivity for medium staleness score
    pub const STALENESS_MEDIUM_DAYS: i64 = 30;

    /// Days since rotation for maximum credential age score
    pub const CREDENTIAL_CRITICAL_DAYS: i64 = 90;
    /// Days since rotation for medium credential age score
    pub const CREDENTIAL_MEDIUM_DAYS: i64 = 30;

    /// Number of entitlements for maximum scope score
    pub const SCOPE_CRITICAL_COUNT: u32 = 50;
    /// Number of entitlements for medium scope score
    pub const SCOPE_MEDIUM_COUNT: u32 = 20;
}

/// Calculates the unified risk score (0-100) from individual factors.
///
/// # Arguments
///
/// * `factors` - The risk factors to consider
///
/// # Returns
///
/// A risk score between 0 and 100, where higher values indicate higher risk.
///
/// # Algorithm
///
/// The score is calculated as:
/// - Staleness: 0-40 points based on days since last activity
/// - Credential Age: 0-30 points based on days since last rotation
/// - Access Scope: 0-30 points based on number of entitlements
///
/// If a factor is not provided, it contributes 0 points.
pub fn calculate_risk_score(factors: &RiskFactors) -> u32 {
    let staleness = calculate_staleness_score(factors.staleness_days);
    let credential_age = calculate_credential_age_score(factors.credential_age_days);
    let scope = calculate_scope_score(factors.scope_count);

    (staleness + credential_age + scope).min(100)
}

/// Calculates the risk level from a numeric score.
pub fn calculate_risk_level(score: u32) -> NhiRiskLevel {
    NhiRiskLevel::from(score)
}

/// Calculates staleness score (0-40) based on days since last activity.
fn calculate_staleness_score(days: Option<i64>) -> u32 {
    match days {
        None => 0, // No activity data = no score contribution
        Some(d) if d < 0 => 0,
        Some(d) if d >= weights::STALENESS_CRITICAL_DAYS => weights::STALENESS_MAX,
        Some(d) if d >= weights::STALENESS_MEDIUM_DAYS => weights::STALENESS_MAX / 2,
        Some(_) => 0,
    }
}

/// Calculates credential age score (0-30) based on days since last rotation.
fn calculate_credential_age_score(days: Option<i64>) -> u32 {
    match days {
        None => 0, // No rotation data = no score contribution
        Some(d) if d < 0 => 0,
        Some(d) if d >= weights::CREDENTIAL_CRITICAL_DAYS => weights::CREDENTIAL_AGE_MAX,
        Some(d) if d >= weights::CREDENTIAL_MEDIUM_DAYS => weights::CREDENTIAL_AGE_MAX / 2,
        Some(_) => 0,
    }
}

/// Calculates access scope score (0-30) based on number of entitlements.
fn calculate_scope_score(count: Option<u32>) -> u32 {
    match count {
        None => 0,
        Some(c) if c >= weights::SCOPE_CRITICAL_COUNT => weights::SCOPE_MAX,
        Some(c) if c >= weights::SCOPE_MEDIUM_COUNT => weights::SCOPE_MAX / 2,
        Some(_) => 0,
    }
}

/// Maps an AI agent's risk_level enum to a numeric score.
///
/// This provides backwards compatibility with agents that use the
/// enum-based risk_level field instead of a computed score.
///
/// # Arguments
///
/// * `risk_level` - The risk level string (low, medium, high, critical)
///
/// # Returns
///
/// A numeric score representing the center of that risk level's range.
pub fn risk_level_to_score(risk_level: &str) -> u32 {
    match risk_level.to_lowercase().as_str() {
        "low" => 20,
        "medium" => 40,
        "high" => 70,
        "critical" => 90,
        _ => 0,
    }
}

/// Normalizes a score to the 0-100 range.
///
/// Useful for ensuring scores from different sources are comparable.
pub fn normalize_score(score: i32) -> u32 {
    score.clamp(0, 100) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_risk_score_empty_factors() {
        let factors = RiskFactors::default();
        assert_eq!(calculate_risk_score(&factors), 0);
    }

    #[test]
    fn test_calculate_risk_score_staleness_only() {
        let factors = RiskFactors {
            staleness_days: Some(100),
            ..Default::default()
        };
        assert_eq!(calculate_risk_score(&factors), 40);

        let factors = RiskFactors {
            staleness_days: Some(45),
            ..Default::default()
        };
        assert_eq!(calculate_risk_score(&factors), 20);

        let factors = RiskFactors {
            staleness_days: Some(10),
            ..Default::default()
        };
        assert_eq!(calculate_risk_score(&factors), 0);
    }

    #[test]
    fn test_calculate_risk_score_credential_age_only() {
        let factors = RiskFactors {
            credential_age_days: Some(100),
            ..Default::default()
        };
        assert_eq!(calculate_risk_score(&factors), 30);

        let factors = RiskFactors {
            credential_age_days: Some(45),
            ..Default::default()
        };
        assert_eq!(calculate_risk_score(&factors), 15);
    }

    #[test]
    fn test_calculate_risk_score_scope_only() {
        let factors = RiskFactors {
            scope_count: Some(100),
            ..Default::default()
        };
        assert_eq!(calculate_risk_score(&factors), 30);

        let factors = RiskFactors {
            scope_count: Some(30),
            ..Default::default()
        };
        assert_eq!(calculate_risk_score(&factors), 15);
    }

    #[test]
    fn test_calculate_risk_score_all_factors() {
        let factors = RiskFactors {
            staleness_days: Some(100),
            credential_age_days: Some(100),
            scope_count: Some(100),
        };
        // 40 + 30 + 30 = 100
        assert_eq!(calculate_risk_score(&factors), 100);
    }

    #[test]
    fn test_calculate_risk_score_capped_at_100() {
        // Even if factors somehow exceed 100, cap it
        let factors = RiskFactors {
            staleness_days: Some(1000),
            credential_age_days: Some(1000),
            scope_count: Some(1000),
        };
        assert_eq!(calculate_risk_score(&factors), 100);
    }

    #[test]
    fn test_calculate_risk_level() {
        assert_eq!(calculate_risk_level(0), NhiRiskLevel::Low);
        assert_eq!(calculate_risk_level(25), NhiRiskLevel::Low);
        assert_eq!(calculate_risk_level(26), NhiRiskLevel::Medium);
        assert_eq!(calculate_risk_level(50), NhiRiskLevel::Medium);
        assert_eq!(calculate_risk_level(51), NhiRiskLevel::High);
        assert_eq!(calculate_risk_level(75), NhiRiskLevel::High);
        assert_eq!(calculate_risk_level(76), NhiRiskLevel::Critical);
        assert_eq!(calculate_risk_level(100), NhiRiskLevel::Critical);
    }

    #[test]
    fn test_risk_level_to_score() {
        assert_eq!(risk_level_to_score("low"), 20);
        assert_eq!(risk_level_to_score("medium"), 40);
        assert_eq!(risk_level_to_score("high"), 70);
        assert_eq!(risk_level_to_score("critical"), 90);
        assert_eq!(risk_level_to_score("unknown"), 0);
        assert_eq!(risk_level_to_score("LOW"), 20);
        assert_eq!(risk_level_to_score("HIGH"), 70);
    }

    #[test]
    fn test_normalize_score() {
        assert_eq!(normalize_score(-10), 0);
        assert_eq!(normalize_score(0), 0);
        assert_eq!(normalize_score(50), 50);
        assert_eq!(normalize_score(100), 100);
        assert_eq!(normalize_score(150), 100);
    }

    #[test]
    fn test_staleness_negative_days() {
        let factors = RiskFactors {
            staleness_days: Some(-10),
            ..Default::default()
        };
        assert_eq!(calculate_risk_score(&factors), 0);
    }
}
