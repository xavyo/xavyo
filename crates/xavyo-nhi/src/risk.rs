//! Risk score calculation and normalization utilities.
//!
//! This module provides functions for calculating unified risk scores
//! from various factors like staleness, credential age, and access scope.
//!
//! # Algorithm
//!
//! Risk scores range from 0-100, composed of three weighted factors:
//!
//! | Factor | Weight | Low | Medium | High |
//! |--------|--------|-----|--------|------|
//! | Staleness | 0-40 pts | <30 days | 30-89 days | ≥90 days |
//! | Credential Age | 0-30 pts | <30 days | 30-89 days | ≥90 days |
//! | Access Scope | 0-30 pts | <20 entitlements | 20-49 | ≥50 |
//!
//! # Risk Levels
//!
//! The total score maps to risk levels:
//!
//! | Score Range | Level | Should Alert? |
//! |-------------|-------|---------------|
//! | 0-25 | Low | No |
//! | 26-50 | Medium | No |
//! | 51-75 | High | Yes |
//! | 76-100 | Critical | Yes |
//!
//! # Example
//!
//! ```rust
//! use xavyo_nhi::{RiskFactors, calculate_risk_score, calculate_risk_level, NhiRiskLevel};
//!
//! let factors = RiskFactors {
//!     staleness_days: Some(45),       // 30-89 days → 20 pts
//!     credential_age_days: Some(100), // ≥90 days → 30 pts
//!     scope_count: Some(25),          // 20-49 → 15 pts
//! };
//!
//! let score = calculate_risk_score(&factors);
//! assert_eq!(score, 65); // 20 + 30 + 15 = 65
//!
//! let level = calculate_risk_level(score);
//! assert_eq!(level, NhiRiskLevel::High); // 51-75 = High
//! assert!(level.should_alert()); // High and Critical should alert
//! ```

use crate::types::NhiRiskLevel;

/// Factors that contribute to the risk score calculation.
///
/// Each factor is optional. When a factor is `None`, it contributes 0 points
/// to the total score. This allows partial risk assessment when not all
/// data is available.
///
/// # Example
///
/// ```rust
/// use xavyo_nhi::{RiskFactors, calculate_risk_score};
///
/// // All factors provided
/// let full = RiskFactors {
///     staleness_days: Some(45),
///     credential_age_days: Some(60),
///     scope_count: Some(30),
/// };
/// assert_eq!(calculate_risk_score(&full), 50); // 20 + 15 + 15
///
/// // Partial factors (unknown values are None)
/// let partial = RiskFactors {
///     staleness_days: Some(100), // Critical: 40 pts
///     credential_age_days: None, // Unknown: 0 pts
///     scope_count: None,         // Unknown: 0 pts
/// };
/// assert_eq!(calculate_risk_score(&partial), 40);
///
/// // Empty factors (new NHI with no history)
/// let empty = RiskFactors::default();
/// assert_eq!(calculate_risk_score(&empty), 0);
/// ```
#[derive(Debug, Clone, Default)]
pub struct RiskFactors {
    /// Days since last activity. Used to detect stale/orphaned accounts.
    ///
    /// - `None`: No activity data available (contributes 0 points)
    /// - `Some(d)` where `d < 0`: Invalid, treated as 0 points
    /// - `Some(d)` where `d < 30`: Low risk (0 points)
    /// - `Some(d)` where `30 <= d < 90`: Medium risk (20 points)
    /// - `Some(d)` where `d >= 90`: High risk (40 points)
    pub staleness_days: Option<i64>,

    /// Days since last credential rotation. Helps enforce rotation policies.
    ///
    /// - `None`: No rotation data available (contributes 0 points)
    /// - `Some(d)` where `d < 0`: Invalid, treated as 0 points
    /// - `Some(d)` where `d < 30`: Low risk (0 points)
    /// - `Some(d)` where `30 <= d < 90`: Medium risk (15 points)
    /// - `Some(d)` where `d >= 90`: High risk (30 points)
    pub credential_age_days: Option<i64>,

    /// Number of entitlements/permissions assigned. Measures blast radius.
    ///
    /// - `None`: No scope data available (contributes 0 points)
    /// - `Some(c)` where `c < 20`: Low risk (0 points)
    /// - `Some(c)` where `20 <= c < 50`: Medium risk (15 points)
    /// - `Some(c)` where `c >= 50`: High risk (30 points)
    pub scope_count: Option<u32>,
}

/// Risk factor weights and thresholds for score calculation.
///
/// These constants define the scoring algorithm parameters. They can be
/// used to understand score composition or for display in risk reports.
///
/// # Example
///
/// ```rust
/// use xavyo_nhi::risk::weights;
///
/// // Display risk thresholds in a report
/// println!("Staleness:");
/// println!("  - Low: <{} days (0 pts)", weights::STALENESS_MEDIUM_DAYS);
/// println!("  - Medium: {}-{} days ({} pts)",
///     weights::STALENESS_MEDIUM_DAYS,
///     weights::STALENESS_CRITICAL_DAYS - 1,
///     weights::STALENESS_MAX / 2);
/// println!("  - High: ≥{} days ({} pts)",
///     weights::STALENESS_CRITICAL_DAYS,
///     weights::STALENESS_MAX);
///
/// // Verify total max score = 100
/// let max_total = weights::STALENESS_MAX
///     + weights::CREDENTIAL_AGE_MAX
///     + weights::SCOPE_MAX;
/// assert_eq!(max_total, 100);
/// ```
pub mod weights {
    /// Maximum points for staleness factor (40 points).
    ///
    /// Staleness has the highest weight because stale/orphaned accounts
    /// represent significant security risks (forgotten credentials, no oversight).
    pub const STALENESS_MAX: u32 = 40;

    /// Maximum points for credential age factor (30 points).
    ///
    /// Old credentials increase risk of compromise through key leakage.
    pub const CREDENTIAL_AGE_MAX: u32 = 30;

    /// Maximum points for access scope factor (30 points).
    ///
    /// More entitlements = larger blast radius if compromised.
    pub const SCOPE_MAX: u32 = 30;

    /// Days of inactivity for maximum staleness score (90 days).
    ///
    /// Accounts inactive for 90+ days are considered potentially orphaned.
    pub const STALENESS_CRITICAL_DAYS: i64 = 90;

    /// Days of inactivity for medium staleness score (30 days).
    ///
    /// Accounts inactive for 30-89 days warrant monitoring.
    pub const STALENESS_MEDIUM_DAYS: i64 = 30;

    /// Days since rotation for maximum credential age score (90 days).
    ///
    /// Credentials older than 90 days violate most security policies.
    pub const CREDENTIAL_CRITICAL_DAYS: i64 = 90;

    /// Days since rotation for medium credential age score (30 days).
    ///
    /// Credentials 30-89 days old are approaching rotation deadline.
    pub const CREDENTIAL_MEDIUM_DAYS: i64 = 30;

    /// Number of entitlements for maximum scope score (50 entitlements).
    ///
    /// Accounts with 50+ entitlements have excessive access.
    pub const SCOPE_CRITICAL_COUNT: u32 = 50;

    /// Number of entitlements for medium scope score (20 entitlements).
    ///
    /// Accounts with 20-49 entitlements have elevated access.
    pub const SCOPE_MEDIUM_COUNT: u32 = 20;
}

/// Calculates the unified risk score (0-100) from individual factors.
///
/// # Arguments
///
/// * `factors` - The [`RiskFactors`] to evaluate
///
/// # Returns
///
/// A risk score between 0 and 100, where higher values indicate higher risk.
/// The score is capped at 100 even if individual factors would sum higher.
///
/// # Algorithm
///
/// The score is the sum of three components:
///
/// | Component | Points | Threshold |
/// |-----------|--------|-----------|
/// | Staleness | 0, 20, or 40 | <30d, 30-89d, ≥90d |
/// | Credential Age | 0, 15, or 30 | <30d, 30-89d, ≥90d |
/// | Scope | 0, 15, or 30 | <20, 20-49, ≥50 |
///
/// Missing factors (`None`) contribute 0 points, allowing partial assessment.
///
/// # Example
///
/// ```rust
/// use xavyo_nhi::{RiskFactors, calculate_risk_score, calculate_risk_level, NhiRiskLevel};
///
/// // Low risk: new account with minimal access
/// let low_risk = RiskFactors {
///     staleness_days: Some(5),   // Recent activity: 0 pts
///     credential_age_days: Some(10), // Fresh credential: 0 pts
///     scope_count: Some(3),      // Few entitlements: 0 pts
/// };
/// assert_eq!(calculate_risk_score(&low_risk), 0);
/// assert_eq!(calculate_risk_level(0), NhiRiskLevel::Low);
///
/// // High risk: stale account with old credentials and excessive access
/// let high_risk = RiskFactors {
///     staleness_days: Some(95),      // Stale: 40 pts
///     credential_age_days: Some(100), // Old credential: 30 pts
///     scope_count: Some(60),         // Excessive access: 30 pts
/// };
/// assert_eq!(calculate_risk_score(&high_risk), 100);
/// assert_eq!(calculate_risk_level(100), NhiRiskLevel::Critical);
/// ```
pub fn calculate_risk_score(factors: &RiskFactors) -> u32 {
    let staleness = calculate_staleness_score(factors.staleness_days);
    let credential_age = calculate_credential_age_score(factors.credential_age_days);
    let scope = calculate_scope_score(factors.scope_count);

    (staleness + credential_age + scope).min(100)
}

/// Converts a numeric risk score (0-100) to a risk level category.
///
/// This function provides a categorical interpretation of the numeric score,
/// useful for display, alerting, and policy decisions.
///
/// # Arguments
///
/// * `score` - A risk score from 0-100 (typically from [`calculate_risk_score`])
///
/// # Returns
///
/// The corresponding [`NhiRiskLevel`]:
/// - `Low`: 0-25 (no action needed)
/// - `Medium`: 26-50 (monitor, consider remediation)
/// - `High`: 51-75 (action recommended, should alert)
/// - `Critical`: 76-100 (immediate action required, must alert)
///
/// # Example
///
/// ```rust
/// use xavyo_nhi::{calculate_risk_level, NhiRiskLevel};
///
/// // Boundary values
/// assert_eq!(calculate_risk_level(25), NhiRiskLevel::Low);
/// assert_eq!(calculate_risk_level(26), NhiRiskLevel::Medium);
/// assert_eq!(calculate_risk_level(50), NhiRiskLevel::Medium);
/// assert_eq!(calculate_risk_level(51), NhiRiskLevel::High);
/// assert_eq!(calculate_risk_level(75), NhiRiskLevel::High);
/// assert_eq!(calculate_risk_level(76), NhiRiskLevel::Critical);
///
/// // Use for alerting decisions
/// let level = calculate_risk_level(65);
/// if level.should_alert() {
///     println!("Risk level {} requires attention", level);
/// }
/// ```
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

/// Converts a risk level name to its representative numeric score.
///
/// This function provides the inverse of [`calculate_risk_level`], returning
/// the center score for each risk category. Useful for:
/// - Backwards compatibility with string-based risk levels
/// - Converting user-selected risk levels to scores
/// - Setting risk thresholds from configuration
///
/// # Arguments
///
/// * `risk_level` - Case-insensitive risk level name: "low", "medium", "high", or "critical"
///
/// # Returns
///
/// The center score for that risk level's range:
/// - "low" → 20 (center of 0-25)
/// - "medium" → 40 (center of 26-50)
/// - "high" → 70 (center of 51-75)
/// - "critical" → 90 (center of 76-100)
/// - unknown → 0 (defaults to lowest risk)
///
/// # Example
///
/// ```rust
/// use xavyo_nhi::risk::risk_level_to_score;
///
/// // Case insensitive
/// assert_eq!(risk_level_to_score("low"), 20);
/// assert_eq!(risk_level_to_score("LOW"), 20);
/// assert_eq!(risk_level_to_score("Low"), 20);
///
/// // All levels
/// assert_eq!(risk_level_to_score("medium"), 40);
/// assert_eq!(risk_level_to_score("high"), 70);
/// assert_eq!(risk_level_to_score("critical"), 90);
///
/// // Unknown defaults to 0 (safest assumption)
/// assert_eq!(risk_level_to_score("unknown"), 0);
/// assert_eq!(risk_level_to_score(""), 0);
/// ```
pub fn risk_level_to_score(risk_level: &str) -> u32 {
    match risk_level.to_lowercase().as_str() {
        "low" => 20,
        "medium" => 40,
        "high" => 70,
        "critical" => 90,
        _ => 0,
    }
}

/// Normalizes an arbitrary score value to the valid 0-100 range.
///
/// This utility function ensures scores from external sources or calculations
/// are within the valid risk score range. Values below 0 become 0, and values
/// above 100 become 100.
///
/// # Arguments
///
/// * `score` - Any integer score value (can be negative or >100)
///
/// # Returns
///
/// A `u32` score clamped to the 0-100 range.
///
/// # Example
///
/// ```rust
/// use xavyo_nhi::risk::normalize_score;
///
/// // Negative values become 0
/// assert_eq!(normalize_score(-50), 0);
/// assert_eq!(normalize_score(-1), 0);
///
/// // Valid range passes through unchanged
/// assert_eq!(normalize_score(0), 0);
/// assert_eq!(normalize_score(50), 50);
/// assert_eq!(normalize_score(100), 100);
///
/// // Values above 100 are capped
/// assert_eq!(normalize_score(150), 100);
/// assert_eq!(normalize_score(999), 100);
/// ```
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

    // T035: Edge case - RiskFactors with all None values
    #[test]
    fn test_risk_factors_all_none() {
        let factors = RiskFactors {
            staleness_days: None,
            credential_age_days: None,
            scope_count: None,
        };
        // All None should result in score 0
        assert_eq!(calculate_risk_score(&factors), 0);
        assert_eq!(calculate_risk_level(0), NhiRiskLevel::Low);

        // Verify it's the same as default
        let default_factors = RiskFactors::default();
        assert_eq!(
            calculate_risk_score(&factors),
            calculate_risk_score(&default_factors)
        );
    }

    // T036: Edge case - negative staleness_days
    #[test]
    fn test_negative_staleness_days_edge_cases() {
        // Various negative values should all result in 0
        for negative in [-1, -10, -100, -1000, i64::MIN] {
            let factors = RiskFactors {
                staleness_days: Some(negative),
                ..Default::default()
            };
            assert_eq!(
                calculate_risk_score(&factors),
                0,
                "staleness_days={} should yield score 0",
                negative
            );
        }

        // Negative credential age should also be 0
        for negative in [-1, -30, -90] {
            let factors = RiskFactors {
                credential_age_days: Some(negative),
                ..Default::default()
            };
            assert_eq!(
                calculate_risk_score(&factors),
                0,
                "credential_age_days={} should yield score 0",
                negative
            );
        }
    }

    // Additional edge case: boundary values
    #[test]
    fn test_boundary_values() {
        // Staleness boundaries
        assert_eq!(calculate_staleness_score(Some(29)), 0); // Just under medium
        assert_eq!(calculate_staleness_score(Some(30)), 20); // Exactly medium
        assert_eq!(calculate_staleness_score(Some(89)), 20); // Just under critical
        assert_eq!(calculate_staleness_score(Some(90)), 40); // Exactly critical

        // Credential age boundaries
        assert_eq!(calculate_credential_age_score(Some(29)), 0);
        assert_eq!(calculate_credential_age_score(Some(30)), 15);
        assert_eq!(calculate_credential_age_score(Some(89)), 15);
        assert_eq!(calculate_credential_age_score(Some(90)), 30);

        // Scope boundaries
        assert_eq!(calculate_scope_score(Some(19)), 0);
        assert_eq!(calculate_scope_score(Some(20)), 15);
        assert_eq!(calculate_scope_score(Some(49)), 15);
        assert_eq!(calculate_scope_score(Some(50)), 30);
    }

    #[test]
    fn test_zero_values() {
        let factors = RiskFactors {
            staleness_days: Some(0),
            credential_age_days: Some(0),
            scope_count: Some(0),
        };
        // Zero days and zero scope should all be 0 risk
        assert_eq!(calculate_risk_score(&factors), 0);
    }
}
