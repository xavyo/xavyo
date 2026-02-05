//! Correlation statistics and insights service (F067, US7).
//!
//! Provides correlation performance metrics, trends, and optimization suggestions
//! to help administrators tune their correlation configuration.

use sqlx::PgPool;
use uuid::Uuid;

use xavyo_governance::error::Result;

use crate::models::correlation::{
    CorrelationStatisticsResponse, CorrelationTrendsResponse, DailyTrendData,
    ListCorrelationStatsQuery, ListCorrelationTrendsQuery,
};

/// Service for correlation statistics and insights.
pub struct CorrelationStatsService {
    pool: PgPool,
}

impl CorrelationStatsService {
    /// Create a new correlation statistics service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get correlation statistics for a connector within a date range.
    ///
    /// # Arguments
    ///
    /// * `tenant_id` - The tenant ID
    /// * `connector_id` - The connector to get statistics for
    /// * `query` - Query parameters including date range filters
    ///
    /// # Returns
    ///
    /// Statistics including auto-confirm rate, manual review rate, average confidence,
    /// queue depth, and optimization suggestions.
    pub async fn get_statistics(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
        query: &ListCorrelationStatsQuery,
    ) -> Result<CorrelationStatisticsResponse> {
        // Query audit events grouped by outcome
        // Note: We count events where event_type = 'auto_evaluated' to track automatic correlation results
        let rows: Vec<(String, i64, Option<f64>)> =
            sqlx::query_as::<_, (String, i64, Option<f64>)>(
                r"
            SELECT
                outcome::text,
                COUNT(*)::bigint,
                AVG(CASE
                    WHEN confidence_score IS NOT NULL
                    THEN confidence_score::float8
                    ELSE 0
                END)::float8
            FROM gov_correlation_audit_events
            WHERE tenant_id = $1
                AND connector_id = $2
                AND created_at >= COALESCE($3, '1970-01-01'::timestamptz)
                AND created_at <= COALESCE($4, NOW())
            GROUP BY outcome
            ",
            )
            .bind(tenant_id)
            .bind(connector_id)
            .bind(query.start_date)
            .bind(query.end_date)
            .fetch_all(&self.pool)
            .await?;

        // Parse outcomes and aggregate counts
        let mut auto_confirmed_count = 0i64;
        let mut manual_confirmed_count = 0i64;
        let mut manual_rejected_count = 0i64;
        let mut no_match_count = 0i64;
        let mut total_confidence = 0.0f64;
        let mut confidence_count = 0i64;

        for (outcome, count, avg_conf) in rows {
            match outcome.as_str() {
                "auto_confirmed" => {
                    auto_confirmed_count = count;
                }
                "manual_confirmed" => {
                    manual_confirmed_count = count;
                }
                "manual_rejected" => {
                    manual_rejected_count = count;
                }
                "no_match" => {
                    no_match_count = count;
                }
                "deferred_to_review" => {
                    // Count deferred cases as part of manual review workload
                    manual_confirmed_count += count;
                }
                "new_identity_created" => {
                    // Count new identity creation as part of manual review resolution
                    manual_confirmed_count += count;
                }
                "collision_detected" => {
                    // Collisions also go to manual review
                    manual_confirmed_count += count;
                }
                _ => {}
            }

            if let Some(conf) = avg_conf {
                if conf > 0.0 {
                    total_confidence += conf * count as f64;
                    confidence_count += count;
                }
            }
        }

        let manual_review_count = manual_confirmed_count + manual_rejected_count;
        let total_evaluated = auto_confirmed_count + manual_review_count + no_match_count;

        // Calculate percentages
        let auto_confirmed_percentage = if total_evaluated > 0 {
            (auto_confirmed_count as f64 / total_evaluated as f64) * 100.0
        } else {
            0.0
        };

        let manual_review_percentage = if total_evaluated > 0 {
            (manual_review_count as f64 / total_evaluated as f64) * 100.0
        } else {
            0.0
        };

        let no_match_percentage = if total_evaluated > 0 {
            (no_match_count as f64 / total_evaluated as f64) * 100.0
        } else {
            0.0
        };

        // Calculate average confidence
        let average_confidence = if confidence_count > 0 {
            total_confidence / confidence_count as f64
        } else {
            0.0
        };

        // Get current review queue depth
        let review_queue_depth: i64 = sqlx::query_scalar::<_, i64>(
            r"
            SELECT COUNT(*)::bigint
            FROM gov_correlation_cases
            WHERE tenant_id = $1
                AND connector_id = $2
                AND status = 'pending'
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .fetch_one(&self.pool)
        .await?;

        // Generate optimization suggestions
        let suggestions = Self::generate_suggestions(
            auto_confirmed_percentage,
            manual_review_percentage,
            no_match_percentage,
            average_confidence,
        );

        Ok(CorrelationStatisticsResponse {
            connector_id,
            period_start: query.start_date,
            period_end: query.end_date,
            total_evaluated,
            auto_confirmed_count,
            auto_confirmed_percentage,
            manual_review_count,
            manual_review_percentage,
            no_match_count,
            no_match_percentage,
            average_confidence,
            review_queue_depth,
            suggestions,
        })
    }

    /// Get correlation trends over time for a connector.
    ///
    /// # Arguments
    ///
    /// * `tenant_id` - The tenant ID
    /// * `connector_id` - The connector to get trends for
    /// * `query` - Query parameters including required start and end dates
    ///
    /// # Returns
    ///
    /// Daily trend data showing correlation outcomes over time.
    pub async fn get_trends(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
        query: &ListCorrelationTrendsQuery,
    ) -> Result<CorrelationTrendsResponse> {
        // Query daily aggregates
        let rows: Vec<(String, i64, i64, i64, i64, Option<f64>)> = sqlx::query_as::<_, (String, i64, i64, i64, i64, Option<f64>)>(
            r"
            SELECT
                DATE(created_at)::text,
                COUNT(*)::bigint,
                SUM(CASE WHEN outcome IN ('auto_confirmed') THEN 1 ELSE 0 END)::bigint,
                SUM(CASE WHEN outcome IN ('deferred_to_review', 'manual_confirmed', 'manual_rejected', 'new_identity_created', 'collision_detected') THEN 1 ELSE 0 END)::bigint,
                SUM(CASE WHEN outcome = 'no_match' THEN 1 ELSE 0 END)::bigint,
                AVG(CASE
                    WHEN confidence_score IS NOT NULL
                    THEN confidence_score::float8
                    ELSE 0
                END)::float8
            FROM gov_correlation_audit_events
            WHERE tenant_id = $1
                AND connector_id = $2
                AND created_at >= $3
                AND created_at <= $4
            GROUP BY DATE(created_at)
            ORDER BY DATE(created_at)
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .bind(query.start_date)
        .bind(query.end_date)
        .fetch_all(&self.pool)
        .await?;

        // Map rows to daily trend data
        let daily_trends: Vec<DailyTrendData> = rows
            .into_iter()
            .map(
                |(date, total, auto_confirmed, manual_review, no_match, avg_conf)| DailyTrendData {
                    date,
                    total_evaluated: total,
                    auto_confirmed,
                    manual_review,
                    no_match,
                    average_confidence: avg_conf.unwrap_or(0.0),
                },
            )
            .collect();

        // Calculate overall statistics for suggestions
        let total_evaluated: i64 = daily_trends.iter().map(|d| d.total_evaluated).sum();
        let total_auto: i64 = daily_trends.iter().map(|d| d.auto_confirmed).sum();
        let total_manual: i64 = daily_trends.iter().map(|d| d.manual_review).sum();
        let total_no_match: i64 = daily_trends.iter().map(|d| d.no_match).sum();

        let auto_rate = if total_evaluated > 0 {
            (total_auto as f64 / total_evaluated as f64) * 100.0
        } else {
            0.0
        };

        let manual_rate = if total_evaluated > 0 {
            (total_manual as f64 / total_evaluated as f64) * 100.0
        } else {
            0.0
        };

        let no_match_rate = if total_evaluated > 0 {
            (total_no_match as f64 / total_evaluated as f64) * 100.0
        } else {
            0.0
        };

        // Calculate average confidence across all days
        let avg_confidence = if daily_trends.is_empty() {
            0.0
        } else {
            daily_trends
                .iter()
                .map(|d| d.average_confidence)
                .sum::<f64>()
                / daily_trends.len() as f64
        };

        let suggestions =
            Self::generate_suggestions(auto_rate, manual_rate, no_match_rate, avg_confidence);

        Ok(CorrelationTrendsResponse {
            connector_id,
            period_start: query.start_date,
            period_end: query.end_date,
            daily_trends,
            suggestions,
        })
    }

    /// Generate optimization suggestions based on correlation statistics.
    ///
    /// # Arguments
    ///
    /// * `auto_rate` - Percentage of auto-confirmed matches
    /// * `manual_rate` - Percentage of manual reviews
    /// * `no_match_rate` - Percentage of no matches
    /// * `avg_confidence` - Average confidence score (0.0-1.0)
    ///
    /// # Returns
    ///
    /// A list of actionable suggestions for improving correlation configuration.
    fn generate_suggestions(
        auto_rate: f64,
        manual_rate: f64,
        no_match_rate: f64,
        avg_confidence: f64,
    ) -> Vec<String> {
        let mut suggestions = Vec::new();

        // High manual review rate
        if manual_rate > 40.0 {
            suggestions.push(
                "Consider adding more correlation attributes or adjusting thresholds to reduce manual review workload".to_string()
            );
        }

        // High no-match rate
        if no_match_rate > 50.0 {
            suggestions.push(
                "High no-match rate detected. Review attribute mapping configuration and data quality".to_string()
            );
        }

        // Low average confidence
        if avg_confidence < 0.5 {
            suggestions.push(
                "Low average confidence scores. Check source data quality and consider adding more correlation rules".to_string()
            );
        }

        // Excellent auto-match rate
        if auto_rate > 90.0 {
            suggestions.push(
                "Excellent auto-match rate. Current configuration is performing well".to_string(),
            );
        }

        // Moderate performance - provide tuning guidance
        if suggestions.is_empty() && manual_rate > 20.0 && manual_rate <= 40.0 {
            suggestions.push(
                "Moderate manual review rate. Consider fine-tuning thresholds or adding definitive correlation rules".to_string()
            );
        }

        // No issues detected
        if suggestions.is_empty() {
            suggestions.push("Correlation configuration is well-balanced".to_string());
        }

        suggestions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_suggestions_high_manual_rate() {
        let suggestions = CorrelationStatsService::generate_suggestions(30.0, 50.0, 20.0, 0.7);

        assert!(!suggestions.is_empty());
        assert!(suggestions
            .iter()
            .any(|s| s.contains("manual review workload")));
    }

    #[test]
    fn test_generate_suggestions_high_no_match_rate() {
        let suggestions = CorrelationStatsService::generate_suggestions(30.0, 15.0, 55.0, 0.7);

        assert!(suggestions.iter().any(|s| s.contains("High no-match rate")));
    }

    #[test]
    fn test_generate_suggestions_low_confidence() {
        let suggestions = CorrelationStatsService::generate_suggestions(40.0, 30.0, 30.0, 0.4);

        assert!(suggestions
            .iter()
            .any(|s| s.contains("Low average confidence")));
    }

    #[test]
    fn test_generate_suggestions_excellent_auto_rate() {
        let suggestions = CorrelationStatsService::generate_suggestions(92.0, 5.0, 3.0, 0.85);

        assert!(suggestions
            .iter()
            .any(|s| s.contains("Excellent auto-match rate")));
    }

    #[test]
    fn test_generate_suggestions_moderate_performance() {
        let suggestions = CorrelationStatsService::generate_suggestions(60.0, 25.0, 15.0, 0.65);

        assert!(suggestions
            .iter()
            .any(|s| s.contains("Moderate manual review rate") || s.contains("fine-tuning")));
    }

    #[test]
    fn test_generate_suggestions_well_balanced() {
        let suggestions = CorrelationStatsService::generate_suggestions(85.0, 10.0, 5.0, 0.8);

        assert!(suggestions
            .iter()
            .any(|s| s.contains("well-balanced") || s.contains("performing well")));
    }

    #[test]
    fn test_generate_suggestions_multiple_issues() {
        let suggestions = CorrelationStatsService::generate_suggestions(10.0, 45.0, 55.0, 0.3);

        // Should have suggestions for both high manual rate, high no-match rate, and low confidence
        assert!(suggestions.len() >= 3);
        assert!(suggestions
            .iter()
            .any(|s| s.contains("manual review workload")));
        assert!(suggestions.iter().any(|s| s.contains("High no-match rate")));
        assert!(suggestions
            .iter()
            .any(|s| s.contains("Low average confidence")));
    }
}
