//! Outlier scoring service - Core scoring algorithms for F059.
//!
//! Implements Z-score calculation, weighted multi-factor scoring,
//! and outlier classification based on peer group comparisons.

use sqlx::PgPool;
use uuid::Uuid;

use chrono::{DateTime, Utc};

use crate::models::OutlierReportResponse;
use xavyo_db::{
    ConfigSnapshot, CreateAlert, CreateDisposition, CreateOutlierAnalysis, CreateOutlierResult,
    DispositionFilter, FactorBreakdown, FactorScore, GovOutlierAlert, GovOutlierAnalysis,
    GovOutlierConfiguration, GovOutlierDisposition, GovOutlierResult, GovPeerGroup,
    OutlierAlertSeverity, OutlierAlertType, OutlierAnalysisFilter, OutlierAnalysisStatus,
    OutlierClassification, OutlierDispositionStatus, OutlierResultFilter, OutlierTriggerType,
    PeerGroupScore, ScoringWeights, UpdateDisposition,
};
use xavyo_governance::error::{GovernanceError, Result};

/// Internal struct for loading user profiles from database.
#[derive(Debug, sqlx::FromRow)]
struct UserProfileRow {
    user_id: Uuid,
    entitlement_count: i32,
    role_count: i32,
    peer_group_ids: Option<Vec<Uuid>>,
    previous_score: Option<f64>,
}

/// Statistics for a peer group.
#[derive(Debug, Clone)]
pub struct PeerGroupStats {
    pub peer_group_id: Uuid,
    pub peer_group_name: String,
    pub member_count: i32,
    pub mean_entitlements: f64,
    pub std_dev_entitlements: f64,
    pub mean_roles: f64,
    pub std_dev_roles: f64,
    pub role_frequencies: std::collections::HashMap<Uuid, f64>,
}

/// User access profile for scoring.
#[derive(Debug, Clone)]
pub struct UserAccessProfile {
    pub user_id: Uuid,
    pub entitlement_count: i32,
    pub role_ids: Vec<Uuid>,
    pub role_count: i32,
    pub peer_group_ids: Vec<Uuid>,
    /// Historical scores for trend analysis.
    pub previous_score: Option<f64>,
}

/// Result of scoring a user.
#[derive(Debug, Clone)]
pub struct UserScoringResult {
    pub user_id: Uuid,
    pub overall_score: f64,
    pub classification: OutlierClassification,
    pub peer_scores: Vec<PeerGroupScore>,
    pub factor_breakdown: FactorBreakdown,
    pub previous_score: Option<f64>,
    pub score_change: Option<f64>,
}

/// Service for outlier scoring algorithms.
pub struct OutlierScoringService {
    pool: PgPool,
}

impl OutlierScoringService {
    #[must_use] 
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Calculate Z-score for a value given mean and standard deviation.
    ///
    /// Z-score = (value - mean) / `std_dev`
    /// Returns 0 if `std_dev` is 0 (no variation in data).
    #[must_use] 
    pub fn calculate_z_score(value: f64, mean: f64, std_dev: f64) -> f64 {
        if std_dev <= 0.0 {
            return 0.0;
        }
        (value - mean) / std_dev
    }

    /// Normalize Z-score to 0-100 scale.
    ///
    /// Uses sigmoid-like mapping where:
    /// - Z-score of 0 maps to ~50
    /// - Z-score of 2 maps to ~88
    /// - Z-score of 3 maps to ~95
    /// - Negative Z-scores map below 50
    #[must_use] 
    pub fn normalize_z_score_to_percentage(z_score: f64) -> f64 {
        // Use logistic function to map z-score to 0-100
        // Adjusted so z=0 -> 50, z=2 -> ~88, z=-2 -> ~12
        let scaled = 1.0 / (1.0 + (-z_score * 0.8).exp());
        scaled * 100.0
    }

    /// Calculate deviation factor from Z-score (0-100 scale).
    #[must_use] 
    pub fn z_score_to_deviation_factor(z_score: f64) -> f64 {
        // Absolute value since we care about magnitude of deviation
        Self::normalize_z_score_to_percentage(z_score.abs())
    }

    /// Calculate weighted composite score from factor scores.
    ///
    /// Each factor contributes: `raw_value` * weight
    /// Sum is clamped to 0-100.
    #[must_use] 
    pub fn calculate_weighted_score(factors: &FactorBreakdown, weights: &ScoringWeights) -> f64 {
        let mut total = 0.0;

        if let Some(ref rf) = factors.role_frequency {
            total += rf.raw_value * weights.role_frequency;
        }
        if let Some(ref ec) = factors.entitlement_count {
            total += ec.raw_value * weights.entitlement_count;
        }
        if let Some(ref ap) = factors.assignment_pattern {
            total += ap.raw_value * weights.assignment_pattern;
        }
        if let Some(ref pgc) = factors.peer_group_coverage {
            total += pgc.raw_value * weights.peer_group_coverage;
        }
        if let Some(ref hd) = factors.historical_deviation {
            total += hd.raw_value * weights.historical_deviation;
        }

        total.clamp(0.0, 100.0)
    }

    /// Classify a user based on their score and peer group analysis.
    ///
    /// - Normal: Score below threshold or no peer groups flag as outlier
    /// - Outlier: At least one peer group Z-score exceeds confidence threshold
    /// - Unclassifiable: No valid peer groups for comparison
    #[must_use] 
    pub fn classify_user(
        peer_scores: &[PeerGroupScore],
        _confidence_threshold: f64,
    ) -> OutlierClassification {
        if peer_scores.is_empty() {
            return OutlierClassification::Unclassifiable;
        }

        // Check if any peer group flags as outlier (based on the is_outlier field
        // which was calculated using the confidence threshold during scoring)
        let has_outlier = peer_scores.iter().any(|ps| ps.is_outlier);

        if has_outlier {
            OutlierClassification::Outlier
        } else {
            OutlierClassification::Normal
        }
    }

    /// Score a user against a single peer group.
    #[must_use] 
    pub fn score_against_peer_group(
        &self,
        user: &UserAccessProfile,
        stats: &PeerGroupStats,
        confidence_threshold: f64,
    ) -> PeerGroupScore {
        // Calculate Z-score for entitlement count
        let entitlement_z = Self::calculate_z_score(
            f64::from(user.entitlement_count),
            stats.mean_entitlements,
            stats.std_dev_entitlements,
        );

        // Calculate Z-score for role count
        let role_z = Self::calculate_z_score(
            f64::from(user.role_count),
            stats.mean_roles,
            stats.std_dev_roles,
        );

        // Use the higher Z-score (more deviant)
        let max_z = entitlement_z.abs().max(role_z.abs());
        let z_score = if entitlement_z.abs() > role_z.abs() {
            entitlement_z
        } else {
            role_z
        };

        let deviation_factor = Self::z_score_to_deviation_factor(max_z);
        let is_outlier = max_z.abs() >= confidence_threshold;

        PeerGroupScore {
            peer_group_id: stats.peer_group_id,
            peer_group_name: stats.peer_group_name.clone(),
            z_score,
            deviation_factor,
            is_outlier,
        }
    }

    /// Calculate role frequency factor.
    ///
    /// Measures how many of the user's roles are uncommon in their peer groups.
    /// Higher score = more unusual roles.
    #[must_use] 
    pub fn calculate_role_frequency_factor(
        user: &UserAccessProfile,
        peer_stats: &[PeerGroupStats],
        frequency_threshold: f64,
        weight: f64,
    ) -> FactorScore {
        if user.role_ids.is_empty() || peer_stats.is_empty() {
            return FactorScore {
                raw_value: 0.0,
                weight,
                contribution: 0.0,
                details: "No roles to analyze".to_string(),
            };
        }

        let mut unusual_role_count = 0;
        let total_roles = user.role_ids.len();

        for role_id in &user.role_ids {
            // Check if this role is unusual in any peer group
            let is_unusual = peer_stats.iter().any(|stats| {
                stats
                    .role_frequencies
                    .get(role_id)
                    .is_none_or(|&freq| freq < frequency_threshold) // Role not found = unusual
            });

            if is_unusual {
                unusual_role_count += 1;
            }
        }

        let unusual_ratio = f64::from(unusual_role_count) / total_roles as f64;
        let raw_value = unusual_ratio * 100.0;
        let contribution = raw_value * weight;

        FactorScore {
            raw_value,
            weight,
            contribution,
            details: format!(
                "{} of {} roles appear in <{}% of peer group",
                unusual_role_count,
                total_roles,
                (frequency_threshold * 100.0) as i32
            ),
        }
    }

    /// Calculate entitlement count factor.
    ///
    /// Compares user's entitlement count to peer average.
    /// Uses highest deviation across peer groups.
    #[must_use] 
    pub fn calculate_entitlement_count_factor(
        user: &UserAccessProfile,
        peer_stats: &[PeerGroupStats],
        weight: f64,
    ) -> FactorScore {
        if peer_stats.is_empty() {
            return FactorScore {
                raw_value: 0.0,
                weight,
                contribution: 0.0,
                details: "No peer groups for comparison".to_string(),
            };
        }

        let mut max_deviation = 0.0;
        let mut best_comparison = (0.0, 0.0); // (peer_avg, z_score)

        for stats in peer_stats {
            let z_score = Self::calculate_z_score(
                f64::from(user.entitlement_count),
                stats.mean_entitlements,
                stats.std_dev_entitlements,
            );

            if z_score.abs() > max_deviation {
                max_deviation = z_score.abs();
                best_comparison = (stats.mean_entitlements, z_score);
            }
        }

        let raw_value = Self::z_score_to_deviation_factor(max_deviation);
        let contribution = raw_value * weight;

        FactorScore {
            raw_value,
            weight,
            contribution,
            details: format!(
                "User has {} entitlements vs peer avg of {:.1} (z-score: {:.2})",
                user.entitlement_count, best_comparison.0, best_comparison.1
            ),
        }
    }

    /// Calculate assignment pattern factor.
    ///
    /// Analyzes how user's role assignments differ from typical patterns.
    /// Placeholder: Uses role count deviation as proxy.
    #[must_use] 
    pub fn calculate_assignment_pattern_factor(
        user: &UserAccessProfile,
        peer_stats: &[PeerGroupStats],
        weight: f64,
    ) -> FactorScore {
        if peer_stats.is_empty() {
            return FactorScore {
                raw_value: 0.0,
                weight,
                contribution: 0.0,
                details: "No peer groups for comparison".to_string(),
            };
        }

        let mut max_deviation = 0.0;
        let mut best_comparison = (0.0, 0.0);

        for stats in peer_stats {
            let z_score = Self::calculate_z_score(
                f64::from(user.role_count),
                stats.mean_roles,
                stats.std_dev_roles,
            );

            if z_score.abs() > max_deviation {
                max_deviation = z_score.abs();
                best_comparison = (stats.mean_roles, z_score);
            }
        }

        let raw_value = Self::z_score_to_deviation_factor(max_deviation);
        let contribution = raw_value * weight;

        FactorScore {
            raw_value,
            weight,
            contribution,
            details: format!(
                "User has {} roles vs peer avg of {:.1} (z-score: {:.2})",
                user.role_count, best_comparison.0, best_comparison.1
            ),
        }
    }

    /// Calculate peer group coverage factor.
    ///
    /// Measures how many peer groups the user belongs to.
    /// Users in very few groups may be harder to classify.
    #[must_use] 
    pub fn calculate_peer_group_coverage_factor(
        user: &UserAccessProfile,
        total_applicable_groups: i32,
        weight: f64,
    ) -> FactorScore {
        let coverage = if total_applicable_groups > 0 {
            user.peer_group_ids.len() as f64 / f64::from(total_applicable_groups)
        } else {
            0.0
        };

        // Lower coverage = higher score (more unusual)
        let raw_value = (1.0 - coverage) * 100.0;
        let contribution = raw_value * weight;

        FactorScore {
            raw_value,
            weight,
            contribution,
            details: format!(
                "User is in {} of {} applicable peer groups",
                user.peer_group_ids.len(),
                total_applicable_groups
            ),
        }
    }

    /// Calculate historical deviation factor.
    ///
    /// Compares current score to previous score.
    /// Large increases are more concerning.
    #[must_use] 
    pub fn calculate_historical_deviation_factor(
        current_score: f64,
        previous_score: Option<f64>,
        weight: f64,
    ) -> FactorScore {
        match previous_score {
            Some(prev) => {
                let change = current_score - prev;
                // Scale change to 0-100 (assuming max reasonable change is 50 points)
                let raw_value = ((change / 50.0).clamp(-1.0, 1.0) + 1.0) * 50.0;
                let contribution = raw_value * weight;

                FactorScore {
                    raw_value,
                    weight,
                    contribution,
                    details: format!("Score changed by {change:.1} from previous {prev:.1}"),
                }
            }
            None => FactorScore {
                raw_value: 50.0, // Neutral when no history
                weight,
                contribution: 50.0 * weight,
                details: "No previous score for comparison".to_string(),
            },
        }
    }

    /// Score a user against all their peer groups.
    #[must_use] 
    pub fn score_user(
        &self,
        user: &UserAccessProfile,
        peer_stats: &[PeerGroupStats],
        weights: &ScoringWeights,
        confidence_threshold: f64,
        frequency_threshold: f64,
    ) -> UserScoringResult {
        // Score against each peer group
        let peer_scores: Vec<PeerGroupScore> = peer_stats
            .iter()
            .filter(|stats| user.peer_group_ids.contains(&stats.peer_group_id))
            .map(|stats| self.score_against_peer_group(user, stats, confidence_threshold))
            .collect();

        // Calculate each factor
        let user_peer_stats: Vec<_> = peer_stats
            .iter()
            .filter(|s| user.peer_group_ids.contains(&s.peer_group_id))
            .cloned()
            .collect();

        let role_frequency = Self::calculate_role_frequency_factor(
            user,
            &user_peer_stats,
            frequency_threshold,
            weights.role_frequency,
        );

        let entitlement_count = Self::calculate_entitlement_count_factor(
            user,
            &user_peer_stats,
            weights.entitlement_count,
        );

        let assignment_pattern = Self::calculate_assignment_pattern_factor(
            user,
            &user_peer_stats,
            weights.assignment_pattern,
        );

        let peer_group_coverage = Self::calculate_peer_group_coverage_factor(
            user,
            peer_stats.len() as i32,
            weights.peer_group_coverage,
        );

        // We'll calculate preliminary score for historical comparison
        let preliminary_score = role_frequency.contribution
            + entitlement_count.contribution
            + assignment_pattern.contribution
            + peer_group_coverage.contribution
            + (50.0 * weights.historical_deviation); // Neutral historical before we know it

        let historical_deviation = Self::calculate_historical_deviation_factor(
            preliminary_score,
            user.previous_score,
            weights.historical_deviation,
        );

        let factor_breakdown = FactorBreakdown {
            role_frequency: Some(role_frequency),
            entitlement_count: Some(entitlement_count),
            assignment_pattern: Some(assignment_pattern),
            peer_group_coverage: Some(peer_group_coverage),
            historical_deviation: Some(historical_deviation),
        };

        // Calculate final overall score
        let overall_score = Self::calculate_weighted_score(&factor_breakdown, weights);

        // Classify based on peer scores
        let classification = Self::classify_user(&peer_scores, confidence_threshold);

        // Calculate score change
        let score_change = user.previous_score.map(|prev| overall_score - prev);

        UserScoringResult {
            user_id: user.user_id,
            overall_score,
            classification,
            peer_scores,
            factor_breakdown,
            previous_score: user.previous_score,
            score_change,
        }
    }

    /// Load peer group statistics for a tenant.
    pub async fn load_peer_group_stats(&self, tenant_id: Uuid) -> Result<Vec<PeerGroupStats>> {
        let groups =
            GovPeerGroup::list_by_tenant(&self.pool, tenant_id, &Default::default(), 1000, 0)
                .await
                .map_err(GovernanceError::Database)?;

        let stats: Vec<PeerGroupStats> = groups
            .into_iter()
            .map(|g| {
                // Parse role frequencies from JSON if available
                let role_frequencies = std::collections::HashMap::new();
                // TODO: Extend GovPeerGroup to include role_frequency_map

                PeerGroupStats {
                    peer_group_id: g.id,
                    peer_group_name: g.name,
                    member_count: g.user_count,
                    mean_entitlements: g.avg_entitlements.unwrap_or(0.0),
                    std_dev_entitlements: g.stddev_entitlements.unwrap_or(0.0),
                    // GovPeerGroup doesn't track role stats currently, default to entitlement-based
                    mean_roles: g.avg_entitlements.unwrap_or(0.0),
                    std_dev_roles: g.stddev_entitlements.unwrap_or(0.0),
                    role_frequencies,
                }
            })
            .collect();

        Ok(stats)
    }

    // ========================================================================
    // Analysis Operations
    // ========================================================================

    /// List analyses with filtering.
    pub async fn list_analyses(
        &self,
        tenant_id: Uuid,
        status: Option<OutlierAnalysisStatus>,
        triggered_by: Option<OutlierTriggerType>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<GovOutlierAnalysis>, i64)> {
        let filter = OutlierAnalysisFilter {
            status,
            triggered_by,
        };

        let analyses =
            GovOutlierAnalysis::list_by_tenant(&self.pool, tenant_id, &filter, limit, offset)
                .await
                .map_err(GovernanceError::Database)?;

        let total = GovOutlierAnalysis::count_by_tenant(&self.pool, tenant_id, &filter)
            .await
            .map_err(GovernanceError::Database)?;

        Ok((analyses, total))
    }

    /// Get a specific analysis.
    pub async fn get_analysis(
        &self,
        tenant_id: Uuid,
        analysis_id: Uuid,
    ) -> Result<GovOutlierAnalysis> {
        GovOutlierAnalysis::find_by_id(&self.pool, tenant_id, analysis_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or_else(|| GovernanceError::OutlierAnalysisNotFound(analysis_id))
    }

    /// Trigger a new analysis.
    pub async fn trigger_analysis(
        &self,
        tenant_id: Uuid,
        triggered_by: OutlierTriggerType,
    ) -> Result<GovOutlierAnalysis> {
        // Check if there's already a running analysis
        if GovOutlierAnalysis::has_running(&self.pool, tenant_id)
            .await
            .map_err(GovernanceError::Database)?
        {
            return Err(GovernanceError::OutlierAnalysisAlreadyRunning);
        }

        // Get config for snapshot
        let config = GovOutlierConfiguration::get_or_create(&self.pool, tenant_id)
            .await
            .map_err(GovernanceError::Database)?;

        let input = CreateOutlierAnalysis {
            triggered_by,
            config_snapshot: ConfigSnapshot {
                confidence_threshold: config.confidence_threshold,
                frequency_threshold: config.frequency_threshold,
                min_peer_group_size: config.min_peer_group_size,
                scoring_weights: config.scoring_weights.0,
            },
        };

        GovOutlierAnalysis::create(&self.pool, tenant_id, input)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Cancel a running analysis.
    pub async fn cancel_analysis(
        &self,
        tenant_id: Uuid,
        analysis_id: Uuid,
    ) -> Result<GovOutlierAnalysis> {
        let analysis = self.get_analysis(tenant_id, analysis_id).await?;

        if analysis.status != OutlierAnalysisStatus::Pending
            && analysis.status != OutlierAnalysisStatus::Running
        {
            return Err(GovernanceError::Validation(format!(
                "Cannot cancel analysis in {:?} status",
                analysis.status
            )));
        }

        GovOutlierAnalysis::cancel(&self.pool, tenant_id, analysis_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or_else(|| GovernanceError::OutlierAnalysisNotFound(analysis_id))
    }

    /// Execute an analysis - this is the main batch processing method.
    ///
    /// This method:
    /// 1. Marks the analysis as running
    /// 2. Loads all users with entitlements
    /// 3. Loads peer group statistics
    /// 4. Scores each user against their peer groups
    /// 5. Creates results for each user
    /// 6. Creates alerts for outliers
    /// 7. Marks the analysis as complete (or failed)
    pub async fn execute_analysis(
        &self,
        tenant_id: Uuid,
        analysis_id: Uuid,
    ) -> Result<GovOutlierAnalysis> {
        // Start the analysis
        let analysis = GovOutlierAnalysis::start(&self.pool, tenant_id, analysis_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or_else(|| GovernanceError::OutlierAnalysisNotFound(analysis_id))?;

        // Extract config from snapshot
        let config = &analysis.config_snapshot.0;
        let weights = &config.scoring_weights;
        let confidence_threshold = config.confidence_threshold;
        let frequency_threshold = config.frequency_threshold;
        let min_peer_group_size = config.min_peer_group_size;

        // Load peer group statistics
        let peer_stats = self.load_peer_group_stats(tenant_id).await?;

        // Filter out small peer groups
        let valid_peer_stats: Vec<_> = peer_stats
            .into_iter()
            .filter(|s| s.member_count >= min_peer_group_size)
            .collect();

        if valid_peer_stats.is_empty() {
            // No valid peer groups - fail the analysis
            let _ = GovOutlierAnalysis::fail(
                &self.pool,
                tenant_id,
                analysis_id,
                "No peer groups meet minimum size requirement",
            )
            .await;
            return Err(GovernanceError::NoPeerGroupsForAnalysis);
        }

        // Load all users with their entitlement counts and peer group memberships
        let user_profiles = self.load_user_profiles(tenant_id).await?;
        let total_users = user_profiles.len();

        if total_users == 0 {
            // No users to analyze - complete with 0 results
            return GovOutlierAnalysis::complete(&self.pool, tenant_id, analysis_id, 0, 0)
                .await
                .map_err(GovernanceError::Database)?
                .ok_or_else(|| GovernanceError::OutlierAnalysisNotFound(analysis_id));
        }

        let mut users_processed = 0;
        let mut outliers_detected = 0;
        let batch_size = 100;

        // Process users in batches
        for chunk in user_profiles.chunks(batch_size) {
            let mut results_to_create = Vec::with_capacity(chunk.len());
            let mut alerts_to_create = Vec::new();

            for user in chunk {
                // Score the user
                let scoring_result = self.score_user(
                    user,
                    &valid_peer_stats,
                    weights,
                    confidence_threshold,
                    frequency_threshold,
                );

                // Check if outlier
                let is_outlier = matches!(
                    scoring_result.classification,
                    OutlierClassification::Outlier
                );
                if is_outlier {
                    outliers_detected += 1;

                    // Determine alert type
                    let alert_type = if let Some(prev) = scoring_result.previous_score {
                        if scoring_result.overall_score > prev + 10.0 {
                            OutlierAlertType::ScoreIncrease
                        } else {
                            OutlierAlertType::NewOutlier
                        }
                    } else {
                        OutlierAlertType::NewOutlier
                    };

                    alerts_to_create.push(CreateAlert {
                        analysis_id,
                        user_id: user.user_id,
                        alert_type,
                        score: scoring_result.overall_score,
                        classification: scoring_result.classification,
                    });
                }

                results_to_create.push(CreateOutlierResult {
                    analysis_id,
                    user_id: user.user_id,
                    overall_score: scoring_result.overall_score,
                    classification: scoring_result.classification,
                    peer_scores: scoring_result.peer_scores,
                    factor_breakdown: scoring_result.factor_breakdown,
                    previous_score: scoring_result.previous_score,
                    score_change: scoring_result.score_change,
                });

                users_processed += 1;
            }

            // Batch insert results
            for result in results_to_create {
                let _ = GovOutlierResult::create(&self.pool, tenant_id, result)
                    .await
                    .map_err(GovernanceError::Database)?;
            }

            // Batch insert alerts
            for alert in alerts_to_create {
                let _ = GovOutlierAlert::create(&self.pool, tenant_id, alert)
                    .await
                    .map_err(GovernanceError::Database)?;
            }

            // Update progress
            let progress = ((f64::from(users_processed) / total_users as f64) * 100.0) as i32;
            let _ = GovOutlierAnalysis::update_progress(
                &self.pool,
                tenant_id,
                analysis_id,
                progress,
                users_processed,
                outliers_detected,
            )
            .await;
        }

        // Complete the analysis
        GovOutlierAnalysis::complete(
            &self.pool,
            tenant_id,
            analysis_id,
            users_processed,
            outliers_detected,
        )
        .await
        .map_err(GovernanceError::Database)?
        .ok_or_else(|| GovernanceError::OutlierAnalysisNotFound(analysis_id))
    }

    /// Load user profiles with entitlement counts and peer group memberships.
    async fn load_user_profiles(&self, tenant_id: Uuid) -> Result<Vec<UserAccessProfile>> {
        // Query to get users with their entitlement counts and peer group memberships
        let rows: Vec<UserProfileRow> = sqlx::query_as(
            r"
            SELECT
                u.id as user_id,
                COALESCE(ec.entitlement_count, 0) as entitlement_count,
                COALESCE(ec.role_count, 0) as role_count,
                COALESCE(pgm.peer_group_ids, ARRAY[]::uuid[]) as peer_group_ids,
                prev.overall_score as previous_score
            FROM users u
            LEFT JOIN LATERAL (
                SELECT
                    COUNT(DISTINCT ea.entitlement_id) as entitlement_count,
                    COUNT(DISTINCT e.role_id) as role_count
                FROM gov_entitlement_assignments ea
                JOIN gov_entitlements e ON ea.entitlement_id = e.id
                WHERE ea.user_id = u.id AND ea.tenant_id = u.tenant_id
                AND ea.status = 'active'
            ) ec ON true
            LEFT JOIN LATERAL (
                SELECT ARRAY_AGG(group_id) as peer_group_ids
                FROM gov_peer_group_members
                WHERE user_id = u.id AND tenant_id = u.tenant_id
            ) pgm ON true
            LEFT JOIN LATERAL (
                SELECT r.overall_score
                FROM gov_outlier_results r
                JOIN gov_outlier_analyses a ON r.analysis_id = a.id
                WHERE r.user_id = u.id AND r.tenant_id = u.tenant_id
                AND a.status = 'completed'
                ORDER BY r.created_at DESC
                LIMIT 1
            ) prev ON true
            WHERE u.tenant_id = $1 AND u.is_active = true
            ",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        Ok(rows
            .into_iter()
            .map(|row| UserAccessProfile {
                user_id: row.user_id,
                entitlement_count: row.entitlement_count,
                role_ids: vec![], // We don't load individual role IDs for performance
                role_count: row.role_count,
                peer_group_ids: row.peer_group_ids.unwrap_or_default(),
                previous_score: row.previous_score,
            })
            .collect())
    }

    // ========================================================================
    // Result Operations
    // ========================================================================

    /// List results with filtering.
    pub async fn list_results(
        &self,
        tenant_id: Uuid,
        analysis_id: Option<Uuid>,
        user_id: Option<Uuid>,
        classification: Option<OutlierClassification>,
        min_score: Option<f64>,
        max_score: Option<f64>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<GovOutlierResult>, i64)> {
        let filter = OutlierResultFilter {
            analysis_id,
            user_id,
            classification,
            min_score,
            max_score,
        };

        let results =
            GovOutlierResult::list_by_tenant(&self.pool, tenant_id, &filter, limit, offset)
                .await
                .map_err(GovernanceError::Database)?;

        let total = GovOutlierResult::count_by_tenant(&self.pool, tenant_id, &filter)
            .await
            .map_err(GovernanceError::Database)?;

        Ok((results, total))
    }

    /// Get a specific result.
    pub async fn get_result(&self, tenant_id: Uuid, result_id: Uuid) -> Result<GovOutlierResult> {
        GovOutlierResult::find_by_id(&self.pool, tenant_id, result_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or_else(|| GovernanceError::OutlierResultNotFound(result_id))
    }

    /// Get summary statistics.
    pub async fn get_summary(&self, tenant_id: Uuid) -> Result<OutlierSummary> {
        // Get the latest completed analysis first
        let latest = GovOutlierAnalysis::find_latest_completed(&self.pool, tenant_id)
            .await
            .map_err(GovernanceError::Database)?;

        if let Some(analysis) = latest {
            let summary = GovOutlierResult::get_summary(&self.pool, tenant_id, analysis.id)
                .await
                .map_err(GovernanceError::Database)?;

            Ok(OutlierSummary {
                total_users: summary.total_users,
                outlier_count: summary.outlier_count,
                normal_count: summary.normal_count,
                unclassifiable_count: summary.unclassifiable_count,
                avg_score: summary.avg_score,
                max_score: summary.max_score,
                analysis_id: Some(analysis.id),
                analysis_completed_at: analysis.completed_at,
            })
        } else {
            Ok(OutlierSummary::default())
        }
    }

    /// Get user's outlier history.
    pub async fn get_user_history(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        limit: i64,
    ) -> Result<(Vec<GovOutlierResult>, Option<GovOutlierDisposition>)> {
        let results = GovOutlierResult::get_user_history(&self.pool, tenant_id, user_id, limit)
            .await
            .map_err(GovernanceError::Database)?;

        // Get latest disposition for this user
        let disposition = if let Some(latest) = results.first() {
            GovOutlierDisposition::find_by_result(&self.pool, tenant_id, latest.id)
                .await
                .map_err(GovernanceError::Database)?
        } else {
            None
        };

        Ok((results, disposition))
    }

    // ========================================================================
    // Disposition Operations
    // ========================================================================

    /// Create a disposition for a result.
    pub async fn create_disposition(
        &self,
        tenant_id: Uuid,
        result_id: Uuid,
        reviewer_id: Uuid,
        status: OutlierDispositionStatus,
        justification: Option<String>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<GovOutlierDisposition> {
        let result = self.get_result(tenant_id, result_id).await?;

        // First create the disposition with default status
        let input = CreateDisposition {
            result_id,
            user_id: result.user_id,
        };

        let disposition = GovOutlierDisposition::create(&self.pool, tenant_id, input)
            .await
            .map_err(GovernanceError::Database)?;

        // Then update it to the requested status
        if status == OutlierDispositionStatus::New {
            Ok(disposition)
        } else {
            let update_input = UpdateDisposition {
                status,
                justification,
                reviewed_by: reviewer_id,
                expires_at,
            };

            GovOutlierDisposition::update(
                &self.pool,
                tenant_id,
                disposition.id,
                OutlierDispositionStatus::New,
                update_input,
            )
            .await
            .map_err(GovernanceError::Database)?
            .ok_or_else(|| GovernanceError::OutlierDispositionNotFound(disposition.id))
        }
    }

    /// Get a disposition.
    pub async fn get_disposition(
        &self,
        tenant_id: Uuid,
        disposition_id: Uuid,
    ) -> Result<GovOutlierDisposition> {
        GovOutlierDisposition::find_by_id(&self.pool, tenant_id, disposition_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or_else(|| GovernanceError::OutlierDispositionNotFound(disposition_id))
    }

    /// Update a disposition.
    pub async fn update_disposition(
        &self,
        tenant_id: Uuid,
        disposition_id: Uuid,
        reviewer_id: Uuid,
        new_status: OutlierDispositionStatus,
        justification: Option<String>,
    ) -> Result<GovOutlierDisposition> {
        let disposition = self.get_disposition(tenant_id, disposition_id).await?;

        let update_input = UpdateDisposition {
            status: new_status,
            justification,
            reviewed_by: reviewer_id,
            expires_at: None,
        };

        GovOutlierDisposition::update(
            &self.pool,
            tenant_id,
            disposition_id,
            disposition.status,
            update_input,
        )
        .await
        .map_err(GovernanceError::Database)?
        .ok_or_else(|| {
            GovernanceError::OutlierDispositionInvalidTransition(
                format!("{:?}", disposition.status),
                format!("{new_status:?}"),
            )
        })
    }

    /// List dispositions with filtering.
    pub async fn list_dispositions(
        &self,
        tenant_id: Uuid,
        user_id: Option<Uuid>,
        status: Option<OutlierDispositionStatus>,
        reviewed_by: Option<Uuid>,
        include_expired: bool,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<GovOutlierDisposition>, i64)> {
        let filter = DispositionFilter {
            user_id,
            status,
            reviewed_by,
            include_expired,
        };

        let dispositions =
            GovOutlierDisposition::list_by_tenant(&self.pool, tenant_id, &filter, limit, offset)
                .await
                .map_err(GovernanceError::Database)?;

        let total = GovOutlierDisposition::count_by_tenant(&self.pool, tenant_id, &filter)
            .await
            .map_err(GovernanceError::Database)?;

        Ok((dispositions, total))
    }

    /// Get disposition summary.
    pub async fn get_disposition_summary(&self, tenant_id: Uuid) -> Result<DispositionSummary> {
        let summary = GovOutlierDisposition::get_summary(&self.pool, tenant_id)
            .await
            .map_err(GovernanceError::Database)?;

        Ok(DispositionSummary {
            new_count: summary.new_count,
            legitimate_count: summary.legitimate_count,
            requires_remediation_count: summary.requires_remediation_count,
            under_investigation_count: summary.under_investigation_count,
            remediated_count: summary.remediated_count,
        })
    }

    // ========================================================================
    // Alert Operations
    // ========================================================================

    /// List alerts with filtering.
    pub async fn list_alerts(
        &self,
        tenant_id: Uuid,
        user_id: Option<Uuid>,
        analysis_id: Option<Uuid>,
        alert_type: Option<OutlierAlertType>,
        severity: Option<OutlierAlertSeverity>,
        is_read: Option<bool>,
        is_dismissed: Option<bool>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<GovOutlierAlert>, i64)> {
        use xavyo_db::OutlierAlertFilter;

        let filter = OutlierAlertFilter {
            user_id,
            analysis_id,
            alert_type,
            severity,
            is_read,
            is_dismissed,
        };

        let alerts = GovOutlierAlert::list_by_tenant(&self.pool, tenant_id, &filter, limit, offset)
            .await
            .map_err(GovernanceError::Database)?;

        let total = GovOutlierAlert::count_by_tenant(&self.pool, tenant_id, &filter)
            .await
            .map_err(GovernanceError::Database)?;

        Ok((alerts, total))
    }

    /// Get alert summary.
    pub async fn get_alert_summary(&self, tenant_id: Uuid) -> Result<AlertSummary> {
        let summary = GovOutlierAlert::get_summary(&self.pool, tenant_id)
            .await
            .map_err(GovernanceError::Database)?;

        Ok(AlertSummary {
            total_count: summary.total_count,
            unread_count: summary.unread_count,
            critical_count: summary.critical_count,
            high_count: summary.high_count,
            medium_count: summary.medium_count,
            low_count: summary.low_count,
        })
    }

    /// Mark alert as read.
    pub async fn mark_alert_read(
        &self,
        tenant_id: Uuid,
        alert_id: Uuid,
    ) -> Result<GovOutlierAlert> {
        // Verify tenant ownership first
        let _alert = GovOutlierAlert::find_by_id(&self.pool, tenant_id, alert_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or_else(|| GovernanceError::OutlierAlertNotFound(alert_id))?;

        GovOutlierAlert::mark_read(&self.pool, tenant_id, alert_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or_else(|| GovernanceError::OutlierAlertNotFound(alert_id))
    }

    /// Dismiss alert.
    pub async fn dismiss_alert(&self, tenant_id: Uuid, alert_id: Uuid) -> Result<GovOutlierAlert> {
        // Verify tenant ownership first
        let _alert = GovOutlierAlert::find_by_id(&self.pool, tenant_id, alert_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or_else(|| GovernanceError::OutlierAlertNotFound(alert_id))?;

        GovOutlierAlert::dismiss(&self.pool, tenant_id, alert_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or_else(|| GovernanceError::OutlierAlertNotFound(alert_id))
    }

    // ========================================================================
    // Report Operations
    // ========================================================================

    /// Generate outlier report.
    pub async fn generate_report(
        &self,
        tenant_id: Uuid,
        start_date: DateTime<Utc>,
        end_date: DateTime<Utc>,
        include_trends: bool,
        include_peer_breakdown: bool,
    ) -> Result<OutlierReportResponse> {
        // For now, return a basic report structure
        // TODO: Implement full report generation with aggregations

        let summary = self.get_summary(tenant_id).await?;

        let trends = if include_trends {
            // Get trend data from analyses in the date range
            Some(vec![])
        } else {
            None
        };

        let peer_group_breakdown = if include_peer_breakdown {
            // Get breakdown by peer group
            Some(vec![])
        } else {
            None
        };

        Ok(OutlierReportResponse {
            start_date,
            end_date,
            total_analyses: 0,
            total_users_analyzed: summary.total_users,
            total_outliers_detected: summary.outlier_count,
            average_outlier_rate: if summary.total_users > 0 {
                summary.outlier_count as f64 / summary.total_users as f64
            } else {
                0.0
            },
            trends,
            peer_group_breakdown,
            generated_at: Utc::now(),
        })
    }
}

/// Summary statistics for outlier results.
#[derive(Debug, Clone, Default)]
pub struct OutlierSummary {
    pub total_users: i64,
    pub outlier_count: i64,
    pub normal_count: i64,
    pub unclassifiable_count: i64,
    pub avg_score: f64,
    pub max_score: f64,
    pub analysis_id: Option<Uuid>,
    pub analysis_completed_at: Option<DateTime<Utc>>,
}

/// Summary statistics for dispositions.
#[derive(Debug, Clone, Default)]
pub struct DispositionSummary {
    pub new_count: i64,
    pub legitimate_count: i64,
    pub requires_remediation_count: i64,
    pub under_investigation_count: i64,
    pub remediated_count: i64,
}

/// Summary statistics for alerts.
#[derive(Debug, Clone, Default)]
pub struct AlertSummary {
    pub total_count: i64,
    pub unread_count: i64,
    pub critical_count: i64,
    pub high_count: i64,
    pub medium_count: i64,
    pub low_count: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_z_score() {
        // Standard case
        assert!((OutlierScoringService::calculate_z_score(10.0, 5.0, 2.0) - 2.5).abs() < 0.001);

        // Negative Z-score
        assert!((OutlierScoringService::calculate_z_score(3.0, 5.0, 2.0) - (-1.0)).abs() < 0.001);

        // Zero std dev returns 0
        assert!((OutlierScoringService::calculate_z_score(10.0, 5.0, 0.0) - 0.0).abs() < 0.001);

        // Value equals mean
        assert!((OutlierScoringService::calculate_z_score(5.0, 5.0, 2.0) - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_normalize_z_score_to_percentage() {
        // Z=0 should be around 50
        let z0 = OutlierScoringService::normalize_z_score_to_percentage(0.0);
        assert!(z0 > 45.0 && z0 < 55.0);

        // Positive Z should be > 50
        let z2 = OutlierScoringService::normalize_z_score_to_percentage(2.0);
        assert!(z2 > 75.0);

        // Negative Z should be < 50
        let z_neg2 = OutlierScoringService::normalize_z_score_to_percentage(-2.0);
        assert!(z_neg2 < 25.0);
    }

    #[test]
    fn test_classify_user_no_peer_groups() {
        let result = OutlierScoringService::classify_user(&[], 2.0);
        assert!(matches!(result, OutlierClassification::Unclassifiable));
    }

    #[test]
    fn test_classify_user_normal() {
        let peer_scores = vec![PeerGroupScore {
            peer_group_id: Uuid::new_v4(),
            peer_group_name: "Test".to_string(),
            z_score: 1.5,
            deviation_factor: 60.0,
            is_outlier: false,
        }];

        let result = OutlierScoringService::classify_user(&peer_scores, 2.0);
        assert!(matches!(result, OutlierClassification::Normal));
    }

    #[test]
    fn test_classify_user_outlier() {
        let peer_scores = vec![
            PeerGroupScore {
                peer_group_id: Uuid::new_v4(),
                peer_group_name: "Group1".to_string(),
                z_score: 1.5,
                deviation_factor: 60.0,
                is_outlier: false,
            },
            PeerGroupScore {
                peer_group_id: Uuid::new_v4(),
                peer_group_name: "Group2".to_string(),
                z_score: 2.5,
                deviation_factor: 80.0,
                is_outlier: true, // This group flags as outlier
            },
        ];

        let result = OutlierScoringService::classify_user(&peer_scores, 2.0);
        assert!(matches!(result, OutlierClassification::Outlier));
    }

    #[test]
    fn test_weighted_score_calculation() {
        let weights = ScoringWeights::default(); // 0.30, 0.25, 0.20, 0.15, 0.10

        let factors = FactorBreakdown {
            role_frequency: Some(FactorScore {
                raw_value: 100.0,
                weight: 0.30,
                contribution: 30.0,
                details: "test".to_string(),
            }),
            entitlement_count: Some(FactorScore {
                raw_value: 100.0,
                weight: 0.25,
                contribution: 25.0,
                details: "test".to_string(),
            }),
            assignment_pattern: Some(FactorScore {
                raw_value: 100.0,
                weight: 0.20,
                contribution: 20.0,
                details: "test".to_string(),
            }),
            peer_group_coverage: Some(FactorScore {
                raw_value: 100.0,
                weight: 0.15,
                contribution: 15.0,
                details: "test".to_string(),
            }),
            historical_deviation: Some(FactorScore {
                raw_value: 100.0,
                weight: 0.10,
                contribution: 10.0,
                details: "test".to_string(),
            }),
        };

        let score = OutlierScoringService::calculate_weighted_score(&factors, &weights);
        assert!((score - 100.0).abs() < 0.001);
    }

    #[test]
    fn test_weighted_score_partial_factors() {
        let weights = ScoringWeights::default();

        let factors = FactorBreakdown {
            role_frequency: Some(FactorScore {
                raw_value: 50.0,
                weight: 0.30,
                contribution: 15.0,
                details: "test".to_string(),
            }),
            entitlement_count: Some(FactorScore {
                raw_value: 50.0,
                weight: 0.25,
                contribution: 12.5,
                details: "test".to_string(),
            }),
            assignment_pattern: None,
            peer_group_coverage: None,
            historical_deviation: None,
        };

        let score = OutlierScoringService::calculate_weighted_score(&factors, &weights);
        assert!((score - 27.5).abs() < 0.001);
    }

    #[test]
    fn test_historical_deviation_factor() {
        // Significant increase
        let factor =
            OutlierScoringService::calculate_historical_deviation_factor(75.0, Some(25.0), 0.10);
        assert!(factor.raw_value > 75.0); // Increase = higher score

        // Significant decrease
        let factor =
            OutlierScoringService::calculate_historical_deviation_factor(25.0, Some(75.0), 0.10);
        assert!(factor.raw_value < 25.0); // Decrease = lower score

        // No history
        let factor = OutlierScoringService::calculate_historical_deviation_factor(50.0, None, 0.10);
        assert!((factor.raw_value - 50.0).abs() < 0.001); // Neutral
    }

    // ========================================================================
    // Edge Case Tests (IGA parity)
    // ========================================================================

    #[test]
    fn test_z_score_single_user_peer_group() {
        // When std_dev is 0 (single user or identical values), Z-score should be 0
        // This handles the "single user in peer group" edge case
        let z = OutlierScoringService::calculate_z_score(100.0, 50.0, 0.0);
        assert_eq!(z, 0.0, "Single user in group should have Z-score of 0");

        // Negative std_dev should also return 0 (defensive)
        let z_neg = OutlierScoringService::calculate_z_score(100.0, 50.0, -1.0);
        assert_eq!(z_neg, 0.0, "Negative std_dev should return 0");
    }

    #[test]
    fn test_z_score_extreme_values() {
        // Very large positive Z-score
        let z_large = OutlierScoringService::calculate_z_score(1000.0, 50.0, 10.0);
        assert!(
            (z_large - 95.0).abs() < 0.001,
            "Large deviation should produce high Z-score"
        );

        // Very large negative Z-score
        let z_large_neg = OutlierScoringService::calculate_z_score(-900.0, 50.0, 10.0);
        assert!(
            (z_large_neg - (-95.0)).abs() < 0.001,
            "Large negative deviation should produce negative Z-score"
        );
    }

    #[test]
    fn test_normalize_extreme_z_scores() {
        // Very high Z-score should approach 100
        let high = OutlierScoringService::normalize_z_score_to_percentage(10.0);
        assert!(high > 99.0, "Very high Z-score should be near 100");

        // Very low Z-score should approach 0
        let low = OutlierScoringService::normalize_z_score_to_percentage(-10.0);
        assert!(low < 1.0, "Very low Z-score should be near 0");
    }

    #[test]
    fn test_role_frequency_factor_empty_roles() {
        let user = UserAccessProfile {
            user_id: Uuid::new_v4(),
            entitlement_count: 5,
            role_count: 0,
            role_ids: vec![], // Empty roles
            peer_group_ids: vec![Uuid::new_v4()],
            previous_score: None,
        };
        let peer_stats = vec![PeerGroupStats {
            peer_group_id: Uuid::new_v4(),
            peer_group_name: "Test".to_string(),
            mean_entitlements: 5.0,
            std_dev_entitlements: 2.0,
            mean_roles: 3.0,
            std_dev_roles: 1.0,
            member_count: 10,
            role_frequencies: std::collections::HashMap::new(),
        }];

        let factor =
            OutlierScoringService::calculate_role_frequency_factor(&user, &peer_stats, 0.1, 0.30);
        assert_eq!(factor.raw_value, 0.0, "Empty roles should produce 0 score");
        assert!(
            factor.details.contains("No roles"),
            "Should indicate no roles to analyze"
        );
    }

    #[test]
    fn test_role_frequency_factor_empty_peer_stats() {
        let user = UserAccessProfile {
            user_id: Uuid::new_v4(),
            entitlement_count: 5,
            role_count: 2,
            role_ids: vec![Uuid::new_v4(), Uuid::new_v4()],
            peer_group_ids: vec![],
            previous_score: None,
        };

        let factor = OutlierScoringService::calculate_role_frequency_factor(&user, &[], 0.1, 0.30);
        assert_eq!(
            factor.raw_value, 0.0,
            "Empty peer stats should produce 0 score"
        );
    }

    #[test]
    fn test_classify_user_all_peer_groups_outlier() {
        // Edge case: user is outlier in ALL peer groups
        let peer_scores = vec![
            PeerGroupScore {
                peer_group_id: Uuid::new_v4(),
                peer_group_name: "Group1".to_string(),
                z_score: 3.0,
                deviation_factor: 90.0,
                is_outlier: true,
            },
            PeerGroupScore {
                peer_group_id: Uuid::new_v4(),
                peer_group_name: "Group2".to_string(),
                z_score: 4.0,
                deviation_factor: 95.0,
                is_outlier: true,
            },
        ];

        let result = OutlierScoringService::classify_user(&peer_scores, 2.0);
        assert!(matches!(result, OutlierClassification::Outlier));
    }

    #[test]
    fn test_boundary_confidence_threshold() {
        // Z-score exactly at threshold
        let peer_scores_at_threshold = vec![PeerGroupScore {
            peer_group_id: Uuid::new_v4(),
            peer_group_name: "Test".to_string(),
            z_score: 2.0,
            deviation_factor: 80.0,
            is_outlier: true, // At threshold, should be outlier
        }];

        let result = OutlierScoringService::classify_user(&peer_scores_at_threshold, 2.0);
        assert!(matches!(result, OutlierClassification::Outlier));

        // Just below threshold
        let peer_scores_below = vec![PeerGroupScore {
            peer_group_id: Uuid::new_v4(),
            peer_group_name: "Test".to_string(),
            z_score: 1.99,
            deviation_factor: 79.0,
            is_outlier: false, // Below threshold, not outlier
        }];

        let result_below = OutlierScoringService::classify_user(&peer_scores_below, 2.0);
        assert!(matches!(result_below, OutlierClassification::Normal));
    }

    #[test]
    fn test_weighted_score_all_zero_weights() {
        // Edge case: what if weights are all zero?
        let factors = FactorBreakdown {
            role_frequency: Some(FactorScore {
                raw_value: 80.0,
                weight: 0.0,
                contribution: 0.0,
                details: String::new(),
            }),
            entitlement_count: Some(FactorScore {
                raw_value: 60.0,
                weight: 0.0,
                contribution: 0.0,
                details: String::new(),
            }),
            assignment_pattern: Some(FactorScore {
                raw_value: 50.0,
                weight: 0.0,
                contribution: 0.0,
                details: String::new(),
            }),
            peer_group_coverage: Some(FactorScore {
                raw_value: 40.0,
                weight: 0.0,
                contribution: 0.0,
                details: String::new(),
            }),
            historical_deviation: Some(FactorScore {
                raw_value: 30.0,
                weight: 0.0,
                contribution: 0.0,
                details: String::new(),
            }),
        };

        let weights = ScoringWeights {
            role_frequency: 0.0,
            entitlement_count: 0.0,
            assignment_pattern: 0.0,
            peer_group_coverage: 0.0,
            historical_deviation: 0.0,
        };

        let score = OutlierScoringService::calculate_weighted_score(&factors, &weights);
        assert_eq!(score, 0.0, "All zero weights should produce 0 score");
    }

    #[test]
    fn test_weighted_score_missing_factors() {
        // Edge case: some factors are None
        let factors = FactorBreakdown {
            role_frequency: Some(FactorScore {
                raw_value: 80.0,
                weight: 0.30,
                contribution: 24.0,
                details: String::new(),
            }),
            entitlement_count: None,  // Missing
            assignment_pattern: None, // Missing
            peer_group_coverage: Some(FactorScore {
                raw_value: 60.0,
                weight: 0.15,
                contribution: 9.0,
                details: String::new(),
            }),
            historical_deviation: None, // Missing
        };

        let weights = ScoringWeights {
            role_frequency: 0.30,
            entitlement_count: 0.25,
            assignment_pattern: 0.20,
            peer_group_coverage: 0.15,
            historical_deviation: 0.10,
        };

        let score = OutlierScoringService::calculate_weighted_score(&factors, &weights);
        // Only role_frequency (24.0) and peer_group_coverage (9.0) contribute
        assert!(
            (score - 33.0).abs() < 0.001,
            "Missing factors should be skipped"
        );
    }
}
