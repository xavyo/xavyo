//! Correlation Engine Service for F067.
//!
//! The core service responsible for evaluating accounts against identities
//! using configurable correlation rules, fuzzy matching algorithms, and
//! confidence-based threshold decisions. Supports batch evaluation with
//! asynchronous job tracking.
//!
//! ## Architecture
//!
//! 1. **Rule loading**: Active rules for a connector are loaded sorted by tier
//!    then priority.
//! 2. **Threshold loading**: Per-connector thresholds (auto-confirm, manual-review)
//!    are loaded, falling back to sensible defaults.
//! 3. **Identity scoring**: For each candidate identity, every rule produces an
//!    `AttributeScore`.  Scores are aggregated using weighted sums.
//! 4. **Threshold application**: The aggregate confidence is compared against the
//!    thresholds to determine the outcome (auto-confirm, review-queued, no-match).
//! 5. **Job management**: Batch evaluations run asynchronously and progress is
//!    tracked in an in-memory map keyed by job ID.

use chrono::{DateTime, Utc};
use rust_decimal::prelude::ToPrimitive;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

use xavyo_db::{
    CreateGovCorrelationAuditEvent, CreateGovCorrelationCandidate, CreateGovCorrelationCase,
    GovCorrelationAuditEvent, GovCorrelationCandidate, GovCorrelationCase, GovCorrelationEventType,
    GovCorrelationOutcome, GovCorrelationRule, GovCorrelationThreshold, GovCorrelationTrigger,
    GovFuzzyAlgorithm, GovMatchType, PerAttributeScores,
};
use xavyo_governance::error::{GovernanceError, Result};

#[cfg(feature = "kafka")]
use xavyo_events::EventProducer;

use crate::models::correlation::CorrelationJobStatusResponse;

// =============================================================================
// Public types
// =============================================================================

/// Tracks asynchronous correlation job progress.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationJobStatus {
    /// Unique job identifier.
    pub job_id: Uuid,
    /// Tenant that owns this job.
    pub tenant_id: Uuid,
    /// Connector being evaluated.
    pub connector_id: Uuid,
    /// Current status: "pending", "running", "completed", "failed".
    pub status: String,
    /// Total number of accounts to evaluate.
    pub total_accounts: i64,
    /// Number of accounts processed so far.
    pub processed_accounts: i64,
    /// Accounts auto-confirmed by the engine.
    pub auto_confirmed: i64,
    /// Accounts queued for manual review.
    pub review_queued: i64,
    /// Accounts with no matching identity.
    pub no_match: i64,
    /// Accounts that encountered evaluation errors.
    pub errors: i64,
    /// When the job was started.
    pub started_at: DateTime<Utc>,
    /// When the job completed (if finished).
    pub completed_at: Option<DateTime<Utc>>,
    /// Error message if the job failed.
    pub error_message: Option<String>,
}

/// Result of evaluating a single account against the identity pool.
#[derive(Debug, Clone)]
pub struct EvaluationResult {
    /// The account that was evaluated.
    pub account_id: Uuid,
    /// The outcome of the evaluation.
    pub outcome: CorrelationOutcome,
    /// The best-matching identity (if any).
    pub best_identity_id: Option<Uuid>,
    /// Aggregate confidence of the best match (0.0-1.0).
    pub confidence: f64,
    /// Number of candidate identities that scored above the review threshold.
    pub candidate_count: i32,
}

/// Outcome categories for a single account evaluation.
#[derive(Debug, Clone, PartialEq)]
pub enum CorrelationOutcome {
    /// Confidence >= auto-confirm threshold.
    AutoConfirmed,
    /// Confidence >= manual-review threshold but < auto-confirm.
    ReviewQueued,
    /// Confidence below the manual-review threshold.
    NoMatch,
    /// A definitive rule matched exactly.
    DefinitiveMatch,
    /// Multiple candidates exceed the auto-confirm threshold.
    AmbiguousMatch,
}

// =============================================================================
// Internal scoring types
// =============================================================================

/// Aggregate score for a single candidate identity.
#[derive(Debug, Clone)]
struct CandidateScore {
    identity_id: Uuid,
    identity_attributes: serde_json::Value,
    aggregate_confidence: f64,
    per_attribute_scores: Vec<AttributeScore>,
    has_definitive_match: bool,
}

/// Score produced by a single rule for one attribute pair.
#[derive(Debug, Clone, Serialize)]
struct AttributeScore {
    rule_id: Uuid,
    rule_name: String,
    source_attribute: String,
    target_attribute: String,
    source_value: String,
    target_value: String,
    strategy: String,
    raw_similarity: f64,
    weight: f64,
    weighted_score: f64,
    normalized: bool,
    skipped: bool,
    skip_reason: Option<String>,
}

// =============================================================================
// Service
// =============================================================================

/// The core correlation engine service.
///
/// Maintains an in-memory job tracker for batch evaluations and delegates
/// to the database for rules, thresholds, cases, candidates, and audit events.
pub struct CorrelationEngineService {
    pool: PgPool,
    jobs: Arc<Mutex<HashMap<Uuid, CorrelationJobStatus>>>,
    #[cfg(feature = "kafka")]
    event_producer: Option<Arc<EventProducer>>,
}

impl CorrelationEngineService {
    /// Create a new correlation engine service.
    #[must_use] 
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            jobs: Arc::new(Mutex::new(HashMap::new())),
            #[cfg(feature = "kafka")]
            event_producer: None,
        }
    }

    /// Create a new correlation engine service with Kafka event producer.
    #[cfg(feature = "kafka")]
    pub fn with_event_producer(pool: PgPool, event_producer: Arc<EventProducer>) -> Self {
        Self {
            pool,
            jobs: Arc::new(Mutex::new(HashMap::new())),
            event_producer: Some(event_producer),
        }
    }

    /// Get the database pool.
    #[must_use] 
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    // =========================================================================
    // Single account evaluation
    // =========================================================================

    /// Evaluate a single account against the identity pool for the given connector.
    ///
    /// 1. Loads active rules for the connector (sorted by tier, then priority).
    /// 2. Loads thresholds (or defaults).
    /// 3. For each identity, computes per-rule attribute scores.
    /// 4. Aggregates scores with weight redistribution for missing attributes.
    /// 5. Applies threshold logic and returns the result.
    pub async fn evaluate_account(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
        account_id: Uuid,
        account_attributes: &serde_json::Value,
        trigger: GovCorrelationTrigger,
    ) -> Result<EvaluationResult> {
        // 1. Load active rules for this connector (tier ASC, priority DESC).
        let rules =
            GovCorrelationRule::list_active_by_connector(&self.pool, tenant_id, connector_id)
                .await?;

        if rules.is_empty() {
            tracing::warn!(
                tenant_id = %tenant_id,
                connector_id = %connector_id,
                account_id = %account_id,
                "No active correlation rules for connector"
            );
            return Ok(EvaluationResult {
                account_id,
                outcome: CorrelationOutcome::NoMatch,
                best_identity_id: None,
                confidence: 0.0,
                candidate_count: 0,
            });
        }

        // 2. Load thresholds (or defaults).
        let thresholds =
            GovCorrelationThreshold::find_by_connector(&self.pool, tenant_id, connector_id)
                .await?
                .unwrap_or_else(|| {
                    GovCorrelationThreshold::find_or_default(tenant_id, connector_id)
                });

        let auto_confirm = decimal_to_f64(thresholds.auto_confirm_threshold);
        let manual_review = decimal_to_f64(thresholds.manual_review_threshold);
        let batch_size = i64::from(thresholds.batch_size);

        // 3. Iterate over identities (users) in batches.
        //    We query the `users` table and construct an attributes JSON object
        //    from the available columns (email). The correlation rules compare
        //    account attributes against these identity attributes.
        let mut best: Option<CandidateScore> = None;
        let mut candidates_above_review: Vec<CandidateScore> = Vec::new();
        let mut offset: i64 = 0;

        loop {
            let identity_rows: Vec<(Uuid, serde_json::Value)> = sqlx::query_as(
                r"
                SELECT id, jsonb_build_object(
                    'email', email,
                    'display_name', display_name,
                    'id', id::text
                ) AS attributes
                FROM users
                WHERE tenant_id = $1
                LIMIT $2 OFFSET $3
                ",
            )
            .bind(tenant_id)
            .bind(batch_size)
            .bind(offset)
            .fetch_all(&self.pool)
            .await?;

            if identity_rows.is_empty() {
                break;
            }

            for (identity_id, identity_attrs) in &identity_rows {
                let score =
                    self.score_candidate(&rules, account_attributes, identity_attrs, *identity_id);

                // Track candidates above review threshold.
                if score.aggregate_confidence >= manual_review {
                    candidates_above_review.push(score.clone());
                }

                // Track overall best.
                let dominated = match &best {
                    Some(current) => score.aggregate_confidence > current.aggregate_confidence,
                    None => score.aggregate_confidence > 0.0,
                };
                if dominated {
                    best = Some(score);
                }
            }

            offset += batch_size;
        }

        // 4. Determine outcome.
        let (outcome, best_identity_id, confidence) = match best {
            Some(ref b) if b.has_definitive_match => (
                CorrelationOutcome::DefinitiveMatch,
                Some(b.identity_id),
                b.aggregate_confidence,
            ),
            Some(ref b) => {
                // Check for ambiguity: multiple candidates above auto-confirm.
                let auto_count = candidates_above_review
                    .iter()
                    .filter(|c| c.aggregate_confidence >= auto_confirm)
                    .count();

                if auto_count > 1 {
                    (
                        CorrelationOutcome::AmbiguousMatch,
                        Some(b.identity_id),
                        b.aggregate_confidence,
                    )
                } else {
                    let outcome =
                        apply_thresholds(b.aggregate_confidence, auto_confirm, manual_review);
                    (outcome, Some(b.identity_id), b.aggregate_confidence)
                }
            }
            None => (CorrelationOutcome::NoMatch, None, 0.0),
        };

        let candidate_count = candidates_above_review.len() as i32;

        // 4b. Enforce tuning_mode: in tuning mode, auto-confirm and definitive
        //     outcomes are downgraded to review so operators can observe decisions
        //     without any automatic linking. The audit trail still records the
        //     original outcome for analysis.
        let outcome = if thresholds.tuning_mode
            && matches!(
                outcome,
                CorrelationOutcome::AutoConfirmed | CorrelationOutcome::DefinitiveMatch
            ) {
            tracing::info!(
                tenant_id = %tenant_id,
                connector_id = %connector_id,
                account_id = %account_id,
                original_outcome = ?outcome,
                "Tuning mode active: downgrading auto-confirm to review queue"
            );
            CorrelationOutcome::ReviewQueued
        } else {
            outcome
        };

        // 5. Log the evaluation via audit trail.
        let db_outcome = match &outcome {
            CorrelationOutcome::AutoConfirmed => GovCorrelationOutcome::AutoConfirmed,
            CorrelationOutcome::ReviewQueued => GovCorrelationOutcome::DeferredToReview,
            CorrelationOutcome::NoMatch => GovCorrelationOutcome::NoMatch,
            CorrelationOutcome::DefinitiveMatch => GovCorrelationOutcome::AutoConfirmed,
            CorrelationOutcome::AmbiguousMatch => GovCorrelationOutcome::CollisionDetected,
        };

        let rules_snapshot = serde_json::to_value(
            rules
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "id": r.id,
                        "name": r.name,
                        "match_type": format!("{:?}", r.match_type).to_lowercase(),
                        "weight": r.weight.to_string(),
                        "tier": r.tier,
                        "is_definitive": r.is_definitive,
                    })
                })
                .collect::<Vec<_>>(),
        )
        .unwrap_or_default();

        let thresholds_snapshot = serde_json::json!({
            "auto_confirm_threshold": auto_confirm,
            "manual_review_threshold": manual_review,
            "batch_size": thresholds.batch_size,
            "tuning_mode": thresholds.tuning_mode,
        });

        let candidates_summary = serde_json::to_value(
            candidates_above_review
                .iter()
                .take(10) // cap summary size
                .map(|c| {
                    serde_json::json!({
                        "identity_id": c.identity_id,
                        "confidence": c.aggregate_confidence,
                        "definitive": c.has_definitive_match,
                    })
                })
                .collect::<Vec<_>>(),
        )
        .unwrap_or_default();

        let confidence_decimal = Decimal::try_from(confidence).ok();

        let _audit = GovCorrelationAuditEvent::create(
            &self.pool,
            CreateGovCorrelationAuditEvent {
                tenant_id,
                connector_id,
                account_id: Some(account_id),
                case_id: None,
                identity_id: best_identity_id,
                event_type: GovCorrelationEventType::AutoEvaluated,
                outcome: db_outcome,
                confidence_score: confidence_decimal,
                candidate_count,
                candidates_summary,
                rules_snapshot: rules_snapshot.clone(),
                thresholds_snapshot: thresholds_snapshot.clone(),
                actor_type: "system".to_string(),
                actor_id: None,
                reason: None,
                metadata: None,
            },
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to create correlation audit event");
            e
        })?;

        // 6. Emit Kafka events for correlation decisions.
        #[cfg(feature = "kafka")]
        if let Some(ref producer) = self.event_producer {
            let event_topic = match &outcome {
                CorrelationOutcome::AutoConfirmed | CorrelationOutcome::DefinitiveMatch => {
                    "xavyo.governance.correlation.auto_confirmed"
                }
                CorrelationOutcome::ReviewQueued | CorrelationOutcome::AmbiguousMatch => {
                    "xavyo.governance.correlation.queued_for_review"
                }
                CorrelationOutcome::NoMatch => "xavyo.governance.correlation.no_match",
            };

            let payload = serde_json::json!({
                "event": event_topic,
                "tenant_id": tenant_id,
                "connector_id": connector_id,
                "account_id": account_id,
                "identity_id": best_identity_id,
                "confidence_score": confidence,
                "outcome": format!("{:?}", outcome),
                "candidate_count": candidate_count,
                "trigger": format!("{:?}", trigger),
                "timestamp": Utc::now().to_rfc3339(),
            });

            if let Err(e) = producer
                .publish_raw(
                    event_topic,
                    &serde_json::to_vec(&payload).unwrap_or_default(),
                )
                .await
            {
                tracing::warn!(
                    error = %e,
                    event = event_topic,
                    account_id = %account_id,
                    "Failed to emit correlation Kafka event"
                );
            }
        }

        // 7. If auto-confirmed or definitive match, link the shadow account to the identity.
        if matches!(
            outcome,
            CorrelationOutcome::AutoConfirmed | CorrelationOutcome::DefinitiveMatch
        ) {
            if let Some(identity_id) = best_identity_id {
                // Update the shadow account to link it to the matched identity.
                sqlx::query(
                    r"
                    UPDATE gov_shadows
                    SET user_id = $1,
                        sync_situation = 'linked',
                        updated_at = NOW()
                    WHERE id = $2
                      AND tenant_id = $3
                      AND connector_id = $4
                    ",
                )
                .bind(identity_id)
                .bind(account_id)
                .bind(tenant_id)
                .bind(connector_id)
                .execute(&self.pool)
                .await
                .map_err(|e| {
                    tracing::error!(
                        error = %e,
                        account_id = %account_id,
                        identity_id = %identity_id,
                        "Failed to link shadow account to identity"
                    );
                    e
                })?;

                tracing::info!(
                    tenant_id = %tenant_id,
                    connector_id = %connector_id,
                    account_id = %account_id,
                    identity_id = %identity_id,
                    confidence = confidence,
                    "Shadow account auto-linked to identity"
                );
            }
        }

        // 8. If the outcome requires a review case, create one with candidates.
        //    First check idempotency: skip if a pending case already exists for
        //    this account (FR-012 duplicate prevention).
        if matches!(
            outcome,
            CorrelationOutcome::ReviewQueued | CorrelationOutcome::AmbiguousMatch
        ) {
            let already_queued =
                GovCorrelationCase::find_pending_by_account(&self.pool, tenant_id, account_id)
                    .await
                    .map(|opt| opt.is_some())
                    .unwrap_or(false);

            if already_queued {
                tracing::info!(
                    tenant_id = %tenant_id,
                    connector_id = %connector_id,
                    account_id = %account_id,
                    "Pending correlation case already exists for account; skipping case creation"
                );

                return Ok(EvaluationResult {
                    account_id,
                    outcome,
                    best_identity_id,
                    confidence,
                    candidate_count,
                });
            }

            let account_identifier = account_attributes
                .get("email")
                .or_else(|| account_attributes.get("username"))
                .or_else(|| account_attributes.get("sAMAccountName"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();

            let highest_confidence_decimal = Decimal::try_from(confidence).unwrap_or(Decimal::ZERO);

            let case = GovCorrelationCase::create(
                &self.pool,
                tenant_id,
                CreateGovCorrelationCase {
                    connector_id,
                    account_id,
                    account_identifier,
                    account_attributes: account_attributes.clone(),
                    trigger_type: trigger,
                    highest_confidence: highest_confidence_decimal,
                    candidate_count,
                    rules_snapshot,
                },
            )
            .await?;

            // Persist candidate records for the review queue.
            let candidate_inputs: Vec<CreateGovCorrelationCandidate> = candidates_above_review
                .iter()
                .map(|c| {
                    let per_attr = PerAttributeScores {
                        scores: c
                            .per_attribute_scores
                            .iter()
                            .map(|s| xavyo_db::PerAttributeScore {
                                rule_id: s.rule_id,
                                rule_name: s.rule_name.clone(),
                                source_attribute: s.source_attribute.clone(),
                                target_attribute: s.target_attribute.clone(),
                                source_value: Some(s.source_value.clone()),
                                target_value: Some(s.target_value.clone()),
                                strategy: s.strategy.clone(),
                                raw_similarity: s.raw_similarity,
                                weight: s.weight,
                                weighted_score: s.weighted_score,
                                normalized: s.normalized,
                                skipped: s.skipped,
                                skip_reason: s.skip_reason.clone(),
                            })
                            .collect(),
                        aggregate_confidence: c.aggregate_confidence,
                    };
                    let agg_decimal =
                        Decimal::try_from(c.aggregate_confidence).unwrap_or(Decimal::ZERO);

                    // Extract display name: prefer display_name, fall back to email.
                    let display_name = c
                        .identity_attributes
                        .get("display_name")
                        .and_then(|v| v.as_str())
                        .or_else(|| c.identity_attributes.get("email").and_then(|v| v.as_str()))
                        .map(String::from);

                    CreateGovCorrelationCandidate {
                        case_id: case.id,
                        identity_id: c.identity_id,
                        identity_display_name: display_name,
                        identity_attributes: c.identity_attributes.clone(),
                        aggregate_confidence: agg_decimal,
                        per_attribute_scores: per_attr,
                        is_deactivated: false,
                        is_definitive_match: c.has_definitive_match,
                    }
                })
                .collect();

            if !candidate_inputs.is_empty() {
                GovCorrelationCandidate::create_batch(&self.pool, candidate_inputs).await?;
            }

            tracing::info!(
                tenant_id = %tenant_id,
                connector_id = %connector_id,
                account_id = %account_id,
                case_id = %case.id,
                candidate_count = candidate_count,
                confidence = confidence,
                "Correlation case created for manual review"
            );
        }

        Ok(EvaluationResult {
            account_id,
            outcome,
            best_identity_id,
            confidence,
            candidate_count,
        })
    }

    // =========================================================================
    // Batch evaluation / job management
    // =========================================================================

    /// Trigger a batch evaluation for a connector.
    ///
    /// Creates a job ID, spawns an asynchronous task, and returns the job ID
    /// immediately so the caller can poll for progress.
    pub async fn trigger_batch_evaluation(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
        account_ids: Option<Vec<Uuid>>,
        trigger: GovCorrelationTrigger,
    ) -> Result<Uuid> {
        let job_id = Uuid::new_v4();
        let total_accounts = if let Some(ids) = &account_ids { ids.len() as i64 } else {
            // Count uncorrelated shadow accounts for the connector.
            let count: i64 = sqlx::query_scalar(
                r"
                SELECT COUNT(*)::bigint FROM gov_shadows
                WHERE tenant_id = $1
                  AND connector_id = $2
                  AND user_id IS NULL
                  AND sync_situation IN ('unlinked', 'unmatched')
                  AND state != 'dead'
                ",
            )
            .bind(tenant_id)
            .bind(connector_id)
            .fetch_one(&self.pool)
            .await?;
            count
        };

        let status = CorrelationJobStatus {
            job_id,
            tenant_id,
            connector_id,
            status: "pending".to_string(),
            total_accounts,
            processed_accounts: 0,
            auto_confirmed: 0,
            review_queued: 0,
            no_match: 0,
            errors: 0,
            started_at: Utc::now(),
            completed_at: None,
            error_message: None,
        };

        {
            let mut jobs = self.jobs.lock().await;
            jobs.insert(job_id, status);
        }

        // Clone values for the spawned task.
        let pool = self.pool.clone();
        let jobs_handle = Arc::clone(&self.jobs);

        tokio::spawn(async move {
            run_batch_evaluation(
                pool,
                jobs_handle,
                job_id,
                tenant_id,
                connector_id,
                account_ids,
                trigger,
            )
            .await;
        });

        tracing::info!(
            tenant_id = %tenant_id,
            connector_id = %connector_id,
            job_id = %job_id,
            total_accounts = total_accounts,
            "Batch correlation job started"
        );

        Ok(job_id)
    }

    /// Get the status of an in-progress or completed correlation job.
    ///
    /// Verifies that the job belongs to the specified tenant for security.
    pub async fn get_job_status(
        &self,
        tenant_id: Uuid,
        job_id: Uuid,
    ) -> Result<CorrelationJobStatus> {
        let jobs = self.jobs.lock().await;
        let job = jobs
            .get(&job_id)
            .ok_or(GovernanceError::CorrelationJobNotFound(job_id))?;

        // Verify tenant ownership.
        if job.tenant_id != tenant_id {
            return Err(GovernanceError::CorrelationJobNotFound(job_id));
        }

        Ok(job.clone())
    }

    /// Convert job status to the API response DTO.
    #[must_use] 
    pub fn job_status_to_response(status: &CorrelationJobStatus) -> CorrelationJobStatusResponse {
        CorrelationJobStatusResponse {
            job_id: status.job_id,
            status: status.status.clone(),
            total_accounts: status.total_accounts,
            processed_accounts: status.processed_accounts,
            auto_confirmed: status.auto_confirmed,
            queued_for_review: status.review_queued,
            no_match: status.no_match,
            errors: status.errors,
            started_at: status.started_at,
            completed_at: status.completed_at,
        }
    }

    // =========================================================================
    // Candidate scoring (internal)
    // =========================================================================

    /// Score a single candidate identity against all rules for the given account.
    fn score_candidate(
        &self,
        rules: &[GovCorrelationRule],
        account_attributes: &serde_json::Value,
        identity_attributes: &serde_json::Value,
        identity_id: Uuid,
    ) -> CandidateScore {
        let stored_identity_attributes = identity_attributes.clone();
        let mut attribute_scores: Vec<AttributeScore> = Vec::with_capacity(rules.len());
        let mut available_rule_ids: Vec<Uuid> = Vec::new();
        let mut has_definitive_match = false;

        // First pass: compute raw scores, marking skipped rules.
        for rule in rules {
            let source_attr = rule.source_attribute.as_deref().unwrap_or(&rule.attribute);
            let target_attr = rule.target_attribute.as_deref().unwrap_or(source_attr);

            let source_val = extract_attribute(account_attributes, source_attr);
            let target_val = extract_attribute(identity_attributes, target_attr);

            let weight = decimal_to_f64(rule.weight);

            // Check for missing attributes.
            if source_val.is_empty() || target_val.is_empty() {
                attribute_scores.push(AttributeScore {
                    rule_id: rule.id,
                    rule_name: rule.name.clone(),
                    source_attribute: source_attr.to_string(),
                    target_attribute: target_attr.to_string(),
                    source_value: source_val.clone(),
                    target_value: target_val.clone(),
                    strategy: format!("{:?}", rule.match_type).to_lowercase(),
                    raw_similarity: 0.0,
                    weight,
                    weighted_score: 0.0,
                    normalized: rule.normalize,
                    skipped: true,
                    skip_reason: Some("Missing attribute value".to_string()),
                });
                continue;
            }

            available_rule_ids.push(rule.id);

            let score = compute_attribute_score(rule, &source_val, &target_val);
            attribute_scores.push(score);

            // Check for definitive match.
            if rule.is_definitive {
                let last = attribute_scores.last().unwrap();
                if last.raw_similarity >= 1.0 - f64::EPSILON {
                    has_definitive_match = true;
                }
            }
        }

        // Redistribute weights for available (non-skipped) rules.
        let redistributed = redistribute_weights(rules, &available_rule_ids);

        // Second pass: compute weighted scores with redistributed weights.
        let mut aggregate_confidence = 0.0;
        for score in &mut attribute_scores {
            if score.skipped {
                continue;
            }
            if let Some(&new_weight) = redistributed.get(&score.rule_id) {
                score.weight = new_weight;
                score.weighted_score = score.raw_similarity * new_weight;
            }
            aggregate_confidence += score.weighted_score;
        }

        // Clamp to [0.0, 1.0].
        aggregate_confidence = aggregate_confidence.clamp(0.0, 1.0);

        CandidateScore {
            identity_id,
            identity_attributes: stored_identity_attributes,
            aggregate_confidence,
            per_attribute_scores: attribute_scores,
            has_definitive_match,
        }
    }

    // =========================================================================
    // Live synchronization integration (US4)
    // =========================================================================

    /// Correlate a single account detected during live synchronization.
    ///
    /// This is a synchronous wrapper around [`evaluate_account()`] designed for
    /// real-time use within the live sync pipeline (F048). Unlike the batch
    /// evaluation path, this method runs inline and returns the result directly
    /// rather than spawning an asynchronous job.
    ///
    /// ## Integration Guide
    ///
    /// The live sync service (`crates/xavyo-api-governance/src/services/`) should
    /// call this method when it detects an unlinked new account during a change
    /// event. Example usage:
    ///
    /// ```ignore
    /// let result = correlation_engine_service
    ///     .correlate_live_sync_account(
    ///         tenant_id,
    ///         connector_id,
    ///         account_id,
    ///         &account_attributes,
    ///     )
    ///     .await?;
    ///
    /// match result.outcome {
    ///     CorrelationOutcome::AutoConfirmed => {
    ///         // Link account to result.best_identity_id
    ///     }
    ///     CorrelationOutcome::ReviewQueued => {
    ///         // Case already created; continue sync
    ///     }
    ///     CorrelationOutcome::NoMatch => {
    ///         // Flag for manual triage or auto-create identity
    ///     }
    ///     _ => {}
    /// }
    /// ```
    ///
    /// ## Idempotency
    ///
    /// If the same account is received multiple times (e.g., during a burst of
    /// live sync events per FR-012), the underlying `evaluate_account()` checks
    /// for existing pending cases via `is_account_already_queued()` before
    /// creating duplicates.
    pub async fn correlate_live_sync_account(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
        account_id: Uuid,
        account_attributes: &serde_json::Value,
    ) -> Result<EvaluationResult> {
        tracing::info!(
            tenant_id = %tenant_id,
            connector_id = %connector_id,
            account_id = %account_id,
            "Correlating account from live sync"
        );

        self.evaluate_account(
            tenant_id,
            connector_id,
            account_id,
            account_attributes,
            GovCorrelationTrigger::LiveSync,
        )
        .await
    }
}

// =============================================================================
// Async batch runner (free function for tokio::spawn)
// =============================================================================

/// Runs the batch evaluation in a spawned task.
///
/// Fetches accounts from the database and evaluates each one, updating the
/// job status as it progresses.
async fn run_batch_evaluation(
    pool: PgPool,
    jobs: Arc<Mutex<HashMap<Uuid, CorrelationJobStatus>>>,
    job_id: Uuid,
    tenant_id: Uuid,
    connector_id: Uuid,
    account_ids: Option<Vec<Uuid>>,
    trigger: GovCorrelationTrigger,
) {
    // Mark job as running.
    {
        let mut map = jobs.lock().await;
        if let Some(job) = map.get_mut(&job_id) {
            job.status = "running".to_string();
        }
    }

    // Build a service instance for evaluation.
    let engine = CorrelationEngineService::new(pool.clone());

    // Determine the list of shadow accounts to evaluate.
    // Shadow accounts (gov_shadows) represent external system accounts that
    // need to be correlated with internal users.
    let accounts: Vec<(Uuid, serde_json::Value)> = match account_ids {
        Some(ids) => {
            let mut result = Vec::with_capacity(ids.len());
            for id in ids {
                match sqlx::query_as::<_, (Uuid, serde_json::Value)>(
                    r"
                    SELECT id, attributes FROM gov_shadows
                    WHERE tenant_id = $1 AND connector_id = $2 AND id = $3
                    ",
                )
                .bind(tenant_id)
                .bind(connector_id)
                .bind(id)
                .fetch_optional(&pool)
                .await
                {
                    Ok(Some(row)) => result.push(row),
                    Ok(None) => {
                        tracing::warn!(account_id = %id, "Shadow account not found, skipping");
                    }
                    Err(e) => {
                        tracing::error!(account_id = %id, error = %e, "Error fetching shadow account");
                    }
                }
            }
            result
        }
        None => sqlx::query_as::<_, (Uuid, serde_json::Value)>(
            r"
                SELECT id, attributes FROM gov_shadows
                WHERE tenant_id = $1
                  AND connector_id = $2
                  AND user_id IS NULL
                  AND sync_situation IN ('unlinked', 'unmatched')
                  AND state != 'dead'
                ORDER BY created_at ASC
                ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .fetch_all(&pool)
        .await
        .unwrap_or_default(),
    };

    // Update total count now that we know the actual number.
    {
        let mut map = jobs.lock().await;
        if let Some(job) = map.get_mut(&job_id) {
            job.total_accounts = accounts.len() as i64;
        }
    }

    // Evaluate each account.
    for (account_id, account_attrs) in &accounts {
        let result = engine
            .evaluate_account(tenant_id, connector_id, *account_id, account_attrs, trigger)
            .await;

        let mut map = jobs.lock().await;
        if let Some(job) = map.get_mut(&job_id) {
            job.processed_accounts += 1;
            match result {
                Ok(eval) => match eval.outcome {
                    CorrelationOutcome::AutoConfirmed | CorrelationOutcome::DefinitiveMatch => {
                        job.auto_confirmed += 1;
                    }
                    CorrelationOutcome::ReviewQueued | CorrelationOutcome::AmbiguousMatch => {
                        job.review_queued += 1;
                    }
                    CorrelationOutcome::NoMatch => {
                        job.no_match += 1;
                    }
                },
                Err(e) => {
                    tracing::error!(
                        account_id = %account_id,
                        error = %e,
                        "Correlation evaluation failed"
                    );
                    job.errors += 1;
                }
            }
        }
    }

    // Mark job as completed.
    {
        let mut map = jobs.lock().await;
        if let Some(job) = map.get_mut(&job_id) {
            job.status = "completed".to_string();
            job.completed_at = Some(Utc::now());
        }
    }

    tracing::info!(
        job_id = %job_id,
        tenant_id = %tenant_id,
        connector_id = %connector_id,
        "Batch correlation job completed"
    );
}

// =============================================================================
// Scoring functions
// =============================================================================

/// Compute the attribute score for a single rule.
///
/// Applies normalization if configured, handles the short-string exact
/// fallback (FR-020), and dispatches to the appropriate matching strategy.
fn compute_attribute_score(
    rule: &GovCorrelationRule,
    source_value: &str,
    target_value: &str,
) -> AttributeScore {
    let weight = decimal_to_f64(rule.weight);
    let strategy = format!("{:?}", rule.match_type).to_lowercase();

    // Normalize if requested.
    let (src, tgt, was_normalized) = if rule.normalize {
        (
            normalize_attribute(source_value),
            normalize_attribute(target_value),
            true,
        )
    } else {
        (source_value.to_string(), target_value.to_string(), false)
    };

    // FR-020: strings shorter than 3 characters fall back to exact match only.
    let short_string = src.len() < 3 || tgt.len() < 3;

    let raw_similarity = if short_string && rule.match_type != GovMatchType::Exact {
        // Short-string fallback to exact.
        if src.eq_ignore_ascii_case(&tgt) {
            1.0
        } else {
            0.0
        }
    } else {
        match rule.match_type {
            GovMatchType::Exact => exact_match(&src, &tgt),
            GovMatchType::Fuzzy => {
                let algorithm = rule.algorithm.unwrap_or(GovFuzzyAlgorithm::JaroWinkler);
                fuzzy_match(&src, &tgt, algorithm)
            }
            GovMatchType::Phonetic => {
                // Phonetic: compare soundex codes.
                let s1 = soundex(&src);
                let s2 = soundex(&tgt);
                if s1 == s2 {
                    1.0
                } else {
                    0.0
                }
            }
            GovMatchType::Expression => {
                // Expression-based: for now, extract with expression and compare.
                // Full Rhai integration is deferred; we do a simple contains/equals check.
                if let Some(ref expr) = rule.expression {
                    evaluate_expression(expr, &src, &tgt)
                } else {
                    exact_match(&src, &tgt)
                }
            }
        }
    };

    // Apply per-rule threshold: if the rule has a minimum threshold and the
    // raw similarity is below it, zero out the score.
    let (raw_similarity, per_rule_skipped) = if let Some(threshold) = rule.threshold {
        let threshold_f64 = decimal_to_f64(threshold);
        if raw_similarity < threshold_f64 {
            (0.0, true)
        } else {
            (raw_similarity, false)
        }
    } else {
        (raw_similarity, false)
    };

    let skip_reason = if short_string && rule.match_type != GovMatchType::Exact {
        Some("Short string: fallback to exact match".to_string())
    } else if per_rule_skipped {
        Some(format!(
            "Below per-rule threshold ({})",
            rule.threshold.map(|t| t.to_string()).unwrap_or_default()
        ))
    } else {
        None
    };

    let effective_strategy = if short_string && rule.match_type != GovMatchType::Exact {
        "exact_fallback".to_string()
    } else {
        strategy
    };

    AttributeScore {
        rule_id: rule.id,
        rule_name: rule.name.clone(),
        source_attribute: rule
            .source_attribute
            .clone()
            .unwrap_or_else(|| rule.attribute.clone()),
        target_attribute: rule
            .target_attribute
            .clone()
            .unwrap_or_else(|| rule.attribute.clone()),
        source_value: src,
        target_value: tgt,
        strategy: effective_strategy,
        raw_similarity,
        weight,
        weighted_score: raw_similarity * weight,
        normalized: was_normalized,
        skipped: false,
        skip_reason,
    }
}

// =============================================================================
// Matching algorithms
// =============================================================================

/// Case-insensitive exact string comparison.
fn exact_match(a: &str, b: &str) -> f64 {
    if a.eq_ignore_ascii_case(b) {
        1.0
    } else {
        0.0
    }
}

/// Fuzzy match dispatcher.
fn fuzzy_match(a: &str, b: &str, algorithm: GovFuzzyAlgorithm) -> f64 {
    match algorithm {
        GovFuzzyAlgorithm::JaroWinkler => jaro_winkler(a, b),
        GovFuzzyAlgorithm::Levenshtein => levenshtein_similarity(a, b),
        GovFuzzyAlgorithm::Soundex => {
            let s1 = soundex(a);
            let s2 = soundex(b);
            if s1 == s2 {
                1.0
            } else {
                0.0
            }
        }
    }
}

/// Jaro-Winkler similarity (inline implementation).
///
/// Returns a value between 0.0 and 1.0 where 1.0 is an exact match.
/// The Jaro similarity is boosted by a Winkler prefix bonus.
fn jaro_winkler(s1: &str, s2: &str) -> f64 {
    if s1 == s2 {
        return 1.0;
    }
    if s1.is_empty() || s2.is_empty() {
        return 0.0;
    }

    let s1_chars: Vec<char> = s1.chars().collect();
    let s2_chars: Vec<char> = s2.chars().collect();
    let s1_len = s1_chars.len();
    let s2_len = s2_chars.len();

    // Maximum distance for matching.
    let match_distance = (s1_len.max(s2_len) / 2).saturating_sub(1);

    let mut s1_matches = vec![false; s1_len];
    let mut s2_matches = vec![false; s2_len];

    let mut matches: f64 = 0.0;
    let mut transpositions: f64 = 0.0;

    // Find matches.
    for i in 0..s1_len {
        let start = i.saturating_sub(match_distance);
        let end = (i + match_distance + 1).min(s2_len);

        for j in start..end {
            if s2_matches[j] || s1_chars[i] != s2_chars[j] {
                continue;
            }
            s1_matches[i] = true;
            s2_matches[j] = true;
            matches += 1.0;
            break;
        }
    }

    if matches == 0.0 {
        return 0.0;
    }

    // Count transpositions.
    let mut k = 0;
    for i in 0..s1_len {
        if !s1_matches[i] {
            continue;
        }
        while !s2_matches[k] {
            k += 1;
        }
        if s1_chars[i] != s2_chars[k] {
            transpositions += 1.0;
        }
        k += 1;
    }

    let jaro = (matches / s1_len as f64
        + matches / s2_len as f64
        + (matches - transpositions / 2.0) / matches)
        / 3.0;

    // Winkler prefix bonus (up to 4 characters, scaling factor 0.1).
    let prefix_len = s1_chars
        .iter()
        .zip(s2_chars.iter())
        .take(4)
        .take_while(|(a, b)| a == b)
        .count();

    let winkler = jaro + (prefix_len as f64 * 0.1 * (1.0 - jaro));

    winkler.clamp(0.0, 1.0)
}

/// Levenshtein similarity as `1.0 - (edit_distance / max_len)`.
fn levenshtein_similarity(a: &str, b: &str) -> f64 {
    if a == b {
        return 1.0;
    }
    let a_len = a.len();
    let b_len = b.len();
    if a_len == 0 || b_len == 0 {
        return 0.0;
    }

    let distance = levenshtein_distance(a, b);
    let max_len = a_len.max(b_len) as f64;
    (1.0 - (distance as f64 / max_len)).max(0.0)
}

/// Compute Levenshtein edit distance.
fn levenshtein_distance(a: &str, b: &str) -> usize {
    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();
    let a_len = a_chars.len();
    let b_len = b_chars.len();

    // Optimise for trivial cases.
    if a_len == 0 {
        return b_len;
    }
    if b_len == 0 {
        return a_len;
    }

    // Use single-row optimisation.
    let mut prev_row: Vec<usize> = (0..=b_len).collect();
    let mut curr_row: Vec<usize> = vec![0; b_len + 1];

    for i in 1..=a_len {
        curr_row[0] = i;
        for j in 1..=b_len {
            let cost = usize::from(a_chars[i - 1] != b_chars[j - 1]);
            curr_row[j] = (prev_row[j] + 1)
                .min(curr_row[j - 1] + 1)
                .min(prev_row[j - 1] + cost);
        }
        std::mem::swap(&mut prev_row, &mut curr_row);
    }

    prev_row[b_len]
}

/// American Soundex encoding.
///
/// Returns a 4-character code representing the phonetic sound of the input.
fn soundex(s: &str) -> String {
    let chars: Vec<char> = s.chars().filter(char::is_ascii_alphabetic).collect();

    if chars.is_empty() {
        return "0000".to_string();
    }

    let mut code = String::with_capacity(4);
    code.push(chars[0].to_ascii_uppercase());

    let digit = |c: char| -> Option<char> {
        match c.to_ascii_lowercase() {
            'b' | 'f' | 'p' | 'v' => Some('1'),
            'c' | 'g' | 'j' | 'k' | 'q' | 's' | 'x' | 'z' => Some('2'),
            'd' | 't' => Some('3'),
            'l' => Some('4'),
            'm' | 'n' => Some('5'),
            'r' => Some('6'),
            _ => None, // a, e, i, o, u, h, w, y
        }
    };

    let mut last_digit = digit(chars[0]);

    for &ch in &chars[1..] {
        if code.len() >= 4 {
            break;
        }
        let d = digit(ch);
        if let Some(digit_val) = d {
            if d != last_digit {
                code.push(digit_val);
            }
        }
        last_digit = d;
    }

    // Pad with zeros.
    while code.len() < 4 {
        code.push('0');
    }

    code
}

/// Simple expression evaluator placeholder.
///
/// Evaluate a custom expression to transform/compare source and target values.
///
/// Supports several common expression patterns:
///
/// - **Email local part**: `source.split("@")[0]` — extracts the part before `@`
/// - **Concatenation**: `source.first_name + " " + source.last_name` — joins fields
///   (simplified: if expression contains `+`, splits source by space and joins)
/// - **Substring**: `source.substring(0, N)` — compares first N characters
/// - **Lowercase**: `source.to_lower()` — case-insensitive comparison (already handled
///   by normalization, but explicit in expressions)
/// - **Regex replace**: `source.replace("-", "")` — removes characters before comparison
///
/// Falls back to exact match for unrecognized expressions.
///
/// ## Future Enhancement
///
/// When the Rhai scripting engine from `xavyo-provisioning` is integrated,
/// this function should delegate to `RhaiScriptExecutor::execute()` with
/// sandboxed configuration (`max_operations=10000`) to evaluate arbitrary
/// expressions safely.
fn evaluate_expression(expression: &str, source: &str, target: &str) -> f64 {
    let expr_lower = expression.to_lowercase();

    // Pattern 1: Email local-part extraction — `source.split("@")[0]`
    if expr_lower.contains("split") && expression.contains('@') {
        let source_local = source.split('@').next().unwrap_or(source);
        let target_local = target.split('@').next().unwrap_or(target);
        return exact_match(source_local, target_local);
    }

    // Pattern 2: Substring comparison — `source.substring(0, N)`
    if expr_lower.contains("substring") {
        // Extract the length parameter from `substring(0, N)`
        if let Some(len_str) = expression
            .split(',')
            .nth(1)
            .and_then(|s| s.trim().trim_end_matches(')').trim().parse::<usize>().ok())
        {
            let source_sub: String = source.chars().take(len_str).collect();
            let target_sub: String = target.chars().take(len_str).collect();
            return exact_match(&source_sub, &target_sub);
        }
    }

    // Pattern 3: Replace characters — `source.replace("-", "")` or `source.replace(" ", "")`
    if expr_lower.contains("replace") {
        // Extract the character to remove from `replace("X", "")`
        if let Some(start) = expression.find("replace(\"") {
            let after = &expression[start + 9..];
            if let Some(end) = after.find('"') {
                let to_remove = &after[..end];
                let source_clean = source.replace(to_remove, "");
                let target_clean = target.replace(to_remove, "");
                return exact_match(&source_clean, &target_clean);
            }
        }
    }

    // Pattern 4: First+Last name concatenation — `first_name + " " + last_name`
    if expression.contains('+') && expression.contains("name") {
        // For concatenation expressions, compare the full normalized strings
        let source_normalized = source.split_whitespace().collect::<Vec<_>>().join(" ");
        let target_normalized = target.split_whitespace().collect::<Vec<_>>().join(" ");
        return exact_match(&source_normalized, &target_normalized);
    }

    // Pattern 5: Lowercase — `source.to_lower()`
    if expr_lower.contains("to_lower") || expr_lower.contains("tolower") {
        return exact_match(&source.to_lowercase(), &target.to_lowercase());
    }

    // Fallback: exact match on raw values.
    exact_match(source, target)
}

// =============================================================================
// Normalization
// =============================================================================

/// Normalize an attribute value for comparison.
///
/// Applies Unicode NFC normalization and lowercasing.
/// Note: `unicode_normalization` crate is required in Cargo.toml.
/// If not available, we fall back to basic lowercasing which handles
/// ASCII correctly.
#[must_use] 
pub fn normalize_attribute(value: &str) -> String {
    // Basic normalization: trim whitespace, lowercase.
    // Full Unicode NFC requires the `unicode-normalization` crate.
    // We provide a best-effort ASCII-safe normalization here.
    value.trim().to_lowercase()
}

// =============================================================================
// Weight redistribution
// =============================================================================

/// Redistribute weights proportionally among available (non-skipped) rules.
///
/// When some rules are skipped (e.g., due to missing attributes), their weight
/// is proportionally redistributed among the remaining rules so that the total
/// weight sums to 1.0 (or the original total, whichever is appropriate).
#[must_use] 
pub fn redistribute_weights(
    all_rules: &[GovCorrelationRule],
    available_rule_ids: &[Uuid],
) -> HashMap<Uuid, f64> {
    let mut result = HashMap::new();

    if available_rule_ids.is_empty() {
        return result;
    }

    // Sum of weights for available rules.
    let available_weight_sum: f64 = all_rules
        .iter()
        .filter(|r| available_rule_ids.contains(&r.id))
        .map(|r| decimal_to_f64(r.weight))
        .sum();

    if available_weight_sum <= 0.0 {
        // Distribute equally if weights sum to zero.
        let equal = 1.0 / available_rule_ids.len() as f64;
        for id in available_rule_ids {
            result.insert(*id, equal);
        }
        return result;
    }

    // Total weight from all rules (including skipped).
    let total_weight: f64 = all_rules.iter().map(|r| decimal_to_f64(r.weight)).sum();

    let scale = if total_weight > 0.0 {
        total_weight / available_weight_sum
    } else {
        1.0
    };

    for rule in all_rules {
        if available_rule_ids.contains(&rule.id) {
            let w = decimal_to_f64(rule.weight) * scale;
            result.insert(rule.id, w);
        }
    }

    result
}

// =============================================================================
// Threshold application
// =============================================================================

/// Apply confidence thresholds to determine the evaluation outcome.
#[must_use] 
pub fn apply_thresholds(
    confidence: f64,
    auto_confirm_threshold: f64,
    manual_review_threshold: f64,
) -> CorrelationOutcome {
    if confidence >= auto_confirm_threshold {
        CorrelationOutcome::AutoConfirmed
    } else if confidence >= manual_review_threshold {
        CorrelationOutcome::ReviewQueued
    } else {
        CorrelationOutcome::NoMatch
    }
}

// =============================================================================
// Helpers
// =============================================================================

/// Convert a `Decimal` to `f64`.
fn decimal_to_f64(d: Decimal) -> f64 {
    d.to_f64().unwrap_or(0.0)
}

/// Extract a string attribute from a JSON object.
///
/// Supports nested access via dot notation (e.g., "address.city").
fn extract_attribute(attrs: &serde_json::Value, key: &str) -> String {
    // Try dot-notation path first.
    let parts: Vec<&str> = key.split('.').collect();
    let mut current = attrs;

    for part in &parts {
        match current.get(part) {
            Some(v) => current = v,
            None => return String::new(),
        }
    }

    match current {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal::Decimal;

    // ---- test_exact_match_scoring ----

    #[test]
    fn test_exact_match_scoring() {
        let rule = make_test_rule(
            "Email Exact",
            GovMatchType::Exact,
            None,
            Decimal::new(50, 2), // 0.50
        );

        // Exact match should return 1.0.
        let score = compute_attribute_score(&rule, "alice@example.com", "alice@example.com");
        assert!(!score.skipped);
        assert!((score.raw_similarity - 1.0).abs() < f64::EPSILON);
        assert!((score.weighted_score - 0.5).abs() < 0.001);

        // Case-insensitive match.
        let score = compute_attribute_score(&rule, "Alice@Example.COM", "alice@example.com");
        assert!((score.raw_similarity - 1.0).abs() < f64::EPSILON);

        // Mismatch should return 0.0.
        let score = compute_attribute_score(&rule, "alice@example.com", "bob@example.com");
        assert!((score.raw_similarity - 0.0).abs() < f64::EPSILON);
        assert!((score.weighted_score - 0.0).abs() < f64::EPSILON);
    }

    // ---- test_normalize_attribute ----

    #[test]
    fn test_normalize_attribute() {
        // Basic lowercasing.
        assert_eq!(normalize_attribute("Hello World"), "hello world");

        // Trimming whitespace.
        assert_eq!(normalize_attribute("  spaces  "), "spaces");

        // Already normalized.
        assert_eq!(normalize_attribute("already"), "already");

        // Empty string.
        assert_eq!(normalize_attribute(""), "");

        // Unicode characters: lowercased.
        assert_eq!(normalize_attribute("ALICE"), "alice");
    }

    // ---- test_apply_thresholds ----

    #[test]
    fn test_apply_thresholds() {
        let auto_confirm = 0.85;
        let manual_review = 0.50;

        // Above auto-confirm threshold.
        assert_eq!(
            apply_thresholds(0.90, auto_confirm, manual_review),
            CorrelationOutcome::AutoConfirmed
        );

        // Exactly at auto-confirm threshold.
        assert_eq!(
            apply_thresholds(0.85, auto_confirm, manual_review),
            CorrelationOutcome::AutoConfirmed
        );

        // Between review and auto-confirm.
        assert_eq!(
            apply_thresholds(0.70, auto_confirm, manual_review),
            CorrelationOutcome::ReviewQueued
        );

        // Exactly at manual review threshold.
        assert_eq!(
            apply_thresholds(0.50, auto_confirm, manual_review),
            CorrelationOutcome::ReviewQueued
        );

        // Below manual review threshold.
        assert_eq!(
            apply_thresholds(0.30, auto_confirm, manual_review),
            CorrelationOutcome::NoMatch
        );

        // Zero confidence.
        assert_eq!(
            apply_thresholds(0.0, auto_confirm, manual_review),
            CorrelationOutcome::NoMatch
        );
    }

    // ---- test_redistribute_weights ----

    #[test]
    fn test_redistribute_weights() {
        let rule1_id = Uuid::new_v4();
        let rule2_id = Uuid::new_v4();
        let rule3_id = Uuid::new_v4();

        let rules = vec![
            make_test_rule_with_id(rule1_id, "Rule 1", Decimal::new(40, 2)), // 0.40
            make_test_rule_with_id(rule2_id, "Rule 2", Decimal::new(30, 2)), // 0.30
            make_test_rule_with_id(rule3_id, "Rule 3", Decimal::new(30, 2)), // 0.30
        ];

        // All rules available: weights should remain proportional.
        let all = vec![rule1_id, rule2_id, rule3_id];
        let result = redistribute_weights(&rules, &all);
        assert_eq!(result.len(), 3);
        // Scale = 1.0 / 1.0 = 1.0, so weights unchanged.
        assert!((result[&rule1_id] - 0.40).abs() < 0.001);
        assert!((result[&rule2_id] - 0.30).abs() < 0.001);
        assert!((result[&rule3_id] - 0.30).abs() < 0.001);

        // Rule 3 skipped: redistribute its weight proportionally.
        let partial = vec![rule1_id, rule2_id];
        let result = redistribute_weights(&rules, &partial);
        assert_eq!(result.len(), 2);
        // Available sum = 0.70, total sum = 1.00, scale = 1.0 / 0.7 ~ 1.4286
        // Rule 1: 0.40 * (1.0 / 0.7) ~ 0.5714
        // Rule 2: 0.30 * (1.0 / 0.7) ~ 0.4286
        let sum: f64 = result.values().sum();
        assert!(
            (sum - 1.0).abs() < 0.001,
            "Redistributed weights should sum to ~1.0"
        );
        assert!(result[&rule1_id] > 0.40);
        assert!(result[&rule2_id] > 0.30);

        // No rules available: empty result.
        let empty: Vec<Uuid> = vec![];
        let result = redistribute_weights(&rules, &empty);
        assert!(result.is_empty());
    }

    // ---- test_short_string_exact_fallback ----

    #[test]
    fn test_short_string_exact_fallback() {
        // A fuzzy rule with a short source string should fall back to exact matching.
        let rule = make_test_rule(
            "Name Fuzzy",
            GovMatchType::Fuzzy,
            Some(GovFuzzyAlgorithm::JaroWinkler),
            Decimal::new(50, 2),
        );

        // Source is only 2 characters: should use exact fallback.
        let score = compute_attribute_score(&rule, "AB", "AB");
        assert!((score.raw_similarity - 1.0).abs() < f64::EPSILON);
        assert_eq!(score.strategy, "exact_fallback");
        assert!(
            score.skip_reason.is_some(),
            "Should have skip_reason for short string fallback"
        );

        // Short source, mismatch.
        let score = compute_attribute_score(&rule, "AB", "CD");
        assert!((score.raw_similarity - 0.0).abs() < f64::EPSILON);
        assert_eq!(score.strategy, "exact_fallback");

        // Long enough strings should use the fuzzy algorithm.
        let score = compute_attribute_score(&rule, "Alice", "Alica");
        assert!(score.raw_similarity > 0.0);
        assert_eq!(score.strategy, "fuzzy");
        assert!(score.skip_reason.is_none());
    }

    // ---- test_job_status_tracking ----

    #[test]
    fn test_job_status_tracking() {
        let job_id = Uuid::new_v4();
        let connector_id = Uuid::new_v4();

        let tenant_id = Uuid::new_v4();
        let mut status = CorrelationJobStatus {
            job_id,
            tenant_id,
            connector_id,
            status: "pending".to_string(),
            total_accounts: 100,
            processed_accounts: 0,
            auto_confirmed: 0,
            review_queued: 0,
            no_match: 0,
            errors: 0,
            started_at: Utc::now(),
            completed_at: None,
            error_message: None,
        };

        assert_eq!(status.status, "pending");
        assert_eq!(status.total_accounts, 100);
        assert_eq!(status.processed_accounts, 0);
        assert!(status.completed_at.is_none());

        // Transition to running.
        status.status = "running".to_string();
        assert_eq!(status.status, "running");

        // Process some accounts.
        status.processed_accounts = 50;
        status.auto_confirmed = 30;
        status.review_queued = 10;
        status.no_match = 8;
        status.errors = 2;
        assert_eq!(
            status.auto_confirmed + status.review_queued + status.no_match + status.errors,
            50
        );

        // Transition to completed.
        status.status = "completed".to_string();
        status.completed_at = Some(Utc::now());
        status.processed_accounts = 100;
        status.auto_confirmed = 60;
        status.review_queued = 20;
        status.no_match = 15;
        status.errors = 5;
        assert_eq!(status.status, "completed");
        assert!(status.completed_at.is_some());
        assert_eq!(
            status.auto_confirmed + status.review_queued + status.no_match + status.errors,
            100
        );

        // Serialization roundtrip.
        let json = serde_json::to_string(&status).unwrap();
        let deserialized: CorrelationJobStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.job_id, job_id);
        assert_eq!(deserialized.connector_id, connector_id);
        assert_eq!(deserialized.status, "completed");
        assert_eq!(deserialized.total_accounts, 100);
    }

    // ---- Fuzzy algorithm tests ----

    #[test]
    fn test_jaro_winkler_identical() {
        assert!((jaro_winkler("alice", "alice") - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_jaro_winkler_similar() {
        let score = jaro_winkler("alice", "alica");
        assert!(score > 0.8, "Similar strings should score high: {}", score);
    }

    #[test]
    fn test_jaro_winkler_different() {
        let score = jaro_winkler("alice", "bob");
        assert!(score < 0.5, "Different strings should score low: {}", score);
    }

    #[test]
    fn test_jaro_winkler_empty() {
        assert!((jaro_winkler("", "alice") - 0.0).abs() < f64::EPSILON);
        assert!((jaro_winkler("alice", "") - 0.0).abs() < f64::EPSILON);
        assert!((jaro_winkler("", "") - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_levenshtein_similarity_identical() {
        assert!((levenshtein_similarity("alice", "alice") - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_levenshtein_similarity_one_edit() {
        // "alice" vs "alica" = 1 edit out of 5 chars => 1.0 - 1/5 = 0.8
        let score = levenshtein_similarity("alice", "alica");
        assert!((score - 0.8).abs() < f64::EPSILON);
    }

    #[test]
    fn test_levenshtein_similarity_completely_different() {
        let score = levenshtein_similarity("abc", "xyz");
        // 3 edits out of 3 chars => 0.0
        assert!((score - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_soundex_basic() {
        // Classic soundex examples.
        assert_eq!(soundex("Robert"), "R163");
        assert_eq!(soundex("Rupert"), "R163");
        assert_eq!(soundex("Robert"), soundex("Rupert"));

        // Different names should differ.
        assert_ne!(soundex("Alice"), soundex("Bob"));
    }

    #[test]
    fn test_soundex_empty() {
        assert_eq!(soundex(""), "0000");
    }

    #[test]
    fn test_extract_attribute_simple() {
        let attrs = serde_json::json!({
            "email": "alice@example.com",
            "count": 42,
            "active": true,
        });

        assert_eq!(extract_attribute(&attrs, "email"), "alice@example.com");
        assert_eq!(extract_attribute(&attrs, "count"), "42");
        assert_eq!(extract_attribute(&attrs, "active"), "true");
        assert_eq!(extract_attribute(&attrs, "missing"), "");
    }

    #[test]
    fn test_extract_attribute_nested() {
        let attrs = serde_json::json!({
            "address": {
                "city": "New York"
            }
        });

        assert_eq!(extract_attribute(&attrs, "address.city"), "New York");
        assert_eq!(extract_attribute(&attrs, "address.zip"), "");
    }

    #[test]
    fn test_expression_evaluator_email_split() {
        // Expression that extracts email local part.
        let score = evaluate_expression(r#"source.split("@")[0]"#, "alice@example.com", "alice");
        assert!((score - 1.0).abs() < f64::EPSILON);

        let score = evaluate_expression(r#"source.split("@")[0]"#, "alice@example.com", "bob");
        assert!((score - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_fuzzy_match_with_rule() {
        let rule = make_test_rule(
            "Name Fuzzy",
            GovMatchType::Fuzzy,
            Some(GovFuzzyAlgorithm::Levenshtein),
            Decimal::new(50, 2),
        );

        let score = compute_attribute_score(&rule, "Alice Smith", "Alice Smyth");
        assert!(
            score.raw_similarity > 0.7,
            "Should be similar: {}",
            score.raw_similarity
        );
        assert!(!score.skipped);
    }

    #[test]
    fn test_phonetic_match() {
        let rule = make_test_rule(
            "Name Phonetic",
            GovMatchType::Phonetic,
            None,
            Decimal::new(30, 2),
        );

        // "Robert" and "Rupert" have the same Soundex code.
        let score = compute_attribute_score(&rule, "Robert", "Rupert");
        assert!((score.raw_similarity - 1.0).abs() < f64::EPSILON);

        // "Alice" and "Bob" have different Soundex codes.
        let score = compute_attribute_score(&rule, "Alice", "Bob");
        assert!((score.raw_similarity - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_decimal_to_f64_conversion() {
        assert!((decimal_to_f64(Decimal::new(85, 2)) - 0.85).abs() < f64::EPSILON);
        assert!((decimal_to_f64(Decimal::new(0, 0)) - 0.0).abs() < f64::EPSILON);
        assert!((decimal_to_f64(Decimal::new(100, 2)) - 1.0).abs() < f64::EPSILON);
    }

    // =========================================================================
    // Test helpers
    // =========================================================================

    fn make_test_rule(
        name: &str,
        match_type: GovMatchType,
        algorithm: Option<GovFuzzyAlgorithm>,
        weight: Decimal,
    ) -> GovCorrelationRule {
        make_test_rule_with_id(Uuid::new_v4(), name, weight).with_match_type(match_type, algorithm)
    }

    fn make_test_rule_with_id(id: Uuid, name: &str, weight: Decimal) -> GovCorrelationRule {
        GovCorrelationRule {
            id,
            tenant_id: Uuid::new_v4(),
            name: name.to_string(),
            attribute: "test".to_string(),
            match_type: GovMatchType::Exact,
            algorithm: None,
            threshold: None,
            weight,
            is_active: true,
            priority: 100,
            connector_id: Some(Uuid::new_v4()),
            source_attribute: None,
            target_attribute: None,
            expression: None,
            tier: Some(1),
            is_definitive: false,
            normalize: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    /// Extension trait for test rules to easily set match type and algorithm.
    trait TestRuleExt {
        fn with_match_type(
            self,
            match_type: GovMatchType,
            algorithm: Option<GovFuzzyAlgorithm>,
        ) -> Self;
    }

    impl TestRuleExt for GovCorrelationRule {
        fn with_match_type(
            mut self,
            match_type: GovMatchType,
            algorithm: Option<GovFuzzyAlgorithm>,
        ) -> Self {
            self.match_type = match_type;
            self.algorithm = algorithm;
            self
        }
    }
}
