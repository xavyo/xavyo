//! Mining service for role mining and analytics.

use std::collections::HashMap;

use sqlx::PgPool;
use uuid::Uuid;

/// Result counts from mining analysis.
struct MiningAnalysisCounts {
    candidate_count: i32,
    excessive_privilege_count: i32,
    consolidation_suggestion_count: i32,
}

use xavyo_db::{
    AccessPatternFilter, CandidatePromotionStatus, ConsolidationStatus,
    ConsolidationSuggestionFilter, CreateMiningJob, ExcessivePrivilegeFilter, GovAccessPattern,
    GovConsolidationSuggestion, GovEntitlement, GovEntitlementAssignment, GovExcessivePrivilege,
    GovRoleCandidate, GovRoleMiningJob, MiningJobFilter, MiningJobParameters, MiningJobStatus,
    PrivilegeFlagStatus, RoleCandidateFilter, UpdateExcessivePrivilegeStatus, UpdateJobProgress,
};
use xavyo_governance::error::{GovernanceError, Result};

use super::consolidation_analyzer::{ConsolidationAnalyzer, RoleData};
use super::pattern_analyzer::{PatternAnalyzer, UserEntitlements};
use super::privilege_detector::{PeerGroupData, PrivilegeDetector};

/// Minimum users required for meaningful mining analysis.
pub const MIN_USERS_FOR_MINING: i32 = 10;

/// Service for role mining job operations.
pub struct MiningService {
    pool: PgPool,
}

impl MiningService {
    /// Create a new mining service.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get a mining job by ID.
    pub async fn get(&self, tenant_id: Uuid, job_id: Uuid) -> Result<GovRoleMiningJob> {
        GovRoleMiningJob::find_by_id(&self.pool, tenant_id, job_id)
            .await?
            .ok_or(GovernanceError::MiningJobNotFound(job_id))
    }

    /// List mining jobs with filtering and pagination.
    pub async fn list(
        &self,
        tenant_id: Uuid,
        status: Option<MiningJobStatus>,
        created_by: Option<Uuid>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<GovRoleMiningJob>, i64)> {
        let filter = MiningJobFilter { status, created_by };

        let jobs =
            GovRoleMiningJob::list_by_tenant(&self.pool, tenant_id, &filter, limit, offset).await?;
        let total = GovRoleMiningJob::count_by_tenant(&self.pool, tenant_id, &filter).await?;

        Ok((jobs, total))
    }

    /// Create a new mining job.
    pub async fn create_job(
        &self,
        tenant_id: Uuid,
        name: String,
        parameters: MiningJobParameters,
        created_by: Uuid,
    ) -> Result<GovRoleMiningJob> {
        // Validate name
        if name.trim().is_empty() {
            return Err(GovernanceError::Validation(
                "Job name cannot be empty".to_string(),
            ));
        }

        if name.len() > 255 {
            return Err(GovernanceError::Validation(
                "Job name cannot exceed 255 characters".to_string(),
            ));
        }

        // Check if there's already a running job for this tenant
        if GovRoleMiningJob::has_running_job(&self.pool, tenant_id).await? {
            return Err(GovernanceError::MiningJobAlreadyRunning);
        }

        // Validate parameters
        validate_parameters(&parameters)?;

        let input = CreateMiningJob {
            name,
            parameters,
            created_by,
        };

        let job = GovRoleMiningJob::create(&self.pool, tenant_id, input).await?;

        tracing::info!(
            job_id = %job.id,
            tenant_id = %tenant_id,
            "Created mining job"
        );

        Ok(job)
    }

    /// Run a mining job (start execution).
    pub async fn run_job(&self, tenant_id: Uuid, job_id: Uuid) -> Result<GovRoleMiningJob> {
        let job = self.get(tenant_id, job_id).await?;

        if !job.status.can_start() {
            return Err(GovernanceError::MiningJobNotPending(job_id));
        }

        // Check for running jobs
        if GovRoleMiningJob::has_running_job(&self.pool, tenant_id).await? {
            return Err(GovernanceError::MiningJobAlreadyRunning);
        }

        // Start the job
        let job = GovRoleMiningJob::start(&self.pool, tenant_id, job_id)
            .await?
            .ok_or(GovernanceError::MiningJobNotPending(job_id))?;

        tracing::info!(
            job_id = %job.id,
            tenant_id = %tenant_id,
            "Started mining job"
        );

        // Execute the mining analysis
        match self.execute_mining_analysis(tenant_id, &job).await {
            Ok(counts) => {
                tracing::info!(job_id = %job.id, "Mining job completed successfully");
                let job = GovRoleMiningJob::complete(
                    &self.pool,
                    tenant_id,
                    job_id,
                    counts.candidate_count,
                    counts.excessive_privilege_count,
                    counts.consolidation_suggestion_count,
                )
                .await?
                .ok_or(GovernanceError::MiningJobNotFound(job_id))?;
                Ok(job)
            }
            Err(e) => {
                tracing::error!(job_id = %job.id, error = %e, "Mining job failed");
                let _ = GovRoleMiningJob::fail(&self.pool, tenant_id, job_id, &e.to_string()).await;
                Err(e)
            }
        }
    }

    /// Execute the actual mining analysis.
    async fn execute_mining_analysis(
        &self,
        tenant_id: Uuid,
        job: &GovRoleMiningJob,
    ) -> Result<MiningAnalysisCounts> {
        let params = job.parse_parameters();
        let job_id = job.id;

        let mut counts = MiningAnalysisCounts {
            candidate_count: 0,
            excessive_privilege_count: 0,
            consolidation_suggestion_count: 0,
        };

        // Update progress: 10% - Starting
        self.update_job_progress(tenant_id, job_id, 10).await?;

        // Step 1: Collect user-entitlement data
        let user_entitlements = self.collect_user_entitlements(tenant_id).await?;

        if user_entitlements.is_empty() {
            tracing::warn!(job_id = %job_id, "No user entitlements found for mining");
            return Ok(counts);
        }

        tracing::info!(
            job_id = %job_id,
            user_count = user_entitlements.len(),
            "Collected user entitlements for mining"
        );

        // Update progress: 20% - Data collected
        self.update_job_progress(tenant_id, job_id, 20).await?;

        // Step 2: Analyze patterns and generate candidates
        let pattern_analyzer = PatternAnalyzer::new(params.clone());
        let patterns = pattern_analyzer.analyze_entitlement_patterns(&user_entitlements)?;

        tracing::info!(
            job_id = %job_id,
            pattern_count = patterns.len(),
            "Analyzed access patterns"
        );

        // Update progress: 40% - Patterns analyzed
        self.update_job_progress(tenant_id, job_id, 40).await?;

        // Get entitlement names for role naming
        let entitlement_names = self.get_entitlement_names(tenant_id).await?;

        // Generate role candidates
        let candidates =
            pattern_analyzer.generate_role_candidates(&patterns, &entitlement_names)?;
        counts.candidate_count = candidates.len() as i32;

        tracing::info!(
            job_id = %job_id,
            candidate_count = counts.candidate_count,
            "Generated role candidates"
        );

        // Save patterns and candidates to database
        let pattern_requests = pattern_analyzer.patterns_to_create_requests(job_id, &patterns);
        if !pattern_requests.is_empty() {
            GovAccessPattern::create_batch(&self.pool, tenant_id, pattern_requests).await?;
        }

        let candidate_requests =
            pattern_analyzer.candidates_to_create_requests(job_id, &candidates);
        if !candidate_requests.is_empty() {
            GovRoleCandidate::create_batch(&self.pool, tenant_id, candidate_requests).await?;
        }

        // Update progress: 60% - Candidates saved
        self.update_job_progress(tenant_id, job_id, 60).await?;

        // Step 3: Detect excessive privileges (if enabled)
        if params.include_excessive_privilege {
            counts.excessive_privilege_count = self
                .detect_excessive_privileges(tenant_id, job_id, &params, &user_entitlements)
                .await?;
        }

        // Update progress: 80% - Excessive privileges analyzed
        self.update_job_progress(tenant_id, job_id, 80).await?;

        // Step 4: Analyze role consolidation (if enabled)
        if params.include_consolidation {
            counts.consolidation_suggestion_count = self
                .analyze_role_consolidation(tenant_id, job_id, &params)
                .await?;
        }

        // Update progress: 100% - Complete
        self.update_job_progress(tenant_id, job_id, 100).await?;

        Ok(counts)
    }

    /// Collect user entitlements for analysis.
    async fn collect_user_entitlements(&self, tenant_id: Uuid) -> Result<Vec<UserEntitlements>> {
        let mappings =
            GovEntitlementAssignment::get_user_entitlement_mappings(&self.pool, tenant_id).await?;

        let result: Vec<UserEntitlements> = mappings
            .into_iter()
            .map(|(user_id, entitlement_ids)| UserEntitlements {
                user_id,
                entitlement_ids: entitlement_ids.into_iter().collect(),
            })
            .collect();

        Ok(result)
    }

    /// Get entitlement names for role naming.
    async fn get_entitlement_names(&self, tenant_id: Uuid) -> Result<HashMap<Uuid, String>> {
        let entitlements = GovEntitlement::list_all(&self.pool, tenant_id).await?;

        let names: HashMap<Uuid, String> =
            entitlements.into_iter().map(|e| (e.id, e.name)).collect();

        Ok(names)
    }

    /// Detect excessive privileges for users. Returns count of flags created.
    async fn detect_excessive_privileges(
        &self,
        tenant_id: Uuid,
        job_id: Uuid,
        params: &MiningJobParameters,
        user_entitlements: &[UserEntitlements],
    ) -> Result<i32> {
        let detector = PrivilegeDetector::new(params.clone());

        // Build peer groups based on peer_group_attribute or fall back to all users
        let peer_groups = self
            .build_peer_groups(
                tenant_id,
                user_entitlements,
                params.peer_group_attribute.as_deref(),
            )
            .await?;

        let peer_averages = detector.calculate_peer_averages(user_entitlements, &peer_groups)?;
        let excessive_flags =
            detector.detect_excessive_users(user_entitlements, &peer_groups, &peer_averages)?;

        let count = excessive_flags.len() as i32;

        if !excessive_flags.is_empty() {
            let create_requests = detector.detections_to_create_requests(job_id, &excessive_flags);
            GovExcessivePrivilege::create_batch(&self.pool, tenant_id, create_requests).await?;

            tracing::info!(
                job_id = %job_id,
                flag_count = count,
                peer_group_count = peer_groups.len(),
                "Detected excessive privileges"
            );
        }

        Ok(count)
    }

    /// Build peer groups for privilege detection.
    ///
    /// If `peer_group_attribute` is specified, groups users by that attribute (e.g., "department", "team").
    /// Supported attributes: "department", "group", "role".
    /// Falls back to a single "all_users" group if attribute is not specified or has no data.
    async fn build_peer_groups(
        &self,
        tenant_id: Uuid,
        user_entitlements: &[UserEntitlements],
        peer_group_attribute: Option<&str>,
    ) -> Result<Vec<PeerGroupData>> {
        let user_ids: Vec<Uuid> = user_entitlements.iter().map(|u| u.user_id).collect();

        if user_ids.is_empty() {
            return Ok(vec![]);
        }

        match peer_group_attribute {
            Some("department") => {
                // Group users by department from user metadata
                let groups = self.group_users_by_department(tenant_id, &user_ids).await?;
                if groups.is_empty() {
                    Ok(self.create_default_peer_group(&user_ids))
                } else {
                    Ok(groups)
                }
            }
            Some("group") | Some("role") => {
                // Group users by their group memberships
                let groups = self.group_users_by_group(tenant_id, &user_ids).await?;
                if groups.is_empty() {
                    Ok(self.create_default_peer_group(&user_ids))
                } else {
                    Ok(groups)
                }
            }
            _ => {
                // Default: all users in one group
                Ok(self.create_default_peer_group(&user_ids))
            }
        }
    }

    /// Create a default peer group containing all users.
    fn create_default_peer_group(&self, user_ids: &[Uuid]) -> Vec<PeerGroupData> {
        vec![PeerGroupData {
            id: None,
            attribute_value: "all_users".to_string(),
            user_ids: user_ids.to_vec(),
        }]
    }

    /// Group users by department from user metadata.
    async fn group_users_by_department(
        &self,
        tenant_id: Uuid,
        user_ids: &[Uuid],
    ) -> Result<Vec<PeerGroupData>> {
        // Query user departments from metadata or a department field
        let rows: Vec<(Uuid, Option<String>)> = sqlx::query_as(
            r#"
            SELECT id, metadata->>'department' as department
            FROM users
            WHERE tenant_id = $1 AND id = ANY($2)
            "#,
        )
        .bind(tenant_id)
        .bind(user_ids)
        .fetch_all(&self.pool)
        .await?;

        // Group by department
        let mut dept_users: HashMap<String, Vec<Uuid>> = HashMap::new();
        for (user_id, dept) in rows {
            let dept_name = dept.unwrap_or_else(|| "unknown".to_string());
            dept_users.entry(dept_name).or_default().push(user_id);
        }

        // Convert to PeerGroupData
        let groups: Vec<PeerGroupData> = dept_users
            .into_iter()
            .filter(|(_, users)| users.len() >= 2) // Need at least 2 users for meaningful comparison
            .map(|(dept, users)| PeerGroupData {
                id: None,
                attribute_value: dept,
                user_ids: users,
            })
            .collect();

        Ok(groups)
    }

    /// Group users by their group memberships.
    async fn group_users_by_group(
        &self,
        tenant_id: Uuid,
        user_ids: &[Uuid],
    ) -> Result<Vec<PeerGroupData>> {
        // Query user group memberships
        let rows: Vec<(Uuid, Uuid, String)> = sqlx::query_as(
            r#"
            SELECT ug.user_id, ug.group_id, g.name
            FROM user_groups ug
            INNER JOIN groups g ON g.id = ug.group_id AND g.tenant_id = ug.tenant_id
            WHERE ug.tenant_id = $1 AND ug.user_id = ANY($2)
            "#,
        )
        .bind(tenant_id)
        .bind(user_ids)
        .fetch_all(&self.pool)
        .await?;

        // Group by group_id
        let mut group_users: HashMap<Uuid, (String, Vec<Uuid>)> = HashMap::new();
        for (user_id, group_id, group_name) in rows {
            group_users
                .entry(group_id)
                .or_insert_with(|| (group_name, Vec::new()))
                .1
                .push(user_id);
        }

        // Convert to PeerGroupData
        let groups: Vec<PeerGroupData> = group_users
            .into_iter()
            .filter(|(_, (_, users))| users.len() >= 2) // Need at least 2 users for meaningful comparison
            .map(|(group_id, (name, users))| PeerGroupData {
                id: Some(group_id),
                attribute_value: name,
                user_ids: users,
            })
            .collect();

        Ok(groups)
    }

    /// Analyze role consolidation opportunities. Returns count of suggestions created.
    async fn analyze_role_consolidation(
        &self,
        tenant_id: Uuid,
        job_id: Uuid,
        params: &MiningJobParameters,
    ) -> Result<i32> {
        // Get existing roles with their entitlements
        let role_entitlements = self.get_role_entitlements(tenant_id).await?;

        if role_entitlements.len() < 2 {
            // Need at least 2 roles to find overlaps
            return Ok(0);
        }

        let analyzer = ConsolidationAnalyzer::new(params.clone());
        let suggestions = analyzer.find_overlapping_roles(&role_entitlements)?;

        let count = suggestions.len() as i32;

        if !suggestions.is_empty() {
            let create_requests = analyzer.suggestions_to_create_requests(job_id, &suggestions);
            GovConsolidationSuggestion::create_batch(&self.pool, tenant_id, create_requests)
                .await?;

            tracing::info!(
                job_id = %job_id,
                suggestion_count = count,
                "Found consolidation opportunities"
            );
        }

        Ok(count)
    }

    /// Get role entitlements for consolidation analysis.
    /// Roles are represented by groups, and their entitlements come from group assignments.
    async fn get_role_entitlements(&self, tenant_id: Uuid) -> Result<Vec<RoleData>> {
        // Query group-based role entitlements
        // Groups with entitlement assignments are treated as roles
        let rows: Vec<(Uuid, String, Vec<Uuid>)> = sqlx::query_as(
            r#"
            SELECT
                g.id as role_id,
                g.name,
                array_agg(DISTINCT ea.entitlement_id) as entitlement_ids
            FROM groups g
            INNER JOIN gov_entitlement_assignments ea ON ea.target_id = g.id
                AND ea.target_type = 'group'
                AND ea.status = 'active'
            WHERE g.tenant_id = $1
            GROUP BY g.id, g.name
            HAVING COUNT(ea.entitlement_id) > 0
            "#,
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;

        let result: Vec<RoleData> = rows
            .into_iter()
            .map(|(role_id, name, entitlement_ids)| RoleData {
                role_id,
                name,
                entitlement_ids: entitlement_ids.into_iter().collect(),
            })
            .collect();

        Ok(result)
    }

    /// Update job progress percentage.
    async fn update_job_progress(
        &self,
        tenant_id: Uuid,
        job_id: Uuid,
        progress: i32,
    ) -> Result<()> {
        let update = UpdateJobProgress {
            progress_percent: progress,
            candidate_count: None,
            excessive_privilege_count: None,
            consolidation_suggestion_count: None,
        };
        GovRoleMiningJob::update_progress(&self.pool, tenant_id, job_id, update).await?;
        Ok(())
    }

    /// Cancel a running job.
    pub async fn cancel_job(&self, tenant_id: Uuid, job_id: Uuid) -> Result<GovRoleMiningJob> {
        let job = self.get(tenant_id, job_id).await?;

        if !job.status.can_cancel() {
            return Err(GovernanceError::CannotCancelMiningJob(job_id));
        }

        let job = GovRoleMiningJob::cancel(&self.pool, tenant_id, job_id)
            .await?
            .ok_or(GovernanceError::MiningJobNotFound(job_id))?;

        tracing::info!(
            job_id = %job.id,
            tenant_id = %tenant_id,
            "Cancelled mining job"
        );

        Ok(job)
    }

    /// Update job progress (called during execution).
    pub async fn update_progress(
        &self,
        tenant_id: Uuid,
        job_id: Uuid,
        progress_percent: i32,
        candidate_count: Option<i32>,
        excessive_privilege_count: Option<i32>,
        consolidation_suggestion_count: Option<i32>,
    ) -> Result<GovRoleMiningJob> {
        let input = UpdateJobProgress {
            progress_percent,
            candidate_count,
            excessive_privilege_count,
            consolidation_suggestion_count,
        };

        GovRoleMiningJob::update_progress(&self.pool, tenant_id, job_id, input)
            .await?
            .ok_or(GovernanceError::MiningJobNotRunning(job_id))
    }

    /// Complete a job successfully.
    pub async fn complete_job(
        &self,
        tenant_id: Uuid,
        job_id: Uuid,
        candidate_count: i32,
        excessive_privilege_count: i32,
        consolidation_suggestion_count: i32,
    ) -> Result<GovRoleMiningJob> {
        let job = GovRoleMiningJob::complete(
            &self.pool,
            tenant_id,
            job_id,
            candidate_count,
            excessive_privilege_count,
            consolidation_suggestion_count,
        )
        .await?
        .ok_or(GovernanceError::MiningJobNotRunning(job_id))?;

        tracing::info!(
            job_id = %job.id,
            tenant_id = %tenant_id,
            candidates = candidate_count,
            excessive = excessive_privilege_count,
            consolidation = consolidation_suggestion_count,
            "Completed mining job"
        );

        Ok(job)
    }

    /// Fail a job with an error message.
    pub async fn fail_job(
        &self,
        tenant_id: Uuid,
        job_id: Uuid,
        error_message: &str,
    ) -> Result<GovRoleMiningJob> {
        let job = GovRoleMiningJob::fail(&self.pool, tenant_id, job_id, error_message)
            .await?
            .ok_or(GovernanceError::MiningJobNotRunning(job_id))?;

        tracing::warn!(
            job_id = %job.id,
            tenant_id = %tenant_id,
            error = error_message,
            "Mining job failed"
        );

        Ok(job)
    }

    /// Delete a job (only pending or cancelled jobs can be deleted).
    pub async fn delete(&self, tenant_id: Uuid, job_id: Uuid) -> Result<()> {
        let deleted = GovRoleMiningJob::delete(&self.pool, tenant_id, job_id).await?;

        if !deleted {
            return Err(GovernanceError::MiningJobNotFound(job_id));
        }

        tracing::info!(
            job_id = %job_id,
            tenant_id = %tenant_id,
            "Deleted mining job"
        );

        Ok(())
    }

    // =========================================================================
    // Role Candidate Methods
    // =========================================================================

    /// List role candidates from a mining job.
    pub async fn list_candidates(
        &self,
        tenant_id: Uuid,
        job_id: Uuid,
        status: Option<CandidatePromotionStatus>,
        min_confidence: Option<f64>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<GovRoleCandidate>, i64)> {
        // Verify job exists
        let _ = self.get(tenant_id, job_id).await?;

        let filter = RoleCandidateFilter {
            job_id: Some(job_id),
            promotion_status: status,
            min_confidence,
            min_members: None,
        };

        let candidates =
            GovRoleCandidate::list_by_job(&self.pool, tenant_id, job_id, &filter, limit, offset)
                .await?;
        let total = GovRoleCandidate::count_by_job(&self.pool, tenant_id, job_id, &filter).await?;

        Ok((candidates, total))
    }

    /// Get a role candidate by ID.
    pub async fn get_candidate(
        &self,
        tenant_id: Uuid,
        candidate_id: Uuid,
    ) -> Result<GovRoleCandidate> {
        GovRoleCandidate::find_by_id(&self.pool, tenant_id, candidate_id)
            .await?
            .ok_or(GovernanceError::RoleCandidateNotFound(candidate_id))
    }

    /// Promote a role candidate to an actual role.
    ///
    /// This function creates a group for the role and assigns all entitlements
    /// within a single transaction to ensure data consistency.
    pub async fn promote_candidate(
        &self,
        tenant_id: Uuid,
        candidate_id: Uuid,
        role_name: String,
        description: Option<String>,
        reviewed_by: Uuid,
    ) -> Result<GovRoleCandidate> {
        let candidate = self.get_candidate(tenant_id, candidate_id).await?;

        if !matches!(
            candidate.promotion_status,
            CandidatePromotionStatus::Pending
        ) {
            return Err(GovernanceError::RoleCandidateNotPending(candidate_id));
        }

        // Start a transaction for atomic promotion
        let mut tx = self.pool.begin().await?;

        // Create a group for the promoted role (or get existing)
        let promoted_role_id = self
            .create_role_group_tx(&mut tx, tenant_id, &role_name, description.as_deref())
            .await?;

        // Assign the candidate's entitlements to the new role
        let entitlement_ids = &candidate.entitlement_ids;
        for ent_id in entitlement_ids {
            self.assign_entitlement_to_role_tx(
                &mut tx,
                tenant_id,
                promoted_role_id,
                *ent_id,
                reviewed_by,
            )
            .await?;
        }

        // Update candidate status to promoted
        let candidate = sqlx::query_as(
            r#"
            UPDATE gov_role_candidates
            SET promotion_status = 'promoted', promoted_role_id = $3, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND promotion_status = 'pending'
            RETURNING *
            "#,
        )
        .bind(candidate_id)
        .bind(tenant_id)
        .bind(promoted_role_id)
        .fetch_optional(tx.as_mut())
        .await?
        .ok_or(GovernanceError::RoleCandidateNotPending(candidate_id))?;

        // Commit the transaction
        tx.commit().await?;

        tracing::info!(
            candidate_id = %candidate_id,
            role_name = %role_name,
            promoted_role_id = %promoted_role_id,
            entitlements_assigned = entitlement_ids.len(),
            "Promoted role candidate"
        );

        Ok(candidate)
    }

    /// Create a group for a promoted role within a transaction.
    async fn create_role_group_tx<'a>(
        &self,
        tx: &mut sqlx::Transaction<'a, sqlx::Postgres>,
        tenant_id: Uuid,
        name: &str,
        description: Option<&str>,
    ) -> Result<Uuid> {
        // Check if a group with this name already exists
        let existing: Option<Uuid> =
            sqlx::query_scalar(r#"SELECT id FROM groups WHERE tenant_id = $1 AND name = $2"#)
                .bind(tenant_id)
                .bind(name)
                .fetch_optional(tx.as_mut())
                .await?;

        if let Some(group_id) = existing {
            return Ok(group_id);
        }

        let desc = description.unwrap_or("Role created from mining candidate");

        // Create a new group
        let group_id: Uuid = sqlx::query_scalar(
            r#"
            INSERT INTO groups (tenant_id, name, description, created_at, updated_at)
            VALUES ($1, $2, $3, NOW(), NOW())
            RETURNING id
            "#,
        )
        .bind(tenant_id)
        .bind(name)
        .bind(desc)
        .fetch_one(tx.as_mut())
        .await?;

        Ok(group_id)
    }

    /// Assign an entitlement to a role (group) within a transaction.
    async fn assign_entitlement_to_role_tx<'a>(
        &self,
        tx: &mut sqlx::Transaction<'a, sqlx::Postgres>,
        tenant_id: Uuid,
        role_id: Uuid,
        entitlement_id: Uuid,
        assigned_by: Uuid,
    ) -> Result<()> {
        // Check if assignment already exists
        let existing: Option<Uuid> = sqlx::query_scalar(
            r#"
            SELECT id FROM gov_entitlement_assignments
            WHERE tenant_id = $1 AND entitlement_id = $2 AND target_type = 'group' AND target_id = $3
            "#,
        )
        .bind(tenant_id)
        .bind(entitlement_id)
        .bind(role_id)
        .fetch_optional(tx.as_mut())
        .await?;

        if existing.is_some() {
            return Ok(()); // Already assigned
        }

        // Create the assignment
        sqlx::query(
            r#"
            INSERT INTO gov_entitlement_assignments
            (tenant_id, entitlement_id, target_type, target_id, assigned_by, status, justification, created_at, updated_at)
            VALUES ($1, $2, 'group', $3, $4, 'active', 'Assigned from promoted role candidate', NOW(), NOW())
            "#,
        )
        .bind(tenant_id)
        .bind(entitlement_id)
        .bind(role_id)
        .bind(assigned_by)
        .execute(tx.as_mut())
        .await?;

        Ok(())
    }

    /// Dismiss a role candidate.
    pub async fn dismiss_candidate(
        &self,
        tenant_id: Uuid,
        candidate_id: Uuid,
        reason: Option<String>,
        _reviewed_by: Uuid,
    ) -> Result<GovRoleCandidate> {
        let candidate = self.get_candidate(tenant_id, candidate_id).await?;

        if !matches!(
            candidate.promotion_status,
            CandidatePromotionStatus::Pending
        ) {
            return Err(GovernanceError::RoleCandidateNotPending(candidate_id));
        }

        let reason_str = reason.as_deref().unwrap_or("");
        let candidate = GovRoleCandidate::dismiss(&self.pool, tenant_id, candidate_id, reason_str)
            .await?
            .ok_or(GovernanceError::RoleCandidateNotPending(candidate_id))?;

        tracing::info!(
            candidate_id = %candidate_id,
            "Dismissed role candidate"
        );

        Ok(candidate)
    }

    // =========================================================================
    // Access Pattern Methods
    // =========================================================================

    /// List access patterns from a mining job.
    pub async fn list_patterns(
        &self,
        tenant_id: Uuid,
        job_id: Uuid,
        min_frequency: Option<i32>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<GovAccessPattern>, i64)> {
        // Verify job exists
        let _ = self.get(tenant_id, job_id).await?;

        let filter = AccessPatternFilter {
            min_frequency,
            min_users: None,
        };

        let patterns =
            GovAccessPattern::list_by_job(&self.pool, tenant_id, job_id, &filter, limit, offset)
                .await?;
        let total = GovAccessPattern::count_by_job(&self.pool, tenant_id, job_id, &filter).await?;

        Ok((patterns, total))
    }

    /// Get an access pattern by ID.
    pub async fn get_pattern(&self, tenant_id: Uuid, pattern_id: Uuid) -> Result<GovAccessPattern> {
        GovAccessPattern::find_by_id(&self.pool, tenant_id, pattern_id)
            .await?
            .ok_or(GovernanceError::Validation(format!(
                "Access pattern {} not found",
                pattern_id
            )))
    }

    // =========================================================================
    // Excessive Privilege Methods
    // =========================================================================

    /// List excessive privilege flags from a mining job.
    pub async fn list_excessive_privileges(
        &self,
        tenant_id: Uuid,
        job_id: Uuid,
        status: Option<PrivilegeFlagStatus>,
        user_id: Option<Uuid>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<GovExcessivePrivilege>, i64)> {
        // Verify job exists
        let _ = self.get(tenant_id, job_id).await?;

        let filter = ExcessivePrivilegeFilter {
            job_id: Some(job_id),
            user_id,
            status,
            min_deviation: None,
        };

        let flags = GovExcessivePrivilege::list_by_job(
            &self.pool, tenant_id, job_id, &filter, limit, offset,
        )
        .await?;
        let total =
            GovExcessivePrivilege::count_by_job(&self.pool, tenant_id, job_id, &filter).await?;

        Ok((flags, total))
    }

    /// Get an excessive privilege flag by ID.
    pub async fn get_excessive_privilege(
        &self,
        tenant_id: Uuid,
        flag_id: Uuid,
    ) -> Result<GovExcessivePrivilege> {
        GovExcessivePrivilege::find_by_id(&self.pool, tenant_id, flag_id)
            .await?
            .ok_or(GovernanceError::ExcessivePrivilegeFlagNotFound(flag_id))
    }

    /// Review an excessive privilege flag.
    pub async fn review_excessive_privilege(
        &self,
        tenant_id: Uuid,
        flag_id: Uuid,
        action: &str,
        notes: Option<String>,
        reviewed_by: Uuid,
    ) -> Result<GovExcessivePrivilege> {
        let flag = self.get_excessive_privilege(tenant_id, flag_id).await?;

        if !matches!(flag.status, PrivilegeFlagStatus::Pending) {
            return Err(GovernanceError::ExcessivePrivilegeFlagAlreadyReviewed(
                flag_id,
            ));
        }

        let new_status = match action {
            "accept" => PrivilegeFlagStatus::Accepted,
            "remediate" => PrivilegeFlagStatus::Remediated,
            _ => PrivilegeFlagStatus::Reviewed,
        };

        let input = UpdateExcessivePrivilegeStatus {
            status: new_status,
            reviewed_by,
            notes,
        };

        let flag = GovExcessivePrivilege::update_status(&self.pool, tenant_id, flag_id, input)
            .await?
            .ok_or(GovernanceError::ExcessivePrivilegeFlagNotFound(flag_id))?;

        tracing::info!(
            flag_id = %flag_id,
            action = action,
            "Reviewed excessive privilege flag"
        );

        Ok(flag)
    }

    // =========================================================================
    // Consolidation Suggestion Methods
    // =========================================================================

    /// List consolidation suggestions from a mining job.
    pub async fn list_consolidation_suggestions(
        &self,
        tenant_id: Uuid,
        job_id: Uuid,
        status: Option<ConsolidationStatus>,
        min_overlap: Option<f64>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<GovConsolidationSuggestion>, i64)> {
        // Verify job exists
        let _ = self.get(tenant_id, job_id).await?;

        let filter = ConsolidationSuggestionFilter {
            job_id: Some(job_id),
            status,
            min_overlap,
            role_id: None,
        };

        let suggestions = GovConsolidationSuggestion::list_by_job(
            &self.pool, tenant_id, job_id, &filter, limit, offset,
        )
        .await?;
        let total =
            GovConsolidationSuggestion::count_by_job(&self.pool, tenant_id, job_id, &filter)
                .await?;

        Ok((suggestions, total))
    }

    /// Get a consolidation suggestion by ID.
    pub async fn get_consolidation_suggestion(
        &self,
        tenant_id: Uuid,
        suggestion_id: Uuid,
    ) -> Result<GovConsolidationSuggestion> {
        GovConsolidationSuggestion::find_by_id(&self.pool, tenant_id, suggestion_id)
            .await?
            .ok_or(GovernanceError::ConsolidationSuggestionNotFound(
                suggestion_id,
            ))
    }

    /// Dismiss a consolidation suggestion.
    pub async fn dismiss_consolidation_suggestion(
        &self,
        tenant_id: Uuid,
        suggestion_id: Uuid,
        reason: Option<String>,
        _reviewed_by: Uuid,
    ) -> Result<GovConsolidationSuggestion> {
        let suggestion = self
            .get_consolidation_suggestion(tenant_id, suggestion_id)
            .await?;

        if !matches!(suggestion.status, ConsolidationStatus::Pending) {
            return Err(GovernanceError::ConsolidationSuggestionAlreadyProcessed(
                suggestion_id,
            ));
        }

        let reason_str = reason.as_deref().unwrap_or("");
        let suggestion =
            GovConsolidationSuggestion::dismiss(&self.pool, tenant_id, suggestion_id, reason_str)
                .await?
                .ok_or(GovernanceError::ConsolidationSuggestionNotFound(
                    suggestion_id,
                ))?;

        tracing::info!(
            suggestion_id = %suggestion_id,
            "Dismissed consolidation suggestion"
        );

        Ok(suggestion)
    }
}

/// Validate mining job parameters.
fn validate_parameters(params: &MiningJobParameters) -> Result<()> {
    if params.min_users < 1 {
        return Err(GovernanceError::InvalidMiningParameters(
            "min_users must be at least 1".to_string(),
        ));
    }

    if params.min_entitlements < 1 {
        return Err(GovernanceError::InvalidMiningParameters(
            "min_entitlements must be at least 1".to_string(),
        ));
    }

    if !(0.0..=1.0).contains(&params.confidence_threshold) {
        return Err(GovernanceError::InvalidMiningParameters(
            "confidence_threshold must be between 0.0 and 1.0".to_string(),
        ));
    }

    if !(0.0..=100.0).contains(&params.consolidation_threshold) {
        return Err(GovernanceError::InvalidMiningParameters(
            "consolidation_threshold must be between 0.0 and 100.0".to_string(),
        ));
    }

    if !(0.0..=100.0).contains(&params.deviation_threshold) {
        return Err(GovernanceError::InvalidMiningParameters(
            "deviation_threshold must be between 0.0 and 100.0".to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper to create valid parameters for tests
    fn valid_params() -> MiningJobParameters {
        MiningJobParameters {
            min_users: 3,
            min_entitlements: 2,
            confidence_threshold: 0.6,
            include_excessive_privilege: true,
            include_consolidation: true,
            consolidation_threshold: 70.0,
            deviation_threshold: 50.0,
            peer_group_attribute: None,
        }
    }

    // =========================================================================
    // T022: Unit tests for MiningService.create_job
    // =========================================================================

    #[test]
    fn test_validate_parameters_valid() {
        let params = valid_params();
        assert!(validate_parameters(&params).is_ok());
    }

    #[test]
    fn test_validate_parameters_invalid_min_users() {
        let params = MiningJobParameters {
            min_users: 0,
            ..valid_params()
        };
        assert!(validate_parameters(&params).is_err());
    }

    #[test]
    fn test_validate_parameters_invalid_min_entitlements() {
        let params = MiningJobParameters {
            min_entitlements: 0,
            ..valid_params()
        };
        let result = validate_parameters(&params);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::InvalidMiningParameters(_)
        ));
    }

    #[test]
    fn test_validate_parameters_invalid_confidence() {
        let params = MiningJobParameters {
            confidence_threshold: 1.5,
            ..valid_params()
        };
        assert!(validate_parameters(&params).is_err());

        let params = MiningJobParameters {
            confidence_threshold: -0.1,
            ..valid_params()
        };
        assert!(validate_parameters(&params).is_err());
    }

    #[test]
    fn test_validate_parameters_invalid_consolidation_threshold() {
        let params = MiningJobParameters {
            consolidation_threshold: 150.0,
            ..valid_params()
        };
        assert!(validate_parameters(&params).is_err());

        let params = MiningJobParameters {
            consolidation_threshold: -10.0,
            ..valid_params()
        };
        assert!(validate_parameters(&params).is_err());
    }

    #[test]
    fn test_validate_parameters_invalid_deviation_threshold() {
        let params = MiningJobParameters {
            deviation_threshold: 200.0,
            ..valid_params()
        };
        assert!(validate_parameters(&params).is_err());

        let params = MiningJobParameters {
            deviation_threshold: -5.0,
            ..valid_params()
        };
        assert!(validate_parameters(&params).is_err());
    }

    #[test]
    fn test_validate_parameters_boundary_values() {
        // Test boundary values that should be valid
        let params = MiningJobParameters {
            min_users: 1,
            min_entitlements: 1,
            confidence_threshold: 0.0,
            consolidation_threshold: 0.0,
            deviation_threshold: 0.0,
            ..valid_params()
        };
        assert!(validate_parameters(&params).is_ok());

        let params = MiningJobParameters {
            min_users: 1,
            min_entitlements: 1,
            confidence_threshold: 1.0,
            consolidation_threshold: 100.0,
            deviation_threshold: 100.0,
            ..valid_params()
        };
        assert!(validate_parameters(&params).is_ok());
    }

    // =========================================================================
    // T023: Unit tests for MiningService.run_job
    // =========================================================================

    #[test]
    fn test_job_status_can_start_from_pending() {
        assert!(MiningJobStatus::Pending.can_start());
    }

    #[test]
    fn test_job_status_cannot_start_from_running() {
        assert!(!MiningJobStatus::Running.can_start());
    }

    #[test]
    fn test_job_status_cannot_start_from_completed() {
        assert!(!MiningJobStatus::Completed.can_start());
    }

    #[test]
    fn test_job_status_cannot_start_from_failed() {
        assert!(!MiningJobStatus::Failed.can_start());
    }

    #[test]
    fn test_job_status_cannot_start_from_cancelled() {
        assert!(!MiningJobStatus::Cancelled.can_start());
    }

    #[test]
    fn test_job_status_can_cancel_from_running() {
        assert!(MiningJobStatus::Running.can_cancel());
    }

    #[test]
    fn test_job_status_cannot_cancel_from_pending() {
        // Pending jobs should be deleted, not cancelled
        assert!(!MiningJobStatus::Pending.can_cancel());
    }

    #[test]
    fn test_job_status_cannot_cancel_from_completed() {
        assert!(!MiningJobStatus::Completed.can_cancel());
    }

    #[test]
    fn test_job_status_is_terminal() {
        assert!(MiningJobStatus::Completed.is_terminal());
        assert!(MiningJobStatus::Failed.is_terminal());
        assert!(MiningJobStatus::Cancelled.is_terminal());
        assert!(!MiningJobStatus::Pending.is_terminal());
        assert!(!MiningJobStatus::Running.is_terminal());
    }
}
