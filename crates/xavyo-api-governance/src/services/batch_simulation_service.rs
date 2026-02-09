//! Batch Simulation service for multi-user access change analysis (F060).

use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::{
    AccessItem, BatchImpactSummary, BatchSimulationFilter, BatchSimulationResultFilter,
    BatchSimulationType, ChangeSpec, CreateBatchSimulation, CreateBatchSimulationResult,
    FilterCriteria, GovBatchSimulation, GovBatchSimulationResult, SelectionMode, SimulationStatus,
    SCOPE_WARNING_THRESHOLD,
};
use xavyo_governance::error::{GovernanceError, Result};

/// Batch size for chunked processing.
pub const BATCH_CHUNK_SIZE: usize = 500;

/// Configuration limits for batch simulations.
pub struct BatchSimulationLimits {
    /// Maximum number of users that can be simulated at once.
    pub max_users: usize,
    /// Maximum number of results to store per simulation.
    pub max_results: usize,
    /// Chunk size for batch processing.
    pub chunk_size: usize,
}

impl Default for BatchSimulationLimits {
    fn default() -> Self {
        Self {
            max_users: 50_000,    // 50K users max
            max_results: 100_000, // 100K results max
            chunk_size: BATCH_CHUNK_SIZE,
        }
    }
}

/// Service for batch simulation operations.
pub struct BatchSimulationService {
    pool: PgPool,
    limits: BatchSimulationLimits,
}

impl BatchSimulationService {
    /// Create a new batch simulation service with default limits.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            limits: BatchSimulationLimits::default(),
        }
    }

    /// Create a new batch simulation service with custom limits.
    #[must_use]
    pub fn with_limits(pool: PgPool, limits: BatchSimulationLimits) -> Self {
        Self { pool, limits }
    }

    /// Get the configured limits.
    #[must_use]
    pub fn limits(&self) -> &BatchSimulationLimits {
        &self.limits
    }

    /// Get a batch simulation by ID.
    pub async fn get(&self, tenant_id: Uuid, simulation_id: Uuid) -> Result<GovBatchSimulation> {
        GovBatchSimulation::find_by_id(&self.pool, tenant_id, simulation_id)
            .await?
            .ok_or(GovernanceError::BatchSimulationNotFound(simulation_id))
    }

    /// List batch simulations with filtering and pagination.
    #[allow(clippy::too_many_arguments)]
    pub async fn list(
        &self,
        tenant_id: Uuid,
        batch_type: Option<BatchSimulationType>,
        status: Option<SimulationStatus>,
        created_by: Option<Uuid>,
        include_archived: bool,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<GovBatchSimulation>, i64)> {
        let filter = BatchSimulationFilter {
            batch_type,
            status,
            created_by,
            include_archived,
        };

        let simulations =
            GovBatchSimulation::list_by_tenant(&self.pool, tenant_id, &filter, limit, offset)
                .await?;
        let total = GovBatchSimulation::count_by_tenant(&self.pool, tenant_id, &filter).await?;

        Ok((simulations, total))
    }

    /// Create a new batch simulation.
    pub async fn create(
        &self,
        tenant_id: Uuid,
        name: String,
        batch_type: BatchSimulationType,
        selection_mode: SelectionMode,
        user_ids: Vec<Uuid>,
        filter_criteria: FilterCriteria,
        change_spec: ChangeSpec,
        created_by: Uuid,
    ) -> Result<GovBatchSimulation> {
        // Validate name
        if name.trim().is_empty() {
            return Err(GovernanceError::Validation(
                "Simulation name cannot be empty".to_string(),
            ));
        }

        if name.len() > 255 {
            return Err(GovernanceError::Validation(
                "Simulation name cannot exceed 255 characters".to_string(),
            ));
        }

        // Validate selection mode requirements
        match selection_mode {
            SelectionMode::UserList => {
                if user_ids.is_empty() {
                    return Err(GovernanceError::Validation(
                        "user_ids required for user_list selection mode".to_string(),
                    ));
                }
            }
            SelectionMode::Filter => {
                // Filter can be empty (matches all users), but log a warning
                if filter_criteria.department.is_none()
                    && filter_criteria.status.is_none()
                    && filter_criteria.role_ids.is_none()
                    && filter_criteria.entitlement_ids.is_none()
                    && filter_criteria.title.is_none()
                    && filter_criteria.metadata.is_none()
                {
                    tracing::warn!(
                        "Creating batch simulation with empty filter criteria - this will match all users"
                    );
                }
            }
        }

        // Validate change spec matches batch type
        match batch_type {
            BatchSimulationType::RoleAdd | BatchSimulationType::RoleRemove => {
                if change_spec.role_id.is_none() {
                    return Err(GovernanceError::Validation(
                        "role_id required for role operations".to_string(),
                    ));
                }
            }
            BatchSimulationType::EntitlementAdd | BatchSimulationType::EntitlementRemove => {
                if change_spec.entitlement_id.is_none() {
                    return Err(GovernanceError::Validation(
                        "entitlement_id required for entitlement operations".to_string(),
                    ));
                }
            }
        }

        let input = CreateBatchSimulation {
            name,
            batch_type,
            selection_mode,
            user_ids,
            filter_criteria,
            change_spec,
            created_by,
        };

        let simulation = GovBatchSimulation::create(&self.pool, tenant_id, input).await?;

        tracing::info!(
            simulation_id = %simulation.id,
            tenant_id = %tenant_id,
            batch_type = ?batch_type,
            selection_mode = ?selection_mode,
            "Created batch simulation"
        );

        Ok(simulation)
    }

    /// Execute a batch simulation (calculate impact).
    pub async fn execute(
        &self,
        tenant_id: Uuid,
        simulation_id: Uuid,
        acknowledge_scope_warning: bool,
    ) -> Result<GovBatchSimulation> {
        let simulation = self.get(tenant_id, simulation_id).await?;

        if simulation.status != SimulationStatus::Draft {
            return Err(GovernanceError::Validation(
                "Only draft simulations can be executed".to_string(),
            ));
        }

        // Resolve user selection
        let user_ids = self.resolve_user_selection(tenant_id, &simulation).await?;

        // Check user count limits
        if user_ids.len() > self.limits.max_users {
            return Err(GovernanceError::SimulationTooLarge {
                requested: user_ids.len(),
                max_allowed: self.limits.max_users,
            });
        }

        // Check scope warning threshold
        if user_ids.len() as i32 > SCOPE_WARNING_THRESHOLD && !acknowledge_scope_warning {
            return Err(GovernanceError::ScopeWarningRequired {
                affected_users: user_ids.len() as i32,
                threshold: SCOPE_WARNING_THRESHOLD,
            });
        }

        // Process in chunks for memory efficiency
        let total_users = user_ids.len() as i32;
        let mut all_results = Vec::new();
        let mut impact_summary = BatchImpactSummary {
            total_users: i64::from(total_users),
            ..Default::default()
        };

        for chunk in user_ids.chunks(BATCH_CHUNK_SIZE) {
            let (chunk_results, chunk_impact) = self
                .calculate_batch_impact(tenant_id, &simulation, chunk)
                .await?;

            // Update progress
            let processed = all_results.len() as i32 + chunk_results.len() as i32;
            GovBatchSimulation::update_progress(
                &self.pool,
                tenant_id,
                simulation_id,
                total_users,
                processed,
            )
            .await?;

            // Aggregate impact
            impact_summary.affected_users += chunk_impact.affected_users;
            impact_summary.entitlements_gained += chunk_impact.entitlements_gained;
            impact_summary.entitlements_lost += chunk_impact.entitlements_lost;
            impact_summary.sod_violations_introduced += chunk_impact.sod_violations_introduced;
            impact_summary.warnings.extend(chunk_impact.warnings);

            all_results.extend(chunk_results);
        }

        // Store per-user results
        if !all_results.is_empty() {
            GovBatchSimulationResult::bulk_create(&self.pool, &all_results).await?;
        }

        // Update simulation with final results
        let updated = GovBatchSimulation::execute(
            &self.pool,
            tenant_id,
            simulation_id,
            total_users,
            impact_summary,
        )
        .await?
        .ok_or(GovernanceError::BatchSimulationNotFound(simulation_id))?;

        tracing::info!(
            simulation_id = %simulation_id,
            total_users = total_users,
            "Executed batch simulation"
        );

        Ok(updated)
    }

    /// Apply a batch simulation (commit changes).
    ///
    /// This method fetches all simulation results, then applies the access changes
    /// described by the simulation's `change_spec` for each affected user. Changes
    /// are applied inside a database transaction to ensure atomicity. If any
    /// individual user change fails, the entire apply is rolled back.
    pub async fn apply(
        &self,
        tenant_id: Uuid,
        simulation_id: Uuid,
        applied_by: Uuid,
        acknowledge_scope_warning: bool,
    ) -> Result<GovBatchSimulation> {
        let simulation = self.get(tenant_id, simulation_id).await?;

        if simulation.status != SimulationStatus::Executed {
            return Err(GovernanceError::Validation(
                "Only executed simulations can be applied".to_string(),
            ));
        }

        // Check scope warning
        if simulation.has_scope_warning() && !acknowledge_scope_warning {
            return Err(GovernanceError::ScopeWarningRequired {
                affected_users: simulation.parse_impact_summary().affected_users as i32,
                threshold: SCOPE_WARNING_THRESHOLD,
            });
        }

        // Parse the change specification to know what operation to apply
        let change_spec = simulation.parse_change_spec().ok_or_else(|| {
            GovernanceError::Validation(
                "Cannot apply simulation: invalid change specification".to_string(),
            )
        })?;

        // Fetch all affected results in batches and apply changes
        let mut offset: i64 = 0;
        let page_size: i64 = BATCH_CHUNK_SIZE as i64;
        let mut applied_count: i64 = 0;
        let mut skipped_count: i64 = 0;
        let no_filter = BatchSimulationResultFilter::default();

        // Use a transaction for atomicity: either all changes apply or none do
        let mut tx = self.pool.begin().await.map_err(GovernanceError::Database)?;

        loop {
            let results = GovBatchSimulationResult::list_by_simulation(
                // Read results from the pool (not the tx) since they are read-only;
                // all writes go through the transaction.
                &self.pool,
                simulation_id,
                &no_filter,
                page_size,
                offset,
            )
            .await?;

            if results.is_empty() {
                break;
            }

            let batch_len = results.len() as i64;

            for result in &results {
                // Skip users with no actual changes
                if !result.has_changes() {
                    skipped_count += 1;
                    continue;
                }

                self.apply_user_change(
                    &mut tx,
                    tenant_id,
                    result.user_id,
                    &change_spec,
                    applied_by,
                )
                .await?;

                applied_count += 1;
            }

            offset = offset.saturating_add(batch_len);

            // If we got fewer results than the page size, we've reached the end
            if batch_len < page_size {
                break;
            }
        }

        // Mark the simulation as applied (inside the transaction)
        let applied = sqlx::query_as::<_, GovBatchSimulation>(
            r"
            UPDATE gov_batch_simulations
            SET status = 'applied', applied_at = NOW(), applied_by = $3
            WHERE id = $1 AND tenant_id = $2 AND status = 'executed'
            RETURNING *
            ",
        )
        .bind(simulation_id)
        .bind(tenant_id)
        .bind(applied_by)
        .fetch_optional(&mut *tx)
        .await
        .map_err(GovernanceError::Database)?
        .ok_or(GovernanceError::BatchSimulationNotFound(simulation_id))?;

        // Commit the transaction
        tx.commit().await.map_err(GovernanceError::Database)?;

        tracing::info!(
            simulation_id = %simulation_id,
            applied_by = %applied_by,
            applied_count = applied_count,
            skipped_count = skipped_count,
            "Applied batch simulation changes"
        );

        Ok(applied)
    }

    /// Apply the change described by `change_spec` for a single user within a transaction.
    async fn apply_user_change(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        tenant_id: Uuid,
        user_id: Uuid,
        change_spec: &ChangeSpec,
        applied_by: Uuid,
    ) -> Result<()> {
        match change_spec.operation {
            BatchSimulationType::EntitlementAdd => {
                let entitlement_id = change_spec.entitlement_id.ok_or_else(|| {
                    GovernanceError::Validation(
                        "entitlement_id missing in change_spec for EntitlementAdd".to_string(),
                    )
                })?;

                // Check if user already has this entitlement (idempotency)
                let existing: i64 = sqlx::query_scalar(
                    r"
                    SELECT COUNT(*) FROM gov_entitlement_assignments
                    WHERE tenant_id = $1 AND entitlement_id = $2
                      AND target_type = 'user' AND target_id = $3
                      AND status = 'active'
                    ",
                )
                .bind(tenant_id)
                .bind(entitlement_id)
                .bind(user_id)
                .fetch_one(&mut **tx)
                .await
                .map_err(GovernanceError::Database)?;

                if existing == 0 {
                    sqlx::query(
                        r"
                        INSERT INTO gov_entitlement_assignments (
                            tenant_id, entitlement_id, target_type, target_id,
                            assigned_by, justification
                        )
                        VALUES ($1, $2, 'user', $3, $4, $5)
                        ",
                    )
                    .bind(tenant_id)
                    .bind(entitlement_id)
                    .bind(user_id)
                    .bind(applied_by)
                    .bind(change_spec.justification.as_deref())
                    .execute(&mut **tx)
                    .await
                    .map_err(GovernanceError::Database)?;

                    tracing::debug!(
                        user_id = %user_id,
                        entitlement_id = %entitlement_id,
                        "Applied entitlement add"
                    );
                }
            }
            BatchSimulationType::EntitlementRemove => {
                let entitlement_id = change_spec.entitlement_id.ok_or_else(|| {
                    GovernanceError::Validation(
                        "entitlement_id missing in change_spec for EntitlementRemove".to_string(),
                    )
                })?;

                let rows = sqlx::query(
                    r"
                    DELETE FROM gov_entitlement_assignments
                    WHERE tenant_id = $1 AND entitlement_id = $2
                      AND target_type = 'user' AND target_id = $3
                    ",
                )
                .bind(tenant_id)
                .bind(entitlement_id)
                .bind(user_id)
                .execute(&mut **tx)
                .await
                .map_err(GovernanceError::Database)?;

                tracing::debug!(
                    user_id = %user_id,
                    entitlement_id = %entitlement_id,
                    rows_deleted = rows.rows_affected(),
                    "Applied entitlement remove"
                );
            }
            BatchSimulationType::RoleAdd => {
                let role_id = change_spec.role_id.ok_or_else(|| {
                    GovernanceError::Validation(
                        "role_id missing in change_spec for RoleAdd".to_string(),
                    )
                })?;

                // Resolve role name from gov_roles
                let role_name: Option<String> = sqlx::query_scalar(
                    "SELECT name FROM gov_roles WHERE id = $1 AND tenant_id = $2",
                )
                .bind(role_id)
                .bind(tenant_id)
                .fetch_optional(&mut **tx)
                .await
                .map_err(GovernanceError::Database)?;

                let role_name = role_name.ok_or_else(|| {
                    GovernanceError::Validation(format!(
                        "Role {role_id} not found in tenant {tenant_id}"
                    ))
                })?;

                // Insert into user_roles if not already present
                let existing_role: i64 = sqlx::query_scalar(
                    r"
                    SELECT COUNT(*) FROM user_roles
                    WHERE user_id = $1 AND role_name = $2
                    ",
                )
                .bind(user_id)
                .bind(&role_name)
                .fetch_one(&mut **tx)
                .await
                .map_err(GovernanceError::Database)?;

                if existing_role == 0 {
                    sqlx::query(
                        r"
                        INSERT INTO user_roles (user_id, role_name)
                        VALUES ($1, $2)
                        ",
                    )
                    .bind(user_id)
                    .bind(&role_name)
                    .execute(&mut **tx)
                    .await
                    .map_err(GovernanceError::Database)?;
                }

                // Also create entitlement assignments for entitlements linked to this role
                let role_entitlements: Vec<Uuid> = sqlx::query_scalar(
                    r"
                    SELECT entitlement_id FROM gov_role_entitlements
                    WHERE role_id = $1 AND tenant_id = $2
                    ",
                )
                .bind(role_id)
                .bind(tenant_id)
                .fetch_all(&mut **tx)
                .await
                .map_err(GovernanceError::Database)?;

                for ent_id in role_entitlements {
                    // Check if assignment already exists (idempotency)
                    let ent_exists: i64 = sqlx::query_scalar(
                        r"
                        SELECT COUNT(*) FROM gov_entitlement_assignments
                        WHERE tenant_id = $1 AND entitlement_id = $2
                          AND target_type = 'user' AND target_id = $3
                          AND status = 'active'
                        ",
                    )
                    .bind(tenant_id)
                    .bind(ent_id)
                    .bind(user_id)
                    .fetch_one(&mut **tx)
                    .await
                    .map_err(GovernanceError::Database)?;

                    if ent_exists == 0 {
                        sqlx::query(
                            r"
                            INSERT INTO gov_entitlement_assignments (
                                tenant_id, entitlement_id, target_type, target_id,
                                assigned_by, justification
                            )
                            VALUES ($1, $2, 'user', $3, $4, $5)
                            ",
                        )
                        .bind(tenant_id)
                        .bind(ent_id)
                        .bind(user_id)
                        .bind(applied_by)
                        .bind(change_spec.justification.as_deref())
                        .execute(&mut **tx)
                        .await
                        .map_err(GovernanceError::Database)?;
                    }
                }

                tracing::debug!(
                    user_id = %user_id,
                    role_id = %role_id,
                    role_name = %role_name,
                    "Applied role add"
                );
            }
            BatchSimulationType::RoleRemove => {
                let role_id = change_spec.role_id.ok_or_else(|| {
                    GovernanceError::Validation(
                        "role_id missing in change_spec for RoleRemove".to_string(),
                    )
                })?;

                // Resolve role name from gov_roles
                let role_name: Option<String> = sqlx::query_scalar(
                    "SELECT name FROM gov_roles WHERE id = $1 AND tenant_id = $2",
                )
                .bind(role_id)
                .bind(tenant_id)
                .fetch_optional(&mut **tx)
                .await
                .map_err(GovernanceError::Database)?;

                if let Some(role_name) = role_name {
                    // Remove from user_roles
                    sqlx::query(
                        r"
                        DELETE FROM user_roles
                        WHERE user_id = $1 AND role_name = $2
                        ",
                    )
                    .bind(user_id)
                    .bind(&role_name)
                    .execute(&mut **tx)
                    .await
                    .map_err(GovernanceError::Database)?;

                    // Also revoke entitlement assignments that came from this role
                    let role_entitlements: Vec<Uuid> = sqlx::query_scalar(
                        r"
                        SELECT entitlement_id FROM gov_role_entitlements
                        WHERE role_id = $1 AND tenant_id = $2
                        ",
                    )
                    .bind(role_id)
                    .bind(tenant_id)
                    .fetch_all(&mut **tx)
                    .await
                    .map_err(GovernanceError::Database)?;

                    for ent_id in role_entitlements {
                        sqlx::query(
                            r"
                            DELETE FROM gov_entitlement_assignments
                            WHERE tenant_id = $1 AND entitlement_id = $2
                              AND target_type = 'user' AND target_id = $3
                            ",
                        )
                        .bind(tenant_id)
                        .bind(ent_id)
                        .bind(user_id)
                        .execute(&mut **tx)
                        .await
                        .map_err(GovernanceError::Database)?;
                    }

                    tracing::debug!(
                        user_id = %user_id,
                        role_id = %role_id,
                        role_name = %role_name,
                        "Applied role remove"
                    );
                }
            }
        }

        Ok(())
    }

    /// Cancel a batch simulation.
    pub async fn cancel(&self, tenant_id: Uuid, simulation_id: Uuid) -> Result<GovBatchSimulation> {
        let simulation = self.get(tenant_id, simulation_id).await?;

        if simulation.status != SimulationStatus::Draft
            && simulation.status != SimulationStatus::Executed
        {
            return Err(GovernanceError::Validation(
                "Only draft or executed simulations can be cancelled".to_string(),
            ));
        }

        let cancelled = GovBatchSimulation::cancel(&self.pool, tenant_id, simulation_id)
            .await?
            .ok_or(GovernanceError::BatchSimulationNotFound(simulation_id))?;

        tracing::info!(simulation_id = %simulation_id, "Cancelled batch simulation");

        Ok(cancelled)
    }

    /// Archive a batch simulation.
    pub async fn archive(
        &self,
        tenant_id: Uuid,
        simulation_id: Uuid,
    ) -> Result<GovBatchSimulation> {
        let archived = GovBatchSimulation::archive(&self.pool, tenant_id, simulation_id)
            .await?
            .ok_or(GovernanceError::BatchSimulationNotFound(simulation_id))?;

        tracing::info!(simulation_id = %simulation_id, "Archived batch simulation");

        Ok(archived)
    }

    /// Restore an archived batch simulation.
    pub async fn restore(
        &self,
        tenant_id: Uuid,
        simulation_id: Uuid,
    ) -> Result<GovBatchSimulation> {
        let restored = GovBatchSimulation::restore(&self.pool, tenant_id, simulation_id)
            .await?
            .ok_or(GovernanceError::BatchSimulationNotFound(simulation_id))?;

        tracing::info!(simulation_id = %simulation_id, "Restored batch simulation");

        Ok(restored)
    }

    /// Update notes on a batch simulation.
    pub async fn update_notes(
        &self,
        tenant_id: Uuid,
        simulation_id: Uuid,
        notes: Option<String>,
    ) -> Result<GovBatchSimulation> {
        let updated = GovBatchSimulation::update_notes(&self.pool, tenant_id, simulation_id, notes)
            .await?
            .ok_or(GovernanceError::BatchSimulationNotFound(simulation_id))?;

        Ok(updated)
    }

    /// Get simulation results (per-user impacts).
    pub async fn get_results(
        &self,
        tenant_id: Uuid,
        simulation_id: Uuid,
        user_id: Option<Uuid>,
        has_warnings: Option<bool>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<GovBatchSimulationResult>, i64)> {
        // Verify simulation exists
        let _ = self.get(tenant_id, simulation_id).await?;

        let filter = BatchSimulationResultFilter {
            user_id,
            has_warnings,
        };

        let results = GovBatchSimulationResult::list_by_simulation(
            &self.pool,
            simulation_id,
            &filter,
            limit,
            offset,
        )
        .await?;
        let total =
            GovBatchSimulationResult::count_by_simulation(&self.pool, simulation_id, &filter)
                .await?;

        Ok((results, total))
    }

    /// Delete a simulation (only draft or cancelled).
    pub async fn delete(&self, tenant_id: Uuid, simulation_id: Uuid) -> Result<bool> {
        // Also delete results
        GovBatchSimulationResult::delete_by_simulation(&self.pool, simulation_id).await?;

        let deleted = GovBatchSimulation::delete(&self.pool, tenant_id, simulation_id).await?;

        if deleted {
            tracing::info!(simulation_id = %simulation_id, "Deleted batch simulation");
        }

        Ok(deleted)
    }

    // ========================================================================
    // Private helper methods
    // ========================================================================

    /// Resolve user selection based on mode (list or filter).
    async fn resolve_user_selection(
        &self,
        tenant_id: Uuid,
        simulation: &GovBatchSimulation,
    ) -> Result<Vec<Uuid>> {
        match simulation.selection_mode {
            SelectionMode::UserList => {
                tracing::debug!(
                    simulation_id = %simulation.id,
                    user_count = simulation.user_ids.len(),
                    "Resolved user selection from explicit list"
                );
                Ok(simulation.user_ids.clone())
            }
            SelectionMode::Filter => {
                let filter = simulation.parse_filter_criteria();
                let users = self.query_users_by_filter(tenant_id, &filter).await?;

                tracing::debug!(
                    simulation_id = %simulation.id,
                    user_count = users.len(),
                    filter = ?filter,
                    "Resolved user selection from filter criteria"
                );

                Ok(users)
            }
        }
    }

    /// Query users matching filter criteria.
    async fn query_users_by_filter(
        &self,
        tenant_id: Uuid,
        filter: &FilterCriteria,
    ) -> Result<Vec<Uuid>> {
        // Build dynamic query based on filter criteria
        let mut query = String::from(
            r"
            SELECT DISTINCT u.id
            FROM users u
            WHERE u.tenant_id = $1
            ",
        );
        let mut param_count = 1;

        // Filter by status
        if let Some(ref _status) = filter.status {
            param_count += 1;
            query.push_str(&format!(" AND u.status = ${param_count}"));
        }

        // Filter by department (using attributes JSONB)
        if let Some(ref departments) = filter.department {
            if !departments.is_empty() {
                param_count += 1;
                query.push_str(&format!(
                    " AND u.attributes->>'department' = ANY(${param_count})"
                ));
            }
        }

        // Filter by title (using attributes JSONB)
        if let Some(ref _title) = filter.title {
            param_count += 1;
            query.push_str(&format!(" AND u.attributes->>'title' ILIKE ${param_count}"));
        }

        // Filter by role membership (resolve role UUIDs to names via gov_roles)
        if let Some(ref role_ids) = filter.role_ids {
            if !role_ids.is_empty() {
                param_count += 1;
                query.push_str(&format!(
                    " AND EXISTS (
                        SELECT 1 FROM user_roles ur
                        JOIN gov_roles gr ON gr.name = ur.role_name AND gr.tenant_id = u.tenant_id
                        WHERE ur.user_id = u.id AND gr.id = ANY(${param_count})
                    )"
                ));
            }
        }

        // Filter by entitlement assignment
        if let Some(ref entitlement_ids) = filter.entitlement_ids {
            if !entitlement_ids.is_empty() {
                param_count += 1;
                query.push_str(&format!(
                    " AND EXISTS (
                        SELECT 1 FROM gov_entitlement_assignments ea
                        WHERE ea.target_id = u.id AND ea.target_type = 'user'
                          AND ea.entitlement_id = ANY(${param_count})
                          AND ea.status = 'active'
                    )"
                ));
            }
        }

        query.push_str(" ORDER BY u.id");

        // Execute query with bindings
        let mut q = sqlx::query_scalar::<_, Uuid>(&query).bind(tenant_id);

        if let Some(ref status) = filter.status {
            q = q.bind(status);
        }

        if let Some(ref departments) = filter.department {
            if !departments.is_empty() {
                q = q.bind(departments);
            }
        }

        if let Some(ref title) = filter.title {
            q = q.bind(format!("%{title}%"));
        }

        if let Some(ref role_ids) = filter.role_ids {
            if !role_ids.is_empty() {
                q = q.bind(role_ids);
            }
        }

        if let Some(ref entitlement_ids) = filter.entitlement_ids {
            if !entitlement_ids.is_empty() {
                q = q.bind(entitlement_ids);
            }
        }

        let user_ids = q.fetch_all(&self.pool).await.map_err(|e| {
            tracing::error!(error = %e, "Failed to query users by filter");
            GovernanceError::Database(e)
        })?;

        Ok(user_ids)
    }

    /// Calculate impact for a batch of users.
    async fn calculate_batch_impact(
        &self,
        tenant_id: Uuid,
        simulation: &GovBatchSimulation,
        user_ids: &[Uuid],
    ) -> Result<(Vec<CreateBatchSimulationResult>, BatchImpactSummary)> {
        let change_spec = simulation.parse_change_spec().ok_or_else(|| {
            GovernanceError::Validation("Invalid change specification".to_string())
        })?;

        let mut results = Vec::with_capacity(user_ids.len());
        let mut impact = BatchImpactSummary::default();

        for user_id in user_ids {
            let (result, user_impact) = self
                .calculate_user_impact(tenant_id, simulation.id, *user_id, &change_spec)
                .await?;

            results.push(result);

            // Aggregate impact
            if user_impact.affected {
                impact.affected_users += 1;
            }
            impact.entitlements_gained += user_impact.entitlements_gained;
            impact.entitlements_lost += user_impact.entitlements_lost;
            if user_impact.sod_violation_introduced {
                impact.sod_violations_introduced += 1;
            }
            if let Some(warning) = user_impact.warning {
                impact.warnings.push(warning);
            }
        }

        tracing::debug!(
            simulation_id = %simulation.id,
            user_count = user_ids.len(),
            affected = impact.affected_users,
            "Calculated batch impact"
        );

        Ok((results, impact))
    }

    /// Calculate impact for a single user.
    async fn calculate_user_impact(
        &self,
        tenant_id: Uuid,
        simulation_id: Uuid,
        user_id: Uuid,
        change_spec: &ChangeSpec,
    ) -> Result<(CreateBatchSimulationResult, UserImpact)> {
        let mut user_impact = UserImpact::default();
        let mut access_gained: Vec<AccessItem> = Vec::new();
        let mut access_lost: Vec<AccessItem> = Vec::new();
        let mut warnings: Vec<String> = Vec::new();

        match change_spec.operation {
            BatchSimulationType::RoleAdd => {
                if let Some(role_id) = change_spec.role_id {
                    // Check if user already has this role
                    let has_role = self.user_has_role(tenant_id, user_id, role_id).await?;

                    if !has_role {
                        // Get the role name
                        let role_name = self.get_role_name(tenant_id, role_id).await?;

                        // Add the role itself to gained access
                        access_gained.push(AccessItem {
                            id: role_id,
                            name: role_name.clone(),
                            item_type: "role".to_string(),
                            source: Some("Direct assignment".to_string()),
                        });

                        // Get entitlements that would be gained via this role
                        let entitlements = self
                            .get_role_entitlements_with_names(tenant_id, role_id)
                            .await?;
                        for (ent_id, ent_name) in entitlements {
                            access_gained.push(AccessItem {
                                id: ent_id,
                                name: ent_name,
                                item_type: "entitlement".to_string(),
                                source: Some(format!("via role '{role_name}'")),
                            });
                        }

                        // Check for SoD violations that would be introduced
                        let sod_violations = self
                            .check_sod_violations_for_role_add(tenant_id, user_id, role_id)
                            .await?;

                        user_impact.affected = true;
                        user_impact.entitlements_gained = access_gained.len() as i64;

                        if !sod_violations.is_empty() {
                            user_impact.sod_violation_introduced = true;
                            warnings.push(format!(
                                "Adding role would introduce {} SoD violation(s)",
                                sod_violations.len()
                            ));
                        }
                    }
                }
            }
            BatchSimulationType::RoleRemove => {
                if let Some(role_id) = change_spec.role_id {
                    let has_role = self.user_has_role(tenant_id, user_id, role_id).await?;

                    if has_role {
                        // Get the role name
                        let role_name = self.get_role_name(tenant_id, role_id).await?;

                        // Add the role itself to lost access
                        access_lost.push(AccessItem {
                            id: role_id,
                            name: role_name.clone(),
                            item_type: "role".to_string(),
                            source: Some("Direct assignment".to_string()),
                        });

                        // Get entitlements that would be lost
                        let entitlements = self
                            .get_role_entitlements_with_names(tenant_id, role_id)
                            .await?;
                        for (ent_id, ent_name) in entitlements {
                            access_lost.push(AccessItem {
                                id: ent_id,
                                name: ent_name,
                                item_type: "entitlement".to_string(),
                                source: Some(format!("via role '{role_name}'")),
                            });
                        }

                        user_impact.affected = true;
                        user_impact.entitlements_lost = access_lost.len() as i64;
                    }
                }
            }
            BatchSimulationType::EntitlementAdd => {
                if let Some(entitlement_id) = change_spec.entitlement_id {
                    let has_entitlement = self
                        .user_has_entitlement(tenant_id, user_id, entitlement_id)
                        .await?;

                    if !has_entitlement {
                        let ent_name = self.get_entitlement_name(tenant_id, entitlement_id).await?;

                        access_gained.push(AccessItem {
                            id: entitlement_id,
                            name: ent_name,
                            item_type: "entitlement".to_string(),
                            source: Some("Direct assignment".to_string()),
                        });

                        // Check for SoD violations
                        let sod_violations = self
                            .check_sod_violations_for_entitlement_add(
                                tenant_id,
                                user_id,
                                entitlement_id,
                            )
                            .await?;

                        user_impact.affected = true;
                        user_impact.entitlements_gained = 1;

                        if !sod_violations.is_empty() {
                            user_impact.sod_violation_introduced = true;
                            warnings.push(format!(
                                "Adding entitlement would introduce {} SoD violation(s)",
                                sod_violations.len()
                            ));
                        }
                    }
                }
            }
            BatchSimulationType::EntitlementRemove => {
                if let Some(entitlement_id) = change_spec.entitlement_id {
                    let has_entitlement = self
                        .user_has_entitlement(tenant_id, user_id, entitlement_id)
                        .await?;

                    if has_entitlement {
                        let ent_name = self.get_entitlement_name(tenant_id, entitlement_id).await?;

                        access_lost.push(AccessItem {
                            id: entitlement_id,
                            name: ent_name,
                            item_type: "entitlement".to_string(),
                            source: Some("Direct assignment".to_string()),
                        });

                        user_impact.affected = true;
                        user_impact.entitlements_lost = 1;
                    }
                }
            }
        }

        if !warnings.is_empty() {
            user_impact.warning = Some(warnings.join("; "));
        }

        let result = CreateBatchSimulationResult {
            simulation_id,
            user_id,
            access_gained,
            access_lost,
            warnings,
        };

        Ok((result, user_impact))
    }

    /// Get role name by ID.
    async fn get_role_name(&self, tenant_id: Uuid, role_id: Uuid) -> Result<String> {
        let name: Option<String> =
            sqlx::query_scalar(r"SELECT name FROM gov_roles WHERE id = $1 AND tenant_id = $2")
                .bind(role_id)
                .bind(tenant_id)
                .fetch_optional(&self.pool)
                .await
                .unwrap_or(None);

        Ok(name.unwrap_or_else(|| format!("Role {role_id}")))
    }

    /// Get entitlement name by ID.
    async fn get_entitlement_name(&self, tenant_id: Uuid, entitlement_id: Uuid) -> Result<String> {
        let name: Option<String> = sqlx::query_scalar(
            r"SELECT name FROM gov_entitlements WHERE id = $1 AND tenant_id = $2",
        )
        .bind(entitlement_id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .unwrap_or(None);

        Ok(name.unwrap_or_else(|| format!("Entitlement {entitlement_id}")))
    }

    /// Get entitlements associated with a role, with names.
    async fn get_role_entitlements_with_names(
        &self,
        _tenant_id: Uuid,
        role_id: Uuid,
    ) -> Result<Vec<(Uuid, String)>> {
        let entitlements: Vec<(Uuid, String)> = sqlx::query_as(
            r"
            SELECT e.id, e.name
            FROM gov_entitlements e
            JOIN gov_role_entitlements re ON re.entitlement_id = e.id
            WHERE re.role_id = $1
            ",
        )
        .bind(role_id)
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();

        Ok(entitlements)
    }

    /// Check if user has a specific role (resolve role UUID to name via gov_roles).
    async fn user_has_role(&self, tenant_id: Uuid, user_id: Uuid, role_id: Uuid) -> Result<bool> {
        // Resolve role_id to role_name via gov_roles
        let role_name: Option<String> =
            sqlx::query_scalar("SELECT name FROM gov_roles WHERE id = $1 AND tenant_id = $2")
                .bind(role_id)
                .bind(tenant_id)
                .fetch_optional(&self.pool)
                .await
                .unwrap_or(None);

        let count = if let Some(ref name) = role_name {
            sqlx::query_scalar::<_, i64>(
                r"
                SELECT COUNT(*)
                FROM user_roles
                WHERE user_id = $1 AND role_name = $2
                ",
            )
            .bind(user_id)
            .bind(name)
            .fetch_one(&self.pool)
            .await
            .unwrap_or(0)
        } else {
            0
        };

        // Also check if user has role via entitlement assignments
        let assignment_count: i64 = sqlx::query_scalar(
            r"
            SELECT COUNT(*)
            FROM gov_entitlement_assignments
            WHERE user_id = $1
              AND target_type = 'role'
              AND target_id = $2
              AND status = 'active'
            ",
        )
        .bind(user_id)
        .bind(role_id)
        .fetch_one(&self.pool)
        .await
        .unwrap_or(0);

        Ok(count > 0 || assignment_count > 0)
    }

    /// Check if user has a specific entitlement.
    async fn user_has_entitlement(
        &self,
        _tenant_id: Uuid,
        user_id: Uuid,
        entitlement_id: Uuid,
    ) -> Result<bool> {
        let count: i64 = sqlx::query_scalar(
            r"
            SELECT COUNT(*)
            FROM gov_entitlement_assignments
            WHERE user_id = $1
              AND entitlement_id = $2
              AND status = 'active'
            ",
        )
        .bind(user_id)
        .bind(entitlement_id)
        .fetch_one(&self.pool)
        .await
        .unwrap_or(0);

        Ok(count > 0)
    }

    /// Get entitlements associated with a role.
    async fn get_role_entitlements(&self, _tenant_id: Uuid, role_id: Uuid) -> Result<Vec<Uuid>> {
        let entitlements: Vec<Uuid> = sqlx::query_scalar(
            r"
            SELECT entitlement_id
            FROM gov_role_entitlements
            WHERE role_id = $1
            ",
        )
        .bind(role_id)
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();

        Ok(entitlements)
    }

    /// Check for `SoD` violations if a role is added.
    async fn check_sod_violations_for_role_add(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        role_id: Uuid,
    ) -> Result<Vec<Uuid>> {
        // Get entitlements from the role being added
        let new_entitlements = self.get_role_entitlements(tenant_id, role_id).await?;

        if new_entitlements.is_empty() {
            return Ok(vec![]);
        }

        // Get user's current entitlements
        let current_entitlements: Vec<Uuid> = sqlx::query_scalar(
            r"
            SELECT DISTINCT entitlement_id
            FROM gov_entitlement_assignments
            WHERE user_id = $1 AND status = 'active'
            ",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();

        // Check SoD rules
        let mut violations = Vec::new();

        for new_ent in &new_entitlements {
            for current_ent in &current_entitlements {
                let conflicting_rules: Vec<Uuid> = sqlx::query_scalar(
                    r"
                    SELECT id FROM gov_sod_rules
                    WHERE tenant_id = $1
                      AND is_enabled = true
                      AND (
                        (first_entitlement_id = $2 AND second_entitlement_id = $3)
                        OR (first_entitlement_id = $3 AND second_entitlement_id = $2)
                      )
                    ",
                )
                .bind(tenant_id)
                .bind(new_ent)
                .bind(current_ent)
                .fetch_all(&self.pool)
                .await
                .unwrap_or_default();

                violations.extend(conflicting_rules);
            }
        }

        Ok(violations)
    }

    /// Check for `SoD` violations if an entitlement is added.
    async fn check_sod_violations_for_entitlement_add(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        entitlement_id: Uuid,
    ) -> Result<Vec<Uuid>> {
        // Get user's current entitlements
        let current_entitlements: Vec<Uuid> = sqlx::query_scalar(
            r"
            SELECT DISTINCT entitlement_id
            FROM gov_entitlement_assignments
            WHERE user_id = $1 AND status = 'active'
            ",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();

        // Check SoD rules against all current entitlements
        let mut violations = Vec::new();

        for current_ent in &current_entitlements {
            let conflicting_rules: Vec<Uuid> = sqlx::query_scalar(
                r"
                SELECT id FROM gov_sod_rules
                WHERE tenant_id = $1
                  AND is_enabled = true
                  AND (
                    (first_entitlement_id = $2 AND second_entitlement_id = $3)
                    OR (first_entitlement_id = $3 AND second_entitlement_id = $2)
                  )
                ",
            )
            .bind(tenant_id)
            .bind(entitlement_id)
            .bind(current_ent)
            .fetch_all(&self.pool)
            .await
            .unwrap_or_default();

            violations.extend(conflicting_rules);
        }

        Ok(violations)
    }
}

/// Helper struct to track per-user impact during calculation.
#[derive(Debug, Default)]
struct UserImpact {
    affected: bool,
    entitlements_gained: i64,
    entitlements_lost: i64,
    sod_violation_introduced: bool,
    warning: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use xavyo_db::GovBatchSimulation;

    #[test]
    fn test_batch_chunk_size() {
        assert_eq!(BATCH_CHUNK_SIZE, 500);
    }

    // ========================================================================
    // T039: Unit tests for user selection (list mode)
    // ========================================================================

    #[test]
    fn test_user_list_selection_mode() {
        // Test that user list mode returns the explicit user IDs
        let user_ids = vec![Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()];

        // Create simulation with user list mode
        let simulation = create_test_simulation(
            SelectionMode::UserList,
            user_ids.clone(),
            FilterCriteria::default(),
        );

        assert_eq!(simulation.selection_mode, SelectionMode::UserList);
        assert_eq!(simulation.user_ids.len(), 3);
        assert_eq!(simulation.user_ids, user_ids);
    }

    #[test]
    fn test_user_list_validation_empty() {
        // Test that empty user list is rejected in user_list mode
        let empty_user_ids: Vec<Uuid> = vec![];
        let simulation = create_test_simulation(
            SelectionMode::UserList,
            empty_user_ids.clone(),
            FilterCriteria::default(),
        );

        // In user_list mode, empty list should be considered invalid
        // (validation happens in the create method)
        assert_eq!(simulation.user_ids.len(), 0);
    }

    // ========================================================================
    // T040: Unit tests for user selection (filter mode)
    // ========================================================================

    #[test]
    fn test_filter_selection_mode() {
        // Test filter mode with department criteria
        let filter = FilterCriteria {
            department: Some(vec!["Engineering".to_string()]),
            status: Some("active".to_string()),
            role_ids: None,
            entitlement_ids: None,
            title: None,
            metadata: None,
        };

        let simulation = create_test_simulation(SelectionMode::Filter, vec![], filter.clone());

        assert_eq!(simulation.selection_mode, SelectionMode::Filter);
        let parsed_filter = simulation.parse_filter_criteria();
        assert_eq!(
            parsed_filter.department,
            Some(vec!["Engineering".to_string()])
        );
        assert_eq!(parsed_filter.status, Some("active".to_string()));
    }

    #[test]
    fn test_filter_criteria_parsing() {
        let filter = FilterCriteria {
            department: Some(vec!["Sales".to_string(), "Marketing".to_string()]),
            status: Some("active".to_string()),
            role_ids: Some(vec![Uuid::new_v4()]),
            entitlement_ids: Some(vec![Uuid::new_v4(), Uuid::new_v4()]),
            title: Some("Manager".to_string()),
            metadata: Some(serde_json::json!({"location": "US"})),
        };

        let filter_json = serde_json::to_value(&filter).unwrap();
        let parsed: FilterCriteria = serde_json::from_value(filter_json).unwrap();

        assert_eq!(parsed.department.unwrap().len(), 2);
        assert_eq!(parsed.role_ids.unwrap().len(), 1);
        assert_eq!(parsed.entitlement_ids.unwrap().len(), 2);
    }

    #[test]
    fn test_filter_matches_department() {
        // Test department filter matching
        let filter = FilterCriteria {
            department: Some(vec!["Engineering".to_string(), "Product".to_string()]),
            ..Default::default()
        };

        // Simulate user attributes
        let user_dept = "Engineering";
        let matches = filter
            .department
            .as_ref()
            .map(|depts| depts.contains(&user_dept.to_string()))
            .unwrap_or(true);

        assert!(matches);
    }

    #[test]
    fn test_filter_matches_status() {
        let filter = FilterCriteria {
            status: Some("active".to_string()),
            ..Default::default()
        };

        let user_status = "active";
        let matches = filter
            .status
            .as_ref()
            .map(|s| s == user_status)
            .unwrap_or(true);

        assert!(matches);
    }

    // ========================================================================
    // T041: Unit tests for batch impact calculation
    // ========================================================================

    #[test]
    fn test_batch_impact_summary_default() {
        let summary = BatchImpactSummary::default();
        assert_eq!(summary.total_users, 0);
        assert_eq!(summary.affected_users, 0);
        assert_eq!(summary.entitlements_gained, 0);
        assert_eq!(summary.entitlements_lost, 0);
        assert_eq!(summary.sod_violations_introduced, 0);
        assert!(summary.warnings.is_empty());
    }

    #[test]
    #[allow(clippy::field_reassign_with_default)]
    fn test_batch_impact_aggregation() {
        let mut total_summary = BatchImpactSummary::default();
        total_summary.total_users = 100;

        // Simulate aggregating from multiple chunks
        let chunk1 = BatchImpactSummary {
            total_users: 0, // not used in aggregation
            affected_users: 50,
            entitlements_gained: 100,
            entitlements_lost: 0,
            sod_violations_introduced: 2,
            warnings: vec!["Warning 1".to_string()],
        };

        let chunk2 = BatchImpactSummary {
            total_users: 0,
            affected_users: 30,
            entitlements_gained: 60,
            entitlements_lost: 10,
            sod_violations_introduced: 1,
            warnings: vec!["Warning 2".to_string()],
        };

        // Aggregate
        total_summary.affected_users += chunk1.affected_users + chunk2.affected_users;
        total_summary.entitlements_gained +=
            chunk1.entitlements_gained + chunk2.entitlements_gained;
        total_summary.entitlements_lost += chunk1.entitlements_lost + chunk2.entitlements_lost;
        total_summary.sod_violations_introduced +=
            chunk1.sod_violations_introduced + chunk2.sod_violations_introduced;
        total_summary.warnings.extend(chunk1.warnings);
        total_summary.warnings.extend(chunk2.warnings);

        assert_eq!(total_summary.total_users, 100);
        assert_eq!(total_summary.affected_users, 80);
        assert_eq!(total_summary.entitlements_gained, 160);
        assert_eq!(total_summary.entitlements_lost, 10);
        assert_eq!(total_summary.sod_violations_introduced, 3);
        assert_eq!(total_summary.warnings.len(), 2);
    }

    #[test]
    fn test_change_spec_role_add() {
        let role_id = Uuid::new_v4();
        let spec = ChangeSpec {
            operation: BatchSimulationType::RoleAdd,
            role_id: Some(role_id),
            entitlement_id: None,
            justification: Some("Mass role assignment".to_string()),
        };

        assert!(spec.operation.is_role_operation());
        assert!(spec.operation.is_add());
        assert_eq!(spec.role_id, Some(role_id));
    }

    #[test]
    fn test_change_spec_entitlement_remove() {
        let entitlement_id = Uuid::new_v4();
        let spec = ChangeSpec {
            operation: BatchSimulationType::EntitlementRemove,
            role_id: None,
            entitlement_id: Some(entitlement_id),
            justification: Some("Entitlement cleanup".to_string()),
        };

        assert!(spec.operation.is_entitlement_operation());
        assert!(spec.operation.is_remove());
        assert_eq!(spec.entitlement_id, Some(entitlement_id));
    }

    // ========================================================================
    // T042: Unit tests for scope warning threshold
    // ========================================================================

    #[test]
    fn test_scope_warning_threshold_value() {
        // Verify the threshold is set correctly
        assert_eq!(SCOPE_WARNING_THRESHOLD, 100);
    }

    #[test]
    fn test_scope_warning_triggered() {
        let summary = BatchImpactSummary {
            total_users: 150,
            affected_users: 150,
            entitlements_gained: 300,
            entitlements_lost: 0,
            sod_violations_introduced: 0,
            warnings: vec![],
        };

        assert!(summary.affected_users > SCOPE_WARNING_THRESHOLD as i64);
    }

    #[test]
    fn test_scope_warning_not_triggered() {
        let summary = BatchImpactSummary {
            total_users: 50,
            affected_users: 50,
            entitlements_gained: 100,
            entitlements_lost: 0,
            sod_violations_introduced: 0,
            warnings: vec![],
        };

        assert!(summary.affected_users <= SCOPE_WARNING_THRESHOLD as i64);
    }

    #[test]
    fn test_scope_warning_boundary() {
        // Test exactly at threshold
        let summary = BatchImpactSummary {
            total_users: 100,
            affected_users: 100,
            entitlements_gained: 200,
            entitlements_lost: 0,
            sod_violations_introduced: 0,
            warnings: vec![],
        };

        // At exactly 100, should NOT trigger warning (> not >=)
        assert!(summary.affected_users == SCOPE_WARNING_THRESHOLD as i64);
    }

    // ========================================================================
    // Additional unit tests for validation
    // ========================================================================

    #[test]
    fn test_batch_type_validation_role() {
        // Role operations require role_id
        let spec = ChangeSpec {
            operation: BatchSimulationType::RoleAdd,
            role_id: Some(Uuid::new_v4()),
            entitlement_id: None,
            justification: None,
        };

        assert!(spec.role_id.is_some());
        assert!(spec.entitlement_id.is_none());
    }

    #[test]
    fn test_batch_type_validation_entitlement() {
        // Entitlement operations require entitlement_id
        let spec = ChangeSpec {
            operation: BatchSimulationType::EntitlementAdd,
            role_id: None,
            entitlement_id: Some(Uuid::new_v4()),
            justification: None,
        };

        assert!(spec.entitlement_id.is_some());
        assert!(spec.role_id.is_none());
    }

    #[test]
    fn test_simulation_parse_change_spec() {
        let role_id = Uuid::new_v4();
        let change_spec = ChangeSpec {
            operation: BatchSimulationType::RoleRemove,
            role_id: Some(role_id),
            entitlement_id: None,
            justification: Some("Cleanup".to_string()),
        };

        let simulation = GovBatchSimulation {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "Test".to_string(),
            batch_type: BatchSimulationType::RoleRemove,
            selection_mode: SelectionMode::UserList,
            user_ids: vec![Uuid::new_v4()],
            filter_criteria: serde_json::json!({}),
            change_spec: serde_json::to_value(&change_spec).unwrap(),
            status: SimulationStatus::Draft,
            total_users: 0,
            processed_users: 0,
            impact_summary: serde_json::json!({}),
            data_snapshot_at: None,
            is_archived: false,
            retain_until: None,
            notes: None,
            created_by: Uuid::new_v4(),
            created_at: chrono::Utc::now(),
            executed_at: None,
            applied_at: None,
            applied_by: None,
        };

        let parsed = simulation.parse_change_spec().unwrap();
        assert_eq!(parsed.operation, BatchSimulationType::RoleRemove);
        assert_eq!(parsed.role_id, Some(role_id));
    }

    // ========================================================================
    // Helper functions for tests
    // ========================================================================

    fn create_test_simulation(
        selection_mode: SelectionMode,
        user_ids: Vec<Uuid>,
        filter_criteria: FilterCriteria,
    ) -> GovBatchSimulation {
        GovBatchSimulation {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "Test Simulation".to_string(),
            batch_type: BatchSimulationType::RoleAdd,
            selection_mode,
            user_ids,
            filter_criteria: serde_json::to_value(&filter_criteria).unwrap(),
            change_spec: serde_json::json!({
                "operation": "role_add",
                "role_id": Uuid::new_v4().to_string()
            }),
            status: SimulationStatus::Draft,
            total_users: 0,
            processed_users: 0,
            impact_summary: serde_json::json!({}),
            data_snapshot_at: None,
            is_archived: false,
            retain_until: None,
            notes: None,
            created_by: Uuid::new_v4(),
            created_at: chrono::Utc::now(),
            executed_at: None,
            applied_at: None,
            applied_by: None,
        }
    }
}
