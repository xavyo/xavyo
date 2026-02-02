//! Plan management service.
//!
//! F-PLAN-MGMT: Handles tenant plan upgrades, downgrades, and history.

use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::models::{
    next_billing_cycle_date, AdminAction, AdminAuditLog, AdminResourceType, CreateAuditLogEntry,
    PlanChangeType, PlanDefinition, PlanTier, Tenant, TenantPlanChange,
};

use crate::error::TenantError;
use crate::models::{
    DowngradePlanRequest, PendingDowngradeInfo, PlanChangeEntry, PlanChangeResponse,
    PlanDefinitionResponse, PlanHistoryResponse, PlansListResponse, UpgradePlanRequest,
};

/// Service for managing tenant plans.
#[derive(Clone)]
pub struct PlanService {
    pool: PgPool,
}

impl PlanService {
    /// Create a new plan service.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Upgrade a tenant's plan (takes effect immediately).
    ///
    /// Validates that the new plan is higher tier, updates tenant settings,
    /// records the change, and logs the audit trail.
    pub async fn upgrade_plan(
        &self,
        tenant_id: Uuid,
        request: UpgradePlanRequest,
        admin_user_id: Uuid,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<PlanChangeResponse, TenantError> {
        // Get the tenant
        let tenant = Tenant::find_by_id(&self.pool, tenant_id)
            .await
            .map_err(|e| TenantError::Database(e.to_string()))?
            .ok_or(TenantError::TenantNotFound(tenant_id))?;

        // Get current plan from settings
        let current_plan = self.get_current_plan(&tenant);

        // Validate the upgrade request
        let new_tier = request
            .validate(&current_plan)
            .map_err(TenantError::Validation)?;

        // Get the new plan definition
        let new_plan_def = PlanDefinition::for_tier(new_tier);

        // Apply upgrade immediately by updating tenant settings
        let new_settings = new_plan_def.to_settings_json();
        let _updated_tenant = Tenant::update_settings(&self.pool, tenant_id, new_settings)
            .await
            .map_err(|e| TenantError::Database(e.to_string()))?;

        // Record the plan change with status = applied (immediate)
        let now = Utc::now();
        let change = TenantPlanChange::create(
            &self.pool,
            tenant_id,
            PlanChangeType::Upgrade,
            &current_plan,
            new_tier.as_str(),
            now,
            admin_user_id,
            None,
        )
        .await
        .map_err(|e| TenantError::Database(e.to_string()))?;

        // Mark as applied immediately
        let change = TenantPlanChange::mark_applied(&self.pool, change.id)
            .await
            .map_err(|e| TenantError::Database(e.to_string()))?;

        // Log audit trail
        let old_value = serde_json::json!({ "plan": current_plan });
        let new_value =
            serde_json::json!({ "plan": new_tier.as_str(), "effective_at": now.to_rfc3339() });

        AdminAuditLog::create(
            &self.pool,
            CreateAuditLogEntry {
                tenant_id,
                admin_user_id,
                action: AdminAction::Update,
                resource_type: AdminResourceType::TenantPlan,
                resource_id: Some(tenant_id),
                old_value: Some(old_value),
                new_value: Some(new_value),
                ip_address,
                user_agent,
            },
        )
        .await
        .map_err(|e| TenantError::Database(e.to_string()))?;

        tracing::info!(
            tenant_id = %tenant_id,
            old_plan = %current_plan,
            new_plan = %new_tier.as_str(),
            admin_user_id = %admin_user_id,
            "Tenant plan upgraded"
        );

        Ok(PlanChangeResponse {
            id: change.id,
            tenant_id,
            change_type: "upgrade".to_string(),
            old_plan: current_plan,
            new_plan: new_tier.as_str().to_string(),
            effective_at: now,
            status: "applied".to_string(),
            message: format!(
                "Plan upgraded from {} to {} successfully",
                change.old_plan, change.new_plan
            ),
        })
    }

    /// Downgrade a tenant's plan (scheduled for next billing cycle).
    ///
    /// Validates that the new plan is lower tier, schedules the change
    /// for the first day of next month, and logs the audit trail.
    pub async fn downgrade_plan(
        &self,
        tenant_id: Uuid,
        request: DowngradePlanRequest,
        admin_user_id: Uuid,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<PlanChangeResponse, TenantError> {
        // Get the tenant
        let tenant = Tenant::find_by_id(&self.pool, tenant_id)
            .await
            .map_err(|e| TenantError::Database(e.to_string()))?
            .ok_or(TenantError::TenantNotFound(tenant_id))?;

        // Get current plan from settings
        let current_plan = self.get_current_plan(&tenant);

        // Validate the downgrade request
        let new_tier = request
            .validate(&current_plan)
            .map_err(TenantError::Validation)?;

        // Check for existing pending downgrade
        let existing_pending = TenantPlanChange::get_pending_downgrade(&self.pool, tenant_id)
            .await
            .map_err(|e| TenantError::Database(e.to_string()))?;

        if existing_pending.is_some() {
            return Err(TenantError::Validation(
                "A pending downgrade already exists. Cancel it before scheduling a new one."
                    .to_string(),
            ));
        }

        // Calculate effective date (first day of next month)
        let effective_at = next_billing_cycle_date();

        // Create pending downgrade record
        let change = TenantPlanChange::create(
            &self.pool,
            tenant_id,
            PlanChangeType::Downgrade,
            &current_plan,
            new_tier.as_str(),
            effective_at,
            admin_user_id,
            request.reason.as_deref(),
        )
        .await
        .map_err(|e| TenantError::Database(e.to_string()))?;

        // Log audit trail
        let old_value = serde_json::json!({ "plan": current_plan });
        let new_value = serde_json::json!({
            "plan": new_tier.as_str(),
            "effective_at": effective_at.to_rfc3339(),
            "status": "pending"
        });

        AdminAuditLog::create(
            &self.pool,
            CreateAuditLogEntry {
                tenant_id,
                admin_user_id,
                action: AdminAction::Update,
                resource_type: AdminResourceType::TenantPlan,
                resource_id: Some(tenant_id),
                old_value: Some(old_value),
                new_value: Some(new_value),
                ip_address,
                user_agent,
            },
        )
        .await
        .map_err(|e| TenantError::Database(e.to_string()))?;

        tracing::info!(
            tenant_id = %tenant_id,
            old_plan = %current_plan,
            new_plan = %new_tier.as_str(),
            effective_at = %effective_at,
            admin_user_id = %admin_user_id,
            "Tenant plan downgrade scheduled"
        );

        Ok(PlanChangeResponse {
            id: change.id,
            tenant_id,
            change_type: "downgrade".to_string(),
            old_plan: current_plan,
            new_plan: new_tier.as_str().to_string(),
            effective_at,
            status: "pending".to_string(),
            message: format!(
                "Downgrade to {} scheduled for {}",
                new_tier.as_str(),
                effective_at.format("%Y-%m-%d")
            ),
        })
    }

    /// Cancel a pending downgrade.
    ///
    /// Marks the pending downgrade as cancelled and logs the audit trail.
    pub async fn cancel_pending_downgrade(
        &self,
        tenant_id: Uuid,
        admin_user_id: Uuid,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<PlanChangeResponse, TenantError> {
        // Get the tenant to verify it exists
        let tenant = Tenant::find_by_id(&self.pool, tenant_id)
            .await
            .map_err(|e| TenantError::Database(e.to_string()))?
            .ok_or(TenantError::TenantNotFound(tenant_id))?;

        // Get pending downgrade
        let pending = TenantPlanChange::get_pending_downgrade(&self.pool, tenant_id)
            .await
            .map_err(|e| TenantError::Database(e.to_string()))?
            .ok_or_else(|| TenantError::Validation("No pending downgrade to cancel".to_string()))?;

        // Cancel the downgrade
        let cancelled = TenantPlanChange::mark_cancelled(&self.pool, pending.id)
            .await
            .map_err(|e| TenantError::Database(e.to_string()))?;

        // Log audit trail
        let current_plan = self.get_current_plan(&tenant);
        let old_value = serde_json::json!({
            "plan": pending.new_plan,
            "effective_at": pending.effective_at.to_rfc3339(),
            "status": "pending"
        });
        let new_value = serde_json::json!({
            "plan": current_plan,
            "status": "cancelled"
        });

        AdminAuditLog::create(
            &self.pool,
            CreateAuditLogEntry {
                tenant_id,
                admin_user_id,
                action: AdminAction::Update,
                resource_type: AdminResourceType::TenantPlan,
                resource_id: Some(tenant_id),
                old_value: Some(old_value),
                new_value: Some(new_value),
                ip_address,
                user_agent,
            },
        )
        .await
        .map_err(|e| TenantError::Database(e.to_string()))?;

        tracing::info!(
            tenant_id = %tenant_id,
            cancelled_plan = %pending.new_plan,
            admin_user_id = %admin_user_id,
            "Pending downgrade cancelled"
        );

        Ok(PlanChangeResponse {
            id: cancelled.id,
            tenant_id,
            change_type: "downgrade".to_string(),
            old_plan: cancelled.old_plan.clone(),
            new_plan: cancelled.new_plan.clone(),
            effective_at: cancelled.effective_at,
            status: "cancelled".to_string(),
            message: format!(
                "Pending downgrade to {} has been cancelled",
                cancelled.new_plan
            ),
        })
    }

    /// Get plan change history for a tenant.
    pub async fn get_plan_history(
        &self,
        tenant_id: Uuid,
        limit: i32,
    ) -> Result<PlanHistoryResponse, TenantError> {
        // Get the tenant
        let tenant = Tenant::find_by_id(&self.pool, tenant_id)
            .await
            .map_err(|e| TenantError::Database(e.to_string()))?
            .ok_or(TenantError::TenantNotFound(tenant_id))?;

        // Get current plan
        let current_plan = self.get_current_plan(&tenant);

        // Get history
        let changes = TenantPlanChange::get_history(&self.pool, tenant_id, limit)
            .await
            .map_err(|e| TenantError::Database(e.to_string()))?;

        // Get pending downgrade if any
        let pending_downgrade = TenantPlanChange::get_pending_downgrade(&self.pool, tenant_id)
            .await
            .map_err(|e| TenantError::Database(e.to_string()))?
            .map(|p| PendingDowngradeInfo {
                id: p.id,
                new_plan: p.new_plan,
                effective_at: p.effective_at,
                reason: p.reason,
            });

        // Convert to response entries
        let change_entries: Vec<PlanChangeEntry> = changes
            .into_iter()
            .map(|c| PlanChangeEntry {
                id: c.id,
                change_type: c.change_type,
                old_plan: c.old_plan,
                new_plan: c.new_plan,
                effective_at: c.effective_at,
                status: c.status,
                reason: c.reason,
                created_at: c.created_at,
            })
            .collect();

        Ok(PlanHistoryResponse {
            tenant_id,
            current_plan,
            changes: change_entries,
            pending_downgrade,
        })
    }

    /// List all available plans.
    pub fn list_plans(&self) -> PlansListResponse {
        PlansListResponse {
            plans: PlanDefinition::all()
                .into_iter()
                .map(PlanDefinitionResponse::from)
                .collect(),
        }
    }

    /// Apply all due pending plan changes.
    ///
    /// This is called by a background job to apply scheduled downgrades.
    pub async fn apply_pending_changes(&self) -> Result<Vec<PlanChangeResponse>, TenantError> {
        let due_changes = TenantPlanChange::get_due_pending_changes(&self.pool)
            .await
            .map_err(|e| TenantError::Database(e.to_string()))?;

        let mut results = Vec::new();

        for change in due_changes {
            // Parse the new tier
            let new_tier: PlanTier = match change.new_plan.parse() {
                Ok(tier) => tier,
                Err(_) => {
                    tracing::error!(
                        change_id = %change.id,
                        new_plan = %change.new_plan,
                        "Invalid plan tier in pending change"
                    );
                    continue;
                }
            };

            // Get the plan definition
            let new_plan_def = PlanDefinition::for_tier(new_tier);

            // Apply the settings change
            let new_settings = new_plan_def.to_settings_json();
            if let Err(e) =
                Tenant::update_settings(&self.pool, change.tenant_id, new_settings).await
            {
                tracing::error!(
                    change_id = %change.id,
                    tenant_id = %change.tenant_id,
                    error = %e,
                    "Failed to apply pending plan change"
                );
                continue;
            }

            // Mark as applied
            match TenantPlanChange::mark_applied(&self.pool, change.id).await {
                Ok(applied) => {
                    tracing::info!(
                        change_id = %change.id,
                        tenant_id = %change.tenant_id,
                        old_plan = %change.old_plan,
                        new_plan = %change.new_plan,
                        "Applied pending plan change"
                    );

                    results.push(PlanChangeResponse {
                        id: applied.id,
                        tenant_id: applied.tenant_id,
                        change_type: applied.change_type,
                        old_plan: applied.old_plan,
                        new_plan: applied.new_plan,
                        effective_at: applied.effective_at,
                        status: "applied".to_string(),
                        message: "Scheduled plan change applied".to_string(),
                    });
                }
                Err(e) => {
                    tracing::error!(
                        change_id = %change.id,
                        error = %e,
                        "Failed to mark change as applied"
                    );
                }
            }
        }

        Ok(results)
    }

    /// Extract current plan from tenant settings.
    fn get_current_plan(&self, tenant: &Tenant) -> String {
        tenant
            .settings
            .get("plan")
            .and_then(|v| v.as_str())
            .unwrap_or("free")
            .to_string()
    }
}
