//! Bulk action service for F-064: Bulk Action Engine.
//!
//! Provides business logic for creating, previewing, and managing bulk actions
//! that perform mass operations on identities using expression-based filtering.

use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::{CreateGovBulkAction, GovBulkAction, GovBulkActionFilter, GovBulkActionStatus};
use xavyo_governance::{
    eval_expression, validate_expression, EvalContext, ExpressionError, FunctionContext,
};

use crate::error::{ApiGovernanceError, ApiResult};
use crate::models::{
    BulkActionDetailResponse, BulkActionListResponse, BulkActionPreviewResponse,
    BulkActionResponse, CreateBulkActionRequest, ExpressionValidationResponse,
    ListBulkActionsQuery, PreviewBulkActionQuery, PreviewUser,
};

/// User data used for expression evaluation and preview.
#[derive(Debug, Clone, sqlx::FromRow)]
struct UserForEval {
    id: Uuid,
    email: String,
    display_name: Option<String>,
    is_active: bool,
    custom_attributes: serde_json::Value,
}

/// Service for bulk action operations.
pub struct BulkActionService {
    pool: PgPool,
}

impl BulkActionService {
    /// Create a new bulk action service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Validate a filter expression without creating a bulk action.
    ///
    /// Returns information about the expression's validity and the attributes it references.
    pub fn validate_expression(&self, expression: &str) -> ExpressionValidationResponse {
        match validate_expression(expression) {
            Ok(attributes) => ExpressionValidationResponse {
                valid: true,
                error: None,
                parsed_attributes: Some(attributes),
            },
            Err(e) => ExpressionValidationResponse {
                valid: false,
                error: Some(format!("{e}")),
                parsed_attributes: None,
            },
        }
    }

    /// Create a new bulk action.
    ///
    /// The action is created in 'pending' status. Use `preview_bulk_action` to see
    /// which users would be affected, and `execute_bulk_action` (Phase 4) to run it.
    pub async fn create_bulk_action(
        &self,
        tenant_id: Uuid,
        request: CreateBulkActionRequest,
        created_by: Uuid,
    ) -> ApiResult<BulkActionResponse> {
        // Validate the expression first
        let validation = self.validate_expression(&request.filter_expression);
        if !validation.valid {
            return Err(ApiGovernanceError::InvalidExpression(
                validation
                    .error
                    .unwrap_or_else(|| "Invalid expression".to_string()),
            ));
        }

        // Create the bulk action in pending status
        let input = CreateGovBulkAction {
            filter_expression: request.filter_expression,
            action_type: request.action_type,
            action_params: request.action_params,
            justification: request.justification,
            created_by,
        };

        let action = GovBulkAction::create(&self.pool, tenant_id, &input).await?;

        Ok(BulkActionResponse::from(action))
    }

    /// Get a bulk action by ID.
    pub async fn get_bulk_action(
        &self,
        tenant_id: Uuid,
        action_id: Uuid,
    ) -> ApiResult<BulkActionDetailResponse> {
        let action = GovBulkAction::find_by_id(&self.pool, tenant_id, action_id)
            .await?
            .ok_or(ApiGovernanceError::BulkActionNotFound(action_id))?;

        Ok(BulkActionDetailResponse::from_action(action))
    }

    /// List bulk actions for a tenant with optional filtering.
    pub async fn list_bulk_actions(
        &self,
        tenant_id: Uuid,
        query: &ListBulkActionsQuery,
    ) -> ApiResult<BulkActionListResponse> {
        let filter = GovBulkActionFilter {
            status: query.status,
            action_type: query.action_type,
            created_by: query.created_by,
        };

        let limit = query.limit.unwrap_or(50);
        let offset = query.offset.unwrap_or(0).max(0);

        let actions =
            GovBulkAction::list_by_tenant(&self.pool, tenant_id, &filter, limit, offset).await?;
        let total = GovBulkAction::count_by_tenant(&self.pool, tenant_id, &filter).await?;

        let items = actions.into_iter().map(BulkActionResponse::from).collect();

        Ok(BulkActionListResponse {
            items,
            total,
            limit,
            offset,
        })
    }

    /// Preview the users that would be affected by a bulk action.
    ///
    /// Returns a paginated list of users matching the filter expression,
    /// with indication of whether the action would change their state.
    pub async fn preview_bulk_action(
        &self,
        tenant_id: Uuid,
        action_id: Uuid,
        query: &PreviewBulkActionQuery,
    ) -> ApiResult<BulkActionPreviewResponse> {
        // Get the bulk action
        let action = GovBulkAction::find_by_id(&self.pool, tenant_id, action_id)
            .await?
            .ok_or(ApiGovernanceError::BulkActionNotFound(action_id))?;

        // Can only preview pending actions
        if action.status != GovBulkActionStatus::Pending {
            return Err(ApiGovernanceError::BulkActionAlreadyExecuted(action_id));
        }

        let limit = query.limit.unwrap_or(100);
        let offset = query.offset.unwrap_or(0).max(0);

        // Fetch users that might match (we'll filter in-memory using the expression evaluator)
        // In a production system, we might want to translate the expression to SQL for efficiency
        let users = self
            .fetch_users_for_preview(tenant_id, limit, offset)
            .await?;

        // Evaluate each user against the expression
        let mut matched_users = Vec::new();
        let mut would_change_count = 0i64;
        let mut no_change_count = 0i64;

        for user in users {
            if self.evaluate_user(&action.filter_expression, &user)? {
                let (would_change, current_value, new_value) =
                    self.check_would_change(&action, &user).await?;

                if would_change {
                    would_change_count += 1;
                } else {
                    no_change_count += 1;
                }

                matched_users.push(PreviewUser {
                    id: user.id,
                    email: user.email.clone(),
                    display_name: user.display_name.clone(),
                    would_change,
                    current_value,
                    new_value,
                });
            }
        }

        let total_matched = would_change_count + no_change_count;

        Ok(BulkActionPreviewResponse {
            total_matched,
            would_change_count,
            no_change_count,
            users: matched_users,
            limit,
            offset,
        })
    }

    /// Fetch users for preview evaluation.
    async fn fetch_users_for_preview(
        &self,
        tenant_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> ApiResult<Vec<UserForEval>> {
        let users = sqlx::query_as::<_, UserForEval>(
            r#"
            SELECT id, email, display_name, is_active, custom_attributes
            FROM users
            WHERE tenant_id = $1
            ORDER BY email
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(tenant_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok(users)
    }

    /// Evaluate a user against a filter expression.
    fn evaluate_user(&self, expression: &str, user: &UserForEval) -> ApiResult<bool> {
        // Build evaluation context from user attributes
        let mut ctx = EvalContext::new()
            .with_attribute("id", user.id.to_string())
            .with_attribute("email", user.email.as_str())
            .with_attribute("is_active", user.is_active)
            .with_attribute("active", user.is_active); // Common alias

        // Add display_name if present
        if let Some(ref name) = user.display_name {
            ctx = ctx.with_attribute("display_name", name.as_str());
        }

        // Add custom attributes from the JSONB column
        if let serde_json::Value::Object(attrs) = &user.custom_attributes {
            for (key, value) in attrs {
                match value {
                    serde_json::Value::String(s) => {
                        ctx = ctx.with_attribute(key.clone(), s.clone());
                    }
                    serde_json::Value::Bool(b) => {
                        ctx = ctx.with_attribute(key.clone(), *b);
                    }
                    serde_json::Value::Number(n) => {
                        if let Some(i) = n.as_i64() {
                            ctx = ctx.with_attribute(key.clone(), i);
                        } else if let Some(f) = n.as_f64() {
                            ctx = ctx.with_attribute(key.clone(), f);
                        }
                    }
                    serde_json::Value::Null => {
                        // Skip null values
                    }
                    _ => {
                        // For complex values, convert to string
                        ctx = ctx.with_attribute(key.clone(), value.to_string());
                    }
                }
            }
        }

        // Add function context for has_role, has_entitlement, etc.
        // For now, we'll pass empty collections - this will be enhanced in Phase 4
        let func_ctx = FunctionContext::new();
        ctx = ctx.with_function_context(func_ctx);

        match eval_expression(expression, &ctx) {
            Ok(result) => Ok(result),
            Err(ExpressionError::Parse(e)) => {
                Err(ApiGovernanceError::InvalidExpression(format!("{e}")))
            }
            Err(ExpressionError::Eval(e)) => {
                // For evaluation errors on specific users, we treat as non-match
                // This handles cases like missing attributes gracefully
                tracing::debug!("Expression evaluation error for user {}: {}", user.id, e);
                Ok(false)
            }
        }
    }

    /// Check if the action would change the user's state.
    async fn check_would_change(
        &self,
        action: &GovBulkAction,
        user: &UserForEval,
    ) -> ApiResult<(bool, Option<serde_json::Value>, Option<serde_json::Value>)> {
        use xavyo_db::GovBulkActionType;

        match action.action_type {
            GovBulkActionType::Enable => {
                if user.is_active {
                    Ok((false, Some(serde_json::json!(true)), None))
                } else {
                    Ok((
                        true,
                        Some(serde_json::json!(false)),
                        Some(serde_json::json!(true)),
                    ))
                }
            }
            GovBulkActionType::Disable => {
                if !user.is_active {
                    Ok((false, Some(serde_json::json!(false)), None))
                } else {
                    Ok((
                        true,
                        Some(serde_json::json!(true)),
                        Some(serde_json::json!(false)),
                    ))
                }
            }
            GovBulkActionType::AssignRole => {
                // For role assignment, we need to check if user already has the role
                // This will be fully implemented in Phase 4
                let role_id = action
                    .action_params
                    .get("role_id")
                    .and_then(|v| v.as_str())
                    .and_then(|s| Uuid::parse_str(s).ok());

                if let Some(rid) = role_id {
                    let has_role = self.user_has_role(user.id, action.tenant_id, rid).await?;
                    if has_role {
                        Ok((false, Some(serde_json::json!(true)), None))
                    } else {
                        Ok((
                            true,
                            Some(serde_json::json!(false)),
                            Some(serde_json::json!(true)),
                        ))
                    }
                } else {
                    // Invalid role_id in params - still show as would_change
                    Ok((true, None, None))
                }
            }
            GovBulkActionType::RevokeRole => {
                let role_id = action
                    .action_params
                    .get("role_id")
                    .and_then(|v| v.as_str())
                    .and_then(|s| Uuid::parse_str(s).ok());

                if let Some(rid) = role_id {
                    let has_role = self.user_has_role(user.id, action.tenant_id, rid).await?;
                    if !has_role {
                        Ok((false, Some(serde_json::json!(false)), None))
                    } else {
                        Ok((
                            true,
                            Some(serde_json::json!(true)),
                            Some(serde_json::json!(false)),
                        ))
                    }
                } else {
                    Ok((true, None, None))
                }
            }
            GovBulkActionType::ModifyAttribute => {
                // For attribute modification, check current vs new value
                let attr_name = action
                    .action_params
                    .get("attribute")
                    .and_then(|v| v.as_str());
                let new_value = action.action_params.get("value");

                if let (Some(name), Some(val)) = (attr_name, new_value) {
                    let current = user.custom_attributes.get(name);
                    if current == Some(val) {
                        Ok((false, current.cloned(), None))
                    } else {
                        Ok((true, current.cloned(), Some(val.clone())))
                    }
                } else {
                    Ok((true, None, None))
                }
            }
        }
    }

    /// Check if a user has a specific role by resolving role_id to role_name.
    async fn user_has_role(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        role_id: Uuid,
    ) -> ApiResult<bool> {
        // Resolve role_id to role_name via gov_roles
        let role_name: Option<(String,)> =
            sqlx::query_as("SELECT name FROM gov_roles WHERE id = $1 AND tenant_id = $2")
                .bind(role_id)
                .bind(tenant_id)
                .fetch_optional(&self.pool)
                .await?;

        let role_name = match role_name {
            Some((name,)) => name,
            None => return Ok(false),
        };

        let count: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*) FROM user_roles
            WHERE user_id = $1 AND role_name = $2
            "#,
        )
        .bind(user_id)
        .bind(role_name)
        .fetch_one(&self.pool)
        .await?;

        Ok(count.0 > 0)
    }

    /// Execute a bulk action on all matched users.
    ///
    /// Transitions the action from 'pending' to 'running', executes the action
    /// on each matched user, and updates the final status to 'completed' or 'failed'.
    pub async fn execute_bulk_action(
        &self,
        tenant_id: Uuid,
        action_id: Uuid,
        executed_by: Uuid,
    ) -> ApiResult<BulkActionDetailResponse> {
        use super::action_executors::{
            ActionExecutor, AssignRoleExecutor, DisableUserExecutor, EnableUserExecutor,
            ExecutionContext, ModifyAttributeExecutor, RevokeRoleExecutor,
        };
        use xavyo_db::GovBulkActionType;

        // Get the bulk action
        let action = GovBulkAction::find_by_id(&self.pool, tenant_id, action_id)
            .await?
            .ok_or(ApiGovernanceError::BulkActionNotFound(action_id))?;

        // Verify the action is in pending status
        if action.status != GovBulkActionStatus::Pending {
            return Err(ApiGovernanceError::BulkActionAlreadyExecuted(action_id));
        }

        // Update status to running
        GovBulkAction::mark_running(&self.pool, tenant_id, action_id).await?;

        // Get the appropriate executor
        let executor: Box<dyn ActionExecutor> = match action.action_type {
            GovBulkActionType::AssignRole => Box::new(AssignRoleExecutor::new()),
            GovBulkActionType::RevokeRole => Box::new(RevokeRoleExecutor::new()),
            GovBulkActionType::Enable => Box::new(EnableUserExecutor::new()),
            GovBulkActionType::Disable => Box::new(DisableUserExecutor::new()),
            GovBulkActionType::ModifyAttribute => Box::new(ModifyAttributeExecutor::new()),
        };

        // Build execution context
        let ctx = ExecutionContext {
            tenant_id,
            initiated_by: executed_by,
            bulk_action_id: action_id,
            justification: action.justification.clone(),
        };

        // Fetch all users for the tenant (we'll filter by expression)
        let users = self.fetch_users_for_preview(tenant_id, 10000, 0).await?;

        // Track results
        let mut processed_count = 0i32;
        let mut success_count = 0i32;
        let mut failure_count = 0i32;
        let mut skipped_count = 0i32;
        let mut results: Vec<serde_json::Value> = Vec::new();

        // Process each matching user
        for user in users {
            if self.evaluate_user(&action.filter_expression, &user)? {
                let result = self
                    .process_single_user(executor.as_ref(), &ctx, user.id, &action.action_params)
                    .await;

                processed_count += 1;
                if result.success {
                    if result.skipped {
                        skipped_count += 1;
                    } else {
                        success_count += 1;
                    }
                } else {
                    failure_count += 1;
                }

                // Record result for audit
                results.push(serde_json::json!({
                    "user_id": user.id.to_string(),
                    "success": result.success,
                    "skipped": result.skipped,
                    "error": result.error,
                }));

                // Log audit event
                self.record_audit_event(
                    tenant_id,
                    action_id,
                    user.id,
                    executed_by,
                    &action.action_type,
                    &result,
                )
                .await?;
            }
        }

        // Update progress counters
        GovBulkAction::update_progress(
            &self.pool,
            action_id,
            processed_count,
            success_count,
            failure_count,
            skipped_count,
        )
        .await?;

        // Determine final status and mark completed/failed (includes setting results and completed_at)
        let results_json = serde_json::json!(results);
        if failure_count > 0 && success_count == 0 {
            GovBulkAction::mark_failed(&self.pool, action_id, results_json).await?;
        } else {
            GovBulkAction::mark_completed(&self.pool, action_id, results_json).await?;
        }

        // Return updated action
        self.get_bulk_action(tenant_id, action_id).await
    }

    /// Process a single user with the executor.
    async fn process_single_user(
        &self,
        executor: &dyn super::action_executors::ActionExecutor,
        ctx: &super::action_executors::ExecutionContext,
        user_id: Uuid,
        params: &serde_json::Value,
    ) -> super::action_executors::ExecutionResult {
        executor.execute(&self.pool, ctx, user_id, params).await
    }

    /// Cancel a pending or running bulk action.
    ///
    /// Only actions in 'pending' or 'running' status can be cancelled.
    /// Returns the cancelled action.
    pub async fn cancel_bulk_action(
        &self,
        tenant_id: Uuid,
        action_id: Uuid,
    ) -> ApiResult<BulkActionDetailResponse> {
        // Get the bulk action
        let action = GovBulkAction::find_by_id(&self.pool, tenant_id, action_id)
            .await?
            .ok_or(ApiGovernanceError::BulkActionNotFound(action_id))?;

        // Verify the action can be cancelled
        if !action.can_cancel() {
            return Err(ApiGovernanceError::BulkActionCannotBeCancelled(action_id));
        }

        // Cancel the action
        let cancelled = GovBulkAction::cancel(&self.pool, tenant_id, action_id)
            .await?
            .ok_or(ApiGovernanceError::BulkActionCannotBeCancelled(action_id))?;

        Ok(BulkActionDetailResponse::from_action(cancelled))
    }

    /// Delete a bulk action.
    ///
    /// Only actions in 'completed', 'failed', or 'cancelled' status can be deleted.
    pub async fn delete_bulk_action(&self, tenant_id: Uuid, action_id: Uuid) -> ApiResult<()> {
        // Get the bulk action
        let action = GovBulkAction::find_by_id(&self.pool, tenant_id, action_id)
            .await?
            .ok_or(ApiGovernanceError::BulkActionNotFound(action_id))?;

        // Verify the action can be deleted
        if !action.can_delete() {
            return Err(ApiGovernanceError::BulkActionCannotDelete {
                id: action_id,
                status: action.status.to_string(),
            });
        }

        // Delete the action
        let deleted = GovBulkAction::delete(&self.pool, tenant_id, action_id).await?;
        if !deleted {
            return Err(ApiGovernanceError::BulkActionCannotDelete {
                id: action_id,
                status: action.status.to_string(),
            });
        }

        Ok(())
    }

    /// Record an audit event for a bulk action operation.
    async fn record_audit_event(
        &self,
        tenant_id: Uuid,
        bulk_action_id: Uuid,
        user_id: Uuid,
        performed_by: Uuid,
        action_type: &xavyo_db::GovBulkActionType,
        result: &super::action_executors::ExecutionResult,
    ) -> ApiResult<()> {
        let event_type = format!(
            "bulk_action_{}",
            match action_type {
                xavyo_db::GovBulkActionType::AssignRole => "assign_role",
                xavyo_db::GovBulkActionType::RevokeRole => "revoke_role",
                xavyo_db::GovBulkActionType::Enable => "enable",
                xavyo_db::GovBulkActionType::Disable => "disable",
                xavyo_db::GovBulkActionType::ModifyAttribute => "modify_attribute",
            }
        );

        let outcome = if result.success {
            if result.skipped {
                "skipped"
            } else {
                "success"
            }
        } else {
            "failure"
        };

        sqlx::query(
            r#"
            INSERT INTO audit_events (id, tenant_id, event_type, actor_id, target_type, target_id, outcome, details, created_at)
            VALUES ($1, $2, $3, $4, 'user', $5, $6, $7, NOW())
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(tenant_id)
        .bind(&event_type)
        .bind(performed_by)
        .bind(user_id)
        .bind(outcome)
        .bind(serde_json::json!({
            "bulk_action_id": bulk_action_id.to_string(),
            "previous_value": result.previous_value,
            "new_value": result.new_value,
            "error": result.error,
        }))
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xavyo_governance::validate_expression;

    // Test expression validation directly using the governance crate
    // (BulkActionService.validate_expression is just a wrapper around this)

    #[test]
    fn test_validate_expression_valid() {
        let result = validate_expression("department = 'engineering' AND active = true");
        assert!(result.is_ok());
        let attrs = result.unwrap();
        assert!(attrs.contains(&"department".to_string()));
        assert!(attrs.contains(&"active".to_string()));
    }

    #[test]
    fn test_validate_expression_invalid() {
        let result = validate_expression("invalid ??? syntax");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_expression_complex() {
        let result = validate_expression(
            "department IN ('eng', 'product') AND (level >= 3 OR is_manager = true)",
        );
        assert!(result.is_ok());
        let attrs = result.unwrap();
        assert!(attrs.contains(&"department".to_string()));
        assert!(attrs.contains(&"level".to_string()));
        assert!(attrs.contains(&"is_manager".to_string()));
    }
}
