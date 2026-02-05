//! Governance Delegation Scope model.
//!
//! Defines scope restrictions for delegations. When a delegation has no scope
//! (`scope_id` is NULL), it grants full approval authority. When a scope is
//! specified, the deputy can only act on work items matching the scope criteria.
//!
//! Part of F053 Deputy & Power of Attorney feature.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Scope restrictions for a delegation.
///
/// Scope uses OR semantics: a work item matches if it matches ANY of the
/// non-empty criteria arrays. Empty arrays mean "no restriction for this type".
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovDelegationScope {
    /// Unique identifier for the scope.
    pub id: Uuid,

    /// The tenant this scope belongs to.
    pub tenant_id: Uuid,

    /// Applications in scope. Empty = no application restriction.
    pub application_ids: Vec<Uuid>,

    /// Entitlements in scope. Empty = no entitlement restriction.
    pub entitlement_ids: Vec<Uuid>,

    /// Roles in scope. Empty = no role restriction.
    pub role_ids: Vec<Uuid>,

    /// Workflow types in scope. Empty = no type restriction.
    /// Valid values: "`access_request`", "certification", "`state_transition`"
    pub workflow_types: Vec<String>,

    /// When the scope was created.
    pub created_at: DateTime<Utc>,
}

/// Request to create a new delegation scope.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CreateGovDelegationScope {
    pub application_ids: Option<Vec<Uuid>>,
    pub entitlement_ids: Option<Vec<Uuid>>,
    pub role_ids: Option<Vec<Uuid>>,
    pub workflow_types: Option<Vec<String>>,
}

impl GovDelegationScope {
    /// Find a scope by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_delegation_scopes
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Create a new delegation scope.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateGovDelegationScope,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO gov_delegation_scopes (
                tenant_id, application_ids, entitlement_ids, role_ids, workflow_types
            )
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(input.application_ids.unwrap_or_default())
        .bind(input.entitlement_ids.unwrap_or_default())
        .bind(input.role_ids.unwrap_or_default())
        .bind(input.workflow_types.unwrap_or_default())
        .fetch_one(pool)
        .await
    }

    /// Delete a scope by ID.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_delegation_scopes
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Check if the scope is empty (no restrictions defined).
    /// An empty scope is equivalent to full delegation.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.application_ids.is_empty()
            && self.entitlement_ids.is_empty()
            && self.role_ids.is_empty()
            && self.workflow_types.is_empty()
    }

    /// Check if a work item matches this scope.
    ///
    /// Returns true if:
    /// - The scope is empty (full delegation), OR
    /// - The work item matches at least one criterion (OR semantics)
    #[must_use]
    pub fn matches_work_item(
        &self,
        application_id: Option<Uuid>,
        entitlement_id: Option<Uuid>,
        role_id: Option<Uuid>,
        workflow_type: Option<&str>,
    ) -> bool {
        // Empty scope = full delegation = matches everything
        if self.is_empty() {
            return true;
        }

        // Check application match
        if let Some(app_id) = application_id {
            if !self.application_ids.is_empty() && self.application_ids.contains(&app_id) {
                return true;
            }
        }

        // Check entitlement match
        if let Some(ent_id) = entitlement_id {
            if !self.entitlement_ids.is_empty() && self.entitlement_ids.contains(&ent_id) {
                return true;
            }
        }

        // Check role match
        if let Some(r_id) = role_id {
            if !self.role_ids.is_empty() && self.role_ids.contains(&r_id) {
                return true;
            }
        }

        // Check workflow type match
        if let Some(wf_type) = workflow_type {
            if !self.workflow_types.is_empty() && self.workflow_types.contains(&wf_type.to_string())
            {
                return true;
            }
        }

        // No match found and scope has restrictions
        false
    }

    /// Validate that all referenced IDs exist.
    /// Returns a list of validation errors, or empty if valid.
    pub async fn validate_references(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: &CreateGovDelegationScope,
    ) -> Result<Vec<String>, sqlx::Error> {
        let mut errors = Vec::new();

        // Validate application IDs
        if let Some(ref app_ids) = input.application_ids {
            if !app_ids.is_empty() {
                let count: i64 = sqlx::query_scalar(
                    r"
                    SELECT COUNT(*) FROM gov_applications
                    WHERE tenant_id = $1 AND id = ANY($2)
                    ",
                )
                .bind(tenant_id)
                .bind(app_ids)
                .fetch_one(pool)
                .await?;

                if count != app_ids.len() as i64 {
                    errors.push("One or more application IDs do not exist".to_string());
                }
            }
        }

        // Validate entitlement IDs
        if let Some(ref ent_ids) = input.entitlement_ids {
            if !ent_ids.is_empty() {
                let count: i64 = sqlx::query_scalar(
                    r"
                    SELECT COUNT(*) FROM gov_entitlements
                    WHERE tenant_id = $1 AND id = ANY($2)
                    ",
                )
                .bind(tenant_id)
                .bind(ent_ids)
                .fetch_one(pool)
                .await?;

                if count != ent_ids.len() as i64 {
                    errors.push("One or more entitlement IDs do not exist".to_string());
                }
            }
        }

        // Validate workflow types
        if let Some(ref wf_types) = input.workflow_types {
            let valid_types = ["access_request", "certification", "state_transition"];
            for wf_type in wf_types {
                if !valid_types.contains(&wf_type.as_str()) {
                    errors.push(format!("Invalid workflow type: {wf_type}"));
                }
            }
        }

        Ok(errors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_scope() -> GovDelegationScope {
        GovDelegationScope {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            application_ids: vec![],
            entitlement_ids: vec![],
            role_ids: vec![],
            workflow_types: vec![],
            created_at: Utc::now(),
        }
    }

    #[test]
    fn test_empty_scope_is_full_delegation() {
        let scope = make_test_scope();
        assert!(scope.is_empty());

        // Empty scope matches everything
        assert!(scope.matches_work_item(Some(Uuid::new_v4()), None, None, None));
        assert!(scope.matches_work_item(None, None, None, Some("access_request")));
    }

    #[test]
    fn test_application_scope_match() {
        let app_id = Uuid::new_v4();
        let mut scope = make_test_scope();
        scope.application_ids = vec![app_id];

        assert!(!scope.is_empty());

        // Matches when application ID is in scope
        assert!(scope.matches_work_item(Some(app_id), None, None, None));

        // Doesn't match when application ID is not in scope
        assert!(!scope.matches_work_item(Some(Uuid::new_v4()), None, None, None));

        // Doesn't match when no application ID provided and scope has restrictions
        assert!(!scope.matches_work_item(None, None, None, None));
    }

    #[test]
    fn test_entitlement_scope_match() {
        let ent_id = Uuid::new_v4();
        let mut scope = make_test_scope();
        scope.entitlement_ids = vec![ent_id];

        assert!(scope.matches_work_item(None, Some(ent_id), None, None));
        assert!(!scope.matches_work_item(None, Some(Uuid::new_v4()), None, None));
    }

    #[test]
    fn test_workflow_type_scope_match() {
        let mut scope = make_test_scope();
        scope.workflow_types = vec!["access_request".to_string()];

        assert!(scope.matches_work_item(None, None, None, Some("access_request")));
        assert!(!scope.matches_work_item(None, None, None, Some("certification")));
    }

    #[test]
    fn test_or_semantics() {
        let app_id = Uuid::new_v4();
        let ent_id = Uuid::new_v4();
        let mut scope = make_test_scope();
        scope.application_ids = vec![app_id];
        scope.entitlement_ids = vec![ent_id];

        // Matches if either criterion matches (OR semantics)
        assert!(scope.matches_work_item(Some(app_id), None, None, None));
        assert!(scope.matches_work_item(None, Some(ent_id), None, None));
        assert!(scope.matches_work_item(Some(app_id), Some(ent_id), None, None));

        // Doesn't match if neither matches
        assert!(!scope.matches_work_item(Some(Uuid::new_v4()), Some(Uuid::new_v4()), None, None));
    }

    #[test]
    fn test_create_scope_input_default() {
        let input = CreateGovDelegationScope::default();

        assert!(input.application_ids.is_none());
        assert!(input.entitlement_ids.is_none());
        assert!(input.role_ids.is_none());
        assert!(input.workflow_types.is_none());
    }
}
