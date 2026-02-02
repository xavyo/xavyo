//! Approval group service for governance API (F054).

use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::models::{
    ApprovalGroupFilter, CreateApprovalGroup, GovApprovalGroup, UpdateApprovalGroup,
};
use xavyo_governance::error::{GovernanceError, Result};

/// Service for approval group operations.
pub struct ApprovalGroupService {
    pool: PgPool,
}

impl ApprovalGroupService {
    /// Create a new approval group service.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// List approval groups for a tenant with pagination and filtering.
    pub async fn list_groups(
        &self,
        tenant_id: Uuid,
        is_active: Option<bool>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<GovApprovalGroup>, i64)> {
        let filter = ApprovalGroupFilter {
            is_active,
            member_id: None,
        };

        let groups =
            GovApprovalGroup::list_by_tenant(&self.pool, tenant_id, &filter, limit, offset)
                .await
                .map_err(GovernanceError::Database)?;

        let total = GovApprovalGroup::count_by_tenant(&self.pool, tenant_id, &filter)
            .await
            .map_err(GovernanceError::Database)?;

        Ok((groups, total))
    }

    /// Get an approval group by ID.
    pub async fn get_group(&self, tenant_id: Uuid, group_id: Uuid) -> Result<GovApprovalGroup> {
        GovApprovalGroup::find_by_id(&self.pool, tenant_id, group_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::ApprovalGroupNotFound(group_id))
    }

    /// Create a new approval group.
    pub async fn create_group(
        &self,
        tenant_id: Uuid,
        input: CreateApprovalGroup,
    ) -> Result<GovApprovalGroup> {
        // Validate name
        if input.name.trim().is_empty() {
            return Err(GovernanceError::Validation(
                "Group name cannot be empty".to_string(),
            ));
        }

        if input.name.len() > 255 {
            return Err(GovernanceError::Validation(
                "Group name cannot exceed 255 characters".to_string(),
            ));
        }

        // Check for duplicate name
        if GovApprovalGroup::find_by_name(&self.pool, tenant_id, &input.name)
            .await
            .map_err(GovernanceError::Database)?
            .is_some()
        {
            return Err(GovernanceError::ApprovalGroupNameExists(input.name.clone()));
        }

        GovApprovalGroup::create(&self.pool, tenant_id, input)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Update an approval group.
    pub async fn update_group(
        &self,
        tenant_id: Uuid,
        group_id: Uuid,
        input: UpdateApprovalGroup,
    ) -> Result<GovApprovalGroup> {
        // Validate name if provided
        if let Some(ref name) = input.name {
            if name.trim().is_empty() {
                return Err(GovernanceError::Validation(
                    "Group name cannot be empty".to_string(),
                ));
            }

            // Check for duplicate name (excluding current)
            if let Some(existing) =
                GovApprovalGroup::find_by_name(&self.pool, tenant_id, name).await?
            {
                if existing.id != group_id {
                    return Err(GovernanceError::ApprovalGroupNameExists(name.clone()));
                }
            }
        }

        GovApprovalGroup::update(&self.pool, tenant_id, group_id, input)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::ApprovalGroupNotFound(group_id))
    }

    /// Delete an approval group.
    ///
    /// Returns an error if the group is currently in use by escalation rules.
    pub async fn delete_group(&self, tenant_id: Uuid, group_id: Uuid) -> Result<bool> {
        // Check if in use
        if GovApprovalGroup::is_in_use(&self.pool, tenant_id, group_id)
            .await
            .map_err(GovernanceError::Database)?
        {
            return Err(GovernanceError::ApprovalGroupInUse(group_id));
        }

        GovApprovalGroup::delete(&self.pool, tenant_id, group_id)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Add members to an approval group.
    pub async fn add_members(
        &self,
        tenant_id: Uuid,
        group_id: Uuid,
        member_ids: Vec<Uuid>,
    ) -> Result<GovApprovalGroup> {
        // Verify group exists
        self.get_group(tenant_id, group_id).await?;

        GovApprovalGroup::add_members(&self.pool, tenant_id, group_id, &member_ids)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::ApprovalGroupNotFound(group_id))
    }

    /// Remove members from an approval group.
    pub async fn remove_members(
        &self,
        tenant_id: Uuid,
        group_id: Uuid,
        member_ids: Vec<Uuid>,
    ) -> Result<GovApprovalGroup> {
        // Verify group exists
        self.get_group(tenant_id, group_id).await?;

        GovApprovalGroup::remove_members(&self.pool, tenant_id, group_id, &member_ids)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::ApprovalGroupNotFound(group_id))
    }

    /// Get groups that contain a specific user as a member.
    pub async fn get_groups_for_user(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<GovApprovalGroup>> {
        let filter = ApprovalGroupFilter {
            is_active: Some(true), // Only active groups
            member_id: Some(user_id),
        };

        GovApprovalGroup::list_by_tenant(&self.pool, tenant_id, &filter, i64::MAX, 0)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Enable an approval group.
    pub async fn enable_group(&self, tenant_id: Uuid, group_id: Uuid) -> Result<GovApprovalGroup> {
        let input = UpdateApprovalGroup {
            name: None,
            description: None,
            is_active: Some(true),
        };

        GovApprovalGroup::update(&self.pool, tenant_id, group_id, input)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::ApprovalGroupNotFound(group_id))
    }

    /// Disable an approval group.
    pub async fn disable_group(&self, tenant_id: Uuid, group_id: Uuid) -> Result<GovApprovalGroup> {
        let input = UpdateApprovalGroup {
            name: None,
            description: None,
            is_active: Some(false),
        };

        GovApprovalGroup::update(&self.pool, tenant_id, group_id, input)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::ApprovalGroupNotFound(group_id))
    }
}
