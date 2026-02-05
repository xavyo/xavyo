//! Script Service (F066).
//! CRUD, versioning, and rollback for provisioning scripts.

use sqlx::PgPool;
use uuid::Uuid;
use xavyo_db::models::{
    gov_provisioning_script::{
        CreateProvisioningScript, GovProvisioningScript, ScriptFilter, UpdateProvisioningScript,
    },
    gov_script_hook_binding::GovScriptHookBinding,
    gov_script_types::{GovScriptStatus, MAX_SCRIPT_BODY_SIZE},
    gov_script_version::{CreateScriptVersion, GovScriptVersion},
};
use xavyo_governance::error::{GovernanceError, Result};

/// Service for managing provisioning scripts, versions, and rollbacks.
pub struct ScriptService {
    pool: PgPool,
}

impl ScriptService {
    /// Create a new script service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get the database pool.
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Create a new provisioning script with its initial version.
    ///
    /// Creates the script record and version 1 with the provided script body.
    pub async fn create_script(
        &self,
        tenant_id: Uuid,
        name: String,
        description: Option<String>,
        script_body: String,
        created_by: Uuid,
    ) -> Result<(GovProvisioningScript, GovScriptVersion)> {
        if script_body.len() > MAX_SCRIPT_BODY_SIZE {
            return Err(GovernanceError::ScriptBodyTooLarge(MAX_SCRIPT_BODY_SIZE));
        }

        let params = CreateProvisioningScript {
            tenant_id,
            name,
            description,
            script_body: script_body.clone(),
            created_by,
        };

        let script = GovProvisioningScript::create(&self.pool, params).await?;

        let version_params = CreateScriptVersion {
            tenant_id,
            script_id: script.id,
            version_number: 1,
            script_body,
            change_description: Some("Initial version".to_string()),
            created_by,
        };

        let version = GovScriptVersion::create(&self.pool, &version_params).await?;

        tracing::info!(
            tenant_id = %tenant_id,
            script_id = %script.id,
            script_name = %script.name,
            "Provisioning script created"
        );

        Ok((script, version))
    }

    /// Get a script by ID.
    pub async fn get_script(
        &self,
        tenant_id: Uuid,
        script_id: Uuid,
    ) -> Result<GovProvisioningScript> {
        GovProvisioningScript::get_by_id(&self.pool, script_id, tenant_id)
            .await?
            .ok_or(GovernanceError::ProvisioningScriptNotFound(script_id))
    }

    /// List scripts with filters and pagination.
    pub async fn list_scripts(
        &self,
        tenant_id: Uuid,
        status: Option<GovScriptStatus>,
        search: Option<String>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<GovProvisioningScript>, i64)> {
        let filter = ScriptFilter { status, search };

        let (scripts, total) =
            GovProvisioningScript::list_by_tenant(&self.pool, tenant_id, &filter, limit, offset)
                .await?;

        Ok((scripts, total))
    }

    /// Update script metadata (name, description).
    pub async fn update_script(
        &self,
        tenant_id: Uuid,
        script_id: Uuid,
        name: Option<String>,
        description: Option<String>,
    ) -> Result<GovProvisioningScript> {
        let existing = self.get_script(tenant_id, script_id).await?;

        if existing.is_system {
            return Err(GovernanceError::CannotModifySystemScript(script_id));
        }

        let params = UpdateProvisioningScript { name, description };

        GovProvisioningScript::update_metadata(&self.pool, script_id, tenant_id, params)
            .await?
            .ok_or(GovernanceError::ProvisioningScriptNotFound(script_id))
    }

    /// Update script body, creating a new version.
    pub async fn update_script_body(
        &self,
        tenant_id: Uuid,
        script_id: Uuid,
        script_body: String,
        change_description: Option<String>,
        actor_id: Uuid,
    ) -> Result<GovScriptVersion> {
        if script_body.len() > MAX_SCRIPT_BODY_SIZE {
            return Err(GovernanceError::ScriptBodyTooLarge(MAX_SCRIPT_BODY_SIZE));
        }

        let existing = self.get_script(tenant_id, script_id).await?;
        let new_version_number = existing.current_version + 1;

        let version_params = CreateScriptVersion {
            tenant_id,
            script_id,
            version_number: new_version_number,
            script_body,
            change_description,
            created_by: actor_id,
        };

        let version = GovScriptVersion::create(&self.pool, &version_params).await?;

        GovProvisioningScript::update_current_version(
            &self.pool,
            script_id,
            tenant_id,
            new_version_number,
        )
        .await?;

        Ok(version)
    }

    /// Activate a script (set status to Active).
    pub async fn activate_script(
        &self,
        tenant_id: Uuid,
        script_id: Uuid,
    ) -> Result<GovProvisioningScript> {
        let existing = self.get_script(tenant_id, script_id).await?;

        if existing.status == GovScriptStatus::Active {
            return Err(GovernanceError::ScriptAlreadyInStatus(
                "active".to_string(),
                script_id,
            ));
        }

        GovProvisioningScript::update_status(
            &self.pool,
            script_id,
            tenant_id,
            GovScriptStatus::Active,
        )
        .await?
        .ok_or(GovernanceError::ProvisioningScriptNotFound(script_id))
    }

    /// Deactivate a script (set status to Inactive).
    pub async fn deactivate_script(
        &self,
        tenant_id: Uuid,
        script_id: Uuid,
    ) -> Result<GovProvisioningScript> {
        let existing = self.get_script(tenant_id, script_id).await?;

        if existing.status == GovScriptStatus::Inactive {
            return Err(GovernanceError::ScriptAlreadyInStatus(
                "inactive".to_string(),
                script_id,
            ));
        }

        GovProvisioningScript::update_status(
            &self.pool,
            script_id,
            tenant_id,
            GovScriptStatus::Inactive,
        )
        .await?
        .ok_or(GovernanceError::ProvisioningScriptNotFound(script_id))
    }

    /// Delete a script.
    ///
    /// Checks for active bindings before deletion.
    pub async fn delete_script(&self, tenant_id: Uuid, script_id: Uuid) -> Result<()> {
        let has_bindings =
            GovScriptHookBinding::has_active_bindings(&self.pool, script_id, tenant_id).await?;

        if has_bindings {
            // Count the active bindings for the error message.
            let count: i64 = sqlx::query_scalar(
                r"
                SELECT COUNT(*) FROM gov_script_hook_bindings
                WHERE script_id = $1 AND tenant_id = $2 AND enabled = true
                ",
            )
            .bind(script_id)
            .bind(tenant_id)
            .fetch_one(&self.pool)
            .await?;

            return Err(GovernanceError::ScriptHasActiveBindings(count));
        }

        let deleted = GovProvisioningScript::delete(&self.pool, script_id, tenant_id).await?;

        if !deleted {
            return Err(GovernanceError::ProvisioningScriptNotFound(script_id));
        }

        tracing::info!(
            tenant_id = %tenant_id,
            script_id = %script_id,
            "Provisioning script deleted"
        );

        Ok(())
    }

    /// Get version history for a script.
    ///
    /// Returns all versions ordered by version number descending.
    pub async fn list_versions(
        &self,
        tenant_id: Uuid,
        script_id: Uuid,
    ) -> Result<Vec<GovScriptVersion>> {
        // Validate script exists.
        self.get_script(tenant_id, script_id).await?;

        let versions = GovScriptVersion::list_by_script(&self.pool, script_id, tenant_id).await?;

        Ok(versions)
    }

    /// Get a specific version of a script.
    pub async fn get_version(
        &self,
        tenant_id: Uuid,
        script_id: Uuid,
        version_number: i32,
    ) -> Result<GovScriptVersion> {
        GovScriptVersion::get_by_script_and_version(
            &self.pool,
            script_id,
            version_number,
            tenant_id,
        )
        .await?
        .ok_or(GovernanceError::ScriptVersionNotFound(
            script_id,
            version_number,
        ))
    }

    /// Rollback to a previous version.
    ///
    /// Creates a new version with the content of the target version.
    pub async fn rollback_to_version(
        &self,
        tenant_id: Uuid,
        script_id: Uuid,
        target_version: i32,
        actor_id: Uuid,
        reason: Option<String>,
    ) -> Result<GovScriptVersion> {
        let target = GovScriptVersion::get_by_script_and_version(
            &self.pool,
            script_id,
            target_version,
            tenant_id,
        )
        .await?
        .ok_or(GovernanceError::InvalidRollbackVersion(
            target_version,
            script_id,
        ))?;

        let existing = self.get_script(tenant_id, script_id).await?;
        let new_version_number = existing.current_version + 1;

        let change_description =
            reason.unwrap_or_else(|| format!("Rollback to version {target_version}"));

        let version_params = CreateScriptVersion {
            tenant_id,
            script_id,
            version_number: new_version_number,
            script_body: target.script_body,
            change_description: Some(change_description),
            created_by: actor_id,
        };

        let version = GovScriptVersion::create(&self.pool, &version_params).await?;

        GovProvisioningScript::update_current_version(
            &self.pool,
            script_id,
            tenant_id,
            new_version_number,
        )
        .await?;

        tracing::info!(
            tenant_id = %tenant_id,
            script_id = %script_id,
            target_version = target_version,
            new_version = new_version_number,
            "Script rolled back"
        );

        Ok(version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_script_service_creation() {
        // Verifies the type compiles correctly.
        // Actual service tests require a database connection.
    }
}
