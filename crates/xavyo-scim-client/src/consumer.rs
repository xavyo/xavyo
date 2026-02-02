//! Kafka event consumer for SCIM outbound provisioning.
//!
//! Listens for user and group lifecycle events on Kafka topics and dispatches
//! SCIM provisioning operations to all active SCIM targets for the tenant.

use async_trait::async_trait;
use sqlx::PgPool;
use std::sync::Arc;
use tracing::{error, info, warn};
use uuid::Uuid;
use xavyo_connector::crypto::CredentialEncryption;
use xavyo_db::models::{ScimProvisioningState, ScimTarget, ScimTargetAttributeMapping};
use xavyo_events::consumer::EventConsumer;
use xavyo_events::events::{
    GroupCreated, GroupDeleted, GroupMemberAdded, GroupMemberRemoved, UserCreated, UserDeleted,
    UserUpdated,
};

use crate::client::ScimClient;
use crate::provisioner::Provisioner;
use crate::retry::RetryPolicy;

/// Handles `UserCreated` events by provisioning the new user to all active
/// SCIM targets for the tenant.
pub struct ScimUserCreatedHandler {
    pool: PgPool,
    encryption: Arc<CredentialEncryption>,
    provisioner: Arc<Provisioner>,
}

impl ScimUserCreatedHandler {
    /// Create a new handler.
    pub fn new(
        pool: PgPool,
        encryption: Arc<CredentialEncryption>,
        provisioner: Arc<Provisioner>,
    ) -> Self {
        Self {
            pool,
            encryption,
            provisioner,
        }
    }
}

#[async_trait]
impl xavyo_events::consumer::EventHandler<UserCreated> for ScimUserCreatedHandler {
    async fn handle(
        &self,
        event: UserCreated,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // The event doesn't carry tenant_id in its payload; it's in the
        // EventEnvelope which has already been unpacked by TypedConsumer.
        // We look up active targets and use their tenant_id for isolation.
        // For user events, the user_id is sufficient to find the user and
        // their tenant from the database.
        let user = match xavyo_db::models::User::find_by_id(&self.pool, event.user_id).await {
            Ok(Some(u)) => u,
            Ok(None) => {
                warn!(user_id = %event.user_id, "User not found for SCIM provisioning, skipping");
                return Ok(());
            }
            Err(e) => {
                error!(user_id = %event.user_id, error = %e, "Failed to look up user");
                return Err(Box::new(e));
            }
        };

        let tenant_id = user.tenant_id;

        let targets = match ScimTarget::find_active_by_tenant(&self.pool, tenant_id).await {
            Ok(t) => t,
            Err(e) => {
                error!(tenant_id = %tenant_id, error = %e, "Failed to look up active SCIM targets");
                return Err(Box::new(e));
            }
        };

        if targets.is_empty() {
            return Ok(());
        }

        info!(
            user_id = %event.user_id,
            tenant_id = %tenant_id,
            target_count = targets.len(),
            "Provisioning user creation to SCIM targets"
        );

        for target in &targets {
            let client = match build_client(target, &self.encryption, tenant_id) {
                Ok(c) => c,
                Err(e) => {
                    error!(
                        target_id = %target.id,
                        target_name = %target.name,
                        error = %e,
                        "Failed to build SCIM client, skipping target"
                    );
                    continue;
                }
            };

            let mappings =
                ScimTargetAttributeMapping::list_by_target(&self.pool, tenant_id, target.id, None)
                    .await
                    .unwrap_or_default();

            if let Err(e) = self
                .provisioner
                .provision_user_create(
                    &client,
                    tenant_id,
                    target.id,
                    event.user_id,
                    Some(&event.email),
                    event.display_name.as_deref(),
                    user.first_name.as_deref(),
                    user.last_name.as_deref(),
                    true, // new users are active
                    &mappings,
                )
                .await
            {
                error!(
                    target_id = %target.id,
                    user_id = %event.user_id,
                    error = %e,
                    "Failed to provision user creation to SCIM target"
                );
                // Continue to next target — don't fail the entire event.
            }
        }

        Ok(())
    }
}

/// Handles `UserUpdated` events by pushing attribute changes to all active
/// SCIM targets for the tenant.
pub struct ScimUserUpdatedHandler {
    pool: PgPool,
    encryption: Arc<CredentialEncryption>,
    provisioner: Arc<Provisioner>,
}

impl ScimUserUpdatedHandler {
    /// Create a new handler.
    pub fn new(
        pool: PgPool,
        encryption: Arc<CredentialEncryption>,
        provisioner: Arc<Provisioner>,
    ) -> Self {
        Self {
            pool,
            encryption,
            provisioner,
        }
    }
}

#[async_trait]
impl xavyo_events::consumer::EventHandler<UserUpdated> for ScimUserUpdatedHandler {
    async fn handle(
        &self,
        event: UserUpdated,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let user = match xavyo_db::models::User::find_by_id(&self.pool, event.user_id).await {
            Ok(Some(u)) => u,
            Ok(None) => {
                warn!(user_id = %event.user_id, "User not found for SCIM update, skipping");
                return Ok(());
            }
            Err(e) => {
                error!(user_id = %event.user_id, error = %e, "Failed to look up user");
                return Err(Box::new(e));
            }
        };

        let tenant_id = user.tenant_id;

        // Convert changes HashMap<String, Value> to Vec<(String, Option<String>)>.
        let changed_fields: Vec<(String, Option<String>)> = event
            .changes
            .iter()
            .map(|(field, value)| {
                let str_value = match value {
                    serde_json::Value::String(s) => Some(s.clone()),
                    serde_json::Value::Bool(b) => Some(b.to_string()),
                    serde_json::Value::Number(n) => Some(n.to_string()),
                    serde_json::Value::Null => None,
                    other => Some(other.to_string()),
                };
                (field.clone(), str_value)
            })
            .collect();

        if changed_fields.is_empty() {
            return Ok(());
        }

        let targets = match ScimTarget::find_active_by_tenant(&self.pool, tenant_id).await {
            Ok(t) => t,
            Err(e) => {
                error!(tenant_id = %tenant_id, error = %e, "Failed to look up active SCIM targets");
                return Err(Box::new(e));
            }
        };

        if targets.is_empty() {
            return Ok(());
        }

        info!(
            user_id = %event.user_id,
            tenant_id = %tenant_id,
            field_count = changed_fields.len(),
            target_count = targets.len(),
            "Provisioning user update to SCIM targets"
        );

        for target in &targets {
            let client = match build_client(target, &self.encryption, tenant_id) {
                Ok(c) => c,
                Err(e) => {
                    error!(
                        target_id = %target.id,
                        error = %e,
                        "Failed to build SCIM client, skipping target"
                    );
                    continue;
                }
            };

            let mappings =
                ScimTargetAttributeMapping::list_by_target(&self.pool, tenant_id, target.id, None)
                    .await
                    .unwrap_or_default();

            if let Err(e) = self
                .provisioner
                .provision_user_update(
                    &client,
                    tenant_id,
                    target.id,
                    event.user_id,
                    &changed_fields,
                    &mappings,
                )
                .await
            {
                error!(
                    target_id = %target.id,
                    user_id = %event.user_id,
                    error = %e,
                    "Failed to provision user update to SCIM target"
                );
            }
        }

        Ok(())
    }
}

/// Handles `UserDeleted` events by deprovisioning the user from all active
/// SCIM targets for the tenant.
pub struct ScimUserDeletedHandler {
    pool: PgPool,
    encryption: Arc<CredentialEncryption>,
    provisioner: Arc<Provisioner>,
}

impl ScimUserDeletedHandler {
    /// Create a new handler.
    pub fn new(
        pool: PgPool,
        encryption: Arc<CredentialEncryption>,
        provisioner: Arc<Provisioner>,
    ) -> Self {
        Self {
            pool,
            encryption,
            provisioner,
        }
    }
}

#[async_trait]
impl xavyo_events::consumer::EventHandler<UserDeleted> for ScimUserDeletedHandler {
    async fn handle(
        &self,
        event: UserDeleted,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Try to look up the user — it may already be deleted from the DB.
        //
        // NOTE: The EventHandler trait only receives the inner event, not the
        // EventEnvelope which carries tenant_id.  If the user record is already
        // deleted AND RLS prevents the fallback provisioning-state lookup (which
        // queries without tenant_id context), deprovisioning will be skipped
        // gracefully.  This is a known limitation of the consumer architecture —
        // fixing it requires extending EventHandler to pass envelope metadata.
        let tenant_id = match xavyo_db::models::User::find_by_id(&self.pool, event.user_id).await {
            Ok(Some(u)) => u.tenant_id,
            Ok(None) => {
                // User record is already gone. Derive tenant_id from
                // existing provisioning states for this user.
                match ScimProvisioningState::find_by_internal_resource_id(
                    &self.pool,
                    "User",
                    event.user_id,
                )
                .await
                {
                    Ok(states) if !states.is_empty() => states[0].tenant_id,
                    Ok(_) => {
                        warn!(user_id = %event.user_id, "No provisioning states found for deleted user — user may remain on SCIM targets as orphan");
                        return Ok(());
                    }
                    Err(e) => {
                        error!(user_id = %event.user_id, error = %e, "Failed to look up provisioning states for deleted user");
                        return Err(Box::new(e));
                    }
                }
            }
            Err(e) => {
                error!(user_id = %event.user_id, error = %e, "Failed to look up user");
                return Err(Box::new(e));
            }
        };

        let targets = match ScimTarget::find_active_by_tenant(&self.pool, tenant_id).await {
            Ok(t) => t,
            Err(e) => {
                error!(tenant_id = %tenant_id, error = %e, "Failed to look up active SCIM targets");
                return Err(Box::new(e));
            }
        };

        if targets.is_empty() {
            return Ok(());
        }

        info!(
            user_id = %event.user_id,
            tenant_id = %tenant_id,
            target_count = targets.len(),
            "Deprovisioning user from SCIM targets"
        );

        for target in &targets {
            let client = match build_client(target, &self.encryption, tenant_id) {
                Ok(c) => c,
                Err(e) => {
                    error!(
                        target_id = %target.id,
                        error = %e,
                        "Failed to build SCIM client, skipping target"
                    );
                    continue;
                }
            };

            if let Err(e) = self
                .provisioner
                .provision_user_deprovision(
                    &client,
                    tenant_id,
                    target.id,
                    event.user_id,
                    &target.deprovisioning_strategy,
                )
                .await
            {
                error!(
                    target_id = %target.id,
                    user_id = %event.user_id,
                    error = %e,
                    "Failed to deprovision user from SCIM target"
                );
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Group event handlers (F087 - US3)
// ---------------------------------------------------------------------------

/// Handles `GroupCreated` events by provisioning the new group to all active
/// SCIM targets for the tenant.
pub struct ScimGroupCreatedHandler {
    pool: PgPool,
    encryption: Arc<CredentialEncryption>,
    provisioner: Arc<Provisioner>,
}

impl ScimGroupCreatedHandler {
    pub fn new(
        pool: PgPool,
        encryption: Arc<CredentialEncryption>,
        provisioner: Arc<Provisioner>,
    ) -> Self {
        Self {
            pool,
            encryption,
            provisioner,
        }
    }
}

#[async_trait]
impl xavyo_events::consumer::EventHandler<GroupCreated> for ScimGroupCreatedHandler {
    async fn handle(
        &self,
        event: GroupCreated,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let group = match xavyo_db::models::Group::find_by_id_only(&self.pool, event.group_id).await
        {
            Ok(Some(g)) => g,
            Ok(None) => {
                warn!(group_id = %event.group_id, "Group not found for SCIM provisioning, skipping");
                return Ok(());
            }
            Err(e) => {
                error!(group_id = %event.group_id, error = %e, "Failed to look up group");
                return Err(Box::new(e));
            }
        };

        let tenant_id = group.tenant_id;

        let targets = match ScimTarget::find_active_by_tenant(&self.pool, tenant_id).await {
            Ok(t) => t,
            Err(e) => {
                error!(tenant_id = %tenant_id, error = %e, "Failed to look up active SCIM targets");
                return Err(Box::new(e));
            }
        };

        if targets.is_empty() {
            return Ok(());
        }

        info!(
            group_id = %event.group_id,
            tenant_id = %tenant_id,
            target_count = targets.len(),
            member_count = event.member_ids.len(),
            "Provisioning group creation to SCIM targets"
        );

        for target in &targets {
            let client = match build_client(target, &self.encryption, tenant_id) {
                Ok(c) => c,
                Err(e) => {
                    error!(target_id = %target.id, error = %e, "Failed to build SCIM client, skipping target");
                    continue;
                }
            };

            // Look up external resource IDs for member users on this specific target.
            let member_external_ids = get_member_external_ids_for_target(
                &self.pool,
                tenant_id,
                target.id,
                &event.member_ids,
            )
            .await;

            if let Err(e) = self
                .provisioner
                .provision_group_create(
                    &client,
                    tenant_id,
                    target.id,
                    event.group_id,
                    &event.display_name,
                    &member_external_ids,
                )
                .await
            {
                error!(target_id = %target.id, group_id = %event.group_id, error = %e, "Failed to provision group creation");
            }
        }

        Ok(())
    }
}

/// Handles `GroupDeleted` events by deprovisioning the group from all active
/// SCIM targets for the tenant.
pub struct ScimGroupDeletedHandler {
    pool: PgPool,
    encryption: Arc<CredentialEncryption>,
    provisioner: Arc<Provisioner>,
}

impl ScimGroupDeletedHandler {
    pub fn new(
        pool: PgPool,
        encryption: Arc<CredentialEncryption>,
        provisioner: Arc<Provisioner>,
    ) -> Self {
        Self {
            pool,
            encryption,
            provisioner,
        }
    }
}

#[async_trait]
impl xavyo_events::consumer::EventHandler<GroupDeleted> for ScimGroupDeletedHandler {
    async fn handle(
        &self,
        event: GroupDeleted,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Try to look up the group — it may already be deleted from the DB.
        // Same RLS limitation as UserDeleted — see comment in that handler.
        let tenant_id = match xavyo_db::models::Group::find_by_id_only(&self.pool, event.group_id)
            .await
        {
            Ok(Some(g)) => g.tenant_id,
            Ok(None) => {
                // Group record is already gone. Derive tenant_id from
                // existing provisioning states for this group.
                match ScimProvisioningState::find_by_internal_resource_id(
                    &self.pool,
                    "Group",
                    event.group_id,
                )
                .await
                {
                    Ok(states) if !states.is_empty() => states[0].tenant_id,
                    Ok(_) => {
                        warn!(group_id = %event.group_id, "No provisioning states found for deleted group — group may remain on SCIM targets as orphan");
                        return Ok(());
                    }
                    Err(e) => {
                        error!(group_id = %event.group_id, error = %e, "Failed to look up provisioning states for deleted group");
                        return Err(Box::new(e));
                    }
                }
            }
            Err(e) => {
                error!(group_id = %event.group_id, error = %e, "Failed to look up group");
                return Err(Box::new(e));
            }
        };

        let targets = match ScimTarget::find_active_by_tenant(&self.pool, tenant_id).await {
            Ok(t) => t,
            Err(e) => {
                error!(tenant_id = %tenant_id, error = %e, "Failed to look up active SCIM targets");
                return Err(Box::new(e));
            }
        };

        if targets.is_empty() {
            return Ok(());
        }

        info!(
            group_id = %event.group_id,
            tenant_id = %tenant_id,
            target_count = targets.len(),
            "Deprovisioning group from SCIM targets"
        );

        for target in &targets {
            let client = match build_client(target, &self.encryption, tenant_id) {
                Ok(c) => c,
                Err(e) => {
                    error!(target_id = %target.id, error = %e, "Failed to build SCIM client, skipping target");
                    continue;
                }
            };

            if let Err(e) = self
                .provisioner
                .provision_group_delete(&client, tenant_id, target.id, event.group_id)
                .await
            {
                error!(target_id = %target.id, group_id = %event.group_id, error = %e, "Failed to deprovision group");
            }
        }

        Ok(())
    }
}

/// Handles `GroupMemberAdded` events by pushing member add to SCIM targets.
pub struct ScimGroupMemberAddedHandler {
    pool: PgPool,
    encryption: Arc<CredentialEncryption>,
    provisioner: Arc<Provisioner>,
}

impl ScimGroupMemberAddedHandler {
    pub fn new(
        pool: PgPool,
        encryption: Arc<CredentialEncryption>,
        provisioner: Arc<Provisioner>,
    ) -> Self {
        Self {
            pool,
            encryption,
            provisioner,
        }
    }
}

#[async_trait]
impl xavyo_events::consumer::EventHandler<GroupMemberAdded> for ScimGroupMemberAddedHandler {
    async fn handle(
        &self,
        event: GroupMemberAdded,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let group = match xavyo_db::models::Group::find_by_id_only(&self.pool, event.group_id).await
        {
            Ok(Some(g)) => g,
            Ok(None) => {
                warn!(group_id = %event.group_id, "Group not found for SCIM member add, skipping");
                return Ok(());
            }
            Err(e) => {
                error!(group_id = %event.group_id, error = %e, "Failed to look up group");
                return Err(Box::new(e));
            }
        };

        let tenant_id = group.tenant_id;

        let targets = match ScimTarget::find_active_by_tenant(&self.pool, tenant_id).await {
            Ok(t) => t,
            Err(e) => {
                error!(tenant_id = %tenant_id, error = %e, "Failed to look up active SCIM targets");
                return Err(Box::new(e));
            }
        };

        if targets.is_empty() {
            return Ok(());
        }

        for target in &targets {
            let client = match build_client(target, &self.encryption, tenant_id) {
                Ok(c) => c,
                Err(e) => {
                    error!(target_id = %target.id, error = %e, "Failed to build SCIM client, skipping target");
                    continue;
                }
            };

            // Get the member's external resource ID for this specific target.
            let target_member_ids: Vec<String> = get_member_external_ids_for_target(
                &self.pool,
                tenant_id,
                target.id,
                &[event.user_id],
            )
            .await;

            if target_member_ids.is_empty() {
                continue;
            }

            if let Err(e) = self
                .provisioner
                .provision_member_add(
                    &client,
                    tenant_id,
                    target.id,
                    event.group_id,
                    &target_member_ids,
                )
                .await
            {
                error!(target_id = %target.id, group_id = %event.group_id, error = %e, "Failed to add member to group");
            }
        }

        Ok(())
    }
}

/// Handles `GroupMemberRemoved` events by pushing member remove to SCIM targets.
pub struct ScimGroupMemberRemovedHandler {
    pool: PgPool,
    encryption: Arc<CredentialEncryption>,
    provisioner: Arc<Provisioner>,
}

impl ScimGroupMemberRemovedHandler {
    pub fn new(
        pool: PgPool,
        encryption: Arc<CredentialEncryption>,
        provisioner: Arc<Provisioner>,
    ) -> Self {
        Self {
            pool,
            encryption,
            provisioner,
        }
    }
}

#[async_trait]
impl xavyo_events::consumer::EventHandler<GroupMemberRemoved> for ScimGroupMemberRemovedHandler {
    async fn handle(
        &self,
        event: GroupMemberRemoved,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let group = match xavyo_db::models::Group::find_by_id_only(&self.pool, event.group_id).await
        {
            Ok(Some(g)) => g,
            Ok(None) => {
                warn!(group_id = %event.group_id, "Group not found for SCIM member remove, skipping");
                return Ok(());
            }
            Err(e) => {
                error!(group_id = %event.group_id, error = %e, "Failed to look up group");
                return Err(Box::new(e));
            }
        };

        let tenant_id = group.tenant_id;

        let targets = match ScimTarget::find_active_by_tenant(&self.pool, tenant_id).await {
            Ok(t) => t,
            Err(e) => {
                error!(tenant_id = %tenant_id, error = %e, "Failed to look up active SCIM targets");
                return Err(Box::new(e));
            }
        };

        if targets.is_empty() {
            return Ok(());
        }

        for target in &targets {
            let client = match build_client(target, &self.encryption, tenant_id) {
                Ok(c) => c,
                Err(e) => {
                    error!(target_id = %target.id, error = %e, "Failed to build SCIM client, skipping target");
                    continue;
                }
            };

            let target_member_ids: Vec<String> = get_member_external_ids_for_target(
                &self.pool,
                tenant_id,
                target.id,
                &[event.user_id],
            )
            .await;

            if target_member_ids.is_empty() {
                continue;
            }

            if let Err(e) = self
                .provisioner
                .provision_member_remove(
                    &client,
                    tenant_id,
                    target.id,
                    event.group_id,
                    &target_member_ids,
                )
                .await
            {
                error!(target_id = %target.id, group_id = %event.group_id, error = %e, "Failed to remove member from group");
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helpers: look up provisioned external resource IDs for users
// ---------------------------------------------------------------------------

/// Get SCIM external resource IDs for users on a specific target.
async fn get_member_external_ids_for_target(
    pool: &PgPool,
    tenant_id: Uuid,
    target_id: Uuid,
    user_ids: &[Uuid],
) -> Vec<String> {
    let mut ids = Vec::new();
    for user_id in user_ids {
        match ScimProvisioningState::get_by_target_and_resource(
            pool, tenant_id, target_id, "User", *user_id,
        )
        .await
        {
            Ok(Some(state)) => {
                if let Some(ext_id) = state.external_resource_id {
                    ids.push(ext_id);
                }
            }
            Ok(None) => {}
            Err(e) => {
                error!(user_id = %user_id, target_id = %target_id, error = %e, "Failed to look up provisioning state");
            }
        }
    }
    ids
}

// ---------------------------------------------------------------------------
// Helper: build a ScimClient for a target by decrypting credentials
// ---------------------------------------------------------------------------

fn build_client(
    target: &ScimTarget,
    encryption: &CredentialEncryption,
    tenant_id: Uuid,
) -> Result<ScimClient, Box<dyn std::error::Error + Send + Sync>> {
    crate::build_scim_client_from_target(target, encryption, tenant_id)
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })
}

// ---------------------------------------------------------------------------
// Public startup functions — used from idp-api to spawn consumers
// ---------------------------------------------------------------------------

/// Start all SCIM provisioning event consumers as background tasks.
///
/// Spawns seven Kafka consumers: three for user lifecycle events and four for
/// group lifecycle events. Each consumer runs in its own tokio task with an
/// independent consumer group.
pub async fn start_scim_provisioning_consumers(
    pool: PgPool,
    kafka_config: xavyo_events::config::KafkaConfig,
    consumer_group_prefix: &str,
    encryption: Arc<CredentialEncryption>,
) {
    info!("Starting SCIM provisioning event consumers");

    let retry_policy = RetryPolicy::default();
    let provisioner = Arc::new(Provisioner::new(pool.clone(), retry_policy));

    // UserCreated consumer
    {
        let pool = pool.clone();
        let config = kafka_config.clone();
        let encryption = encryption.clone();
        let provisioner = provisioner.clone();
        let group = format!("{consumer_group_prefix}-user-created");

        tokio::spawn(async move {
            if let Err(e) =
                start_user_created_consumer(pool, config, group, encryption, provisioner).await
            {
                error!(error = %e, "SCIM user-created consumer failed");
            }
        });
    }

    // UserUpdated consumer
    {
        let pool = pool.clone();
        let config = kafka_config.clone();
        let encryption = encryption.clone();
        let provisioner = provisioner.clone();
        let group = format!("{consumer_group_prefix}-user-updated");

        tokio::spawn(async move {
            if let Err(e) =
                start_user_updated_consumer(pool, config, group, encryption, provisioner).await
            {
                error!(error = %e, "SCIM user-updated consumer failed");
            }
        });
    }

    // UserDeleted consumer
    {
        let pool = pool.clone();
        let config = kafka_config.clone();
        let encryption = encryption.clone();
        let provisioner = provisioner.clone();
        let group = format!("{consumer_group_prefix}-user-deleted");

        tokio::spawn(async move {
            if let Err(e) =
                start_user_deleted_consumer(pool, config, group, encryption, provisioner).await
            {
                error!(error = %e, "SCIM user-deleted consumer failed");
            }
        });
    }

    // GroupCreated consumer
    {
        let pool = pool.clone();
        let config = kafka_config.clone();
        let encryption = encryption.clone();
        let provisioner = provisioner.clone();
        let group = format!("{consumer_group_prefix}-group-created");

        tokio::spawn(async move {
            if let Err(e) =
                start_group_created_consumer(pool, config, group, encryption, provisioner).await
            {
                error!(error = %e, "SCIM group-created consumer failed");
            }
        });
    }

    // GroupDeleted consumer
    {
        let pool = pool.clone();
        let config = kafka_config.clone();
        let encryption = encryption.clone();
        let provisioner = provisioner.clone();
        let group = format!("{consumer_group_prefix}-group-deleted");

        tokio::spawn(async move {
            if let Err(e) =
                start_group_deleted_consumer(pool, config, group, encryption, provisioner).await
            {
                error!(error = %e, "SCIM group-deleted consumer failed");
            }
        });
    }

    // GroupMemberAdded consumer
    {
        let pool = pool.clone();
        let config = kafka_config.clone();
        let encryption = encryption.clone();
        let provisioner = provisioner.clone();
        let group = format!("{consumer_group_prefix}-group-member-added");

        tokio::spawn(async move {
            if let Err(e) =
                start_group_member_added_consumer(pool, config, group, encryption, provisioner)
                    .await
            {
                error!(error = %e, "SCIM group-member-added consumer failed");
            }
        });
    }

    // GroupMemberRemoved consumer
    {
        let pool = pool.clone();
        let config = kafka_config.clone();
        let encryption = encryption.clone();
        let provisioner = provisioner.clone();
        let group = format!("{consumer_group_prefix}-group-member-removed");

        tokio::spawn(async move {
            if let Err(e) =
                start_group_member_removed_consumer(pool, config, group, encryption, provisioner)
                    .await
            {
                error!(error = %e, "SCIM group-member-removed consumer failed");
            }
        });
    }
}

async fn start_user_created_consumer(
    pool: PgPool,
    config: xavyo_events::config::KafkaConfig,
    consumer_group: String,
    encryption: Arc<CredentialEncryption>,
    provisioner: Arc<Provisioner>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let consumer = EventConsumer::new(config, pool.clone(), consumer_group)?;
    let handler = ScimUserCreatedHandler::new(pool, encryption, provisioner);
    let typed = consumer.subscribe::<UserCreated, _>(handler).await?;
    typed.run().await?;
    Ok(())
}

async fn start_user_updated_consumer(
    pool: PgPool,
    config: xavyo_events::config::KafkaConfig,
    consumer_group: String,
    encryption: Arc<CredentialEncryption>,
    provisioner: Arc<Provisioner>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let consumer = EventConsumer::new(config, pool.clone(), consumer_group)?;
    let handler = ScimUserUpdatedHandler::new(pool, encryption, provisioner);
    let typed = consumer.subscribe::<UserUpdated, _>(handler).await?;
    typed.run().await?;
    Ok(())
}

async fn start_user_deleted_consumer(
    pool: PgPool,
    config: xavyo_events::config::KafkaConfig,
    consumer_group: String,
    encryption: Arc<CredentialEncryption>,
    provisioner: Arc<Provisioner>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let consumer = EventConsumer::new(config, pool.clone(), consumer_group)?;
    let handler = ScimUserDeletedHandler::new(pool, encryption, provisioner);
    let typed = consumer.subscribe::<UserDeleted, _>(handler).await?;
    typed.run().await?;
    Ok(())
}

async fn start_group_created_consumer(
    pool: PgPool,
    config: xavyo_events::config::KafkaConfig,
    consumer_group: String,
    encryption: Arc<CredentialEncryption>,
    provisioner: Arc<Provisioner>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let consumer = EventConsumer::new(config, pool.clone(), consumer_group)?;
    let handler = ScimGroupCreatedHandler::new(pool, encryption, provisioner);
    let typed = consumer.subscribe::<GroupCreated, _>(handler).await?;
    typed.run().await?;
    Ok(())
}

async fn start_group_deleted_consumer(
    pool: PgPool,
    config: xavyo_events::config::KafkaConfig,
    consumer_group: String,
    encryption: Arc<CredentialEncryption>,
    provisioner: Arc<Provisioner>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let consumer = EventConsumer::new(config, pool.clone(), consumer_group)?;
    let handler = ScimGroupDeletedHandler::new(pool, encryption, provisioner);
    let typed = consumer.subscribe::<GroupDeleted, _>(handler).await?;
    typed.run().await?;
    Ok(())
}

async fn start_group_member_added_consumer(
    pool: PgPool,
    config: xavyo_events::config::KafkaConfig,
    consumer_group: String,
    encryption: Arc<CredentialEncryption>,
    provisioner: Arc<Provisioner>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let consumer = EventConsumer::new(config, pool.clone(), consumer_group)?;
    let handler = ScimGroupMemberAddedHandler::new(pool, encryption, provisioner);
    let typed = consumer.subscribe::<GroupMemberAdded, _>(handler).await?;
    typed.run().await?;
    Ok(())
}

async fn start_group_member_removed_consumer(
    pool: PgPool,
    config: xavyo_events::config::KafkaConfig,
    consumer_group: String,
    encryption: Arc<CredentialEncryption>,
    provisioner: Arc<Provisioner>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let consumer = EventConsumer::new(config, pool.clone(), consumer_group)?;
    let handler = ScimGroupMemberRemovedHandler::new(pool, encryption, provisioner);
    let typed = consumer.subscribe::<GroupMemberRemoved, _>(handler).await?;
    typed.run().await?;
    Ok(())
}
