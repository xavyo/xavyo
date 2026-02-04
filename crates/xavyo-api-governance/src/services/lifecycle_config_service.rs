//! Lifecycle configuration service for Object Lifecycle States (F052).
//!
//! This service manages lifecycle configurations, including states and transitions.

use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::{
    CreateGovLifecycleConfig, CreateGovLifecycleState, CreateGovLifecycleTransition,
    GovLifecycleConfig, GovLifecycleState, GovLifecycleTransition,
    GovLifecycleTransitionWithStates, LifecycleConfigFilter, UpdateGovLifecycleConfig,
    UpdateGovLifecycleState,
};
use xavyo_governance::error::{GovernanceError, Result};

use crate::models::{
    CreateLifecycleConfigRequest, CreateLifecycleStateRequest, CreateLifecycleTransitionRequest,
    LifecycleConfigDetailResponse, LifecycleConfigListResponse, LifecycleConfigResponse,
    LifecycleStateResponse, LifecycleTransitionResponse, ListLifecycleConfigsQuery,
    UpdateLifecycleConfigRequest, UpdateLifecycleStateRequest,
};

/// Service for lifecycle configuration operations.
pub struct LifecycleConfigService {
    pool: PgPool,
}

impl LifecycleConfigService {
    /// Create a new lifecycle config service.
    #[must_use] 
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// List lifecycle configurations with filtering and pagination.
    pub async fn list_configs(
        &self,
        tenant_id: Uuid,
        params: &ListLifecycleConfigsQuery,
    ) -> Result<LifecycleConfigListResponse> {
        let filter = LifecycleConfigFilter {
            object_type: params.object_type,
            is_active: params.is_active,
        };

        let limit = params.limit.unwrap_or(50).min(100);
        let offset = params.offset.unwrap_or(0);

        let configs =
            GovLifecycleConfig::list_by_tenant(&self.pool, tenant_id, &filter, limit, offset)
                .await?;
        let total = GovLifecycleConfig::count_by_tenant(&self.pool, tenant_id, &filter).await?;

        let mut items = Vec::new();
        for config in configs {
            let state_count =
                GovLifecycleState::count_by_config(&self.pool, tenant_id, config.id).await?;
            let transition_count =
                GovLifecycleTransition::count_by_config(&self.pool, tenant_id, config.id).await?;

            items.push(LifecycleConfigResponse {
                id: config.id,
                name: config.name,
                object_type: config.object_type,
                description: config.description,
                is_active: config.is_active,
                auto_assign_initial_state: config.auto_assign_initial_state,
                state_count,
                transition_count,
                created_at: config.created_at,
                updated_at: config.updated_at,
            });
        }

        Ok(LifecycleConfigListResponse {
            items,
            total,
            limit,
            offset,
        })
    }

    /// Get a lifecycle configuration by ID.
    pub async fn get_config(
        &self,
        tenant_id: Uuid,
        config_id: Uuid,
    ) -> Result<LifecycleConfigDetailResponse> {
        let config = GovLifecycleConfig::find_by_id(&self.pool, tenant_id, config_id)
            .await?
            .ok_or(GovernanceError::LifecycleConfigNotFound(config_id))?;

        let states = GovLifecycleState::list_by_config(&self.pool, tenant_id, config_id).await?;
        let transitions: Vec<GovLifecycleTransitionWithStates> =
            GovLifecycleTransition::list_by_config_with_states(&self.pool, tenant_id, config_id)
                .await?;

        let state_count = states.len() as i64;
        let transition_count = transitions.len() as i64;

        let mut state_responses = Vec::new();
        for state in states {
            let object_count =
                GovLifecycleState::count_objects_in_state(&self.pool, tenant_id, state.id).await?;
            state_responses.push(LifecycleStateResponse::from_model(state, object_count));
        }

        Ok(LifecycleConfigDetailResponse {
            config: LifecycleConfigResponse {
                id: config.id,
                name: config.name,
                object_type: config.object_type,
                description: config.description,
                is_active: config.is_active,
                auto_assign_initial_state: config.auto_assign_initial_state,
                state_count,
                transition_count,
                created_at: config.created_at,
                updated_at: config.updated_at,
            },
            states: state_responses,
            transitions: transitions
                .into_iter()
                .map(LifecycleTransitionResponse::from)
                .collect(),
        })
    }

    /// Create a new lifecycle configuration.
    pub async fn create_config(
        &self,
        tenant_id: Uuid,
        request: CreateLifecycleConfigRequest,
    ) -> Result<LifecycleConfigResponse> {
        // Check for existing config for same object type
        if GovLifecycleConfig::find_by_object_type(&self.pool, tenant_id, request.object_type)
            .await?
            .is_some()
        {
            return Err(GovernanceError::LifecycleConfigAlreadyExists(format!(
                "{:?}",
                request.object_type
            )));
        }

        let input = CreateGovLifecycleConfig {
            name: request.name,
            description: request.description,
            object_type: request.object_type,
            auto_assign_initial_state: request.auto_assign_initial_state,
        };

        let config = GovLifecycleConfig::create(&self.pool, tenant_id, &input).await?;

        Ok(LifecycleConfigResponse {
            id: config.id,
            name: config.name,
            object_type: config.object_type,
            description: config.description,
            is_active: config.is_active,
            auto_assign_initial_state: config.auto_assign_initial_state,
            state_count: 0,
            transition_count: 0,
            created_at: config.created_at,
            updated_at: config.updated_at,
        })
    }

    /// Update a lifecycle configuration.
    pub async fn update_config(
        &self,
        tenant_id: Uuid,
        config_id: Uuid,
        request: UpdateLifecycleConfigRequest,
    ) -> Result<LifecycleConfigResponse> {
        let input = UpdateGovLifecycleConfig {
            name: request.name,
            description: request.description,
            is_active: request.is_active,
            auto_assign_initial_state: request.auto_assign_initial_state,
        };

        let config = GovLifecycleConfig::update(&self.pool, tenant_id, config_id, &input)
            .await?
            .ok_or(GovernanceError::LifecycleConfigNotFound(config_id))?;

        let state_count =
            GovLifecycleState::count_by_config(&self.pool, tenant_id, config_id).await?;
        let transition_count =
            GovLifecycleTransition::count_by_config(&self.pool, tenant_id, config_id).await?;

        Ok(LifecycleConfigResponse {
            id: config.id,
            name: config.name,
            object_type: config.object_type,
            description: config.description,
            is_active: config.is_active,
            auto_assign_initial_state: config.auto_assign_initial_state,
            state_count,
            transition_count,
            created_at: config.created_at,
            updated_at: config.updated_at,
        })
    }

    /// Delete a lifecycle configuration.
    pub async fn delete_config(&self, tenant_id: Uuid, config_id: Uuid) -> Result<()> {
        let deleted = GovLifecycleConfig::delete(&self.pool, tenant_id, config_id).await?;
        if !deleted {
            return Err(GovernanceError::LifecycleConfigNotFound(config_id));
        }
        Ok(())
    }

    /// Add a state to a lifecycle configuration.
    pub async fn add_state(
        &self,
        tenant_id: Uuid,
        config_id: Uuid,
        request: CreateLifecycleStateRequest,
    ) -> Result<LifecycleStateResponse> {
        // Verify config exists
        let _ = GovLifecycleConfig::find_by_id(&self.pool, tenant_id, config_id)
            .await?
            .ok_or(GovernanceError::LifecycleConfigNotFound(config_id))?;

        // If this is set as initial, clear existing initial flag
        if request.is_initial {
            GovLifecycleState::clear_initial_flag(&self.pool, tenant_id, config_id).await?;
        }

        let input = CreateGovLifecycleState {
            name: request.name,
            description: request.description,
            is_initial: request.is_initial,
            is_terminal: request.is_terminal,
            entitlement_action: request.entitlement_action,
            position: request.position,
        };

        let state = GovLifecycleState::create(&self.pool, tenant_id, config_id, &input).await?;
        Ok(LifecycleStateResponse::from_model(state, 0))
    }

    /// Update a lifecycle state.
    pub async fn update_state(
        &self,
        tenant_id: Uuid,
        config_id: Uuid,
        state_id: Uuid,
        request: UpdateLifecycleStateRequest,
    ) -> Result<LifecycleStateResponse> {
        // Verify state belongs to config
        let existing = GovLifecycleState::find_by_id(&self.pool, tenant_id, state_id)
            .await?
            .ok_or(GovernanceError::LifecycleStateNotFound(state_id))?;

        if existing.config_id != config_id {
            return Err(GovernanceError::LifecycleStateNotFound(state_id));
        }

        // If setting as initial, clear existing initial flag
        if request.is_initial == Some(true) {
            GovLifecycleState::clear_initial_flag(&self.pool, tenant_id, config_id).await?;
        }

        let input = UpdateGovLifecycleState {
            name: request.name,
            description: request.description,
            is_initial: request.is_initial,
            is_terminal: request.is_terminal,
            entitlement_action: request.entitlement_action,
            position: request.position,
        };

        let state = GovLifecycleState::update(&self.pool, tenant_id, state_id, &input)
            .await?
            .ok_or(GovernanceError::LifecycleStateNotFound(state_id))?;

        let object_count =
            GovLifecycleState::count_objects_in_state(&self.pool, tenant_id, state_id).await?;
        Ok(LifecycleStateResponse::from_model(state, object_count))
    }

    /// Delete a lifecycle state.
    pub async fn delete_state(
        &self,
        tenant_id: Uuid,
        config_id: Uuid,
        state_id: Uuid,
    ) -> Result<()> {
        // Verify state belongs to config
        let existing = GovLifecycleState::find_by_id(&self.pool, tenant_id, state_id)
            .await?
            .ok_or(GovernanceError::LifecycleStateNotFound(state_id))?;

        if existing.config_id != config_id {
            return Err(GovernanceError::LifecycleStateNotFound(state_id));
        }

        // Check if objects are in this state
        let object_count =
            GovLifecycleState::count_objects_in_state(&self.pool, tenant_id, state_id).await?;
        if object_count > 0 {
            return Err(GovernanceError::LifecycleStateHasObjects(
                state_id.to_string(),
                object_count,
            ));
        }

        let deleted = GovLifecycleState::delete(&self.pool, tenant_id, state_id).await?;
        if !deleted {
            return Err(GovernanceError::LifecycleStateNotFound(state_id));
        }
        Ok(())
    }

    /// Add a transition to a lifecycle configuration.
    pub async fn add_transition(
        &self,
        tenant_id: Uuid,
        config_id: Uuid,
        request: CreateLifecycleTransitionRequest,
    ) -> Result<LifecycleTransitionResponse> {
        // Verify config exists
        let _ = GovLifecycleConfig::find_by_id(&self.pool, tenant_id, config_id)
            .await?
            .ok_or(GovernanceError::LifecycleConfigNotFound(config_id))?;

        // Verify source state exists
        let from_state =
            GovLifecycleState::find_by_id(&self.pool, tenant_id, request.from_state_id)
                .await?
                .ok_or(GovernanceError::LifecycleStateNotFound(
                    request.from_state_id,
                ))?;

        if from_state.config_id != config_id {
            return Err(GovernanceError::LifecycleStateNotFound(
                request.from_state_id,
            ));
        }

        // Verify target state exists
        let to_state = GovLifecycleState::find_by_id(&self.pool, tenant_id, request.to_state_id)
            .await?
            .ok_or(GovernanceError::LifecycleStateNotFound(request.to_state_id))?;

        if to_state.config_id != config_id {
            return Err(GovernanceError::LifecycleStateNotFound(request.to_state_id));
        }

        let input = CreateGovLifecycleTransition {
            name: request.name,
            from_state_id: request.from_state_id,
            to_state_id: request.to_state_id,
            requires_approval: request.requires_approval,
            approval_workflow_id: request.approval_workflow_id,
            grace_period_hours: request.grace_period_hours,
        };

        let transition =
            GovLifecycleTransition::create(&self.pool, tenant_id, config_id, &input).await?;

        Ok(LifecycleTransitionResponse {
            id: transition.id,
            name: transition.name,
            from_state_id: transition.from_state_id,
            from_state_name: from_state.name,
            to_state_id: transition.to_state_id,
            to_state_name: to_state.name,
            requires_approval: transition.requires_approval,
            approval_workflow_id: transition.approval_workflow_id,
            grace_period_hours: transition.grace_period_hours,
            created_at: transition.created_at,
        })
    }

    /// Delete a transition.
    pub async fn delete_transition(
        &self,
        tenant_id: Uuid,
        config_id: Uuid,
        transition_id: Uuid,
    ) -> Result<()> {
        // Verify transition belongs to config
        let existing = GovLifecycleTransition::find_by_id(&self.pool, tenant_id, transition_id)
            .await?
            .ok_or(GovernanceError::LifecycleTransitionNotFound(transition_id))?;

        if existing.config_id != config_id {
            return Err(GovernanceError::LifecycleTransitionNotFound(transition_id));
        }

        let deleted = GovLifecycleTransition::delete(&self.pool, tenant_id, transition_id).await?;
        if !deleted {
            return Err(GovernanceError::LifecycleTransitionNotFound(transition_id));
        }
        Ok(())
    }
}
