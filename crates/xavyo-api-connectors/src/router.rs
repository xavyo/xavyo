//! Router configuration for connector API.

use axum::{
    routing::{delete, get, post, put},
    Router,
};
use std::sync::Arc;

use crate::handlers;
use crate::services::{
    ConnectorService, MappingService, OperationService, ScheduleService, SchemaService, SyncService,
};
use xavyo_provisioning::{ConflictService, HealthService};

/// Shared state for connector API handlers.
#[derive(Clone)]
pub struct ConnectorState {
    pub connector_service: Arc<ConnectorService>,
    pub schema_service: Arc<SchemaService>,
    pub mapping_service: Arc<MappingService>,
    pub schedule_service: Arc<ScheduleService>,
    pub health_service: Option<Arc<HealthService>>,
}

impl ConnectorState {
    /// Create a new connector state.
    pub fn new(
        connector_service: Arc<ConnectorService>,
        schema_service: Arc<SchemaService>,
        mapping_service: Arc<MappingService>,
        schedule_service: Arc<ScheduleService>,
    ) -> Self {
        Self {
            connector_service,
            schema_service,
            mapping_service,
            schedule_service,
            health_service: None,
        }
    }

    /// Create a new connector state with health service.
    pub fn with_health_service(
        connector_service: Arc<ConnectorService>,
        schema_service: Arc<SchemaService>,
        mapping_service: Arc<MappingService>,
        schedule_service: Arc<ScheduleService>,
        health_service: Arc<HealthService>,
    ) -> Self {
        Self {
            connector_service,
            schema_service,
            mapping_service,
            schedule_service,
            health_service: Some(health_service),
        }
    }
}

/// Create the connector API router.
///
/// # Example
///
/// ```ignore
/// use xavyo_api_connectors::router::{connector_routes, ConnectorState};
///
/// let state = ConnectorState::new(Arc::new(connector_service), Arc::new(schema_service));
/// let app = Router::new()
///     .nest("/api/v1", connector_routes(state));
/// ```
pub fn connector_routes(state: ConnectorState) -> Router {
    Router::new()
        // Connector CRUD (routes are relative to where the router is nested)
        .route("/", get(handlers::list_connectors))
        .route("/", post(handlers::create_connector))
        .route("/:id", get(handlers::get_connector))
        .route("/:id", put(handlers::update_connector))
        .route("/:id", delete(handlers::delete_connector))
        // Connector actions
        .route("/:id/test", post(handlers::test_connector))
        .route("/:id/activate", post(handlers::activate_connector))
        .route("/:id/deactivate", post(handlers::deactivate_connector))
        // Health monitoring
        .route("/:id/health", get(handlers::get_connector_health))
        // Schema discovery
        .route("/:id/schema", get(handlers::get_schema))
        .route("/:id/schema", delete(handlers::clear_schema_cache))
        .route("/:id/schema/discover", post(handlers::discover_schema))
        .route("/:id/schema/:object_class", get(handlers::get_object_class))
        // Attribute mappings
        .route("/:id/mappings", get(handlers::list_mappings))
        .route("/:id/mappings", post(handlers::create_mapping))
        .route("/:id/mappings/:mapping_id", get(handlers::get_mapping))
        .route("/:id/mappings/:mapping_id", put(handlers::update_mapping))
        .route(
            "/:id/mappings/:mapping_id",
            delete(handlers::delete_mapping),
        )
        .route(
            "/:id/mappings/:mapping_id/preview",
            post(handlers::preview_mapping),
        )
        .with_state(state)
}

/// Shared state for operation API handlers.
#[derive(Clone)]
pub struct OperationState {
    pub operation_service: Arc<OperationService>,
    pub conflict_service: Option<Arc<ConflictService>>,
}

impl OperationState {
    /// Create a new operation state.
    pub fn new(operation_service: Arc<OperationService>) -> Self {
        Self {
            operation_service,
            conflict_service: None,
        }
    }

    /// Create a new operation state with conflict service.
    pub fn with_conflict_service(
        operation_service: Arc<OperationService>,
        conflict_service: Arc<ConflictService>,
    ) -> Self {
        Self {
            operation_service,
            conflict_service: Some(conflict_service),
        }
    }
}

/// Create the operation API router.
///
/// # Example
///
/// ```ignore
/// use xavyo_api_connectors::router::{operation_routes, OperationState};
///
/// let state = OperationState::new(Arc::new(operation_service));
/// let app = Router::new()
///     .nest("/api/v1/operations", operation_routes(state));
/// ```
pub fn operation_routes(state: OperationState) -> Router {
    Router::new()
        // Operation CRUD and actions
        .route("/", get(handlers::list_operations))
        .route("/", post(handlers::trigger_operation))
        .route("/stats", get(handlers::get_queue_stats))
        .route("/dlq", get(handlers::list_dead_letter))
        .route("/:id", get(handlers::get_operation))
        .route("/:id/retry", post(handlers::retry_operation))
        .route("/:id/cancel", post(handlers::cancel_operation))
        .route("/:id/resolve", post(handlers::resolve_operation))
        .route("/:id/logs", get(handlers::get_operation_logs))
        .route("/:id/attempts", get(handlers::get_operation_attempts))
        // Conflicts
        .route("/conflicts", get(handlers::list_conflicts))
        .route("/conflicts/:conflict_id", get(handlers::get_conflict))
        .route(
            "/conflicts/:conflict_id/resolve",
            post(handlers::resolve_conflict),
        )
        .with_state(state)
}

/// Shared state for sync API handlers.
#[derive(Clone)]
pub struct SyncState {
    pub sync_service: Arc<SyncService>,
}

impl SyncState {
    /// Create a new sync state.
    pub fn new(sync_service: Arc<SyncService>) -> Self {
        Self { sync_service }
    }
}

/// Create the sync API router.
///
/// # Example
///
/// ```ignore
/// use xavyo_api_connectors::router::{sync_routes, SyncState};
///
/// let state = SyncState::new(Arc::new(sync_service));
/// let app = Router::new()
///     .nest("/api/v1/connectors", sync_routes(state));
/// ```
pub fn sync_routes(state: SyncState) -> Router {
    Router::new()
        // Sync configuration
        .route("/:id/sync/config", get(handlers::get_sync_config))
        .route("/:id/sync/config", put(handlers::update_sync_config))
        .route("/:id/sync/enable", post(handlers::enable_sync))
        .route("/:id/sync/disable", post(handlers::disable_sync))
        // Sync status and token
        .route("/:id/sync/status", get(handlers::get_sync_status))
        .route("/:id/sync/token", get(handlers::get_sync_token))
        .route("/:id/sync/token", delete(handlers::reset_sync_token))
        // Sync trigger
        .route("/:id/sync/trigger", post(handlers::trigger_sync))
        // Inbound changes
        .route("/:id/sync/changes", get(handlers::list_changes))
        .route("/:id/sync/changes/:change_id", get(handlers::get_change))
        .route(
            "/:id/sync/changes/:change_id/retry",
            post(handlers::retry_change),
        )
        .route(
            "/:id/sync/changes/:change_id/link",
            post(handlers::link_change),
        )
        // Sync conflicts
        .route("/:id/sync/conflicts", get(handlers::list_sync_conflicts))
        .route(
            "/:id/sync/conflicts/:conflict_id/resolve",
            post(handlers::resolve_sync_conflict),
        )
        .with_state(state)
}

/// Create a combined router with sync routes merged into connector routes.
pub fn connector_routes_with_sync(
    connector_state: ConnectorState,
    sync_state: SyncState,
) -> Router {
    connector_routes(connector_state).merge(sync_routes(sync_state))
}

use crate::services::ReconciliationService;

/// Shared state for reconciliation API handlers.
#[derive(Clone)]
pub struct ReconciliationState {
    pub reconciliation_service: Arc<ReconciliationService>,
}

impl ReconciliationState {
    /// Create a new reconciliation state.
    pub fn new(reconciliation_service: Arc<ReconciliationService>) -> Self {
        Self {
            reconciliation_service,
        }
    }
}

/// Create the reconciliation API router.
///
/// # Example
///
/// ```ignore
/// use xavyo_api_connectors::router::{reconciliation_routes, ReconciliationState};
///
/// let state = ReconciliationState::new(Arc::new(reconciliation_service));
/// let app = Router::new()
///     .nest("/api/v1/connectors", reconciliation_routes(state));
/// ```
pub fn reconciliation_routes(state: ReconciliationState) -> Router {
    Router::new()
        // Reconciliation runs
        .route(
            "/:id/reconciliation/runs",
            get(handlers::list_reconciliation_runs),
        )
        .route(
            "/:id/reconciliation/runs",
            post(handlers::trigger_reconciliation),
        )
        .route(
            "/:id/reconciliation/runs/:run_id",
            get(handlers::get_reconciliation_run),
        )
        .route(
            "/:id/reconciliation/runs/:run_id/cancel",
            post(handlers::cancel_reconciliation_run),
        )
        .route(
            "/:id/reconciliation/runs/:run_id/resume",
            post(handlers::resume_reconciliation_run),
        )
        // Reconciliation reports
        .route(
            "/:id/reconciliation/runs/:run_id/report",
            get(handlers::get_report),
        )
        // Discrepancies
        .route(
            "/:id/reconciliation/discrepancies",
            get(handlers::list_discrepancies),
        )
        .route(
            "/:id/reconciliation/discrepancies/bulk-remediate",
            post(handlers::bulk_remediate_discrepancies),
        )
        .route(
            "/:id/reconciliation/discrepancies/preview",
            post(handlers::preview_remediation),
        )
        .route(
            "/:id/reconciliation/discrepancies/:discrepancy_id",
            get(handlers::get_discrepancy),
        )
        .route(
            "/:id/reconciliation/discrepancies/:discrepancy_id/remediate",
            post(handlers::remediate_discrepancy),
        )
        .route(
            "/:id/reconciliation/discrepancies/:discrepancy_id/ignore",
            post(handlers::ignore_discrepancy),
        )
        // Schedule
        .route("/:id/reconciliation/schedule", get(handlers::get_schedule))
        .route(
            "/:id/reconciliation/schedule",
            put(handlers::update_schedule),
        )
        .route(
            "/:id/reconciliation/schedule",
            delete(handlers::delete_schedule),
        )
        .route(
            "/:id/reconciliation/schedule/enable",
            post(handlers::enable_schedule),
        )
        .route(
            "/:id/reconciliation/schedule/disable",
            post(handlers::disable_schedule),
        )
        // Actions (audit log)
        .route("/:id/reconciliation/actions", get(handlers::list_actions))
        .with_state(state)
}

/// Create global reconciliation routes (not under a connector ID).
/// These routes should be mounted at the root level, not nested under /connectors.
pub fn reconciliation_global_routes(state: ReconciliationState) -> Router {
    Router::new()
        .route("/reconciliation/schedules", get(handlers::list_schedules))
        .route("/reconciliation/trend", get(handlers::get_trend))
        .with_state(state)
}

/// Create a combined router with sync and reconciliation routes merged into connector routes.
pub fn connector_routes_full(
    connector_state: ConnectorState,
    sync_state: SyncState,
    reconciliation_state: ReconciliationState,
) -> Router {
    connector_routes(connector_state)
        .merge(sync_routes(sync_state))
        .merge(reconciliation_routes(reconciliation_state))
}

// --- SCIM Outbound Provisioning Target routes (F087) ---

use crate::handlers::scim_log;
use crate::handlers::scim_mappings;
use crate::handlers::scim_provisioning;
use crate::handlers::scim_sync;
use crate::handlers::scim_targets::{self, ScimTargetState};

/// Create the SCIM target management router.
///
/// All routes are relative to the nest point (e.g. `/admin/scim-targets`).
pub fn scim_target_routes(state: ScimTargetState) -> Router {
    Router::new()
        // CRUD + health check (US1)
        .route("/", post(scim_targets::create_scim_target))
        .route("/", get(scim_targets::list_scim_targets))
        .route("/:id", get(scim_targets::get_scim_target))
        .route("/:id", put(scim_targets::update_scim_target))
        .route("/:id", delete(scim_targets::delete_scim_target))
        .route(
            "/:id/health-check",
            post(scim_targets::health_check_scim_target),
        )
        // Attribute mapping sub-routes (US4)
        .route("/:id/mappings", get(scim_mappings::list_mappings))
        .route("/:id/mappings", put(scim_mappings::replace_mappings))
        .route(
            "/:id/mappings/defaults",
            post(scim_mappings::reset_mapping_defaults),
        )
        // Sync and reconciliation sub-routes (US5)
        .route("/:id/sync", post(scim_sync::trigger_sync))
        .route("/:id/reconcile", post(scim_sync::trigger_reconciliation))
        .route("/:id/sync-runs", get(scim_sync::list_sync_runs))
        .route("/:id/sync-runs/:run_id", get(scim_sync::get_sync_run))
        // Provisioning state and retry (US6)
        .route(
            "/:id/provisioning-state",
            get(scim_provisioning::list_provisioning_state),
        )
        .route(
            "/:id/provisioning-state/:state_id/retry",
            post(scim_provisioning::retry_provisioning),
        )
        // Provisioning log (US6)
        .route("/:id/log", get(scim_log::list_provisioning_log))
        .route("/:id/log/:log_id", get(scim_log::get_log_detail))
        .with_state(state)
}

// OpenAPI documentation for connector endpoints is available
// when building with utoipa OpenAPI support.
