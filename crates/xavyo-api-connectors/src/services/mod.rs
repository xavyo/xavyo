//! Service layer for connector API operations.

pub mod connector_service;
pub mod discovery_state;
pub mod job_service;
pub mod mapping_service;
pub mod notification_service;
pub mod operation_service;
pub mod reconciliation_service;
pub mod schedule_service;
pub mod schema_service;
pub mod sync_service;

pub use connector_service::ConnectorService;
pub use discovery_state::{
    DiscoveryStateManager, DEFAULT_DISCOVERY_TIMEOUT_SECS, MAX_DISCOVERY_TIMEOUT_SECS,
};
pub use mapping_service::{
    CreateMappingRequest, MappingResponse, MappingService, PreviewMappingRequest,
    PreviewMappingResponse, TransformError, UpdateMappingRequest,
};
pub use operation_service::{
    AttemptListResponse, AttemptResponse, ConflictListResponse, ConflictResponse, DlqListResponse,
    ListConflictsQuery, OperationFilter, OperationListResponse, OperationLogResponse,
    OperationResponse, OperationService, OperationServiceError, QueueStatsResponse,
    ResolveConflictRequest, ResolveOperationRequest, TriggerOperationRequest,
};
pub use reconciliation_service::{
    ReconciliationService, ReconciliationServiceError, ReconciliationServiceResult,
};
pub use schedule_service::{
    compute_next_run_at, validate_schedule_config, ScheduleError, ScheduleResult, ScheduleService,
};
pub use schema_service::{AttributeResponse, ObjectClassResponse, SchemaResponse, SchemaService};
pub use sync_service::{SyncService, SyncServiceError, SyncServiceResult};

// Job tracking service (F044)
pub use job_service::{JobService, JobServiceError, JobServiceResult};

// SCIM Outbound Provisioning Client services (F087)
pub mod scim_target_service;
pub use scim_target_service::{
    CreateScimTargetRequest, HealthCheckResponse, ScimTargetListResponse, ScimTargetResponse,
    ScimTargetService, UpdateScimTargetRequest,
};
