//! # Connector API
//!
//! REST API endpoints for connector management in xavyo.
//!
//! This crate provides the HTTP API layer for managing connectors,
//! schemas, mappings, and provisioning operations.
//!
//! ## Endpoints
//!
//! ### Connectors
//! - `POST /connectors` - Create a new connector
//! - `GET /connectors` - List all connectors
//! - `GET /connectors/{id}` - Get connector details
//! - `PUT /connectors/{id}` - Update connector
//! - `DELETE /connectors/{id}` - Delete connector
//! - `POST /connectors/{id}/test` - Test connector connection
//! - `POST /connectors/{id}/activate` - Activate connector
//! - `POST /connectors/{id}/deactivate` - Deactivate connector
//!
//! ### Schemas
//! - `GET /connectors/{id}/schema` - Get cached schema
//! - `POST /connectors/{id}/schema/discover` - Discover schema
//!
//! ### Mappings
//! - `POST /connectors/{id}/mappings` - Create mapping
//! - `GET /connectors/{id}/mappings` - List mappings
//! - `GET /connectors/{id}/mappings/{mapping_id}` - Get mapping
//! - `PUT /connectors/{id}/mappings/{mapping_id}` - Update mapping
//! - `DELETE /connectors/{id}/mappings/{mapping_id}` - Delete mapping
//! - `POST /connectors/{id}/mappings/{mapping_id}/preview` - Preview mapping
//!
//! ### Operations
//! - `GET /operations` - List operations
//! - `GET /operations/{id}` - Get operation details
//! - `POST /operations/{id}/retry` - Retry failed operation
//! - `POST /operations/{id}/cancel` - Cancel pending operation
//!
//! ### Health
//! - `GET /connectors/{id}/health` - Get connector health
//! - `GET /health/dashboard` - Get health dashboard
//!
//! ## Example
//!
//! ```ignore
//! use xavyo_api_connectors::router;
//!
//! let app = Router::new()
//!     .nest("/api/v1", router::connector_routes(state));
//! ```

pub mod error;
pub mod handlers;
pub mod jobs;
pub mod models;
pub mod router;
pub mod services;

// Re-export for convenience
pub use error::{ConnectorApiError, Result};
pub use handlers::scim_targets::ScimTargetState;
pub use models::*;
pub use router::{
    connector_routes, connector_routes_full, operation_routes, reconciliation_global_routes,
    reconciliation_routes, scim_target_routes, sync_routes, ConnectorState, OperationState,
    ReconciliationState, SyncState,
};
pub use services::{
    compute_next_run_at, validate_schedule_config, AttributeResponse, ConnectorService,
    CreateMappingRequest, DiscoveryStateManager, MappingResponse, MappingService,
    ObjectClassResponse, OperationFilter, OperationListResponse, OperationLogResponse,
    OperationResponse, OperationService, PreviewMappingRequest, PreviewMappingResponse,
    QueueStatsResponse, ReconciliationService, ScheduleError, ScheduleResult, ScheduleService,
    SchemaResponse, SchemaService, ScimTargetService, SyncService, TransformError,
    TriggerOperationRequest, UpdateMappingRequest,
};

// Re-export schema handler types for contract testing
pub use handlers::schemas::{
    AttributeListResponse, AttributeWithSource, DiffSchemaQuery, DiscoverSchemaRequest,
    DiscoveryStatusResponse, GetSchemaQuery, ListAttributesQuery, ListVersionsQuery,
    ObjectClassListResponse, ObjectClassSummary, RefreshScheduleRequest, RefreshScheduleResponse,
    SchemaDiffResponse, SchemaVersionListResponse,
};

// Re-export jobs
pub use jobs::{
    SchedulerError, SchemaCleanupJob, SchemaSchedulerJob, DEFAULT_BATCH_SIZE,
    DEFAULT_POLL_INTERVAL_SECS, DEFAULT_SCHEMA_RETENTION_COUNT,
};

// Re-export connector types
pub use xavyo_connector::prelude::*;
