//! Schema API handlers.
//!
//! Handles schema discovery, versioning, browsing, and scheduling for connectors.
//!
//! This module implements the F046 Schema Discovery feature with the following endpoint groups:
//! - Schema Discovery: POST /discover, GET /status
//! - Schema Retrieval: GET /schema, GET /versions, GET /diff
//! - Schema Browsing: GET /object-classes, GET /object-classes/{name}, GET /object-classes/{name}/attributes
//! - Schema Scheduling: GET/PUT/DELETE /schedule

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use xavyo_connector::schema::{AttributeChanges, DiffSummary, ObjectClassChanges};
use xavyo_db::models::{ScheduleType, SchemaVersionSummary};

use xavyo_auth::JwtClaims;

use crate::error::Result;
use crate::services::{ObjectClassResponse, SchemaResponse};
use crate::ConnectorState;

// =============================================================================
// Request/Response Types
// =============================================================================

/// Request body for triggering schema discovery.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct DiscoverSchemaRequest {
    /// Force discovery even if recent cache exists.
    #[serde(default)]
    pub force_refresh: bool,
    /// Include operational/system attributes (LDAP).
    #[serde(default)]
    pub include_operational: bool,
}

/// Query parameters for schema discovery (legacy, kept for compatibility).
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct DiscoverSchemaQuery {
    /// Force refresh (bypass cache).
    #[serde(default)]
    pub force_refresh: bool,
}

/// Discovery status response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DiscoveryStatusResponse {
    /// Connector ID.
    pub connector_id: Uuid,
    /// Current discovery state.
    pub state: String,
    /// When discovery started.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<DateTime<Utc>>,
    /// When discovery completed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<DateTime<Utc>>,
    /// Progress percentage (0-100).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub progress_percent: Option<i32>,
    /// Object class currently being discovered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_object_class: Option<String>,
    /// Error message if state is failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Version number of discovered schema (if completed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<i32>,
}

/// Query parameters for getting cached schema.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct GetSchemaQuery {
    /// Specific version to retrieve (default is latest).
    pub version: Option<i32>,
}

/// Query parameters for listing schema versions.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListVersionsQuery {
    /// Maximum number of items to return.
    #[serde(default = "default_limit")]
    pub limit: i32,
    /// Number of items to skip.
    #[serde(default)]
    pub offset: i32,
}

fn default_limit() -> i32 {
    50
}

/// Response for listing schema versions.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SchemaVersionListResponse {
    /// List of schema version summaries.
    pub versions: Vec<SchemaVersionSummary>,
    /// Total number of versions.
    pub total: i64,
    /// Items per page.
    pub limit: i32,
    /// Items skipped.
    pub offset: i32,
}

/// Query parameters for schema diff.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct DiffSchemaQuery {
    /// Source version for comparison.
    pub from_version: i32,
    /// Target version for comparison.
    pub to_version: i32,
}

/// Response for schema diff.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SchemaDiffResponse {
    /// Source version.
    pub from_version: i32,
    /// Target version.
    pub to_version: i32,
    /// When source version was discovered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_discovered_at: Option<DateTime<Utc>>,
    /// When target version was discovered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_discovered_at: Option<DateTime<Utc>>,
    /// Diff summary.
    pub summary: DiffSummary,
    /// Object class changes.
    pub object_class_changes: ObjectClassChanges,
    /// Attribute changes per object class.
    pub attribute_changes: std::collections::HashMap<String, AttributeChanges>,
}

/// Summary of an object class for listing.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ObjectClassSummary {
    /// Canonical name.
    pub name: String,
    /// Native name in target system.
    pub native_name: String,
    /// Display name for UI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Object class type (structural, auxiliary, abstract).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_class_type: Option<String>,
    /// Number of attributes.
    pub attribute_count: usize,
    /// Parent class names.
    pub parent_classes: Vec<String>,
}

/// Response for listing object classes.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ObjectClassListResponse {
    /// List of object class summaries.
    pub object_classes: Vec<ObjectClassSummary>,
    /// Total count.
    pub total: usize,
}

/// Query parameters for listing attributes.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListAttributesQuery {
    /// Include inherited attributes (default true).
    #[serde(default = "default_include_inherited")]
    pub include_inherited: bool,
}

fn default_include_inherited() -> bool {
    true
}

/// Attribute with source information.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AttributeWithSource {
    /// Canonical name.
    pub name: String,
    /// Native name in target system.
    pub native_name: String,
    /// Data type.
    pub data_type: String,
    /// Whether multi-valued.
    pub multi_valued: bool,
    /// Whether required.
    pub required: bool,
    /// Whether readable.
    pub readable: bool,
    /// Whether writable.
    pub writable: bool,
    /// Source: direct or inherited.
    pub source: String,
    /// Class name where attribute is defined (if inherited).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_class: Option<String>,
}

/// Response for listing attributes.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AttributeListResponse {
    /// List of attributes with source info.
    pub attributes: Vec<AttributeWithSource>,
    /// Total count.
    pub total: usize,
}

/// Request for configuring refresh schedule.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct RefreshScheduleRequest {
    /// Whether schedule is enabled.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Schedule type: interval or cron.
    pub schedule_type: ScheduleType,
    /// Hours between refreshes (required if interval type).
    pub interval_hours: Option<i32>,
    /// Cron expression (required if cron type).
    pub cron_expression: Option<String>,
    /// Whether to notify on schema changes.
    #[serde(default)]
    pub notify_on_changes: bool,
    /// Email for notifications.
    pub notify_email: Option<String>,
}

fn default_enabled() -> bool {
    true
}

/// Response for refresh schedule.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct RefreshScheduleResponse {
    /// Schedule ID.
    pub id: Uuid,
    /// Connector ID.
    pub connector_id: Uuid,
    /// Whether enabled.
    pub enabled: bool,
    /// Schedule type.
    pub schedule_type: String,
    /// Interval hours.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interval_hours: Option<i32>,
    /// Cron expression.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cron_expression: Option<String>,
    /// Last run timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_run_at: Option<DateTime<Utc>>,
    /// Next run timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_run_at: Option<DateTime<Utc>>,
    /// Last error message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// Whether to notify on changes.
    pub notify_on_changes: bool,
    /// Notification email.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notify_email: Option<String>,
}

// =============================================================================
// Schema Discovery Endpoints
// =============================================================================

/// Discover schema for a connector.
///
/// Discovers the schema from the target system and caches the result.
/// Use `force_refresh=true` to bypass the cache.
#[utoipa::path(
    post,
    path = "/connectors/{id}/schema/discover",
    params(
        ("id" = Uuid, Path, description = "Connector ID"),
        DiscoverSchemaQuery
    ),
    responses(
        (status = 200, description = "Schema discovered successfully", body = SchemaResponse),
        (status = 404, description = "Connector not found"),
        (status = 500, description = "Schema discovery failed")
    ),
    tag = "Connector Schemas"
)]
pub async fn discover_schema(
    State(state): State<ConnectorState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Query(query): Query<DiscoverSchemaQuery>,
) -> Result<Json<SchemaResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;

    let schema = state
        .schema_service
        .get_or_discover_schema(tenant_id, id, query.force_refresh)
        .await?;

    Ok(Json(schema))
}

/// Get cached schema for a connector.
///
/// Returns the cached schema if available. Returns 404 if no schema is cached.
#[utoipa::path(
    get,
    path = "/connectors/{id}/schema",
    params(
        ("id" = Uuid, Path, description = "Connector ID")
    ),
    responses(
        (status = 200, description = "Cached schema", body = SchemaResponse),
        (status = 404, description = "No cached schema found")
    ),
    tag = "Connector Schemas"
)]
pub async fn get_schema(
    State(state): State<ConnectorState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> Result<Json<SchemaResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;

    let schema = state
        .schema_service
        .get_schema(tenant_id, id)
        .await?
        .ok_or_else(|| crate::error::ConnectorApiError::NotFound {
            resource: "schema".to_string(),
            id: id.to_string(),
        })?;

    Ok(Json(schema))
}

/// Get a specific object class from the schema.
#[utoipa::path(
    get,
    path = "/connectors/{id}/schema/{object_class}",
    params(
        ("id" = Uuid, Path, description = "Connector ID"),
        ("object_class" = String, Path, description = "Object class name")
    ),
    responses(
        (status = 200, description = "Object class details", body = ObjectClassResponse),
        (status = 404, description = "Object class not found")
    ),
    tag = "Connector Schemas"
)]
pub async fn get_object_class(
    State(state): State<ConnectorState>,
    Extension(claims): Extension<JwtClaims>,
    Path((id, object_class)): Path<(Uuid, String)>,
) -> Result<Json<ObjectClassResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;

    let oc = state
        .schema_service
        .get_object_class(tenant_id, id, &object_class)
        .await?
        .ok_or_else(|| crate::error::ConnectorApiError::NotFound {
            resource: "object_class".to_string(),
            id: format!("{id}/{object_class}"),
        })?;

    Ok(Json(oc))
}

/// Clear schema cache for a connector.
#[utoipa::path(
    delete,
    path = "/connectors/{id}/schema",
    params(
        ("id" = Uuid, Path, description = "Connector ID")
    ),
    responses(
        (status = 204, description = "Schema cache cleared"),
        (status = 404, description = "Connector not found")
    ),
    tag = "Connector Schemas"
)]
pub async fn clear_schema_cache(
    State(state): State<ConnectorState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode> {
    let tenant_id = extract_tenant_id(&claims)?;

    state.schema_service.clear_cache(tenant_id, id).await?;

    Ok(StatusCode::NO_CONTENT)
}

// =============================================================================
// F046 Schema Discovery - New Endpoints
// =============================================================================

/// Trigger schema discovery (async).
///
/// Initiates schema discovery for a connector. Returns immediately with status.
/// Returns 409 if discovery is already in progress.
#[utoipa::path(
    post,
    path = "/connectors/{id}/schema/discover",
    params(
        ("id" = Uuid, Path, description = "Connector ID")
    ),
    request_body = DiscoverSchemaRequest,
    responses(
        (status = 202, description = "Discovery started", body = DiscoveryStatusResponse),
        (status = 409, description = "Discovery already in progress"),
        (status = 404, description = "Connector not found")
    ),
    tag = "Schema Discovery"
)]
pub async fn trigger_schema_discovery(
    State(state): State<ConnectorState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(_request): Json<DiscoverSchemaRequest>,
) -> Result<(StatusCode, Json<DiscoveryStatusResponse>)> {
    use xavyo_connector::schema::DiscoveryState;
    use xavyo_db::models::TriggeredBy;

    let tenant_id = extract_tenant_id(&claims)?;
    let user_id = Uuid::parse_str(&claims.sub).ok();

    // Trigger async discovery
    let discovery_status = state
        .schema_service
        .trigger_discovery(tenant_id, id, TriggeredBy::Manual, user_id)
        .await?;

    // Convert to response format
    let status = DiscoveryStatusResponse {
        connector_id: discovery_status.connector_id,
        state: match discovery_status.state {
            DiscoveryState::Idle => "idle".to_string(),
            DiscoveryState::InProgress => "in_progress".to_string(),
            DiscoveryState::Completed => "completed".to_string(),
            DiscoveryState::Failed => "failed".to_string(),
        },
        started_at: discovery_status.started_at,
        completed_at: discovery_status.completed_at,
        progress_percent: discovery_status.progress_percent,
        current_object_class: discovery_status.current_object_class,
        error: discovery_status.error,
        version: discovery_status.version,
    };

    Ok((StatusCode::ACCEPTED, Json(status)))
}

/// Get discovery status.
///
/// Returns the current discovery status for a connector.
#[utoipa::path(
    get,
    path = "/connectors/{id}/schema/status",
    params(
        ("id" = Uuid, Path, description = "Connector ID")
    ),
    responses(
        (status = 200, description = "Discovery status", body = DiscoveryStatusResponse),
        (status = 404, description = "Connector not found")
    ),
    tag = "Schema Discovery"
)]
pub async fn get_discovery_status(
    State(state): State<ConnectorState>,
    Path(id): Path<Uuid>,
) -> Result<Json<DiscoveryStatusResponse>> {
    use xavyo_connector::schema::DiscoveryState;

    // Get status from state manager
    let discovery_status = state.schema_service.get_discovery_status(id).await;

    // Convert to response format
    let status = DiscoveryStatusResponse {
        connector_id: discovery_status.connector_id,
        state: match discovery_status.state {
            DiscoveryState::Idle => "idle".to_string(),
            DiscoveryState::InProgress => "in_progress".to_string(),
            DiscoveryState::Completed => "completed".to_string(),
            DiscoveryState::Failed => "failed".to_string(),
        },
        started_at: discovery_status.started_at,
        completed_at: discovery_status.completed_at,
        progress_percent: discovery_status.progress_percent,
        current_object_class: discovery_status.current_object_class,
        error: discovery_status.error,
        version: discovery_status.version,
    };

    Ok(Json(status))
}

/// Get cached schema with optional version.
///
/// Returns the latest cached schema or a specific version if requested.
#[utoipa::path(
    get,
    path = "/connectors/{id}/schema",
    params(
        ("id" = Uuid, Path, description = "Connector ID"),
        GetSchemaQuery
    ),
    responses(
        (status = 200, description = "Cached schema", body = SchemaResponse),
        (status = 404, description = "Schema not found")
    ),
    tag = "Schema Discovery"
)]
pub async fn get_cached_schema(
    State(state): State<ConnectorState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Query(query): Query<GetSchemaQuery>,
) -> Result<Json<SchemaResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;

    // If specific version requested, fetch from versioned storage
    if let Some(version) = query.version {
        let version_data = state
            .schema_service
            .get_schema_version(tenant_id, id, version)
            .await?
            .ok_or_else(|| crate::error::ConnectorApiError::NotFound {
                resource: "schema_version".to_string(),
                id: format!("{id}/v{version}"),
            })?;

        // Convert versioned schema to response
        let object_classes: Vec<crate::services::ObjectClassResponse> = serde_json::from_value(
            version_data
                .schema_data
                .get("object_classes")
                .cloned()
                .unwrap_or_default(),
        )
        .unwrap_or_default();

        return Ok(Json(crate::services::SchemaResponse {
            connector_id: id,
            object_classes,
            discovered_at: version_data.discovered_at,
            expires_at: version_data.discovered_at + chrono::Duration::days(365), // Versioned schemas don't expire
            from_cache: true,
        }));
    }

    // Get latest cached schema
    let schema = state
        .schema_service
        .get_schema(tenant_id, id)
        .await?
        .ok_or_else(|| crate::error::ConnectorApiError::NotFound {
            resource: "schema".to_string(),
            id: id.to_string(),
        })?;

    Ok(Json(schema))
}

/// List schema versions.
///
/// Returns a paginated list of all schema version snapshots.
#[utoipa::path(
    get,
    path = "/connectors/{id}/schema/versions",
    params(
        ("id" = Uuid, Path, description = "Connector ID"),
        ListVersionsQuery
    ),
    responses(
        (status = 200, description = "List of schema versions", body = SchemaVersionListResponse),
        (status = 404, description = "Connector not found")
    ),
    tag = "Schema Discovery"
)]
pub async fn list_schema_versions(
    State(state): State<ConnectorState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Query(query): Query<ListVersionsQuery>,
) -> Result<Json<SchemaVersionListResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;

    let limit = query.limit.min(100);
    let offset = query.offset.max(0);

    let (versions, total) = state
        .schema_service
        .list_versions(tenant_id, id, limit, offset)
        .await?;

    let response = SchemaVersionListResponse {
        versions,
        total,
        limit,
        offset,
    };

    Ok(Json(response))
}

/// Compare schema versions.
///
/// Computes diff between two schema versions, identifying added/removed/modified
/// object classes and attributes, and highlighting breaking changes.
#[utoipa::path(
    get,
    path = "/connectors/{id}/schema/diff",
    params(
        ("id" = Uuid, Path, description = "Connector ID"),
        DiffSchemaQuery
    ),
    responses(
        (status = 200, description = "Schema diff", body = SchemaDiffResponse),
        (status = 404, description = "One or both versions not found")
    ),
    tag = "Schema Discovery"
)]
pub async fn diff_schema_versions(
    State(state): State<ConnectorState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Query(query): Query<DiffSchemaQuery>,
) -> Result<Json<SchemaDiffResponse>> {
    use xavyo_connector::schema::SchemaDiff;

    let tenant_id = extract_tenant_id(&claims)?;

    // Load both schema versions
    let from_version = state
        .schema_service
        .get_schema_version(tenant_id, id, query.from_version)
        .await?
        .ok_or_else(|| crate::error::ConnectorApiError::NotFound {
            resource: "schema_version".to_string(),
            id: format!("{}/v{}", id, query.from_version),
        })?;

    let to_version = state
        .schema_service
        .get_schema_version(tenant_id, id, query.to_version)
        .await?
        .ok_or_else(|| crate::error::ConnectorApiError::NotFound {
            resource: "schema_version".to_string(),
            id: format!("{}/v{}", id, query.to_version),
        })?;

    // Parse schema data from JSON
    let from_schema: xavyo_connector::schema::Schema =
        serde_json::from_value(from_version.schema_data.clone()).map_err(|e| {
            crate::error::ConnectorApiError::InvalidConfiguration(format!(
                "Failed to parse from_version schema: {e}"
            ))
        })?;

    let to_schema: xavyo_connector::schema::Schema =
        serde_json::from_value(to_version.schema_data.clone()).map_err(|e| {
            crate::error::ConnectorApiError::InvalidConfiguration(format!(
                "Failed to parse to_version schema: {e}"
            ))
        })?;

    // Compute diff
    let diff = SchemaDiff::compute(
        &from_schema,
        &to_schema,
        query.from_version,
        query.to_version,
        from_version.discovered_at,
        to_version.discovered_at,
    );

    let response = SchemaDiffResponse {
        from_version: diff.from_version,
        to_version: diff.to_version,
        from_discovered_at: Some(diff.from_discovered_at),
        to_discovered_at: Some(diff.to_discovered_at),
        summary: diff.summary,
        object_class_changes: diff.object_class_changes,
        attribute_changes: diff.attribute_changes,
    };

    Ok(Json(response))
}

// =============================================================================
// Schema Browsing Endpoints
// =============================================================================

/// List object classes.
///
/// Returns all object classes in the cached schema with summary info
/// including attribute count and parent class hierarchy.
#[utoipa::path(
    get,
    path = "/connectors/{id}/schema/object-classes",
    params(
        ("id" = Uuid, Path, description = "Connector ID")
    ),
    responses(
        (status = 200, description = "List of object classes", body = ObjectClassListResponse),
        (status = 404, description = "Schema not found")
    ),
    tag = "Schema Browsing"
)]
pub async fn list_object_classes(
    State(state): State<ConnectorState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> Result<Json<ObjectClassListResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;

    // Get cached schema
    let schema = state
        .schema_service
        .get_schema(tenant_id, id)
        .await?
        .ok_or_else(|| crate::error::ConnectorApiError::NotFound {
            resource: "schema".to_string(),
            id: id.to_string(),
        })?;

    // Transform to summary list
    let object_classes: Vec<ObjectClassSummary> = schema
        .object_classes
        .iter()
        .map(|oc| ObjectClassSummary {
            name: oc.name.clone(),
            native_name: oc.native_name.clone(),
            display_name: oc.display_name.clone(),
            object_class_type: oc.object_class_type.clone(),
            attribute_count: oc.attributes.len() + oc.inherited_attributes.len(),
            parent_classes: oc.parent_classes.clone(),
        })
        .collect();

    let total = object_classes.len();

    let response = ObjectClassListResponse {
        object_classes,
        total,
    };

    Ok(Json(response))
}

/// Get object class details.
///
/// Returns detailed information about a specific object class.
#[utoipa::path(
    get,
    path = "/connectors/{id}/schema/object-classes/{name}",
    params(
        ("id" = Uuid, Path, description = "Connector ID"),
        ("name" = String, Path, description = "Object class name")
    ),
    responses(
        (status = 200, description = "Object class details", body = ObjectClassResponse),
        (status = 404, description = "Object class not found")
    ),
    tag = "Schema Browsing"
)]
pub async fn get_object_class_details(
    State(state): State<ConnectorState>,
    Extension(claims): Extension<JwtClaims>,
    Path((id, name)): Path<(Uuid, String)>,
) -> Result<Json<ObjectClassResponse>> {
    // TODO: Extend in User Story 3 (T044) to include hierarchy info
    let tenant_id = extract_tenant_id(&claims)?;

    let oc = state
        .schema_service
        .get_object_class(tenant_id, id, &name)
        .await?
        .ok_or_else(|| crate::error::ConnectorApiError::NotFound {
            resource: "object_class".to_string(),
            id: format!("{id}/{name}"),
        })?;

    Ok(Json(oc))
}

/// List attributes for object class.
///
/// Returns all attributes for a specific object class with source info
/// indicating whether each attribute is directly defined or inherited.
/// Use `include_inherited=false` to exclude inherited attributes.
#[utoipa::path(
    get,
    path = "/connectors/{id}/schema/object-classes/{name}/attributes",
    params(
        ("id" = Uuid, Path, description = "Connector ID"),
        ("name" = String, Path, description = "Object class name"),
        ListAttributesQuery
    ),
    responses(
        (status = 200, description = "List of attributes", body = AttributeListResponse),
        (status = 404, description = "Object class not found")
    ),
    tag = "Schema Browsing"
)]
pub async fn list_object_class_attributes(
    State(state): State<ConnectorState>,
    Extension(claims): Extension<JwtClaims>,
    Path((id, name)): Path<(Uuid, String)>,
    Query(query): Query<ListAttributesQuery>,
) -> Result<Json<AttributeListResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;

    // Get object class details
    let oc = state
        .schema_service
        .get_object_class(tenant_id, id, &name)
        .await?
        .ok_or_else(|| crate::error::ConnectorApiError::NotFound {
            resource: "object_class".to_string(),
            id: format!("{id}/{name}"),
        })?;

    let mut attributes: Vec<AttributeWithSource> = Vec::new();

    // Add direct attributes
    for attr in &oc.attributes {
        attributes.push(AttributeWithSource {
            name: attr.name.clone(),
            native_name: attr.native_name.clone(),
            data_type: attr.data_type.clone(),
            multi_valued: attr.multi_valued,
            required: attr.required,
            readable: attr.readable,
            writable: attr.writable,
            source: "direct".to_string(),
            source_class: None,
        });
    }

    // Add inherited attributes if requested
    if query.include_inherited {
        for attr in &oc.inherited_attributes {
            attributes.push(AttributeWithSource {
                name: attr.name.clone(),
                native_name: attr.native_name.clone(),
                data_type: attr.data_type.clone(),
                multi_valued: attr.multi_valued,
                required: attr.required,
                readable: attr.readable,
                writable: attr.writable,
                source: "inherited".to_string(),
                source_class: attr.source_class.clone(),
            });
        }
    }

    let total = attributes.len();

    let response = AttributeListResponse { attributes, total };

    Ok(Json(response))
}

// =============================================================================
// Schema Scheduling Endpoints
// =============================================================================

/// Get refresh schedule.
///
/// Returns the automatic refresh schedule configuration.
#[utoipa::path(
    get,
    path = "/connectors/{id}/schema/schedule",
    params(
        ("id" = Uuid, Path, description = "Connector ID")
    ),
    responses(
        (status = 200, description = "Schedule configuration", body = RefreshScheduleResponse),
        (status = 404, description = "No schedule configured")
    ),
    tag = "Schema Scheduling"
)]
pub async fn get_refresh_schedule(
    State(state): State<ConnectorState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> Result<Json<RefreshScheduleResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;

    let schedule = state
        .schedule_service
        .get_schedule(tenant_id, id)
        .await
        .map_err(|e| crate::error::ConnectorApiError::Validation(e.to_string()))?
        .ok_or_else(|| crate::error::ConnectorApiError::NotFound {
            resource: "schedule".to_string(),
            id: id.to_string(),
        })?;

    let response = RefreshScheduleResponse {
        id: schedule.id,
        connector_id: schedule.connector_id,
        enabled: schedule.enabled,
        schedule_type: schedule.schedule_type,
        interval_hours: schedule.interval_hours,
        cron_expression: schedule.cron_expression,
        last_run_at: schedule.last_run_at,
        next_run_at: schedule.next_run_at,
        last_error: schedule.last_error,
        notify_on_changes: schedule.notify_on_changes,
        notify_email: schedule.notify_email,
    };

    Ok(Json(response))
}

/// Configure refresh schedule.
///
/// Creates or updates automatic refresh schedule.
#[utoipa::path(
    put,
    path = "/connectors/{id}/schema/schedule",
    params(
        ("id" = Uuid, Path, description = "Connector ID")
    ),
    request_body = RefreshScheduleRequest,
    responses(
        (status = 200, description = "Schedule updated", body = RefreshScheduleResponse),
        (status = 400, description = "Invalid schedule configuration")
    ),
    tag = "Schema Scheduling"
)]
pub async fn set_refresh_schedule(
    State(state): State<ConnectorState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<RefreshScheduleRequest>,
) -> Result<Json<RefreshScheduleResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;

    // Upsert the schedule (validation is done in the service layer)
    let schedule = state
        .schedule_service
        .upsert_schedule(
            tenant_id,
            id,
            request.enabled,
            request.schedule_type,
            request.interval_hours,
            request.cron_expression.clone(),
            request.notify_on_changes,
            request.notify_email.clone(),
        )
        .await
        .map_err(|e| match e {
            crate::services::ScheduleError::InvalidCronExpression(msg) => {
                crate::error::ConnectorApiError::InvalidConfiguration(format!(
                    "Invalid cron expression: {msg}"
                ))
            }
            crate::services::ScheduleError::InvalidInterval => {
                crate::error::ConnectorApiError::InvalidConfiguration(
                    "interval_hours must be positive".to_string(),
                )
            }
            crate::services::ScheduleError::ConfigurationError(msg) => {
                crate::error::ConnectorApiError::InvalidConfiguration(msg)
            }
            crate::services::ScheduleError::DatabaseError(e) => {
                crate::error::ConnectorApiError::Database(e)
            }
            _ => crate::error::ConnectorApiError::Validation(e.to_string()),
        })?;

    let response = RefreshScheduleResponse {
        id: schedule.id,
        connector_id: schedule.connector_id,
        enabled: schedule.enabled,
        schedule_type: schedule.schedule_type,
        interval_hours: schedule.interval_hours,
        cron_expression: schedule.cron_expression,
        last_run_at: schedule.last_run_at,
        next_run_at: schedule.next_run_at,
        last_error: schedule.last_error,
        notify_on_changes: schedule.notify_on_changes,
        notify_email: schedule.notify_email,
    };

    Ok(Json(response))
}

/// Delete refresh schedule.
///
/// Removes automatic refresh schedule.
#[utoipa::path(
    delete,
    path = "/connectors/{id}/schema/schedule",
    params(
        ("id" = Uuid, Path, description = "Connector ID")
    ),
    responses(
        (status = 204, description = "Schedule deleted"),
        (status = 404, description = "No schedule exists")
    ),
    tag = "Schema Scheduling"
)]
pub async fn delete_refresh_schedule(
    State(state): State<ConnectorState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode> {
    let tenant_id = extract_tenant_id(&claims)?;

    let deleted = state
        .schedule_service
        .delete_schedule(tenant_id, id)
        .await
        .map_err(|e| crate::error::ConnectorApiError::Validation(e.to_string()))?;

    if deleted {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(crate::error::ConnectorApiError::NotFound {
            resource: "schedule".to_string(),
            id: id.to_string(),
        })
    }
}

// =============================================================================
// Helpers
// =============================================================================

fn extract_tenant_id(claims: &JwtClaims) -> Result<Uuid> {
    claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(crate::error::ConnectorApiError::Validation(
            "Missing tenant_id in claims".to_string(),
        ))
}
