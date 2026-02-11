//! Batch simulation handlers for governance API (F060).

use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use uuid::Uuid;
use validator::Validate;

use xavyo_auth::JwtClaims;

use crate::error::{ApiGovernanceError, ApiResult};
use crate::models::{
    ApplyBatchSimulationRequest, BatchSimulationResponse, BatchSimulationResultResponse,
    CreateBatchSimulationRequest, ExecuteBatchSimulationRequest, ListBatchSimulationResultsQuery,
    ListBatchSimulationsQuery, PaginatedResponse, UpdateNotesRequest,
};
use crate::router::GovernanceState;

// ============================================================================
// Batch Simulation CRUD Endpoints
// ============================================================================

/// Get a batch simulation by ID.
#[utoipa::path(
    get,
    path = "/governance/simulations/batch/{simulation_id}",
    tag = "Governance - Enhanced Simulation",
    params(
        ("simulation_id" = Uuid, Path, description = "Simulation ID")
    ),
    responses(
        (status = 200, description = "Simulation retrieved", body = BatchSimulationResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Simulation not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_batch_simulation(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(simulation_id): Path<Uuid>,
) -> ApiResult<Json<BatchSimulationResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let simulation = state
        .batch_simulation_service
        .get(tenant_id, simulation_id)
        .await?;

    Ok(Json(BatchSimulationResponse::from(simulation)))
}

/// List batch simulations.
#[utoipa::path(
    get,
    path = "/governance/simulations/batch",
    tag = "Governance - Enhanced Simulation",
    params(ListBatchSimulationsQuery),
    responses(
        (status = 200, description = "Simulations listed", body = PaginatedBatchSimulationResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_batch_simulations(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListBatchSimulationsQuery>,
) -> ApiResult<Json<PaginatedResponse<BatchSimulationResponse>>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = query.limit.unwrap_or(20).min(100);
    let offset = query.offset.unwrap_or(0).max(0);

    let (simulations, total) = state
        .batch_simulation_service
        .list(
            tenant_id,
            query.batch_type,
            query.status,
            query.created_by,
            query.include_archived.unwrap_or(false),
            limit,
            offset,
        )
        .await?;

    let items: Vec<BatchSimulationResponse> = simulations
        .into_iter()
        .map(std::convert::Into::into)
        .collect();

    Ok(Json(PaginatedResponse {
        items,
        total,
        limit,
        offset,
    }))
}

/// Create a new batch simulation.
#[utoipa::path(
    post,
    path = "/governance/simulations/batch",
    tag = "Governance - Enhanced Simulation",
    request_body = CreateBatchSimulationRequest,
    responses(
        (status = 201, description = "Simulation created", body = BatchSimulationResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_batch_simulation(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateBatchSimulationRequest>,
) -> ApiResult<Json<BatchSimulationResponse>> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    // Validate request
    request.validate().map_err(ApiGovernanceError::Validation)?;

    let simulation = state
        .batch_simulation_service
        .create(
            tenant_id,
            request.name,
            request.batch_type,
            request.selection_mode,
            request.user_ids,
            request.filter_criteria,
            request.change_spec,
            user_id,
        )
        .await?;

    Ok(Json(BatchSimulationResponse::from(simulation)))
}

/// Execute a batch simulation (calculate impact).
#[utoipa::path(
    post,
    path = "/governance/simulations/batch/{simulation_id}/execute",
    tag = "Governance - Enhanced Simulation",
    params(
        ("simulation_id" = Uuid, Path, description = "Simulation ID")
    ),
    request_body = ExecuteBatchSimulationRequest,
    responses(
        (status = 200, description = "Simulation executed", body = BatchSimulationResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Simulation not found"),
        (status = 409, description = "Scope warning - acknowledge required"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn execute_batch_simulation(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(simulation_id): Path<Uuid>,
    Json(request): Json<ExecuteBatchSimulationRequest>,
) -> ApiResult<Json<BatchSimulationResponse>> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let simulation = state
        .batch_simulation_service
        .execute(tenant_id, simulation_id, request.acknowledge_scope_warning)
        .await?;

    Ok(Json(BatchSimulationResponse::from(simulation)))
}

/// Apply a batch simulation (commit changes).
#[utoipa::path(
    post,
    path = "/governance/simulations/batch/{simulation_id}/apply",
    tag = "Governance - Enhanced Simulation",
    params(
        ("simulation_id" = Uuid, Path, description = "Simulation ID")
    ),
    request_body = ApplyBatchSimulationRequest,
    responses(
        (status = 200, description = "Simulation applied", body = BatchSimulationResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Simulation not found"),
        (status = 409, description = "Scope warning - acknowledge required"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn apply_batch_simulation(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(simulation_id): Path<Uuid>,
    Json(request): Json<ApplyBatchSimulationRequest>,
) -> ApiResult<Json<BatchSimulationResponse>> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }
    request.validate()?;
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let simulation = state
        .batch_simulation_service
        .apply(
            tenant_id,
            simulation_id,
            user_id,
            request.acknowledge_scope_warning,
        )
        .await?;

    Ok(Json(BatchSimulationResponse::from(simulation)))
}

/// Cancel a batch simulation.
#[utoipa::path(
    post,
    path = "/governance/simulations/batch/{simulation_id}/cancel",
    tag = "Governance - Enhanced Simulation",
    params(
        ("simulation_id" = Uuid, Path, description = "Simulation ID")
    ),
    responses(
        (status = 200, description = "Simulation cancelled", body = BatchSimulationResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Simulation not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn cancel_batch_simulation(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(simulation_id): Path<Uuid>,
) -> ApiResult<Json<BatchSimulationResponse>> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let simulation = state
        .batch_simulation_service
        .cancel(tenant_id, simulation_id)
        .await?;

    Ok(Json(BatchSimulationResponse::from(simulation)))
}

/// Archive a batch simulation.
#[utoipa::path(
    post,
    path = "/governance/simulations/batch/{simulation_id}/archive",
    tag = "Governance - Enhanced Simulation",
    params(
        ("simulation_id" = Uuid, Path, description = "Simulation ID")
    ),
    responses(
        (status = 200, description = "Simulation archived", body = BatchSimulationResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Simulation not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn archive_batch_simulation(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(simulation_id): Path<Uuid>,
) -> ApiResult<Json<BatchSimulationResponse>> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let simulation = state
        .batch_simulation_service
        .archive(tenant_id, simulation_id)
        .await?;

    Ok(Json(BatchSimulationResponse::from(simulation)))
}

/// Restore an archived batch simulation.
#[utoipa::path(
    post,
    path = "/governance/simulations/batch/{simulation_id}/restore",
    tag = "Governance - Enhanced Simulation",
    params(
        ("simulation_id" = Uuid, Path, description = "Simulation ID")
    ),
    responses(
        (status = 200, description = "Simulation restored", body = BatchSimulationResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Simulation not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn restore_batch_simulation(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(simulation_id): Path<Uuid>,
) -> ApiResult<Json<BatchSimulationResponse>> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let simulation = state
        .batch_simulation_service
        .restore(tenant_id, simulation_id)
        .await?;

    Ok(Json(BatchSimulationResponse::from(simulation)))
}

/// Update notes on a batch simulation.
#[utoipa::path(
    patch,
    path = "/governance/simulations/batch/{simulation_id}/notes",
    tag = "Governance - Enhanced Simulation",
    params(
        ("simulation_id" = Uuid, Path, description = "Simulation ID")
    ),
    request_body = UpdateNotesRequest,
    responses(
        (status = 200, description = "Notes updated", body = BatchSimulationResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Simulation not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_batch_simulation_notes(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(simulation_id): Path<Uuid>,
    Json(request): Json<UpdateNotesRequest>,
) -> ApiResult<Json<BatchSimulationResponse>> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }
    request.validate()?;
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let simulation = state
        .batch_simulation_service
        .update_notes(tenant_id, simulation_id, request.notes)
        .await?;

    Ok(Json(BatchSimulationResponse::from(simulation)))
}

/// Get batch simulation results (per-user impacts).
#[utoipa::path(
    get,
    path = "/governance/simulations/batch/{simulation_id}/results",
    tag = "Governance - Enhanced Simulation",
    params(
        ("simulation_id" = Uuid, Path, description = "Simulation ID"),
        ListBatchSimulationResultsQuery
    ),
    responses(
        (status = 200, description = "Results retrieved", body = PaginatedBatchSimulationResultResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Simulation not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_batch_simulation_results(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(simulation_id): Path<Uuid>,
    Query(query): Query<ListBatchSimulationResultsQuery>,
) -> ApiResult<Json<PaginatedResponse<BatchSimulationResultResponse>>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = query.limit.unwrap_or(20).min(100);
    let offset = query.offset.unwrap_or(0).max(0);

    let (results, total) = state
        .batch_simulation_service
        .get_results(
            tenant_id,
            simulation_id,
            query.user_id,
            query.has_warnings,
            limit,
            offset,
        )
        .await?;

    let items: Vec<BatchSimulationResultResponse> =
        results.into_iter().map(std::convert::Into::into).collect();

    Ok(Json(PaginatedResponse {
        items,
        total,
        limit,
        offset,
    }))
}

/// Delete a batch simulation.
#[utoipa::path(
    delete,
    path = "/governance/simulations/batch/{simulation_id}",
    tag = "Governance - Enhanced Simulation",
    params(
        ("simulation_id" = Uuid, Path, description = "Simulation ID")
    ),
    responses(
        (status = 204, description = "Simulation deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Simulation not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_batch_simulation(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(simulation_id): Path<Uuid>,
) -> ApiResult<()> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    state
        .batch_simulation_service
        .delete(tenant_id, simulation_id)
        .await?;

    Ok(())
}

// ============================================================================
// Export Endpoint
// ============================================================================

use axum::http::header;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::models::ExportBatchSimulationQuery;

/// Export batch simulation results.
#[utoipa::path(
    get,
    path = "/governance/simulations/batch/{simulation_id}/export",
    tag = "Governance - Enhanced Simulation",
    params(
        ("simulation_id" = Uuid, Path, description = "Simulation ID"),
        ExportBatchSimulationQuery
    ),
    responses(
        (status = 200, description = "Export data", content_type = ["application/json", "text/csv"]),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Simulation not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn export_batch_simulation(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(simulation_id): Path<Uuid>,
    Query(query): Query<ExportBatchSimulationQuery>,
) -> Result<Response, ApiGovernanceError> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    // Get the simulation
    let simulation = state
        .batch_simulation_service
        .get(tenant_id, simulation_id)
        .await?;

    // Get all results (no pagination for export)
    let (results, _total) = state
        .batch_simulation_service
        .get_results(tenant_id, simulation_id, None, None, 10000, 0)
        .await?;

    let format = query.format.as_deref().unwrap_or("json");

    if format == "csv" {
        // Generate CSV export
        let mut csv_output =
            String::from("user_id,access_gained,access_lost,has_warnings,warnings\n");

        for result in results {
            let access_gained_count = result.parse_access_gained().len();
            let access_lost_count = result.parse_access_lost().len();
            let warnings = result.parse_warnings();
            let warnings_str = warnings.join("; ").replace('"', "\"\"");

            csv_output.push_str(&format!(
                "{},{},{},{},\"{}\"\n",
                result.user_id,
                access_gained_count,
                access_lost_count,
                result.has_warnings(),
                warnings_str
            ));
        }

        let filename = format!("batch_simulation_{simulation_id}.csv");

        Ok((
            [
                (header::CONTENT_TYPE, "text/csv"),
                (
                    header::CONTENT_DISPOSITION,
                    &format!("attachment; filename=\"{filename}\""),
                ),
            ],
            csv_output,
        )
            .into_response())
    } else {
        // JSON export (default)
        let export_data = BatchSimulationExport {
            simulation: BatchSimulationResponse::from(simulation),
            results: results.into_iter().map(std::convert::Into::into).collect(),
        };

        let json = serde_json::to_string_pretty(&export_data)
            .map_err(|e| ApiGovernanceError::Internal(e.to_string()))?;

        let filename = format!("batch_simulation_{simulation_id}.json");

        Ok((
            [
                (header::CONTENT_TYPE, "application/json"),
                (
                    header::CONTENT_DISPOSITION,
                    &format!("attachment; filename=\"{filename}\""),
                ),
            ],
            json,
        )
            .into_response())
    }
}

/// Export data structure for batch simulation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BatchSimulationExport {
    /// The simulation metadata.
    pub simulation: BatchSimulationResponse,
    /// All simulation results.
    pub results: Vec<BatchSimulationResultResponse>,
}
