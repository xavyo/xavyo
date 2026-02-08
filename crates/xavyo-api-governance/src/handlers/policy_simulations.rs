//! Policy simulation handlers for governance API (F060).

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use uuid::Uuid;

use xavyo_auth::JwtClaims;

use crate::error::{ApiGovernanceError, ApiResult};
use crate::models::{
    CreatePolicySimulationRequest, ExecutePolicySimulationRequest, ExportPolicySimulationQuery,
    ListPolicySimulationResultsQuery, ListPolicySimulationsQuery, PaginatedResponse,
    PolicySimulationResponse, PolicySimulationResultResponse, UpdateNotesRequest,
};
use crate::router::GovernanceState;

// ============================================================================
// Policy Simulation CRUD Endpoints
// ============================================================================

/// Get a policy simulation by ID.
#[utoipa::path(
    get,
    path = "/governance/simulations/policy/{simulation_id}",
    tag = "Governance - Enhanced Simulation",
    params(
        ("simulation_id" = Uuid, Path, description = "Simulation ID")
    ),
    responses(
        (status = 200, description = "Simulation retrieved", body = PolicySimulationResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Simulation not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_policy_simulation(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(simulation_id): Path<Uuid>,
) -> ApiResult<Json<PolicySimulationResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let simulation = state
        .policy_simulation_service
        .get(tenant_id, simulation_id)
        .await?;

    Ok(Json(PolicySimulationResponse::from(simulation)))
}

/// List policy simulations.
#[utoipa::path(
    get,
    path = "/governance/simulations/policy",
    tag = "Governance - Enhanced Simulation",
    params(ListPolicySimulationsQuery),
    responses(
        (status = 200, description = "Simulations listed", body = PaginatedPolicySimulationResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_policy_simulations(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListPolicySimulationsQuery>,
) -> ApiResult<Json<PaginatedResponse<PolicySimulationResponse>>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = query.limit.unwrap_or(20).min(100);
    let offset = query.offset.unwrap_or(0).max(0);

    let (simulations, total) = state
        .policy_simulation_service
        .list(
            tenant_id,
            query.simulation_type,
            query.status,
            query.created_by,
            query.include_archived.unwrap_or(false),
            limit,
            offset,
        )
        .await?;

    let items: Vec<PolicySimulationResponse> = simulations
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

/// Create a new policy simulation.
#[utoipa::path(
    post,
    path = "/governance/simulations/policy",
    tag = "Governance - Enhanced Simulation",
    request_body = CreatePolicySimulationRequest,
    responses(
        (status = 201, description = "Simulation created", body = PolicySimulationResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_policy_simulation(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreatePolicySimulationRequest>,
) -> ApiResult<Json<PolicySimulationResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let simulation = state
        .policy_simulation_service
        .create(
            tenant_id,
            request.name,
            request.simulation_type,
            request.policy_id,
            request.policy_config,
            user_id,
        )
        .await?;

    Ok(Json(PolicySimulationResponse::from(simulation)))
}

/// Execute a policy simulation (calculate impact).
#[utoipa::path(
    post,
    path = "/governance/simulations/policy/{simulation_id}/execute",
    tag = "Governance - Enhanced Simulation",
    params(
        ("simulation_id" = Uuid, Path, description = "Simulation ID")
    ),
    request_body = ExecutePolicySimulationRequest,
    responses(
        (status = 200, description = "Simulation executed", body = PolicySimulationResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Simulation not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn execute_policy_simulation(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(simulation_id): Path<Uuid>,
    Json(request): Json<ExecutePolicySimulationRequest>,
) -> ApiResult<Json<PolicySimulationResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let simulation = state
        .policy_simulation_service
        .execute(tenant_id, simulation_id, request.user_ids)
        .await?;

    Ok(Json(PolicySimulationResponse::from(simulation)))
}

/// Cancel a policy simulation.
#[utoipa::path(
    post,
    path = "/governance/simulations/policy/{simulation_id}/cancel",
    tag = "Governance - Enhanced Simulation",
    params(
        ("simulation_id" = Uuid, Path, description = "Simulation ID")
    ),
    responses(
        (status = 200, description = "Simulation cancelled", body = PolicySimulationResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Simulation not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn cancel_policy_simulation(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(simulation_id): Path<Uuid>,
) -> ApiResult<Json<PolicySimulationResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let simulation = state
        .policy_simulation_service
        .cancel(tenant_id, simulation_id)
        .await?;

    Ok(Json(PolicySimulationResponse::from(simulation)))
}

/// Archive a policy simulation.
#[utoipa::path(
    post,
    path = "/governance/simulations/policy/{simulation_id}/archive",
    tag = "Governance - Enhanced Simulation",
    params(
        ("simulation_id" = Uuid, Path, description = "Simulation ID")
    ),
    responses(
        (status = 200, description = "Simulation archived", body = PolicySimulationResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Simulation not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn archive_policy_simulation(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(simulation_id): Path<Uuid>,
) -> ApiResult<Json<PolicySimulationResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let simulation = state
        .policy_simulation_service
        .archive(tenant_id, simulation_id)
        .await?;

    Ok(Json(PolicySimulationResponse::from(simulation)))
}

/// Restore an archived policy simulation.
#[utoipa::path(
    post,
    path = "/governance/simulations/policy/{simulation_id}/restore",
    tag = "Governance - Enhanced Simulation",
    params(
        ("simulation_id" = Uuid, Path, description = "Simulation ID")
    ),
    responses(
        (status = 200, description = "Simulation restored", body = PolicySimulationResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Simulation not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn restore_policy_simulation(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(simulation_id): Path<Uuid>,
) -> ApiResult<Json<PolicySimulationResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let simulation = state
        .policy_simulation_service
        .restore(tenant_id, simulation_id)
        .await?;

    Ok(Json(PolicySimulationResponse::from(simulation)))
}

/// Update notes on a policy simulation.
#[utoipa::path(
    patch,
    path = "/governance/simulations/policy/{simulation_id}/notes",
    tag = "Governance - Enhanced Simulation",
    params(
        ("simulation_id" = Uuid, Path, description = "Simulation ID")
    ),
    request_body = UpdateNotesRequest,
    responses(
        (status = 200, description = "Notes updated", body = PolicySimulationResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Simulation not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_policy_simulation_notes(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(simulation_id): Path<Uuid>,
    Json(request): Json<UpdateNotesRequest>,
) -> ApiResult<Json<PolicySimulationResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let simulation = state
        .policy_simulation_service
        .update_notes(tenant_id, simulation_id, request.notes)
        .await?;

    Ok(Json(PolicySimulationResponse::from(simulation)))
}

/// Get policy simulation results (per-user impacts).
#[utoipa::path(
    get,
    path = "/governance/simulations/policy/{simulation_id}/results",
    tag = "Governance - Enhanced Simulation",
    params(
        ("simulation_id" = Uuid, Path, description = "Simulation ID"),
        ListPolicySimulationResultsQuery
    ),
    responses(
        (status = 200, description = "Results retrieved", body = PaginatedPolicySimulationResultResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Simulation not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_policy_simulation_results(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(simulation_id): Path<Uuid>,
    Query(query): Query<ListPolicySimulationResultsQuery>,
) -> ApiResult<Json<PaginatedResponse<PolicySimulationResultResponse>>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = query.limit.unwrap_or(20).min(100);
    let offset = query.offset.unwrap_or(0).max(0);

    let (results, total) = state
        .policy_simulation_service
        .get_results(
            tenant_id,
            simulation_id,
            query.impact_type,
            query.severity,
            query.user_id,
            limit,
            offset,
        )
        .await?;

    let items: Vec<PolicySimulationResultResponse> =
        results.into_iter().map(std::convert::Into::into).collect();

    Ok(Json(PaginatedResponse {
        items,
        total,
        limit,
        offset,
    }))
}

/// Check if a policy simulation is stale.
#[utoipa::path(
    get,
    path = "/governance/simulations/policy/{simulation_id}/staleness",
    tag = "Governance - Enhanced Simulation",
    params(
        ("simulation_id" = Uuid, Path, description = "Simulation ID")
    ),
    responses(
        (status = 200, description = "Staleness status", body = StalenessResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Simulation not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn check_policy_simulation_staleness(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(simulation_id): Path<Uuid>,
) -> ApiResult<Json<StalenessResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let is_stale = state
        .policy_simulation_service
        .check_staleness(tenant_id, simulation_id)
        .await?;

    Ok(Json(StalenessResponse { is_stale }))
}

/// Delete a policy simulation.
#[utoipa::path(
    delete,
    path = "/governance/simulations/policy/{simulation_id}",
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
pub async fn delete_policy_simulation(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(simulation_id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    state
        .policy_simulation_service
        .delete(tenant_id, simulation_id)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

// ============================================================================
// Response Types
// ============================================================================

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Response for staleness check.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct StalenessResponse {
    /// Whether the simulation is stale.
    pub is_stale: bool,
}

// ============================================================================
// Export Endpoint
// ============================================================================

use axum::http::header;
use axum::response::{IntoResponse, Response};

/// Export policy simulation results.
#[utoipa::path(
    get,
    path = "/governance/simulations/policy/{simulation_id}/export",
    tag = "Governance - Enhanced Simulation",
    params(
        ("simulation_id" = Uuid, Path, description = "Simulation ID"),
        ExportPolicySimulationQuery
    ),
    responses(
        (status = 200, description = "Export data", content_type = ["application/json", "text/csv"]),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Simulation not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn export_policy_simulation(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(simulation_id): Path<Uuid>,
    Query(query): Query<ExportPolicySimulationQuery>,
) -> Result<Response, ApiGovernanceError> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    // Get the simulation
    let simulation = state
        .policy_simulation_service
        .get(tenant_id, simulation_id)
        .await?;

    // Get all results (no pagination for export)
    let (results, _total) = state
        .policy_simulation_service
        .get_results(tenant_id, simulation_id, None, None, None, 10000, 0)
        .await?;

    let format = query.format.as_deref().unwrap_or("json");

    if format == "csv" {
        // Generate CSV export
        let mut csv_output = String::from("user_id,impact_type,severity,details\n");

        for result in results {
            let details_str = serde_json::to_string(&result.details)
                .unwrap_or_default()
                .replace('"', "\"\""); // Escape quotes for CSV

            csv_output.push_str(&format!(
                "{},{:?},{},\"{}\"\n",
                result.user_id,
                result.impact_type,
                result.severity.as_deref().unwrap_or(""),
                details_str
            ));
        }

        let filename = format!("simulation_{simulation_id}.csv");

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
        let export_data = PolicySimulationExport {
            simulation: PolicySimulationResponse::from(simulation),
            results: results.into_iter().map(std::convert::Into::into).collect(),
        };

        let json = serde_json::to_string_pretty(&export_data)
            .map_err(|e| ApiGovernanceError::Internal(e.to_string()))?;

        let filename = format!("simulation_{simulation_id}.json");

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

/// Export data structure for policy simulation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PolicySimulationExport {
    /// The simulation metadata.
    pub simulation: PolicySimulationResponse,
    /// All simulation results.
    pub results: Vec<PolicySimulationResultResponse>,
}
