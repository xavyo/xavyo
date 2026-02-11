//! Role mining and analytics handlers.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use uuid::Uuid;

use xavyo_auth::JwtClaims;
use xavyo_db::MiningJobParameters;

use crate::error::{ApiGovernanceError, ApiResult};
use crate::models::{
    AccessPatternListResponse, AccessPatternResponse, CalculateMetricsRequest,
    ConsolidationSuggestionListResponse, ConsolidationSuggestionResponse, CreateMiningJobRequest,
    CreateSimulationRequest, DismissCandidateRequest, DismissConsolidationRequest,
    ExcessivePrivilegeListResponse, ExcessivePrivilegeResponse, ListAccessPatternsQuery,
    ListCandidatesQuery, ListConsolidationSuggestionsQuery, ListExcessivePrivilegesQuery,
    ListMetricsQuery, ListMiningJobsQuery, ListSimulationsQuery, MiningJobListResponse,
    MiningJobResponse, PrivilegeReviewAction, PromoteCandidateRequest, ReviewPrivilegeRequest,
    RoleCandidateListResponse, RoleCandidateResponse, RoleMetricsListResponse, RoleMetricsResponse,
    SimulationListResponse, SimulationResponse,
};
use crate::router::GovernanceState;

// ============================================================================
// Mining Job Handlers
// ============================================================================

/// List role mining jobs.
#[utoipa::path(
    get,
    path = "/governance/role-mining/jobs",
    tag = "Governance - Role Mining",
    params(ListMiningJobsQuery),
    responses(
        (status = 200, description = "List of mining jobs", body = MiningJobListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_mining_jobs(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListMiningJobsQuery>,
) -> ApiResult<Json<MiningJobListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = query.limit.min(100);
    let offset = query.offset.max(0);

    let (jobs, total) = state
        .mining_service
        .list(tenant_id, query.status, None, limit, offset)
        .await?;

    let page = if limit > 0 { offset / limit } else { 0 };

    Ok(Json(MiningJobListResponse {
        items: jobs.into_iter().map(Into::into).collect(),
        total,
        page,
        page_size: limit,
    }))
}

/// Get a mining job by ID.
#[utoipa::path(
    get,
    path = "/governance/role-mining/jobs/{job_id}",
    tag = "Governance - Role Mining",
    params(
        ("job_id" = Uuid, Path, description = "Mining job ID")
    ),
    responses(
        (status = 200, description = "Mining job details", body = MiningJobResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Job not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_mining_job(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(job_id): Path<Uuid>,
) -> ApiResult<Json<MiningJobResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let job = state.mining_service.get(tenant_id, job_id).await?;

    Ok(Json(job.into()))
}

/// Create a new mining job.
#[utoipa::path(
    post,
    path = "/governance/role-mining/jobs",
    tag = "Governance - Role Mining",
    request_body = CreateMiningJobRequest,
    responses(
        (status = 201, description = "Mining job created", body = MiningJobResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_mining_job(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateMiningJobRequest>,
) -> ApiResult<(StatusCode, Json<MiningJobResponse>)> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let parameters: MiningJobParameters = request.parameters.map(Into::into).unwrap_or_default();

    let job = state
        .mining_service
        .create_job(tenant_id, request.name, parameters, user_id)
        .await?;

    Ok((StatusCode::CREATED, Json(job.into())))
}

/// Run a pending mining job.
#[utoipa::path(
    post,
    path = "/governance/role-mining/jobs/{job_id}/run",
    tag = "Governance - Role Mining",
    params(
        ("job_id" = Uuid, Path, description = "Mining job ID")
    ),
    responses(
        (status = 200, description = "Job started", body = MiningJobResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Job not found"),
        (status = 409, description = "Job cannot be started")
    ),
    security(("bearer_auth" = []))
)]
pub async fn run_mining_job(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(job_id): Path<Uuid>,
) -> ApiResult<Json<MiningJobResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let job = state.mining_service.run_job(tenant_id, job_id).await?;

    Ok(Json(job.into()))
}

/// Cancel a running mining job.
#[utoipa::path(
    delete,
    path = "/governance/role-mining/jobs/{job_id}",
    tag = "Governance - Role Mining",
    params(
        ("job_id" = Uuid, Path, description = "Mining job ID")
    ),
    responses(
        (status = 200, description = "Job cancelled", body = MiningJobResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Job not found"),
        (status = 409, description = "Job cannot be cancelled")
    ),
    security(("bearer_auth" = []))
)]
pub async fn cancel_mining_job(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(job_id): Path<Uuid>,
) -> ApiResult<Json<MiningJobResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let job = state.mining_service.cancel_job(tenant_id, job_id).await?;

    Ok(Json(job.into()))
}

// ============================================================================
// Role Candidate Handlers
// ============================================================================

/// List role candidates from a mining job.
#[utoipa::path(
    get,
    path = "/governance/role-mining/jobs/{job_id}/candidates",
    tag = "Governance - Role Mining",
    params(
        ("job_id" = Uuid, Path, description = "Mining job ID"),
        ListCandidatesQuery
    ),
    responses(
        (status = 200, description = "List of candidates", body = RoleCandidateListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Job not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_candidates(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(job_id): Path<Uuid>,
    Query(query): Query<ListCandidatesQuery>,
) -> ApiResult<Json<RoleCandidateListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = query.limit.min(100);
    let offset = query.offset.max(0);

    let (candidates, total) = state
        .mining_service
        .list_candidates(
            tenant_id,
            job_id,
            query.status,
            query.min_confidence,
            limit,
            offset,
        )
        .await?;

    let page = if limit > 0 { offset / limit } else { 0 };

    Ok(Json(RoleCandidateListResponse {
        items: candidates.into_iter().map(Into::into).collect(),
        total,
        page,
        page_size: limit,
    }))
}

/// Get a role candidate by ID.
#[utoipa::path(
    get,
    path = "/governance/role-mining/candidates/{candidate_id}",
    tag = "Governance - Role Mining",
    params(
        ("candidate_id" = Uuid, Path, description = "Candidate ID")
    ),
    responses(
        (status = 200, description = "Candidate details", body = RoleCandidateResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Candidate not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_candidate(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(candidate_id): Path<Uuid>,
) -> ApiResult<Json<RoleCandidateResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let candidate = state
        .mining_service
        .get_candidate(tenant_id, candidate_id)
        .await?;

    Ok(Json(candidate.into()))
}

/// Promote a candidate to an actual role.
#[utoipa::path(
    post,
    path = "/governance/role-mining/candidates/{candidate_id}/promote",
    tag = "Governance - Role Mining",
    params(
        ("candidate_id" = Uuid, Path, description = "Candidate ID")
    ),
    request_body = PromoteCandidateRequest,
    responses(
        (status = 200, description = "Candidate promoted", body = RoleCandidateResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Candidate not found"),
        (status = 409, description = "Candidate already promoted or dismissed")
    ),
    security(("bearer_auth" = []))
)]
pub async fn promote_candidate(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(candidate_id): Path<Uuid>,
    Json(request): Json<PromoteCandidateRequest>,
) -> ApiResult<Json<RoleCandidateResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let candidate = state
        .mining_service
        .promote_candidate(
            tenant_id,
            candidate_id,
            request.role_name,
            request.description,
            user_id,
        )
        .await?;

    Ok(Json(candidate.into()))
}

/// Dismiss a role candidate.
#[utoipa::path(
    post,
    path = "/governance/role-mining/candidates/{candidate_id}/dismiss",
    tag = "Governance - Role Mining",
    params(
        ("candidate_id" = Uuid, Path, description = "Candidate ID")
    ),
    request_body = DismissCandidateRequest,
    responses(
        (status = 200, description = "Candidate dismissed", body = RoleCandidateResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Candidate not found"),
        (status = 409, description = "Candidate already processed")
    ),
    security(("bearer_auth" = []))
)]
pub async fn dismiss_candidate(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(candidate_id): Path<Uuid>,
    Json(request): Json<DismissCandidateRequest>,
) -> ApiResult<Json<RoleCandidateResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let candidate = state
        .mining_service
        .dismiss_candidate(tenant_id, candidate_id, request.reason, user_id)
        .await?;

    Ok(Json(candidate.into()))
}

// ============================================================================
// Access Pattern Handlers
// ============================================================================

/// List access patterns from a mining job.
#[utoipa::path(
    get,
    path = "/governance/role-mining/jobs/{job_id}/patterns",
    tag = "Governance - Role Mining",
    params(
        ("job_id" = Uuid, Path, description = "Mining job ID"),
        ListAccessPatternsQuery
    ),
    responses(
        (status = 200, description = "List of access patterns", body = AccessPatternListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Job not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_access_patterns(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(job_id): Path<Uuid>,
    Query(query): Query<ListAccessPatternsQuery>,
) -> ApiResult<Json<AccessPatternListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = query.limit.min(100);
    let offset = query.offset.max(0);

    let (patterns, total) = state
        .mining_service
        .list_patterns(tenant_id, job_id, query.min_frequency, limit, offset)
        .await?;

    let page = if limit > 0 { offset / limit } else { 0 };

    Ok(Json(AccessPatternListResponse {
        items: patterns.into_iter().map(Into::into).collect(),
        total,
        page,
        page_size: limit,
    }))
}

/// Get an access pattern by ID.
#[utoipa::path(
    get,
    path = "/governance/role-mining/patterns/{pattern_id}",
    tag = "Governance - Role Mining",
    params(
        ("pattern_id" = Uuid, Path, description = "Pattern ID")
    ),
    responses(
        (status = 200, description = "Pattern details", body = AccessPatternResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Pattern not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_access_pattern(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(pattern_id): Path<Uuid>,
) -> ApiResult<Json<AccessPatternResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let pattern = state
        .mining_service
        .get_pattern(tenant_id, pattern_id)
        .await?;

    Ok(Json(pattern.into()))
}

// ============================================================================
// Excessive Privilege Handlers
// ============================================================================

/// List excessive privilege flags from a mining job.
#[utoipa::path(
    get,
    path = "/governance/role-mining/jobs/{job_id}/excessive-privileges",
    tag = "Governance - Role Mining",
    params(
        ("job_id" = Uuid, Path, description = "Mining job ID"),
        ListExcessivePrivilegesQuery
    ),
    responses(
        (status = 200, description = "List of excessive privilege flags", body = ExcessivePrivilegeListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Job not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_excessive_privileges(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(job_id): Path<Uuid>,
    Query(query): Query<ListExcessivePrivilegesQuery>,
) -> ApiResult<Json<ExcessivePrivilegeListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = query.limit.min(100);
    let offset = query.offset.max(0);

    let (flags, total) = state
        .mining_service
        .list_excessive_privileges(
            tenant_id,
            job_id,
            query.status,
            query.user_id,
            limit,
            offset,
        )
        .await?;

    let page = if limit > 0 { offset / limit } else { 0 };

    Ok(Json(ExcessivePrivilegeListResponse {
        items: flags.into_iter().map(Into::into).collect(),
        total,
        page,
        page_size: limit,
    }))
}

/// Get an excessive privilege flag by ID.
#[utoipa::path(
    get,
    path = "/governance/role-mining/excessive-privileges/{flag_id}",
    tag = "Governance - Role Mining",
    params(
        ("flag_id" = Uuid, Path, description = "Flag ID")
    ),
    responses(
        (status = 200, description = "Excessive privilege details", body = ExcessivePrivilegeResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Flag not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_excessive_privilege(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(flag_id): Path<Uuid>,
) -> ApiResult<Json<ExcessivePrivilegeResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let flag = state
        .mining_service
        .get_excessive_privilege(tenant_id, flag_id)
        .await?;

    Ok(Json(flag.into()))
}

/// Review an excessive privilege flag.
#[utoipa::path(
    post,
    path = "/governance/role-mining/excessive-privileges/{flag_id}/review",
    tag = "Governance - Role Mining",
    params(
        ("flag_id" = Uuid, Path, description = "Flag ID")
    ),
    request_body = ReviewPrivilegeRequest,
    responses(
        (status = 200, description = "Flag reviewed", body = ExcessivePrivilegeResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Flag not found"),
        (status = 409, description = "Flag already reviewed")
    ),
    security(("bearer_auth" = []))
)]
pub async fn review_excessive_privilege(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(flag_id): Path<Uuid>,
    Json(request): Json<ReviewPrivilegeRequest>,
) -> ApiResult<Json<ExcessivePrivilegeResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let action = match request.action {
        PrivilegeReviewAction::Accept => "accept",
        PrivilegeReviewAction::Remediate => "remediate",
    };

    let flag = state
        .mining_service
        .review_excessive_privilege(tenant_id, flag_id, action, request.notes, user_id)
        .await?;

    Ok(Json(flag.into()))
}

// ============================================================================
// Consolidation Suggestion Handlers
// ============================================================================

/// List consolidation suggestions from a mining job.
#[utoipa::path(
    get,
    path = "/governance/role-mining/jobs/{job_id}/consolidation-suggestions",
    tag = "Governance - Role Mining",
    params(
        ("job_id" = Uuid, Path, description = "Mining job ID"),
        ListConsolidationSuggestionsQuery
    ),
    responses(
        (status = 200, description = "List of consolidation suggestions", body = ConsolidationSuggestionListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Job not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_consolidation_suggestions(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(job_id): Path<Uuid>,
    Query(query): Query<ListConsolidationSuggestionsQuery>,
) -> ApiResult<Json<ConsolidationSuggestionListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = query.limit.min(100);
    let offset = query.offset.max(0);

    let (suggestions, total) = state
        .mining_service
        .list_consolidation_suggestions(
            tenant_id,
            job_id,
            query.status,
            query.min_overlap,
            limit,
            offset,
        )
        .await?;

    let page = if limit > 0 { offset / limit } else { 0 };

    Ok(Json(ConsolidationSuggestionListResponse {
        items: suggestions.into_iter().map(Into::into).collect(),
        total,
        page,
        page_size: limit,
    }))
}

/// Get a consolidation suggestion by ID.
#[utoipa::path(
    get,
    path = "/governance/role-mining/consolidation-suggestions/{suggestion_id}",
    tag = "Governance - Role Mining",
    params(
        ("suggestion_id" = Uuid, Path, description = "Suggestion ID")
    ),
    responses(
        (status = 200, description = "Suggestion details", body = ConsolidationSuggestionResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Suggestion not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_consolidation_suggestion(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(suggestion_id): Path<Uuid>,
) -> ApiResult<Json<ConsolidationSuggestionResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let suggestion = state
        .mining_service
        .get_consolidation_suggestion(tenant_id, suggestion_id)
        .await?;

    Ok(Json(suggestion.into()))
}

/// Dismiss a consolidation suggestion.
#[utoipa::path(
    post,
    path = "/governance/role-mining/consolidation-suggestions/{suggestion_id}/dismiss",
    tag = "Governance - Role Mining",
    params(
        ("suggestion_id" = Uuid, Path, description = "Suggestion ID")
    ),
    request_body = DismissConsolidationRequest,
    responses(
        (status = 200, description = "Suggestion dismissed", body = ConsolidationSuggestionResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Suggestion not found"),
        (status = 409, description = "Suggestion already processed")
    ),
    security(("bearer_auth" = []))
)]
pub async fn dismiss_consolidation_suggestion(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(suggestion_id): Path<Uuid>,
    Json(request): Json<DismissConsolidationRequest>,
) -> ApiResult<Json<ConsolidationSuggestionResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let suggestion = state
        .mining_service
        .dismiss_consolidation_suggestion(tenant_id, suggestion_id, request.reason, user_id)
        .await?;

    Ok(Json(suggestion.into()))
}

// ============================================================================
// Simulation Handlers
// ============================================================================

/// List role simulations.
#[utoipa::path(
    get,
    path = "/governance/role-mining/simulations",
    tag = "Governance - Role Mining",
    params(ListSimulationsQuery),
    responses(
        (status = 200, description = "List of simulations", body = SimulationListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_simulations(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListSimulationsQuery>,
) -> ApiResult<Json<SimulationListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = query.limit.min(100);
    let offset = query.offset.max(0);

    let (simulations, total) = state
        .simulation_service
        .list(
            tenant_id,
            query.scenario_type,
            query.status,
            query.target_role_id,
            None, // created_by filter
            limit,
            offset,
        )
        .await?;

    let page = if limit > 0 { offset / limit } else { 0 };

    Ok(Json(SimulationListResponse {
        items: simulations.into_iter().map(Into::into).collect(),
        total,
        page,
        page_size: limit,
    }))
}

/// Get a simulation by ID.
#[utoipa::path(
    get,
    path = "/governance/role-mining/simulations/{simulation_id}",
    tag = "Governance - Role Mining",
    params(
        ("simulation_id" = Uuid, Path, description = "Simulation ID")
    ),
    responses(
        (status = 200, description = "Simulation details", body = SimulationResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Simulation not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_simulation(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(simulation_id): Path<Uuid>,
) -> ApiResult<Json<SimulationResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let simulation = state
        .simulation_service
        .get(tenant_id, simulation_id)
        .await?;

    Ok(Json(simulation.into()))
}

/// Create a new simulation.
#[utoipa::path(
    post,
    path = "/governance/role-mining/simulations",
    tag = "Governance - Role Mining",
    request_body = CreateSimulationRequest,
    responses(
        (status = 201, description = "Simulation created", body = SimulationResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_simulation(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateSimulationRequest>,
) -> ApiResult<(StatusCode, Json<SimulationResponse>)> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let simulation = state
        .simulation_service
        .create_simulation(
            tenant_id,
            request.name,
            request.scenario_type,
            request.target_role_id,
            request.changes,
            user_id,
        )
        .await?;

    Ok((StatusCode::CREATED, Json(simulation.into())))
}

/// Execute a simulation.
#[utoipa::path(
    post,
    path = "/governance/role-mining/simulations/{simulation_id}/execute",
    tag = "Governance - Role Mining",
    params(
        ("simulation_id" = Uuid, Path, description = "Simulation ID")
    ),
    responses(
        (status = 200, description = "Simulation executed", body = SimulationResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Simulation not found"),
        (status = 409, description = "Simulation cannot be executed")
    ),
    security(("bearer_auth" = []))
)]
pub async fn execute_simulation(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(simulation_id): Path<Uuid>,
) -> ApiResult<Json<SimulationResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let simulation = state
        .simulation_service
        .execute_simulation(tenant_id, simulation_id)
        .await?;

    Ok(Json(simulation.into()))
}

/// Apply a simulation (commit the changes).
#[utoipa::path(
    post,
    path = "/governance/role-mining/simulations/{simulation_id}/apply",
    tag = "Governance - Role Mining",
    params(
        ("simulation_id" = Uuid, Path, description = "Simulation ID")
    ),
    responses(
        (status = 200, description = "Simulation applied", body = SimulationResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Simulation not found"),
        (status = 409, description = "Simulation not ready or already applied")
    ),
    security(("bearer_auth" = []))
)]
pub async fn apply_simulation(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(simulation_id): Path<Uuid>,
) -> ApiResult<Json<SimulationResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let simulation = state
        .simulation_service
        .apply_simulation(tenant_id, simulation_id, user_id)
        .await?;

    Ok(Json(simulation.into()))
}

/// Cancel a simulation.
#[utoipa::path(
    delete,
    path = "/governance/role-mining/simulations/{simulation_id}",
    tag = "Governance - Role Mining",
    params(
        ("simulation_id" = Uuid, Path, description = "Simulation ID")
    ),
    responses(
        (status = 200, description = "Simulation cancelled", body = SimulationResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Simulation not found"),
        (status = 409, description = "Simulation already applied")
    ),
    security(("bearer_auth" = []))
)]
pub async fn cancel_simulation(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(simulation_id): Path<Uuid>,
) -> ApiResult<Json<SimulationResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let simulation = state
        .simulation_service
        .cancel_simulation(tenant_id, simulation_id)
        .await?;

    Ok(Json(simulation.into()))
}

// ============================================================================
// Metrics Handlers
// ============================================================================

/// List role effectiveness metrics.
#[utoipa::path(
    get,
    path = "/governance/role-mining/metrics",
    tag = "Governance - Role Mining",
    params(ListMetricsQuery),
    responses(
        (status = 200, description = "List of role metrics", body = RoleMetricsListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_metrics(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListMetricsQuery>,
) -> ApiResult<Json<RoleMetricsListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = query.limit.min(100);
    let offset = query.offset.max(0);

    let (metrics, total) = state
        .metrics_service
        .list_latest(
            tenant_id,
            query.role_id,
            query.trend_direction,
            query.min_utilization,
            query.max_utilization,
            limit,
            offset,
        )
        .await?;

    let page = if limit > 0 { offset / limit } else { 0 };

    Ok(Json(RoleMetricsListResponse {
        items: metrics.into_iter().map(Into::into).collect(),
        total,
        page,
        page_size: limit,
    }))
}

/// Get metrics for a specific role.
#[utoipa::path(
    get,
    path = "/governance/role-mining/metrics/{role_id}",
    tag = "Governance - Role Mining",
    params(
        ("role_id" = Uuid, Path, description = "Role ID")
    ),
    responses(
        (status = 200, description = "Role metrics", body = RoleMetricsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Metrics not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_role_metrics(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(role_id): Path<Uuid>,
) -> ApiResult<Json<RoleMetricsResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let metrics = state
        .metrics_service
        .get_latest_by_role(tenant_id, role_id)
        .await?;

    Ok(Json(metrics.into()))
}

/// Calculate metrics for roles.
#[utoipa::path(
    post,
    path = "/governance/role-mining/metrics/calculate",
    tag = "Governance - Role Mining",
    request_body = CalculateMetricsRequest,
    responses(
        (status = 200, description = "Metrics calculated", body = RoleMetricsListResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn calculate_metrics(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CalculateMetricsRequest>,
) -> ApiResult<Json<RoleMetricsListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let role_ids = request.role_ids.unwrap_or_default();
    let metrics = state
        .metrics_service
        .calculate_metrics_for_roles(tenant_id, &role_ids)
        .await?;

    Ok(Json(RoleMetricsListResponse {
        items: metrics.into_iter().map(Into::into).collect(),
        total: role_ids.len() as i64,
        page: 0,
        page_size: role_ids.len() as i64,
    }))
}
