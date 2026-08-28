//! Micro-certification handlers for governance API (F055).

use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use uuid::Uuid;
use validator::Validate;

use xavyo_auth::JwtClaims;
use xavyo_db::models::{
    GovApplication, GovEntitlement, GovMicroCertTrigger, GovMicroCertification, GovRiskLevel,
    MicroCertificationFilter, User,
};
use xavyo_db::MicroCertEventFilter;

use crate::error::{ApiGovernanceError, ApiResult};
use crate::models::{
    BulkDecisionFailure, BulkDecisionRequest, BulkDecisionResponse,
    DecideMicroCertificationRequest, DelegateMicroCertificationRequest, ListMicroCertEventsQuery,
    ListMicroCertificationsQuery, ManualTriggerRequest, ManualTriggerResponse,
    MicroCertEntitlementSummary, MicroCertEventListResponse, MicroCertEventResponse,
    MicroCertUserSummary, MicroCertificationListResponse, MicroCertificationResponse,
    MicroCertificationStatsResponse, MicroCertificationWithDetailsResponse,
    SkipMicroCertificationRequest, TriggerRuleSummary,
};
use crate::router::GovernanceState;

fn user_display_name(display_name: Option<&str>, email: &str) -> String {
    display_name
        .filter(|name| !name.is_empty())
        .unwrap_or(email)
        .to_string()
}

fn entitlement_risk_level(level: GovRiskLevel) -> String {
    match level {
        GovRiskLevel::Low => "low",
        GovRiskLevel::Medium => "medium",
        GovRiskLevel::High => "high",
        GovRiskLevel::Critical => "critical",
    }
    .to_string()
}

async fn micro_cert_user_summary(
    pool: &sqlx::PgPool,
    tenant_id: Uuid,
    user_id: Uuid,
) -> ApiResult<Option<MicroCertUserSummary>> {
    Ok(User::find_by_id_in_tenant(pool, tenant_id, user_id)
        .await?
        .map(|user| MicroCertUserSummary {
            id: user.id,
            email: user.email.clone(),
            display_name: user_display_name(user.display_name.as_deref(), &user.email),
            department: user.department(),
            manager_id: user.manager_id,
        }))
}

async fn micro_cert_entitlement_summary(
    pool: &sqlx::PgPool,
    tenant_id: Uuid,
    entitlement_id: Uuid,
) -> ApiResult<Option<MicroCertEntitlementSummary>> {
    let Some(entitlement) = GovEntitlement::find_by_id(pool, tenant_id, entitlement_id).await?
    else {
        return Ok(None);
    };
    let application_name = GovApplication::find_by_id(pool, tenant_id, entitlement.application_id)
        .await?
        .map(|app| app.name)
        .unwrap_or_default();
    Ok(Some(MicroCertEntitlementSummary {
        id: entitlement.id,
        name: entitlement.name,
        description: entitlement.description,
        application_id: entitlement.application_id,
        application_name,
        risk_level: Some(entitlement_risk_level(entitlement.risk_level)),
        is_sensitive: matches!(
            entitlement.risk_level,
            GovRiskLevel::High | GovRiskLevel::Critical
        ),
    }))
}

async fn micro_cert_trigger_summary(
    pool: &sqlx::PgPool,
    tenant_id: Uuid,
    trigger_rule_id: Option<Uuid>,
) -> ApiResult<Option<TriggerRuleSummary>> {
    let Some(trigger_rule_id) = trigger_rule_id else {
        return Ok(None);
    };
    Ok(
        GovMicroCertTrigger::find_by_id(pool, tenant_id, trigger_rule_id)
            .await?
            .map(|trigger| TriggerRuleSummary {
                id: trigger.id,
                name: trigger.name,
                trigger_type: trigger.trigger_type,
            }),
    )
}

async fn micro_cert_with_details(
    pool: &sqlx::PgPool,
    tenant_id: Uuid,
    cert: GovMicroCertification,
) -> ApiResult<MicroCertificationWithDetailsResponse> {
    let user = micro_cert_user_summary(pool, tenant_id, cert.user_id).await?;
    let entitlement = micro_cert_entitlement_summary(pool, tenant_id, cert.entitlement_id).await?;
    let reviewer = micro_cert_user_summary(pool, tenant_id, cert.reviewer_id).await?;
    let trigger_rule = micro_cert_trigger_summary(pool, tenant_id, cert.trigger_rule_id).await?;
    Ok(MicroCertificationWithDetailsResponse {
        certification: MicroCertificationResponse::from(cert),
        user,
        entitlement,
        reviewer,
        trigger_rule,
        events: None,
    })
}

/// List micro-certifications with filtering.
#[utoipa::path(
    get,
    path = "/governance/micro-certifications",
    tag = "Governance - Micro-certification",
    params(ListMicroCertificationsQuery),
    responses(
        (status = 200, description = "List of micro-certifications", body = MicroCertificationListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_certifications(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListMicroCertificationsQuery>,
) -> ApiResult<Json<MicroCertificationListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0).max(0);

    let filter = MicroCertificationFilter {
        entitlement_id: query.entitlement_id,
        trigger_rule_id: query.trigger_rule_id,
        from_date: query.from_date,
        to_date: query.to_date,
        escalated: query.escalated,
        past_deadline: query.past_deadline,
        status: query.status,
        reviewer_id: query.reviewer_id,
        user_id: query.user_id,
        assignment_id: query.assignment_id,
    };

    let (certs, total) = state
        .micro_certification_service
        .list(tenant_id, &filter, limit, offset)
        .await?;

    let mut items = Vec::with_capacity(certs.len());
    for cert in certs {
        items.push(micro_cert_with_details(state.pool(), tenant_id, cert).await?);
    }

    Ok(Json(MicroCertificationListResponse {
        items,
        total,
        limit,
        offset,
    }))
}

/// Get micro-certifications pending for the current user.
#[utoipa::path(
    get,
    path = "/governance/micro-certifications/my-pending",
    tag = "Governance - Micro-certification",
    params(
        ("limit" = Option<i64>, Query, description = "Maximum results"),
        ("offset" = Option<i64>, Query, description = "Skip results")
    ),
    responses(
        (status = 200, description = "My pending micro-certifications", body = MicroCertificationListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn my_pending(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListMicroCertificationsQuery>,
) -> ApiResult<Json<MicroCertificationListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0).max(0);

    let (certs, total) = state
        .micro_certification_service
        .get_my_pending(tenant_id, user_id, limit, offset)
        .await?;

    let mut items = Vec::with_capacity(certs.len());
    for cert in certs {
        items.push(micro_cert_with_details(state.pool(), tenant_id, cert).await?);
    }

    Ok(Json(MicroCertificationListResponse {
        items,
        total,
        limit,
        offset,
    }))
}

/// Get a micro-certification by ID.
#[utoipa::path(
    get,
    path = "/governance/micro-certifications/{id}",
    tag = "Governance - Micro-certification",
    params(
        ("id" = Uuid, Path, description = "Micro-certification ID")
    ),
    responses(
        (status = 200, description = "Micro-certification details", body = MicroCertificationWithDetailsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Micro-certification not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_certification(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<MicroCertificationWithDetailsResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let cert = state.micro_certification_service.get(tenant_id, id).await?;

    Ok(Json(
        micro_cert_with_details(state.pool(), tenant_id, cert).await?,
    ))
}

/// Make a decision on a micro-certification.
#[utoipa::path(
    post,
    path = "/governance/micro-certifications/{id}/decide",
    tag = "Governance - Micro-certification",
    params(
        ("id" = Uuid, Path, description = "Micro-certification ID")
    ),
    request_body = DecideMicroCertificationRequest,
    responses(
        (status = 200, description = "Decision recorded", body = MicroCertificationResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Not authorized to decide"),
        (status = 404, description = "Micro-certification not found"),
        (status = 409, description = "Already decided"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn decide(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<DecideMicroCertificationRequest>,
) -> ApiResult<Json<MicroCertificationResponse>> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let result = state
        .micro_certification_service
        .decide(tenant_id, id, user_id, request.decision, request.comment)
        .await?;

    Ok(Json(MicroCertificationResponse::from(result.certification)))
}

/// Delegate a micro-certification to another reviewer.
#[utoipa::path(
    post,
    path = "/governance/micro-certifications/{id}/delegate",
    tag = "Governance - Micro-certification",
    params(
        ("id" = Uuid, Path, description = "Micro-certification ID")
    ),
    request_body = DelegateMicroCertificationRequest,
    responses(
        (status = 200, description = "Delegation recorded", body = MicroCertificationResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Not authorized to delegate"),
        (status = 404, description = "Micro-certification not found"),
        (status = 409, description = "Already decided"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn delegate(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<DelegateMicroCertificationRequest>,
) -> ApiResult<Json<MicroCertificationResponse>> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let result = state
        .micro_certification_service
        .delegate(tenant_id, id, user_id, request.delegate_to, request.comment)
        .await?;

    Ok(Json(MicroCertificationResponse::from(result)))
}

/// Bulk decide on multiple micro-certifications.
#[utoipa::path(
    post,
    path = "/governance/micro-certifications/bulk-decide",
    tag = "Governance - Micro-certification",
    request_body = BulkDecisionRequest,
    responses(
        (status = 200, description = "Bulk decision result", body = BulkDecisionResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn bulk_decide(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<BulkDecisionRequest>,
) -> ApiResult<Json<BulkDecisionResponse>> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let result = state
        .micro_certification_service
        .bulk_decide(
            tenant_id,
            &request.certification_ids,
            user_id,
            request.decision,
            request.comment,
        )
        .await?;

    let failures: Vec<BulkDecisionFailure> = result
        .failed
        .iter()
        .map(|(id, err)| BulkDecisionFailure {
            certification_id: *id,
            error: err.clone(),
        })
        .collect();

    Ok(Json(BulkDecisionResponse {
        success_count: result.succeeded.len() as i64,
        failure_count: failures.len() as i64,
        succeeded: result.succeeded,
        failures,
    }))
}

/// Get events for a micro-certification.
#[utoipa::path(
    get,
    path = "/governance/micro-certifications/{id}/events",
    tag = "Governance - Micro-certification",
    params(
        ("id" = Uuid, Path, description = "Micro-certification ID"),
        ListMicroCertEventsQuery
    ),
    responses(
        (status = 200, description = "Micro-certification events", body = MicroCertEventListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Micro-certification not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_events(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Query(query): Query<ListMicroCertEventsQuery>,
) -> ApiResult<Json<MicroCertEventListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    // Verify certification exists
    let _ = state.micro_certification_service.get(tenant_id, id).await?;

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0).max(0);
    let filter = MicroCertEventFilter {
        micro_certification_id: Some(id),
        event_type: query.event_type,
        actor_id: query.actor_id,
        from_date: query.from_date,
        to_date: query.to_date,
    };

    let (events, total) = state
        .micro_certification_service
        .search_events(tenant_id, &filter, limit, offset)
        .await?;

    let items: Vec<MicroCertEventResponse> = events
        .into_iter()
        .map(MicroCertEventResponse::from)
        .collect();

    Ok(Json(MicroCertEventListResponse {
        items,
        total,
        limit,
        offset,
    }))
}

/// Get statistics for micro-certifications.
#[utoipa::path(
    get,
    path = "/governance/micro-certifications/stats",
    tag = "Governance - Micro-certification",
    responses(
        (status = 200, description = "Micro-certification statistics", body = MicroCertificationStatsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_stats(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
) -> ApiResult<Json<MicroCertificationStatsResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let stats = state
        .micro_certification_service
        .get_stats(tenant_id)
        .await?;

    Ok(Json(MicroCertificationStatsResponse::from(stats)))
}

/// Search micro-certification events across all certifications (audit trail).
#[utoipa::path(
    get,
    path = "/governance/micro-cert-events",
    tag = "Governance - Micro-certification",
    params(ListMicroCertEventsQuery),
    responses(
        (status = 200, description = "List of micro-certification events", body = MicroCertEventListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn search_events(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListMicroCertEventsQuery>,
) -> ApiResult<Json<MicroCertEventListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0).max(0);

    let filter = MicroCertEventFilter {
        micro_certification_id: query.micro_certification_id,
        event_type: query.event_type,
        actor_id: query.actor_id,
        from_date: query.from_date,
        to_date: query.to_date,
    };

    let (events, total) = state
        .micro_certification_service
        .search_events(tenant_id, &filter, limit, offset)
        .await?;

    let items: Vec<MicroCertEventResponse> = events
        .into_iter()
        .map(MicroCertEventResponse::from)
        .collect();

    Ok(Json(MicroCertEventListResponse {
        items,
        total,
        limit,
        offset,
    }))
}

/// Manually trigger a micro-certification for a user's entitlement.
#[utoipa::path(
    post,
    path = "/governance/micro-certifications/trigger",
    tag = "Governance - Micro-certification",
    request_body = ManualTriggerRequest,
    responses(
        (status = 200, description = "Micro-certification created or existing returned", body = ManualTriggerResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "User, entitlement, or trigger rule not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn manual_trigger(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<ManualTriggerRequest>,
) -> ApiResult<Json<ManualTriggerResponse>> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let triggered_by =
        Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let result = state
        .micro_certification_service
        .create_manual(
            tenant_id,
            request.user_id,
            request.entitlement_id,
            request.trigger_rule_id,
            request.reviewer_id,
            &request.reason,
            triggered_by,
        )
        .await?;

    let message = if result.duplicate_skipped {
        "Existing pending certification returned - duplicate skipped".to_string()
    } else {
        "Micro-certification created successfully".to_string()
    };

    Ok(Json(ManualTriggerResponse {
        certification: MicroCertificationResponse::from(result.certification),
        duplicate_skipped: result.duplicate_skipped,
        message,
    }))
}

/// Skip a micro-certification (when assignment is already deleted).
#[utoipa::path(
    post,
    path = "/governance/micro-certifications/{id}/skip",
    tag = "Governance - Micro-certification",
    params(
        ("id" = Uuid, Path, description = "Micro-certification ID")
    ),
    request_body = SkipMicroCertificationRequest,
    responses(
        (status = 200, description = "Micro-certification skipped", body = MicroCertificationResponse),
        (status = 400, description = "Invalid request - reason required"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Micro-certification not found"),
        (status = 409, description = "Already decided"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn skip_certification(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<SkipMicroCertificationRequest>,
) -> ApiResult<Json<MicroCertificationResponse>> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let _user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    // Get the certification first to find its assignment
    let cert = state.micro_certification_service.get(tenant_id, id).await?;

    // Skip the certification - use assignment-based skip if available, otherwise skip by ID
    if let Some(assignment_id) = cert.assignment_id {
        state
            .micro_certification_service
            .skip_by_assignment(tenant_id, assignment_id)
            .await?;

        // Refetch the updated certification
        let updated = state.micro_certification_service.get(tenant_id, id).await?;
        Ok(Json(MicroCertificationResponse::from(updated)))
    } else {
        // No assignment context (e.g., manually triggered) - skip by ID directly
        let updated = state
            .micro_certification_service
            .skip_by_id(tenant_id, id)
            .await?
            .ok_or(ApiGovernanceError::MicroCertificationNotFound(id))?;
        Ok(Json(MicroCertificationResponse::from(updated)))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn my_pending_uses_count_not_page_length() {
        let src = include_str!("micro_certifications.rs");
        let production = src.split("mod tests").next().expect("production source");
        let pending = production
            .split("pub async fn my_pending")
            .nth(1)
            .and_then(|s| s.split("pub async fn ").next())
            .expect("my_pending");
        assert!(
            pending.contains("let (certs, total)") && !pending.contains("certs.len() as i64"),
            "GET /governance/micro-certifications/my-pending must report the filtered total, not the page length"
        );
    }

    #[test]
    fn get_events_honors_pagination_and_filters() {
        let src = include_str!("micro_certifications.rs");
        let production = src.split("mod tests").next().expect("production source");
        let events = production
            .split("pub async fn get_events")
            .nth(1)
            .and_then(|s| s.split("pub async fn ").next())
            .expect("get_events");
        assert!(
            events.contains("search_events(")
                && events.contains("query.limit")
                && !events.contains("limit: 100")
                && !events.contains("events.len() as i64"),
            "GET micro-certification events must paginate with a real total, not a fake limit of 100"
        );
    }

    #[test]
    fn micro_certification_lists_include_related_details() {
        let src = include_str!("micro_certifications.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            production.contains("micro_cert_with_details(")
                && production.contains("micro_cert_user_summary(")
                && production.contains("micro_cert_entitlement_summary(")
                && production.contains("GovEntitlement::find_by_id")
                && production.contains("User::find_by_id_in_tenant")
                && production.contains("manager_id: user.manager_id")
                && production.contains("department: user.department()")
                && !production.contains("manager_id: None")
                && !production.contains("department: None"),
            "micro-certification list/my-pending must look up user, entitlement, reviewer, manager_id, and department"
        );
        assert!(
            !production.contains(
                "user: None,\n            entitlement: None,\n            reviewer: None"
            ),
            "must not return micro-certifications with empty related details"
        );
    }

    #[test]
    fn get_certification_returns_nested_details() {
        let src = include_str!("micro_certifications.rs");
        let production = src.split("mod tests").next().expect("production source");
        let get = production
            .split("pub async fn get_certification")
            .nth(1)
            .and_then(|s| s.split("pub async fn ").next())
            .expect("get_certification");
        assert!(
            get.contains("micro_cert_with_details(")
                && get.contains("MicroCertificationWithDetailsResponse")
                && !get.contains("MicroCertificationResponse::from(cert)"),
            "GET /governance/micro-certifications/{{id}} must return nested user/entitlement/reviewer details"
        );
    }
}
