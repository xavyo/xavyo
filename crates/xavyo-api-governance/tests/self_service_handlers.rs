//! Drive shipped self-service IGA handlers with a non-admin JWT.
//!
//! These tests call `create_request`, `list_my_requests`, `approve_request`,
//! `reject_request`, `list_catalog_categories`, `decide_item`, and
//! `launch_campaign` (admin-only → 403), plus oneshot
//! `governance_self_service_router`.

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{Method, Request, StatusCode};
use axum::response::IntoResponse;
use axum::{Extension, Json};
use chrono::{Duration, Utc};
use common::*;
use serde_json::Value;
use tower::ServiceExt;
use uuid::Uuid;
use xavyo_api_governance::handlers::access_requests::{create_request, list_my_requests};
use xavyo_api_governance::handlers::approvals::{approve_request, reject_request};
use xavyo_api_governance::handlers::catalog::list_catalog_categories;
use xavyo_api_governance::handlers::certification_campaigns::launch_campaign;
use xavyo_api_governance::handlers::certification_items::decide_item;
use xavyo_api_governance::models::{
    ApproveRequestRequest, CreateAccessRequestRequest, DecisionRequest, ListAccessRequestsQuery,
    ListCategoriesQuery, ListPendingApprovalsQuery, RejectRequestRequest,
};
use xavyo_api_governance::router::{governance_self_service_router, GovernanceState};
use xavyo_auth::JwtClaims;
use xavyo_core::TenantId;
use xavyo_db::{
    CertDecisionType, CertReviewerType, CertScopeType, CreateCertificationCampaign,
    CreateCertificationItem, CreateGovApprovalStep, CreateGovApprovalWorkflow, GovApprovalStep,
    GovApprovalWorkflow, GovApproverType, GovCertificationCampaign, GovCertificationItem,
};
use xavyo_ssf::NoopEmitter;

fn ensure_siem_key() {
    if std::env::var("XAVYO_SIEM_ENCRYPTION_KEY").is_ok() {
        return;
    }
    // 32-byte key from docker-compose.yml default (tests only).
    // SAFETY: process-wide test setup; value is a dummy key.
    unsafe {
        std::env::set_var(
            "XAVYO_SIEM_ENCRYPTION_KEY",
            "zxDtnpmuQkkoKKupjsjDjgdx/OGnAaS4O65YpGHNY+M=",
        );
    }
}

fn user_claims(user_id: Uuid, tenant_id: Uuid) -> JwtClaims {
    JwtClaims::builder()
        .subject(user_id.to_string())
        .tenant_id(TenantId::from_uuid(tenant_id))
        .roles(vec!["user"])
        .expires_in_secs(3600)
        .build()
}

async fn json_body(response: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("read body");
    serde_json::from_slice(&bytes).unwrap_or_else(|_| Value::Null)
}

#[tokio::test]
async fn non_admin_jwt_drives_self_service_handlers() {
    ensure_siem_key();
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let requester_id = create_test_user(&pool, tenant_id).await;
    let approver_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;
    let entitlement_approve = create_test_entitlement(&pool, tenant_id, app_id, None).await;
    let entitlement_reject = create_test_entitlement(&pool, tenant_id, app_id, None).await;

    let workflow = GovApprovalWorkflow::create(
        &pool,
        tenant_id,
        CreateGovApprovalWorkflow {
            name: format!("wf-{tenant_id}"),
            description: Some("self-service handler test".into()),
            is_default: true,
        },
    )
    .await
    .expect("create workflow");
    GovApprovalStep::create(
        &pool,
        workflow.id,
        CreateGovApprovalStep {
            step_order: 1,
            approver_type: GovApproverType::SpecificUsers,
            specific_approvers: Some(vec![approver_id]),
            escalation_enabled: false,
        },
    )
    .await
    .expect("create approval step");

    let state = GovernanceState::new(pool.clone())
        .expect("GovernanceState")
        .with_caep_emitter(Arc::new(NoopEmitter));

    let requester = user_claims(requester_id, tenant_id);
    let approver = user_claims(approver_id, tenant_id);
    assert!(
        !requester.has_role("admin") && !approver.has_role("admin"),
        "fixtures must be non-admin"
    );

    // --- catalog (handler) ---
    let catalog = list_catalog_categories(
        State(state.clone()),
        Extension(requester.clone()),
        Query(ListCategoriesQuery {
            parent_id: None,
            limit: 50,
            offset: 0,
        }),
    )
    .await
    .expect("list_catalog_categories");
    assert!(catalog.0.total >= 0);

    // --- catalog via shipped self-service router (oneshot) ---
    let router = governance_self_service_router(pool.clone(), Arc::new(NoopEmitter))
        .layer(Extension(requester.clone()));
    let catalog_http = router
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/catalog/categories")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot catalog");
    assert_eq!(
        catalog_http.status(),
        StatusCode::OK,
        "non-admin GET /catalog/categories via governance_self_service_router"
    );

    // --- create + list (requester) ---
    let justification = "Business need for access that is long enough".to_string();
    let (created_status, Json(created)) = create_request(
        State(state.clone()),
        Extension(requester.clone()),
        None,
        Json(CreateAccessRequestRequest {
            entitlement_id: entitlement_approve,
            justification: justification.clone(),
            requested_expires_at: None,
        }),
    )
    .await
    .unwrap_or_else(|e| panic!("create_request: {e:?}"));
    assert_eq!(created_status, StatusCode::CREATED);
    assert_eq!(created.request.requester_id, requester_id);
    let approve_id = created.request.id;

    let (reject_status, Json(to_reject)) = create_request(
        State(state.clone()),
        Extension(requester.clone()),
        None,
        Json(CreateAccessRequestRequest {
            entitlement_id: entitlement_reject,
            justification: justification.clone(),
            requested_expires_at: None,
        }),
    )
    .await
    .unwrap_or_else(|e| panic!("create_request reject fixture: {e:?}"));
    assert_eq!(reject_status, StatusCode::CREATED);
    let reject_id = to_reject.request.id;

    let Json(listed) = list_my_requests(
        State(state.clone()),
        Extension(requester.clone()),
        Query(ListAccessRequestsQuery::default()),
    )
    .await
    .expect("list_my_requests");
    assert!(
        listed.items.iter().any(|r| r.id == approve_id),
        "list_my_requests must include the request created by this non-admin JWT"
    );

    // --- approve / reject (approver, still non-admin) ---
    let Json(approved) = approve_request(
        State(state.clone()),
        Extension(approver.clone()),
        None,
        Path(approve_id),
        Json(ApproveRequestRequest {
            comments: Some("looks good".into()),
        }),
    )
    .await
    .unwrap_or_else(|e| panic!("approve_request: {e:?}"));
    assert_eq!(approved.request_id, approve_id);

    let Json(rejected) = reject_request(
        State(state.clone()),
        Extension(approver.clone()),
        None,
        Path(reject_id),
        Json(RejectRequestRequest {
            comments: "does not meet policy".into(),
        }),
    )
    .await
    .unwrap_or_else(|e| panic!("reject_request: {e:?}"));
    assert_eq!(rejected.request_id, reject_id);

    // list_pending_approvals is the shipped queue handler
    let _ = xavyo_api_governance::handlers::approvals::list_pending_approvals(
        State(state.clone()),
        Extension(approver.clone()),
        Query(ListPendingApprovalsQuery::default()),
    )
    .await
    .expect("list_pending_approvals");

    // --- certification decide ---
    let campaign = GovCertificationCampaign::create(
        &pool,
        tenant_id,
        CreateCertificationCampaign {
            name: format!("camp-{tenant_id}"),
            description: None,
            scope_type: CertScopeType::AllUsers,
            scope_config: None,
            reviewer_type: CertReviewerType::SpecificUsers,
            specific_reviewers: Some(vec![approver_id]),
            deadline: Utc::now() + Duration::days(7),
            created_by: requester_id,
        },
    )
    .await
    .expect("create campaign");
    GovCertificationCampaign::launch(&pool, tenant_id, campaign.id)
        .await
        .expect("launch campaign row")
        .expect("campaign launched");
    let item = GovCertificationItem::create(
        &pool,
        tenant_id,
        CreateCertificationItem {
            campaign_id: campaign.id,
            assignment_id: None,
            user_id: requester_id,
            entitlement_id: entitlement_approve,
            reviewer_id: approver_id,
            assignment_snapshot: serde_json::json!({}),
        },
    )
    .await
    .expect("create cert item");

    let Json(decided) = decide_item(
        State(state.clone()),
        Extension(approver.clone()),
        Path(item.id),
        Json(DecisionRequest {
            decision_type: CertDecisionType::Approved,
            justification: None,
        }),
    )
    .await
    .unwrap_or_else(|e| panic!("decide_item: {e:?}"));
    assert_eq!(decided.item.id, item.id);

    // --- admin-only write stays 403 for the same non-admin principal ---
    let launch_err = launch_campaign(
        State(state.clone()),
        Extension(requester.clone()),
        Path(campaign.id),
    )
    .await
    .expect_err("non-admin launch_campaign must fail");
    let forbidden = launch_err.into_response();
    assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);

    // router path: non-admin POST to an admin campaign launch is not on the
    // self-service router; GET my-approvals is.
    let router = governance_self_service_router(pool.clone(), Arc::new(NoopEmitter))
        .layer(Extension(approver));
    let my_approvals = router
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/my-approvals")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot my-approvals");
    assert_eq!(my_approvals.status(), StatusCode::OK);
    let _ = json_body(my_approvals).await;

    cleanup_test_tenant(&pool, tenant_id).await;
}
