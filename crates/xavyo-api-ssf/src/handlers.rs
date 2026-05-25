//! SSF Transmitter HTTP handlers (stream management + configuration metadata).
//!
//! Stream-management endpoints are tenant-scoped: the tenant comes from the
//! authenticated request (`Extension<TenantId>`, set by the app's auth layer),
//! and every DB call runs under that tenant's RLS context. The configuration
//! metadata endpoint is public discovery.

use axum::{
    extract::{Extension, Query, State},
    http::StatusCode,
    Json,
};
use sqlx::pool::PoolConnection;
use sqlx::Postgres;
use xavyo_core::TenantId;
use xavyo_db::models::{CreateSsfStream, SsfPollToken, SsfStream, SsfSubject};
use xavyo_ssf::{CaepEvent, SubjectId, CREDENTIAL_CHANGE_URI, SESSION_REVOKED_URI};

use crate::error::SsfApiError;
use crate::models::{
    CreateStreamRequest, SsfConfigurationMetadata, StatusResponse, StreamIdQuery, StreamResponse,
    SubjectRequest, UpdateStatusRequest, VerifyRequest,
};

/// Shared state for the SSF API.
#[derive(Clone)]
pub struct SsfState {
    /// Database pool.
    pub pool: sqlx::PgPool,
    /// Transmitter issuer identifier (stamped into metadata + responses).
    pub issuer: String,
    /// SET signer/deliverer — used to send stream-verification events (SSF
    /// §7.1.4) on demand (the CAEP fan-out uses its own emitter copy).
    pub transmitter: std::sync::Arc<crate::transmitter::SsfTransmitter>,
}

/// CAEP event types this transmitter can actually deliver (v1).
const SUPPORTED_EVENTS: [&str; 2] = [SESSION_REVOKED_URI, CREDENTIAL_CHANGE_URI];

/// Acquire a pooled connection with the tenant RLS context set.
pub(crate) async fn tenant_conn(
    pool: &sqlx::PgPool,
    tenant_id: uuid::Uuid,
) -> Result<PoolConnection<Postgres>, SsfApiError> {
    let mut conn = pool.acquire().await?;
    sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
        .bind(tenant_id.to_string())
        .execute(&mut *conn)
        .await?;
    Ok(conn)
}

/// `GET /.well-known/ssf-configuration` — transmitter configuration (SSF §7).
pub async fn ssf_configuration(State(state): State<SsfState>) -> Json<SsfConfigurationMetadata> {
    Json(SsfConfigurationMetadata::new(&state.issuer))
}

/// `POST /ssf/streams` — create a stream.
pub async fn create_stream(
    State(state): State<SsfState>,
    Extension(tenant_id): Extension<TenantId>,
    Json(req): Json<CreateStreamRequest>,
) -> Result<(StatusCode, Json<StreamResponse>), SsfApiError> {
    req.validate()?;
    let tenant = *tenant_id.as_uuid();
    let is_poll = req.is_poll();

    // We deliver only the requested events we actually support.
    let events_delivered: Vec<String> = req
        .events_requested
        .iter()
        .filter(|e| SUPPORTED_EVENTS.contains(&e.as_str()))
        .cloned()
        .collect();

    let mut conn = tenant_conn(&state.pool, tenant).await?;
    let stream = SsfStream::create(
        &mut *conn,
        CreateSsfStream {
            tenant_id: tenant,
            aud: req.aud,
            delivery_method: req.delivery.method,
            endpoint_url: req.delivery.endpoint_url,
            delivery_authorization_header: req.delivery_authorization_header,
            events_requested: req.events_requested,
            events_delivered,
            description: req.description,
        },
    )
    .await?;

    // RFC 8936: a poll stream gets a one-time bearer token (hash stored) the
    // receiver presents to POST /ssf/poll. Returned once in this response.
    let response = if is_poll {
        let token = crate::poll::generate_poll_token();
        SsfPollToken::create(
            &mut *conn,
            &crate::poll::hash_poll_token(&token),
            stream.stream_id,
            tenant,
        )
        .await?;
        StreamResponse::from_stream(stream, &state.issuer).with_poll_token(token)
    } else {
        StreamResponse::from_stream(stream, &state.issuer)
    };

    Ok((StatusCode::CREATED, Json(response)))
}

/// `POST /ssf/verify` — request a stream-verification event (SSF §7.1.4).
///
/// Admin-triggered via the tenant-authed management API: sends a verification
/// SET to the stream (pushed for RFC 8935 streams, queued for RFC 8936), which
/// the receiver echoes back to confirm it can receive and process SETs.
pub async fn verify_stream(
    State(state): State<SsfState>,
    Extension(tenant_id): Extension<TenantId>,
    Json(req): Json<VerifyRequest>,
) -> Result<StatusCode, SsfApiError> {
    let tenant = *tenant_id.as_uuid();
    let stream = {
        let mut conn = tenant_conn(&state.pool, tenant).await?;
        SsfStream::get(&mut *conn, tenant, req.stream_id)
            .await?
            .ok_or(SsfApiError::StreamNotFound)?
    };

    let subject = SubjectId::iss_sub(state.issuer.clone(), stream.stream_id.to_string());
    let event = CaepEvent::Verification { state: req.state };
    state
        .transmitter
        .send_one(&state.pool, tenant, &stream, &subject, &event)
        .await
        .map_err(|e| SsfApiError::Internal(e.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}

/// `GET /ssf/streams` — list the tenant's streams.
pub async fn list_streams(
    State(state): State<SsfState>,
    Extension(tenant_id): Extension<TenantId>,
) -> Result<Json<Vec<StreamResponse>>, SsfApiError> {
    let tenant = *tenant_id.as_uuid();
    let mut conn = tenant_conn(&state.pool, tenant).await?;
    let streams = SsfStream::list_by_tenant(&mut *conn, tenant).await?;
    Ok(Json(
        streams
            .into_iter()
            .map(|s| StreamResponse::from_stream(s, &state.issuer))
            .collect(),
    ))
}

/// `GET /ssf/stream?stream_id=…` — read one stream's configuration.
pub async fn get_stream(
    State(state): State<SsfState>,
    Extension(tenant_id): Extension<TenantId>,
    Query(q): Query<StreamIdQuery>,
) -> Result<Json<StreamResponse>, SsfApiError> {
    let tenant = *tenant_id.as_uuid();
    let mut conn = tenant_conn(&state.pool, tenant).await?;
    let stream = SsfStream::get(&mut *conn, tenant, q.stream_id)
        .await?
        .ok_or(SsfApiError::StreamNotFound)?;
    Ok(Json(StreamResponse::from_stream(stream, &state.issuer)))
}

/// `DELETE /ssf/stream?stream_id=…` — delete a stream.
pub async fn delete_stream(
    State(state): State<SsfState>,
    Extension(tenant_id): Extension<TenantId>,
    Query(q): Query<StreamIdQuery>,
) -> Result<StatusCode, SsfApiError> {
    let tenant = *tenant_id.as_uuid();
    let mut conn = tenant_conn(&state.pool, tenant).await?;
    let deleted = SsfStream::delete(&mut *conn, tenant, q.stream_id).await?;
    if deleted {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(SsfApiError::StreamNotFound)
    }
}

/// `GET /ssf/status?stream_id=…` — read a stream's status (SSF §8.1.2).
pub async fn get_status(
    State(state): State<SsfState>,
    Extension(tenant_id): Extension<TenantId>,
    Query(q): Query<StreamIdQuery>,
) -> Result<Json<StatusResponse>, SsfApiError> {
    let tenant = *tenant_id.as_uuid();
    let mut conn = tenant_conn(&state.pool, tenant).await?;
    let stream = SsfStream::get(&mut *conn, tenant, q.stream_id)
        .await?
        .ok_or(SsfApiError::StreamNotFound)?;
    Ok(Json(StatusResponse {
        stream_id: stream.stream_id,
        status: stream.status,
    }))
}

/// `POST /ssf/status` — update a stream's status (SSF §8.1.2).
pub async fn update_status(
    State(state): State<SsfState>,
    Extension(tenant_id): Extension<TenantId>,
    Json(req): Json<UpdateStatusRequest>,
) -> Result<Json<StatusResponse>, SsfApiError> {
    req.validate()?;
    let tenant = *tenant_id.as_uuid();
    let mut conn = tenant_conn(&state.pool, tenant).await?;
    let stream = SsfStream::update_status(&mut *conn, tenant, req.stream_id, &req.status)
        .await?
        .ok_or(SsfApiError::StreamNotFound)?;
    Ok(Json(StatusResponse {
        stream_id: stream.stream_id,
        status: stream.status,
    }))
}

/// `POST /ssf/subjects:add` — register a subject on a stream.
pub async fn add_subject(
    State(state): State<SsfState>,
    Extension(tenant_id): Extension<TenantId>,
    Json(req): Json<SubjectRequest>,
) -> Result<StatusCode, SsfApiError> {
    let tenant = *tenant_id.as_uuid();
    let mut conn = tenant_conn(&state.pool, tenant).await?;
    // Ensure the stream exists in this tenant before attaching a subject.
    SsfStream::get(&mut *conn, tenant, req.stream_id)
        .await?
        .ok_or(SsfApiError::StreamNotFound)?;
    SsfSubject::add(&mut *conn, tenant, req.stream_id, &req.subject).await?;
    Ok(StatusCode::OK)
}

/// `POST /ssf/subjects:remove` — unregister a subject from a stream.
pub async fn remove_subject(
    State(state): State<SsfState>,
    Extension(tenant_id): Extension<TenantId>,
    Json(req): Json<SubjectRequest>,
) -> Result<StatusCode, SsfApiError> {
    let tenant = *tenant_id.as_uuid();
    let mut conn = tenant_conn(&state.pool, tenant).await?;
    SsfSubject::remove(&mut *conn, tenant, req.stream_id, &req.subject).await?;
    Ok(StatusCode::NO_CONTENT)
}
