//! SSF API router wiring.
//!
//! Two routers: the tenant-scoped stream-management API (mount under `/ssf`,
//! behind the app's authentication + tenant-context layer) and the public
//! configuration metadata (mount under `/.well-known`).

use axum::{
    routing::{get, post},
    Router,
};

use crate::handlers::{
    add_subject, create_stream, delete_stream, get_status, get_stream, list_streams,
    remove_subject, ssf_configuration, update_status, SsfState,
};

/// Stream-management router. Mount at `/ssf` behind auth + `Extension<TenantId>`.
///
/// - `POST /ssf/streams` create · `GET /ssf/streams` list
/// - `GET /ssf/stream?stream_id=…` read · `DELETE /ssf/stream?stream_id=…` delete
/// - `GET /ssf/status?stream_id=…` · `POST /ssf/status` (update)
/// - `POST /ssf/subjects:add` · `POST /ssf/subjects:remove`
pub fn ssf_router(state: SsfState) -> Router {
    Router::new()
        .route("/streams", post(create_stream).get(list_streams))
        .route("/stream", get(get_stream).delete(delete_stream))
        .route("/status", get(get_status).post(update_status))
        .route("/subjects:add", post(add_subject))
        .route("/subjects:remove", post(remove_subject))
        .with_state(state)
}

/// Public configuration-metadata router. Mount at `/.well-known`.
///
/// - `GET /.well-known/ssf-configuration`
pub fn ssf_well_known_router(state: SsfState) -> Router {
    Router::new()
        .route("/ssf-configuration", get(ssf_configuration))
        .with_state(state)
}
