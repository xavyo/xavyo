//! SSF API router wiring.
//!
//! Two routers: the tenant-scoped stream-management API (mount under `/ssf`,
//! behind the app's authentication + tenant-context layer) and the public
//! configuration metadata (mount under `/.well-known`).

use axum::{
    extract::{Json, Path, State},
    http::{StatusCode, Uri},
    routing::{get, post},
    Extension, Router,
};
use xavyo_auth::JwtClaims;
use xavyo_core::TenantId;

use crate::error::SsfApiError;
use crate::handlers::{
    add_subject, create_stream, delete_stream, get_status, get_stream, list_streams,
    remove_subject, ssf_configuration, update_status, verify_stream, SsfState,
};
use crate::models::SubjectRequest;

/// Axum 0.7 / matchit treats `:name` in a path as a parameter. Registering
/// both `/subjects:add` and `/subjects:remove` therefore collides (same
/// static prefix + param) and panics at router build. One `/subjects:op`
/// route matches the SSF paths `/subjects:add` and `/subjects:remove`.
const SUBJECTS_ROUTE: &str = "/subjects:op";

/// Stream-management router. Mount at `/ssf` behind auth + `Extension<TenantId>`.
///
/// - `POST /ssf/streams` create · `GET /ssf/streams` list
/// - `GET /ssf/stream?stream_id=…` read · `DELETE /ssf/stream?stream_id=…` delete
/// - `GET /ssf/status?stream_id=…` · `POST /ssf/status` (update)
/// - `POST /ssf/subjects:add` · `POST /ssf/subjects:remove`
/// - `POST /ssf/verify` request a stream-verification event (SSF §7.1.4)
pub fn ssf_router(state: SsfState) -> Router {
    Router::new()
        .route("/streams", post(create_stream).get(list_streams))
        .route("/stream", get(get_stream).delete(delete_stream))
        .route("/status", get(get_status).post(update_status))
        .route(SUBJECTS_ROUTE, post(subject_mutation))
        .route("/verify", post(verify_stream))
        .with_state(state)
}

/// Dispatch `POST /subjects:add` vs `POST /subjects:remove` without two Axum routes.
pub async fn subject_mutation(
    Path(op): Path<String>,
    uri: Uri,
    State(state): State<SsfState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Json(req): Json<SubjectRequest>,
) -> Result<StatusCode, SsfApiError> {
    // Prefer the URI suffix (SSF `subjects:add` / `subjects:remove`); the
    // captured `:op` param is the same value when the route matches.
    let op = subject_op_from_path(uri.path())
        .map(str::to_owned)
        .unwrap_or(op);
    match op.as_str() {
        "add" => {
            add_subject(
                State(state),
                Extension(tenant_id),
                Extension(claims),
                Json(req),
            )
            .await
        }
        "remove" => {
            remove_subject(
                State(state),
                Extension(tenant_id),
                Extension(claims),
                Json(req),
            )
            .await
        }
        other => Err(SsfApiError::InvalidRequest(format!(
            "unknown subjects operation '{other}' (supported: add, remove)"
        ))),
    }
}

/// Last `:segment` of an SSF subjects path (`/ssf/subjects:add` → `add`).
#[must_use]
pub fn subject_op_from_path(path: &str) -> Option<&str> {
    path.rsplit_once(':')
        .map(|(_, op)| op)
        .filter(|op| !op.is_empty() && !op.contains('/'))
}

/// Public configuration-metadata router. Mount at `/.well-known`.
///
/// - `GET /.well-known/ssf-configuration`
pub fn ssf_well_known_router(state: SsfState) -> Router {
    Router::new()
        .route("/ssf-configuration", get(ssf_configuration))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use std::sync::Arc;
    use tower::ServiceExt;

    fn dummy_state() -> SsfState {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://ssf-router-test:unused@127.0.0.1/unused")
            .expect("lazy pool does not connect");
        let transmitter = crate::transmitter::SsfTransmitter::new(
            Arc::new(b"not-a-real-key".to_vec()),
            "test-kid",
            "https://idp.example.com",
        )
        .expect("http client");
        SsfState {
            pool,
            issuer: "https://idp.example.com".into(),
            transmitter: Arc::new(transmitter),
        }
    }

    #[test]
    fn subject_op_from_path_reads_ssf_colon_suffix() {
        assert_eq!(subject_op_from_path("/ssf/subjects:add"), Some("add"));
        assert_eq!(subject_op_from_path("/subjects:remove"), Some("remove"));
        assert_eq!(subject_op_from_path("/subjects:add"), Some("add"));
        assert_ne!(
            subject_op_from_path("/subjects:add"),
            subject_op_from_path("/subjects:remove")
        );
    }

    #[test]
    fn dual_colon_subject_routes_panic_on_axum_07() {
        let panicked = std::panic::catch_unwind(|| {
            let _ = Router::<()>::new()
                .route("/subjects:add", post(|| async {}))
                .route("/subjects:remove", post(|| async {}));
        });
        assert!(
            panicked.is_err(),
            "Axum 0.7 must still reject two /subjects:NAME routes so we keep the dispatcher"
        );
    }

    #[tokio::test]
    async fn ssf_router_constructs_and_distinguishes_subject_add_and_remove() {
        let app = ssf_router(dummy_state());
        let body = Body::from(
            r#"{"stream_id":"00000000-0000-0000-0000-000000000001","subject":{"format":"opaque","id":"u1"}}"#,
        );

        let add = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/subjects:add")
                    .header("content-type", "application/json")
                    .body(body)
                    .unwrap(),
            )
            .await
            .expect("oneshot add");
        assert_ne!(
            add.status(),
            StatusCode::NOT_FOUND,
            "POST /subjects:add must be registered"
        );

        let remove = ssf_router(dummy_state())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/subjects:remove")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"stream_id":"00000000-0000-0000-0000-000000000001","subject":{"format":"opaque","id":"u1"}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .expect("oneshot remove");
        assert_ne!(
            remove.status(),
            StatusCode::NOT_FOUND,
            "POST /subjects:remove must be registered as a distinct path from add"
        );
    }
}
