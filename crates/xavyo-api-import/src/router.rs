//! Router and state for the bulk user import API (F086).
//!
//! Provides the `ImportState` struct and `import_router()` function
//! that creates the Axum router for all import-related endpoints.

use axum::{
    middleware,
    routing::{get, post},
    Extension, Router,
};
use sqlx::PgPool;
use std::sync::Arc;
use xavyo_api_auth::{jwt_auth_middleware, EmailSender};

use crate::handlers;

/// Shared state for import routes.
#[derive(Clone)]
pub struct ImportState {
    /// Database connection pool.
    pub pool: PgPool,
    /// Email sender for invitation emails.
    pub email_sender: Arc<dyn EmailSender>,
}

impl ImportState {
    /// Create a new `ImportState`.
    pub fn new(pool: PgPool, email_sender: Arc<dyn EmailSender>) -> Self {
        Self { pool, email_sender }
    }
}

/// Create the import router with admin (JWT-protected) and public routes.
///
/// Admin routes (require JWT auth):
/// - POST   /admin/users/import                              — Upload CSV
/// - GET    /admin/users/imports                             — List jobs
/// - GET    /`admin/users/imports/:job_id`                     — Get job
/// - GET    /`admin/users/imports/:job_id/errors`              — List errors
/// - GET    /`admin/users/imports/:job_id/errors/download`     — Download error CSV
/// - POST   /admin/users/imports/:job_id/resend-invitations  — Bulk resend
/// - POST   /`admin/users/:user_id/invite`                    — Resend single invite
///
/// Public routes (no auth required):
/// - GET    /invite/:token                                   — Validate token
/// - POST   /invite/:token                                   — Accept invitation
pub fn import_router(state: ImportState) -> Router {
    let admin_routes = Router::new()
        // CSV upload
        .route(
            "/admin/users/import",
            post(handlers::import::create_import_job),
        )
        // Job listing and details
        .route(
            "/admin/users/imports",
            get(handlers::import::list_import_jobs),
        )
        .route(
            "/admin/users/imports/:job_id",
            get(handlers::import::get_import_job),
        )
        // Error listing and download
        .route(
            "/admin/users/imports/:job_id/errors",
            get(handlers::errors::list_import_errors),
        )
        .route(
            "/admin/users/imports/:job_id/errors/download",
            get(handlers::errors::download_import_errors),
        )
        // Invitation management
        .route(
            "/admin/users/imports/:job_id/resend-invitations",
            post(handlers::invitations::bulk_resend_invitations),
        )
        .route(
            "/admin/users/:user_id/invite",
            post(handlers::invitations::resend_user_invitation),
        )
        // Apply JWT auth middleware to all admin routes
        .layer(middleware::from_fn(jwt_auth_middleware));

    let public_routes = Router::new().route(
        "/invite/:token",
        get(handlers::invitations::validate_invitation_token)
            .post(handlers::invitations::accept_invitation),
    );

    Router::new()
        .merge(admin_routes)
        .merge(public_routes)
        .layer(Extension(state.pool.clone()))
        .layer(Extension(state.email_sender.clone()))
}
