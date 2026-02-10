//! Import error handlers (F086).
//!
//! - GET /`admin/users/imports/:job_id/errors` — List per-row errors
//! - GET /`admin/users/imports/:job_id/errors/download` — Download errors as CSV

use axum::{
    extract::{Path, Query},
    http::{header, StatusCode},
    response::IntoResponse,
    Extension, Json,
};
use sqlx::PgPool;
use uuid::Uuid;
use xavyo_auth::JwtClaims;

use crate::error::ImportError;
use crate::models::{ImportErrorListResponse, ImportErrorResponse, ListImportErrorsParams};
use crate::services::import_service::ImportService;
use xavyo_db::models::UserImportError;

/// GET /`admin/users/imports/:job_id/errors`
///
/// List per-row errors for an import job with pagination.
#[utoipa::path(
    get,
    path = "/admin/users/imports/{job_id}/errors",
    tag = "Import",
    params(
        ("job_id" = Uuid, Path, description = "Import job ID"),
        ("limit" = Option<i64>, Query, description = "Maximum results to return"),
        ("offset" = Option<i64>, Query, description = "Results to skip"),
    ),
    responses(
        (status = 200, description = "Import errors listed", body = ImportErrorListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Job not found"),
    ),
)]
pub async fn list_import_errors(
    Extension(claims): Extension<JwtClaims>,
    Extension(pool): Extension<PgPool>,
    Path(job_id): Path<Uuid>,
    Query(params): Query<ListImportErrorsParams>,
) -> Result<Json<ImportErrorListResponse>, ImportError> {
    let tenant_id = extract_tenant_id(&claims)?;
    if !claims.has_role("admin") {
        return Err(ImportError::Forbidden);
    }

    // Verify job exists and belongs to tenant
    let _ = ImportService::get_job(&pool, tenant_id, job_id).await?;

    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);

    let (errors, total) =
        UserImportError::list_by_job(&pool, tenant_id, job_id, limit, offset).await?;

    let items: Vec<ImportErrorResponse> =
        errors.into_iter().map(ImportErrorResponse::from).collect();

    Ok(Json(ImportErrorListResponse {
        items,
        total,
        limit,
        offset,
    }))
}

/// GET /`admin/users/imports/:job_id/errors/download`
///
/// Download all errors for an import job as a CSV file.
#[utoipa::path(
    get,
    path = "/admin/users/imports/{job_id}/errors/download",
    tag = "Import",
    params(
        ("job_id" = Uuid, Path, description = "Import job ID"),
    ),
    responses(
        (status = 200, description = "Error CSV file", content_type = "text/csv"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Job not found"),
    ),
)]
pub async fn download_import_errors(
    Extension(claims): Extension<JwtClaims>,
    Extension(pool): Extension<PgPool>,
    Path(job_id): Path<Uuid>,
) -> Result<impl IntoResponse, ImportError> {
    let tenant_id = extract_tenant_id(&claims)?;
    if !claims.has_role("admin") {
        return Err(ImportError::Forbidden);
    }

    // Verify job exists and belongs to tenant
    let job = ImportService::get_job(&pool, tenant_id, job_id).await?;

    let errors = UserImportError::list_all_by_job(&pool, tenant_id, job_id).await?;

    // Build CSV content
    let mut csv_writer = csv::Writer::from_writer(Vec::new());

    // Write header
    csv_writer
        .write_record([
            "line_number",
            "email",
            "column_name",
            "error_type",
            "error_message",
        ])
        .map_err(|e| ImportError::Internal(format!("CSV write error: {e}")))?;

    // Write error rows
    for err in &errors {
        csv_writer
            .write_record(&[
                err.line_number.to_string(),
                err.email.clone().unwrap_or_default(),
                err.column_name.clone().unwrap_or_default(),
                err.error_type.clone(),
                err.error_message.clone(),
            ])
            .map_err(|e| ImportError::Internal(format!("CSV write error: {e}")))?;
    }

    let csv_bytes = csv_writer
        .into_inner()
        .map_err(|e| ImportError::Internal(format!("CSV flush error: {e}")))?;

    // Sanitize filename to prevent Content-Disposition header injection
    let safe_name: String = job
        .file_name
        .replace(".csv", "")
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
        .collect();
    let filename = format!(
        "{}_errors.csv",
        if safe_name.is_empty() {
            "import"
        } else {
            &safe_name
        }
    );

    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/csv; charset=utf-8".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{filename}\""),
            ),
        ],
        csv_bytes,
    ))
}

/// Extract `tenant_id` from JWT claims.
fn extract_tenant_id(claims: &JwtClaims) -> Result<Uuid, ImportError> {
    claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(ImportError::Unauthorized)
}
