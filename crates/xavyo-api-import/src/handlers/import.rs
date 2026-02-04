//! Import job handlers (F086).
//!
//! - POST /admin/users/import — CSV upload and job creation
//! - GET  /admin/users/imports — List import jobs
//! - GET  /`admin/users/imports/:job_id` — Get import job details

use axum::{
    extract::{Path, Query},
    http::StatusCode,
    Extension, Json,
};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;
use xavyo_api_auth::EmailSender;
use xavyo_auth::JwtClaims;

use crate::error::ImportError;
use crate::models::{
    ImportJobCreatedResponse, ImportJobListResponse, ImportJobResponse, ImportJobSummary,
    ListImportJobsParams,
};
use crate::services::import_service::ImportService;
use crate::services::job_processor;
use xavyo_webhooks::EventPublisher;

/// Maximum allowed filename length (bytes).
const MAX_FILENAME_LENGTH: usize = 255;

/// SECURITY: Sanitize uploaded filename to prevent path traversal and other attacks.
///
/// This function:
/// - Removes directory components (path traversal prevention)
/// - Filters to only allow safe characters (alphanumeric, dash, underscore, period)
/// - Limits the filename length
/// - Preserves the .csv extension
fn sanitize_filename(raw_filename: &str) -> String {
    // Extract just the filename part (remove any path components)
    let filename = raw_filename
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(raw_filename);

    // Filter to safe characters only: alphanumeric, dash, underscore, period
    let sanitized: String = filename
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
        .collect();

    // Ensure we don't start with a period (hidden file) or have multiple consecutive periods
    let sanitized = sanitized.trim_start_matches('.');
    let sanitized: String = sanitized.chars().fold(String::new(), |mut acc, c| {
        if c == '.' && acc.ends_with('.') {
            // Skip consecutive periods
        } else {
            acc.push(c);
        }
        acc
    });

    // Limit length (preserve extension if possible)
    let result = if sanitized.len() > MAX_FILENAME_LENGTH {
        if let Some(ext_pos) = sanitized.rfind('.') {
            let ext = &sanitized[ext_pos..];
            if ext.len() < MAX_FILENAME_LENGTH {
                let name_len = MAX_FILENAME_LENGTH - ext.len();
                format!("{}{}", &sanitized[..name_len], ext)
            } else {
                sanitized[..MAX_FILENAME_LENGTH].to_string()
            }
        } else {
            sanitized[..MAX_FILENAME_LENGTH].to_string()
        }
    } else {
        sanitized
    };

    // If result is empty or just an extension, use a default
    if result.is_empty() || result == "csv" || result == ".csv" {
        "upload.csv".to_string()
    } else {
        result
    }
}

/// POST /admin/users/import
///
/// Upload a CSV file and create an import job. Processing happens asynchronously.
pub async fn create_import_job(
    Extension(claims): Extension<JwtClaims>,
    Extension(pool): Extension<PgPool>,
    Extension(email_sender): Extension<Arc<dyn EmailSender>>,
    event_publisher: Option<Extension<EventPublisher>>,
    mut multipart: axum_extra::extract::Multipart,
) -> Result<(StatusCode, Json<ImportJobCreatedResponse>), ImportError> {
    let tenant_id = extract_tenant_id(&claims)?;
    let user_id = extract_user_id(&claims);

    let mut file_data: Option<Vec<u8>> = None;
    let mut file_name: Option<String> = None;
    let mut send_invitations = false;

    // Read multipart fields
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| ImportError::Internal(format!("Multipart read error: {e}")))?
    {
        let name = field.name().unwrap_or("").to_string();

        match name.as_str() {
            "file" => {
                file_name = field.file_name().map(std::string::ToString::to_string);
                let bytes = field
                    .bytes()
                    .await
                    .map_err(|e| ImportError::Internal(format!("Failed to read file: {e}")))?;
                file_data = Some(bytes.to_vec());
            }
            "send_invitations" => {
                let text = field
                    .text()
                    .await
                    .map_err(|e| ImportError::Internal(format!("Failed to read field: {e}")))?;
                send_invitations = matches!(text.to_lowercase().as_str(), "true" | "1" | "yes");
            }
            _ => {
                // Ignore unknown fields
            }
        }
    }

    let data = file_data.ok_or_else(|| {
        ImportError::InvalidFileType("No 'file' field found in multipart upload".to_string())
    })?;

    // SECURITY: Sanitize filename to prevent path traversal and injection attacks
    let fname = sanitize_filename(&file_name.unwrap_or_else(|| "upload.csv".to_string()));

    // Validate file extension (after sanitization)
    if !fname.to_lowercase().ends_with(".csv") {
        return Err(ImportError::InvalidFileType(
            "File must have a .csv extension".to_string(),
        ));
    }

    // Create import job (validates file, parses CSV, creates DB record)
    let (job, parse_result) = ImportService::create_import_job(
        &pool,
        tenant_id,
        user_id,
        &fname,
        &data,
        send_invitations,
    )
    .await?;

    let job_id = job.id;
    let total_rows = job.total_rows;
    let job_file_name = job.file_name.clone();

    // Spawn background processing task
    let bg_pool = pool.clone();
    let bg_email = email_sender.clone();
    let bg_publisher = event_publisher.map(|Extension(p)| p);
    tokio::spawn(async move {
        job_processor::process_job(
            bg_pool,
            tenant_id,
            job_id,
            parse_result,
            send_invitations,
            bg_email,
            bg_publisher,
        )
        .await;
    });

    Ok((
        StatusCode::ACCEPTED,
        Json(ImportJobCreatedResponse {
            job_id,
            status: "pending".to_string(),
            file_name: job_file_name,
            total_rows,
            message: Some("Import job created. Processing will begin shortly.".to_string()),
        }),
    ))
}

/// GET /admin/users/imports
///
/// List import jobs with optional status filter and pagination.
pub async fn list_import_jobs(
    Extension(claims): Extension<JwtClaims>,
    Extension(pool): Extension<PgPool>,
    Query(params): Query<ListImportJobsParams>,
) -> Result<Json<ImportJobListResponse>, ImportError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);

    let (jobs, total) =
        ImportService::list_jobs(&pool, tenant_id, params.status.as_deref(), limit, offset).await?;

    let items: Vec<ImportJobSummary> = jobs.into_iter().map(ImportJobSummary::from).collect();

    Ok(Json(ImportJobListResponse {
        items,
        total,
        limit,
        offset,
    }))
}

/// GET /`admin/users/imports/:job_id`
///
/// Get detailed import job status.
pub async fn get_import_job(
    Extension(claims): Extension<JwtClaims>,
    Extension(pool): Extension<PgPool>,
    Path(job_id): Path<Uuid>,
) -> Result<Json<ImportJobResponse>, ImportError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let job = ImportService::get_job(&pool, tenant_id, job_id).await?;

    Ok(Json(ImportJobResponse::from(job)))
}

/// Extract `tenant_id` from JWT claims.
fn extract_tenant_id(claims: &JwtClaims) -> Result<Uuid, ImportError> {
    claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(ImportError::Unauthorized)
}

/// Extract `user_id` from JWT claims (optional, for audit).
fn extract_user_id(claims: &JwtClaims) -> Option<Uuid> {
    Uuid::parse_str(&claims.sub).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_filename_removes_path_components() {
        // Path traversal attempts - extracts just the filename part
        assert_eq!(sanitize_filename("../../../etc/passwd"), "passwd");
        assert_eq!(sanitize_filename("/etc/passwd"), "passwd");
        assert_eq!(
            sanitize_filename("..\\..\\windows\\system32\\cmd.exe"),
            "cmd.exe"
        );
        assert_eq!(sanitize_filename("C:\\Users\\Admin\\file.csv"), "file.csv");
    }

    #[test]
    fn test_sanitize_filename_removes_dangerous_characters() {
        assert_eq!(sanitize_filename("file<script>.csv"), "filescript.csv");
        assert_eq!(sanitize_filename("file;rm -rf.csv"), "filerm-rf.csv");
        assert_eq!(sanitize_filename("file$(whoami).csv"), "filewhoami.csv");
        assert_eq!(sanitize_filename("file`id`.csv"), "fileid.csv");
    }

    #[test]
    fn test_sanitize_filename_allows_safe_characters() {
        assert_eq!(sanitize_filename("my-file_2023.csv"), "my-file_2023.csv");
        assert_eq!(
            sanitize_filename("Test.File.Name.csv"),
            "Test.File.Name.csv"
        );
        assert_eq!(sanitize_filename("UPPERCASE.csv"), "UPPERCASE.csv");
    }

    #[test]
    fn test_sanitize_filename_handles_hidden_files() {
        assert_eq!(sanitize_filename(".hidden.csv"), "hidden.csv");
        assert_eq!(sanitize_filename("...multiple.csv"), "multiple.csv");
    }

    #[test]
    fn test_sanitize_filename_handles_consecutive_periods() {
        assert_eq!(sanitize_filename("file..csv"), "file.csv");
        assert_eq!(sanitize_filename("file....csv"), "file.csv");
    }

    #[test]
    fn test_sanitize_filename_truncates_long_names() {
        let long_name = "a".repeat(300) + ".csv";
        let sanitized = sanitize_filename(&long_name);
        assert!(sanitized.len() <= MAX_FILENAME_LENGTH);
        assert!(sanitized.ends_with(".csv"));
    }

    #[test]
    fn test_sanitize_filename_handles_empty_or_invalid() {
        assert_eq!(sanitize_filename(""), "upload.csv");
        assert_eq!(sanitize_filename("..."), "upload.csv");
        // After stripping leading period, ".csv" becomes "csv" which matches
        // the "just extension" check and becomes "upload.csv"
        assert_eq!(sanitize_filename(".csv"), "upload.csv");
        // Plain "csv" (just the extension name) also becomes "upload.csv"
        assert_eq!(sanitize_filename("csv"), "upload.csv");
        // But "data.csv" remains unchanged
        assert_eq!(sanitize_filename("data.csv"), "data.csv");
    }

    #[test]
    fn test_sanitize_filename_preserves_extension() {
        assert_eq!(sanitize_filename("data.csv"), "data.csv");
        assert_eq!(sanitize_filename("file.CSV"), "file.CSV");
    }
}
