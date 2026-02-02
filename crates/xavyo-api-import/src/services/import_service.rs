//! Import service for managing import jobs (F086).
//!
//! Handles job creation (file validation, SHA-256 hashing),
//! job status queries, and concurrent import enforcement.

use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::ImportError;
use crate::services::csv_parser::{self, CsvParseResult, DEFAULT_MAX_FILE_SIZE, DEFAULT_MAX_ROWS};
use xavyo_db::models::{CreateImportJob, UserImportJob};

/// Import service for job lifecycle management.
pub struct ImportService;

impl ImportService {
    /// Validate a CSV upload and create a pending import job.
    ///
    /// Validates file size, parses CSV headers and rows, computes SHA-256 file hash,
    /// checks for concurrent imports, and creates the DB job record.
    ///
    /// Returns the created job and the parse result (for background processing).
    pub async fn create_import_job(
        pool: &PgPool,
        tenant_id: Uuid,
        created_by: Option<Uuid>,
        file_name: &str,
        file_data: &[u8],
        send_invitations: bool,
    ) -> Result<(UserImportJob, CsvParseResult), ImportError> {
        // Validate file size
        if file_data.len() > DEFAULT_MAX_FILE_SIZE {
            return Err(ImportError::FileTooLarge(format!(
                "File size {} bytes exceeds maximum of {} bytes",
                file_data.len(),
                DEFAULT_MAX_FILE_SIZE
            )));
        }

        // Validate file is not empty
        if file_data.is_empty() {
            return Err(ImportError::InvalidFileType("File is empty".to_string()));
        }

        // Parse CSV
        let parse_result = csv_parser::parse_csv(file_data).map_err(ImportError::InvalidCsv)?;

        // Validate row count
        if parse_result.total_rows > DEFAULT_MAX_ROWS {
            return Err(ImportError::TooManyRows(format!(
                "CSV contains {} data rows, maximum allowed is {}",
                parse_result.total_rows, DEFAULT_MAX_ROWS
            )));
        }

        if parse_result.total_rows == 0 {
            return Err(ImportError::InvalidCsv(
                "CSV file contains no data rows".to_string(),
            ));
        }

        // Check for concurrent import
        let has_concurrent = UserImportJob::check_concurrent_import(pool, tenant_id).await?;
        if has_concurrent {
            return Err(ImportError::ConcurrentImport);
        }

        // Compute SHA-256 file hash
        let file_hash = {
            let mut hasher = Sha256::new();
            hasher.update(file_data);
            hex::encode(hasher.finalize())
        };

        // Create job record
        let job = UserImportJob::create(
            pool,
            CreateImportJob {
                tenant_id,
                file_name: file_name.to_string(),
                file_hash,
                file_size_bytes: file_data.len() as i64,
                total_rows: parse_result.total_rows as i32,
                send_invitations,
                created_by,
            },
        )
        .await?;

        tracing::info!(
            tenant_id = %tenant_id,
            job_id = %job.id,
            file_name = file_name,
            total_rows = parse_result.total_rows,
            "Import job created"
        );

        Ok((job, parse_result))
    }

    /// Get an import job by ID for a specific tenant.
    pub async fn get_job(
        pool: &PgPool,
        tenant_id: Uuid,
        job_id: Uuid,
    ) -> Result<UserImportJob, ImportError> {
        UserImportJob::find_by_id(pool, tenant_id, job_id)
            .await?
            .ok_or(ImportError::JobNotFound)
    }

    /// List import jobs for a tenant with optional status filter and pagination.
    pub async fn list_jobs(
        pool: &PgPool,
        tenant_id: Uuid,
        status: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<UserImportJob>, i64), ImportError> {
        let (jobs, total) =
            UserImportJob::list_by_tenant(pool, tenant_id, status, limit, offset).await?;
        Ok((jobs, total))
    }
}
