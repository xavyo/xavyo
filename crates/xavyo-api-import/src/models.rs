//! API request/response models for bulk user import (F086, F-021).
//!
//! All models include serde and utoipa derives for JSON serialization
//! and `OpenAPI` documentation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// CSV Parsing Configuration (F-021)
// ---------------------------------------------------------------------------

/// Supported CSV delimiters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CsvDelimiter {
    /// Comma (,) - default delimiter
    #[default]
    Comma,
    /// Semicolon (;) - common in European exports
    Semicolon,
    /// Tab character (\t)
    Tab,
    /// Pipe character (|)
    Pipe,
}

impl CsvDelimiter {
    /// Convert delimiter to byte for csv crate.
    #[must_use]
    pub fn as_byte(&self) -> u8 {
        match self {
            CsvDelimiter::Comma => b',',
            CsvDelimiter::Semicolon => b';',
            CsvDelimiter::Tab => b'\t',
            CsvDelimiter::Pipe => b'|',
        }
    }

    /// Parse delimiter from string input.
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "," | "comma" => Ok(CsvDelimiter::Comma),
            ";" | "semicolon" => Ok(CsvDelimiter::Semicolon),
            "\t" | "tab" | "\\t" => Ok(CsvDelimiter::Tab),
            "|" | "pipe" => Ok(CsvDelimiter::Pipe),
            _ => Err(format!(
                "Invalid delimiter '{s}'. Valid values: ',', ';', '\\t', '|'"
            )),
        }
    }
}

/// Fields to check for duplicates during CSV parsing.
#[derive(Debug, Clone, Default)]
pub struct DuplicateCheckFields {
    /// Check for duplicate emails (always enabled by default)
    pub email: bool,
    /// Check for duplicate usernames
    pub username: bool,
    /// Check for duplicate external IDs
    pub external_id: bool,
}

impl DuplicateCheckFields {
    /// Create with only email check (default, backward compatible).
    #[must_use]
    pub fn email_only() -> Self {
        Self {
            email: true,
            username: false,
            external_id: false,
        }
    }

    /// Parse from comma-separated string (e.g., "`email,username,external_id`").
    #[must_use]
    pub fn parse(s: &str) -> Self {
        let mut fields = Self::default();
        for field in s.split(',').map(|f| f.trim().to_lowercase()) {
            match field.as_str() {
                "email" => fields.email = true,
                "username" => fields.username = true,
                "external_id" | "externalid" => fields.external_id = true,
                _ => {} // Ignore unknown fields
            }
        }
        // Default to email if nothing specified
        if !fields.email && !fields.username && !fields.external_id {
            fields.email = true;
        }
        fields
    }
}

/// Configuration for CSV parsing (F-021).
///
/// All fields are optional for backward compatibility with existing imports.
#[derive(Debug, Clone, Default)]
pub struct CsvParseConfig {
    /// Field delimiter character. Default: comma
    pub delimiter: CsvDelimiter,
    /// Maximum rows to process. Default: 10,000
    pub max_rows: Option<usize>,
    /// Column name mapping: source header -> target field name
    pub column_mapping: Option<HashMap<String, String>>,
    /// Fields to check for duplicates
    pub duplicate_check_fields: DuplicateCheckFields,
    /// Whether to check database for existing duplicates
    pub check_database_duplicates: bool,
}

impl CsvParseConfig {
    /// Create config with defaults (backward compatible).
    #[must_use]
    pub fn new() -> Self {
        Self {
            delimiter: CsvDelimiter::Comma,
            max_rows: Some(10_000),
            column_mapping: None,
            duplicate_check_fields: DuplicateCheckFields::email_only(),
            check_database_duplicates: false,
        }
    }

    /// Set the delimiter.
    #[must_use]
    pub fn with_delimiter(mut self, delimiter: CsvDelimiter) -> Self {
        self.delimiter = delimiter;
        self
    }

    /// Set the maximum rows.
    #[must_use]
    pub fn with_max_rows(mut self, max_rows: usize) -> Self {
        self.max_rows = Some(max_rows);
        self
    }

    /// Set column mapping.
    #[must_use]
    pub fn with_column_mapping(mut self, mapping: HashMap<String, String>) -> Self {
        self.column_mapping = Some(mapping);
        self
    }

    /// Set duplicate check fields.
    #[must_use]
    pub fn with_duplicate_check_fields(mut self, fields: DuplicateCheckFields) -> Self {
        self.duplicate_check_fields = fields;
        self
    }
}

// ---------------------------------------------------------------------------
// Import Job responses
// ---------------------------------------------------------------------------

/// Response returned when an import job is created (202 Accepted).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ImportJobCreatedResponse {
    /// Unique job identifier for polling.
    pub job_id: Uuid,
    /// Initial job status (always "pending").
    pub status: String,
    /// Original uploaded filename.
    pub file_name: String,
    /// Total data rows detected in the CSV.
    pub total_rows: i32,
    /// Human-readable message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Full import job details.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ImportJobResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub status: String,
    pub file_name: String,
    pub file_hash: String,
    pub file_size_bytes: i64,
    pub total_rows: i32,
    pub processed_rows: i32,
    pub success_count: i32,
    pub error_count: i32,
    pub skip_count: i32,
    pub send_invitations: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_by: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Summary view of an import job for list responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ImportJobSummary {
    pub id: Uuid,
    pub status: String,
    pub file_name: String,
    pub total_rows: i32,
    pub success_count: i32,
    pub error_count: i32,
    pub skip_count: i32,
    pub send_invitations: bool,
    pub created_at: DateTime<Utc>,
}

/// Paginated list of import jobs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ImportJobListResponse {
    pub items: Vec<ImportJobSummary>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

// ---------------------------------------------------------------------------
// Import Error responses
// ---------------------------------------------------------------------------

/// A single per-row import error.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ImportErrorResponse {
    pub id: Uuid,
    pub line_number: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column_name: Option<String>,
    pub error_type: String,
    pub error_message: String,
    pub created_at: DateTime<Utc>,
}

/// Paginated list of import errors.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ImportErrorListResponse {
    pub items: Vec<ImportErrorResponse>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

// ---------------------------------------------------------------------------
// Invitation responses
// ---------------------------------------------------------------------------

/// Response after sending or resending an invitation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct InvitationResponse {
    pub invitation_id: Uuid,
    /// User ID for import invitations. May be None for admin invitations (F-ADMIN-INVITE).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<Uuid>,
    pub status: String,
    pub expires_at: DateTime<Utc>,
}

/// Response after bulk resending invitations.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct BulkResendResponse {
    pub resent_count: i32,
    pub skipped_count: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Response for invitation token validation (public endpoint).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct InvitationValidationResponse {
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Request body for accepting an invitation (setting password).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AcceptInvitationRequest {
    pub password: String,
}

/// Response after accepting an invitation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AcceptInvitationResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_url: Option<String>,
}

// ---------------------------------------------------------------------------
// Query parameters
// ---------------------------------------------------------------------------

/// Query parameters for listing import jobs.
#[derive(Debug, Clone, Deserialize)]
pub struct ListImportJobsParams {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
    pub status: Option<String>,
}

fn default_limit() -> i64 {
    20
}

/// Query parameters for listing import errors.
#[derive(Debug, Clone, Deserialize)]
pub struct ListImportErrorsParams {
    #[serde(default = "default_error_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_error_limit() -> i64 {
    50
}

// ---------------------------------------------------------------------------
// Conversions from DB models
// ---------------------------------------------------------------------------

impl From<xavyo_db::models::UserImportJob> for ImportJobResponse {
    fn from(job: xavyo_db::models::UserImportJob) -> Self {
        Self {
            id: job.id,
            tenant_id: job.tenant_id,
            status: job.status,
            file_name: job.file_name,
            file_hash: job.file_hash,
            file_size_bytes: job.file_size_bytes,
            total_rows: job.total_rows,
            processed_rows: job.processed_rows,
            success_count: job.success_count,
            error_count: job.error_count,
            skip_count: job.skip_count,
            send_invitations: job.send_invitations,
            created_by: job.created_by,
            started_at: job.started_at,
            completed_at: job.completed_at,
            error_message: job.error_message,
            created_at: job.created_at,
            updated_at: job.updated_at,
        }
    }
}

impl From<xavyo_db::models::UserImportJob> for ImportJobSummary {
    fn from(job: xavyo_db::models::UserImportJob) -> Self {
        Self {
            id: job.id,
            status: job.status,
            file_name: job.file_name,
            total_rows: job.total_rows,
            success_count: job.success_count,
            error_count: job.error_count,
            skip_count: job.skip_count,
            send_invitations: job.send_invitations,
            created_at: job.created_at,
        }
    }
}

impl From<xavyo_db::models::UserImportError> for ImportErrorResponse {
    fn from(err: xavyo_db::models::UserImportError) -> Self {
        Self {
            id: err.id,
            line_number: err.line_number,
            email: err.email,
            column_name: err.column_name,
            error_type: err.error_type,
            error_message: err.error_message,
            created_at: err.created_at,
        }
    }
}

impl From<xavyo_db::models::UserInvitation> for InvitationResponse {
    fn from(inv: xavyo_db::models::UserInvitation) -> Self {
        Self {
            invitation_id: inv.id,
            user_id: inv.user_id,
            status: inv.status,
            expires_at: inv.expires_at,
        }
    }
}
