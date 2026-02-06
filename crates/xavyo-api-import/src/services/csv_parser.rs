//! CSV parsing service for bulk user import (F086, F-021).
//!
//! Handles CSV header validation, row-by-row parsing, configurable delimiters,
//! column mapping, extended duplicate detection (email, username, `external_id`),
//! and per-field validation including custom attribute columns.

use std::collections::{HashMap, HashSet};

use crate::models::{CsvParseConfig, DuplicateCheckFields};
use crate::validation::{self, apply_column_mapping, validate_mapping_sources, HeaderValidation};

/// Maximum file size (10MB default, configurable).
pub const DEFAULT_MAX_FILE_SIZE: usize = 10 * 1024 * 1024;

/// Maximum rows per import (10,000 default, configurable).
pub const DEFAULT_MAX_ROWS: usize = 10_000;

/// Maximum rows allowed (100,000 for streaming).
pub const MAX_ROWS_LIMIT: usize = 100_000;

/// UTF-8 BOM bytes.
const UTF8_BOM: &[u8] = &[0xEF, 0xBB, 0xBF];

/// A single parsed CSV row with typed fields.
#[derive(Debug, Clone)]
pub struct ParsedRow {
    /// 1-based line number (header = 1, first data row = 2).
    pub line_number: i32,
    /// Email address (required).
    pub email: String,
    /// First name.
    pub first_name: Option<String>,
    /// Last name.
    pub last_name: Option<String>,
    /// Display name.
    pub display_name: Option<String>,
    /// Comma-separated role names.
    pub roles: Vec<String>,
    /// Comma-separated group display names.
    pub groups: Vec<String>,
    /// Department.
    pub department: Option<String>,
    /// Whether the user should be active (defaults to false for invitation flow).
    pub is_active: bool,
    /// Custom attribute values: `attribute_name` -> raw value string.
    pub custom_attributes: HashMap<String, String>,
    /// Username for login (F-021).
    pub username: Option<String>,
    /// External system ID (F-021).
    pub external_id: Option<String>,
}

/// Per-row validation error.
#[derive(Debug, Clone)]
pub struct RowError {
    pub line_number: i32,
    pub email: Option<String>,
    pub column_name: Option<String>,
    pub error_type: String,
    pub error_message: String,
}

/// Result of parsing a complete CSV file.
#[derive(Debug)]
pub struct CsvParseResult {
    /// Successfully parsed rows.
    pub rows: Vec<ParsedRow>,
    /// Per-row validation errors.
    pub errors: Vec<RowError>,
    /// Total data rows in the CSV (excluding header).
    pub total_rows: usize,
}

/// Tracks seen values for duplicate detection within a file.
#[derive(Debug, Default)]
struct DuplicateChecker {
    seen_emails: HashSet<String>,
    seen_usernames: HashSet<String>,
    seen_external_ids: HashSet<String>,
    check_fields: DuplicateCheckFields,
}

impl DuplicateChecker {
    fn new(check_fields: DuplicateCheckFields) -> Self {
        Self {
            seen_emails: HashSet::new(),
            seen_usernames: HashSet::new(),
            seen_external_ids: HashSet::new(),
            check_fields,
        }
    }

    /// Check for duplicates and return error if found.
    fn check_and_insert(
        &mut self,
        email: &str,
        username: Option<&str>,
        external_id: Option<&str>,
        line_number: i32,
    ) -> Option<RowError> {
        // Check email duplicates (if enabled)
        if self.check_fields.email {
            let email_lower = email.to_lowercase();
            if self.seen_emails.contains(&email_lower) {
                return Some(RowError {
                    line_number,
                    email: Some(email.to_string()),
                    column_name: Some("email".to_string()),
                    error_type: "duplicate_in_file".to_string(),
                    error_message: format!("Duplicate email '{email}' within CSV file"),
                });
            }
            self.seen_emails.insert(email_lower);
        }

        // Check username duplicates (if enabled and present)
        if self.check_fields.username {
            if let Some(uname) = username {
                if !uname.is_empty() {
                    let uname_lower = uname.to_lowercase();
                    if self.seen_usernames.contains(&uname_lower) {
                        return Some(RowError {
                            line_number,
                            email: Some(email.to_string()),
                            column_name: Some("username".to_string()),
                            error_type: "duplicate_username_in_file".to_string(),
                            error_message: format!("Duplicate username '{uname}' within CSV file"),
                        });
                    }
                    self.seen_usernames.insert(uname_lower);
                }
            }
        }

        // Check external_id duplicates (if enabled and present)
        if self.check_fields.external_id {
            if let Some(ext_id) = external_id {
                if !ext_id.is_empty() {
                    if self.seen_external_ids.contains(ext_id) {
                        return Some(RowError {
                            line_number,
                            email: Some(email.to_string()),
                            column_name: Some("external_id".to_string()),
                            error_type: "duplicate_external_id_in_file".to_string(),
                            error_message: format!(
                                "Duplicate external_id '{ext_id}' within CSV file"
                            ),
                        });
                    }
                    self.seen_external_ids.insert(ext_id.to_string());
                }
            }
        }

        None
    }
}

/// Strip UTF-8 BOM from the beginning of data if present.
fn strip_utf8_bom(data: &[u8]) -> &[u8] {
    if data.starts_with(UTF8_BOM) {
        &data[UTF8_BOM.len()..]
    } else {
        data
    }
}

/// Parse and validate a CSV file from raw bytes with default configuration.
///
/// Returns parsed rows, per-row errors, and total row count.
/// Does not fail the entire import for per-row errors.
pub fn parse_csv(data: &[u8]) -> Result<CsvParseResult, String> {
    parse_csv_with_config(data, &CsvParseConfig::new())
}

/// Parse and validate a CSV file from raw bytes with custom configuration.
///
/// Returns parsed rows, per-row errors, and total row count.
/// Does not fail the entire import for per-row errors.
pub fn parse_csv_with_config(
    data: &[u8],
    config: &CsvParseConfig,
) -> Result<CsvParseResult, String> {
    // Strip UTF-8 BOM if present
    let data = strip_utf8_bom(data);

    // Check for empty data
    if data.is_empty() {
        return Err("CSV file is empty".to_string());
    }

    let mut reader = csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(true)
        .delimiter(config.delimiter.as_byte())
        .from_reader(data);

    // Parse and validate headers
    let mut headers: Vec<String> = reader
        .headers()
        .map_err(|e| format!("Failed to read CSV headers: {e}"))?
        .iter()
        .map(std::string::ToString::to_string)
        .collect();

    // Apply column mapping if configured
    if let Some(mapping) = &config.column_mapping {
        validate_mapping_sources(&headers, mapping)?;
        headers = apply_column_mapping(&headers, mapping)?;
    }

    let header_validation = validation::validate_csv_headers(&headers);
    if !header_validation.valid {
        return Err(header_validation
            .error
            .unwrap_or_else(|| "Invalid CSV headers".to_string()));
    }

    let HeaderValidation {
        known_columns,
        custom_columns,
        ..
    } = header_validation;

    let mut rows = Vec::new();
    let mut errors = Vec::new();
    let mut duplicate_checker = DuplicateChecker::new(config.duplicate_check_fields.clone());
    let mut total_rows = 0usize;
    let max_rows = config.max_rows.unwrap_or(DEFAULT_MAX_ROWS);

    for (idx, result) in reader.records().enumerate() {
        let line_number = (idx + 2) as i32; // +2 because header=1, first data=2
        total_rows += 1;

        // Check max_rows limit
        if total_rows > max_rows {
            return Err(format!(
                "CSV file exceeds maximum row limit of {max_rows}. Processing stopped at row {total_rows}."
            ));
        }

        let record = match result {
            Ok(r) => r,
            Err(e) => {
                errors.push(RowError {
                    line_number,
                    email: None,
                    column_name: None,
                    error_type: "parse_error".to_string(),
                    error_message: format!("Failed to parse CSV row: {e}"),
                });
                continue;
            }
        };

        // Extract email (required)
        let email_idx = if let Some(&idx) = known_columns.get("email") {
            idx
        } else {
            errors.push(RowError {
                line_number,
                email: None,
                column_name: Some("email".to_string()),
                error_type: "validation".to_string(),
                error_message: "Email column index not found".to_string(),
            });
            continue;
        };

        let raw_email = record.get(email_idx).unwrap_or("").trim().to_string();
        let email = raw_email.to_lowercase();

        // Validate email format
        if let Err(msg) = validation::validate_email(&email) {
            errors.push(RowError {
                line_number,
                email: Some(raw_email),
                column_name: Some("email".to_string()),
                error_type: "validation".to_string(),
                error_message: msg,
            });
            continue;
        }

        // Extract username and external_id for duplicate checking
        let username = get_optional_field(&record, &known_columns, "username");
        let external_id = get_optional_field(&record, &known_columns, "external_id");

        // Check for duplicates
        if let Some(error) = duplicate_checker.check_and_insert(
            &email,
            username.as_deref(),
            external_id.as_deref(),
            line_number,
        ) {
            errors.push(error);
            continue;
        }

        // Extract optional known columns
        let first_name = get_optional_field(&record, &known_columns, "first_name");
        let last_name = get_optional_field(&record, &known_columns, "last_name");
        let display_name = get_optional_field(&record, &known_columns, "display_name")
            .map(|n| validation::sanitize_display_name(&n));
        let department = get_optional_field(&record, &known_columns, "department");

        // Parse roles (comma-separated)
        let roles = get_optional_field(&record, &known_columns, "roles")
            .map(|r| {
                r.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default();

        // Parse groups (comma-separated)
        let groups = get_optional_field(&record, &known_columns, "groups")
            .map(|g| {
                g.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default();

        // Parse is_active (defaults to false for invitation flow)
        let is_active = get_optional_field(&record, &known_columns, "is_active")
            .is_some_and(|v| matches!(v.to_lowercase().as_str(), "true" | "1" | "yes"));

        // Extract custom attribute columns
        let mut custom_attributes = HashMap::new();
        for (col_name, col_idx) in &custom_columns {
            if let Some(val) = record.get(*col_idx) {
                let trimmed = val.trim();
                if !trimmed.is_empty() {
                    custom_attributes.insert(col_name.clone(), trimmed.to_string());
                }
            }
        }

        rows.push(ParsedRow {
            line_number,
            email,
            first_name,
            last_name,
            display_name,
            roles,
            groups,
            department,
            is_active,
            custom_attributes,
            username,
            external_id,
        });
    }

    // Check for empty file (no data rows)
    if total_rows == 0 {
        return Err("CSV file contains no data rows".to_string());
    }

    Ok(CsvParseResult {
        rows,
        errors,
        total_rows,
    })
}

/// Get an optional string field from a CSV record by column name.
fn get_optional_field(
    record: &csv::StringRecord,
    columns: &HashMap<String, usize>,
    name: &str,
) -> Option<String> {
    columns
        .get(name)
        .and_then(|&idx| record.get(idx))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::CsvDelimiter;

    // =========================================================================
    // Existing tests (backward compatibility)
    // =========================================================================

    #[test]
    fn test_parse_csv_valid() {
        let csv =
            b"email,first_name,last_name\nuser1@example.com,John,Doe\nuser2@example.com,Jane,Smith";
        let result = parse_csv(csv).unwrap();
        assert_eq!(result.total_rows, 2);
        assert_eq!(result.rows.len(), 2);
        assert!(result.errors.is_empty());
        assert_eq!(result.rows[0].email, "user1@example.com");
        assert_eq!(result.rows[0].first_name.as_deref(), Some("John"));
    }

    #[test]
    fn test_parse_csv_missing_email_header() {
        let csv = b"first_name,last_name\nJohn,Doe";
        let result = parse_csv(csv);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_csv_invalid_email() {
        let csv = b"email\nnotanemail\nvalid@example.com";
        let result = parse_csv(csv).unwrap();
        assert_eq!(result.rows.len(), 1);
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.errors[0].error_type, "validation");
    }

    #[test]
    fn test_parse_csv_duplicate_email() {
        let csv = b"email\nuser@example.com\nuser@example.com";
        let result = parse_csv(csv).unwrap();
        assert_eq!(result.rows.len(), 1);
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.errors[0].error_type, "duplicate_in_file");
    }

    #[test]
    fn test_parse_csv_with_groups_and_roles() {
        let csv = b"email,roles,groups\nuser@example.com,\"admin,viewer\",\"Finance,IT\"";
        let result = parse_csv(csv).unwrap();
        assert_eq!(result.rows[0].roles, vec!["admin", "viewer"]);
        assert_eq!(result.rows[0].groups, vec!["Finance", "IT"]);
    }

    #[test]
    fn test_parse_csv_custom_columns() {
        let csv = b"email,cost_center,employee_id\nuser@example.com,CC001,EMP123";
        let result = parse_csv(csv).unwrap();
        assert_eq!(
            result.rows[0].custom_attributes.get("cost_center"),
            Some(&"CC001".to_string())
        );
    }

    #[test]
    fn test_parse_csv_is_active_defaults_false() {
        let csv = b"email\nuser@example.com";
        let result = parse_csv(csv).unwrap();
        assert!(!result.rows[0].is_active);
    }

    // =========================================================================
    // F-021 US1: Delimiter Configuration Tests
    // =========================================================================

    #[test]
    fn test_parse_csv_comma_delimiter_default() {
        let csv = b"email,first_name\nuser@example.com,John";
        let result = parse_csv(csv).unwrap();
        assert_eq!(result.rows.len(), 1);
        assert_eq!(result.rows[0].email, "user@example.com");
        assert_eq!(result.rows[0].first_name.as_deref(), Some("John"));
    }

    #[test]
    fn test_parse_csv_semicolon_delimiter() {
        let csv = b"email;first_name;last_name\nuser@example.com;John;Doe";
        let config = CsvParseConfig::new().with_delimiter(CsvDelimiter::Semicolon);
        let result = parse_csv_with_config(csv, &config).unwrap();
        assert_eq!(result.rows.len(), 1);
        assert_eq!(result.rows[0].email, "user@example.com");
        assert_eq!(result.rows[0].first_name.as_deref(), Some("John"));
        assert_eq!(result.rows[0].last_name.as_deref(), Some("Doe"));
    }

    #[test]
    fn test_parse_csv_tab_delimiter() {
        let csv = b"email\tfirst_name\tlast_name\nuser@example.com\tJohn\tDoe";
        let config = CsvParseConfig::new().with_delimiter(CsvDelimiter::Tab);
        let result = parse_csv_with_config(csv, &config).unwrap();
        assert_eq!(result.rows.len(), 1);
        assert_eq!(result.rows[0].email, "user@example.com");
        assert_eq!(result.rows[0].first_name.as_deref(), Some("John"));
    }

    #[test]
    fn test_parse_csv_pipe_delimiter() {
        let csv = b"email|first_name|last_name\nuser@example.com|John|Doe";
        let config = CsvParseConfig::new().with_delimiter(CsvDelimiter::Pipe);
        let result = parse_csv_with_config(csv, &config).unwrap();
        assert_eq!(result.rows.len(), 1);
        assert_eq!(result.rows[0].email, "user@example.com");
        assert_eq!(result.rows[0].first_name.as_deref(), Some("John"));
    }

    #[test]
    fn test_parse_csv_quoted_fields_with_embedded_delimiter() {
        // Semicolon delimiter with semicolon inside quoted field
        let csv = b"email;notes\nuser@example.com;\"Note with; semicolon\"";
        let config = CsvParseConfig::new().with_delimiter(CsvDelimiter::Semicolon);
        let result = parse_csv_with_config(csv, &config).unwrap();
        assert_eq!(result.rows.len(), 1);
        // The "notes" column is custom, check it's captured
        assert_eq!(
            result.rows[0].custom_attributes.get("notes"),
            Some(&"Note with; semicolon".to_string())
        );
    }

    #[test]
    fn test_parse_csv_utf8_bom_handling() {
        // UTF-8 BOM + CSV content
        let mut csv = vec![0xEF, 0xBB, 0xBF]; // BOM
        csv.extend_from_slice(b"email,first_name\nuser@example.com,John");
        let result = parse_csv(&csv).unwrap();
        assert_eq!(result.rows.len(), 1);
        assert_eq!(result.rows[0].email, "user@example.com");
    }

    #[test]
    fn test_delimiter_parse() {
        assert_eq!(CsvDelimiter::parse(",").unwrap(), CsvDelimiter::Comma);
        assert_eq!(CsvDelimiter::parse("comma").unwrap(), CsvDelimiter::Comma);
        assert_eq!(CsvDelimiter::parse(";").unwrap(), CsvDelimiter::Semicolon);
        assert_eq!(
            CsvDelimiter::parse("semicolon").unwrap(),
            CsvDelimiter::Semicolon
        );
        assert_eq!(CsvDelimiter::parse("\t").unwrap(), CsvDelimiter::Tab);
        assert_eq!(CsvDelimiter::parse("tab").unwrap(), CsvDelimiter::Tab);
        assert_eq!(CsvDelimiter::parse("\\t").unwrap(), CsvDelimiter::Tab);
        assert_eq!(CsvDelimiter::parse("|").unwrap(), CsvDelimiter::Pipe);
        assert_eq!(CsvDelimiter::parse("pipe").unwrap(), CsvDelimiter::Pipe);
        assert!(CsvDelimiter::parse("invalid").is_err());
    }

    // =========================================================================
    // F-021 US2: Extended Duplicate Detection Tests
    // =========================================================================

    #[test]
    fn test_parse_csv_duplicate_username_detection() {
        let csv = b"email,username\nuser1@example.com,jdoe\nuser2@example.com,jdoe";
        let config = CsvParseConfig::new().with_duplicate_check_fields(DuplicateCheckFields {
            email: true,
            username: true,
            external_id: false,
        });
        let result = parse_csv_with_config(csv, &config).unwrap();
        assert_eq!(result.rows.len(), 1);
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.errors[0].error_type, "duplicate_username_in_file");
    }

    #[test]
    fn test_parse_csv_duplicate_external_id_detection() {
        let csv = b"email,external_id\nuser1@example.com,EMP001\nuser2@example.com,EMP001";
        let config = CsvParseConfig::new().with_duplicate_check_fields(DuplicateCheckFields {
            email: true,
            username: false,
            external_id: true,
        });
        let result = parse_csv_with_config(csv, &config).unwrap();
        assert_eq!(result.rows.len(), 1);
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.errors[0].error_type, "duplicate_external_id_in_file");
    }

    #[test]
    fn test_parse_csv_mixed_duplicate_detection() {
        // First row OK, second duplicate email, third duplicate username
        let csv = b"email,username\nuser1@example.com,jdoe\nuser1@example.com,jsmith\nuser3@example.com,jdoe";
        let config = CsvParseConfig::new().with_duplicate_check_fields(DuplicateCheckFields {
            email: true,
            username: true,
            external_id: false,
        });
        let result = parse_csv_with_config(csv, &config).unwrap();
        assert_eq!(result.rows.len(), 1); // Only first row succeeds
        assert_eq!(result.errors.len(), 2); // Two duplicates
        assert_eq!(result.errors[0].error_type, "duplicate_in_file"); // email duplicate
        assert_eq!(result.errors[1].error_type, "duplicate_username_in_file"); // username duplicate
    }

    #[test]
    fn test_parse_csv_case_insensitive_username_duplicate() {
        let csv = b"email,username\nuser1@example.com,JDoe\nuser2@example.com,jdoe";
        let config = CsvParseConfig::new().with_duplicate_check_fields(DuplicateCheckFields {
            email: true,
            username: true,
            external_id: false,
        });
        let result = parse_csv_with_config(csv, &config).unwrap();
        assert_eq!(result.rows.len(), 1);
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.errors[0].error_type, "duplicate_username_in_file");
    }

    #[test]
    fn test_parse_csv_empty_username_not_duplicate() {
        // Empty usernames should not trigger duplicate detection
        let csv = b"email,username\nuser1@example.com,\nuser2@example.com,";
        let config = CsvParseConfig::new().with_duplicate_check_fields(DuplicateCheckFields {
            email: true,
            username: true,
            external_id: false,
        });
        let result = parse_csv_with_config(csv, &config).unwrap();
        assert_eq!(result.rows.len(), 2);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_duplicate_check_fields_parse() {
        let fields = DuplicateCheckFields::parse("email,username");
        assert!(fields.email);
        assert!(fields.username);
        assert!(!fields.external_id);

        let fields = DuplicateCheckFields::parse("username,external_id");
        assert!(!fields.email); // Not specified, but will default to email if all false
        assert!(fields.username);
        assert!(fields.external_id);

        let fields = DuplicateCheckFields::parse("");
        assert!(fields.email); // Defaults to email when empty
    }

    // =========================================================================
    // F-021 US3: Column Mapping Tests
    // =========================================================================

    #[test]
    fn test_parse_csv_simple_column_mapping() {
        let csv = b"E-mail,Given Name\nuser@example.com,John";
        let mut mapping = HashMap::new();
        mapping.insert("E-mail".to_string(), "email".to_string());
        mapping.insert("Given Name".to_string(), "first_name".to_string());
        let config = CsvParseConfig::new().with_column_mapping(mapping);
        let result = parse_csv_with_config(csv, &config).unwrap();
        assert_eq!(result.rows.len(), 1);
        assert_eq!(result.rows[0].email, "user@example.com");
        assert_eq!(result.rows[0].first_name.as_deref(), Some("John"));
    }

    #[test]
    fn test_parse_csv_multiple_column_mappings() {
        let csv = b"E-mail,Given Name,Surname,Employee ID\nuser@example.com,John,Doe,EMP001";
        let mut mapping = HashMap::new();
        mapping.insert("E-mail".to_string(), "email".to_string());
        mapping.insert("Given Name".to_string(), "first_name".to_string());
        mapping.insert("Surname".to_string(), "last_name".to_string());
        mapping.insert("Employee ID".to_string(), "external_id".to_string());
        let config = CsvParseConfig::new().with_column_mapping(mapping);
        let result = parse_csv_with_config(csv, &config).unwrap();
        assert_eq!(result.rows.len(), 1);
        assert_eq!(result.rows[0].email, "user@example.com");
        assert_eq!(result.rows[0].first_name.as_deref(), Some("John"));
        assert_eq!(result.rows[0].last_name.as_deref(), Some("Doe"));
        assert_eq!(result.rows[0].external_id.as_deref(), Some("EMP001"));
    }

    #[test]
    fn test_parse_csv_invalid_mapping_target() {
        let csv = b"E-mail\nuser@example.com";
        let mut mapping = HashMap::new();
        mapping.insert("E-mail".to_string(), "invalid_field".to_string());
        let config = CsvParseConfig::new().with_column_mapping(mapping);
        let result = parse_csv_with_config(csv, &config);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid_field"));
    }

    #[test]
    fn test_parse_csv_missing_mapped_source_column() {
        let csv = b"email\nuser@example.com";
        let mut mapping = HashMap::new();
        mapping.insert("NonExistent".to_string(), "first_name".to_string());
        let config = CsvParseConfig::new().with_column_mapping(mapping);
        let result = parse_csv_with_config(csv, &config);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("NonExistent"));
    }

    #[test]
    fn test_parse_csv_case_insensitive_mapping() {
        let csv = b"EMAIL,FIRST_NAME\nuser@example.com,John";
        let mut mapping = HashMap::new();
        mapping.insert("email".to_string(), "email".to_string());
        mapping.insert("first_name".to_string(), "first_name".to_string());
        let config = CsvParseConfig::new().with_column_mapping(mapping);
        let result = parse_csv_with_config(csv, &config).unwrap();
        assert_eq!(result.rows.len(), 1);
        assert_eq!(result.rows[0].email, "user@example.com");
    }

    // =========================================================================
    // F-021 US4: Large File / Streaming Tests
    // =========================================================================

    #[test]
    fn test_parse_csv_max_rows_limit() {
        let mut csv = String::from("email\n");
        for i in 0..15 {
            csv.push_str(&format!("user{i}@example.com\n"));
        }
        let config = CsvParseConfig::new().with_max_rows(10);
        let result = parse_csv_with_config(csv.as_bytes(), &config);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("exceeds maximum row limit"));
    }

    #[test]
    fn test_parse_csv_empty_file() {
        let csv = b"";
        let result = parse_csv(csv);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("empty"));
    }

    #[test]
    fn test_parse_csv_no_data_rows() {
        let csv = b"email,first_name,last_name";
        let result = parse_csv(csv);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("no data rows"));
    }

    #[test]
    fn test_parse_csv_large_file_streaming() {
        // Generate a file with 1000 rows
        let mut csv = String::from("email,first_name,last_name\n");
        for i in 0..1000 {
            csv.push_str(&format!("user{i}@example.com,User{i},Last{i}\n"));
        }
        let config = CsvParseConfig::new().with_max_rows(2000);
        let result = parse_csv_with_config(csv.as_bytes(), &config).unwrap();
        assert_eq!(result.total_rows, 1000);
        assert_eq!(result.rows.len(), 1000);
        assert!(result.errors.is_empty());
    }

    // =========================================================================
    // Additional Edge Cases
    // =========================================================================

    #[test]
    fn test_parse_csv_username_and_external_id_fields() {
        let csv = b"email,username,external_id\nuser@example.com,jdoe,EMP001";
        let result = parse_csv(csv).unwrap();
        assert_eq!(result.rows[0].username.as_deref(), Some("jdoe"));
        assert_eq!(result.rows[0].external_id.as_deref(), Some("EMP001"));
    }

    #[test]
    fn test_parse_csv_mixed_line_endings() {
        // Mix of CRLF and LF
        let csv = b"email\r\nuser1@example.com\nuser2@example.com\r\n";
        let result = parse_csv(csv).unwrap();
        assert_eq!(result.rows.len(), 2);
    }

    #[test]
    fn test_parse_csv_preserves_custom_attributes_with_new_columns() {
        let csv = b"email,username,external_id,cost_center\nuser@example.com,jdoe,EMP001,CC100";
        let result = parse_csv(csv).unwrap();
        assert_eq!(result.rows[0].username.as_deref(), Some("jdoe"));
        assert_eq!(result.rows[0].external_id.as_deref(), Some("EMP001"));
        assert_eq!(
            result.rows[0].custom_attributes.get("cost_center"),
            Some(&"CC100".to_string())
        );
    }
}
