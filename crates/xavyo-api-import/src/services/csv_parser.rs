//! CSV parsing service for bulk user import (F086).
//!
//! Handles CSV header validation, row-by-row parsing, email duplicate detection,
//! and per-field validation including custom attribute columns.

use std::collections::{HashMap, HashSet};

use crate::validation::{self, HeaderValidation};

/// Maximum file size (10MB default, configurable).
pub const DEFAULT_MAX_FILE_SIZE: usize = 10 * 1024 * 1024;

/// Maximum rows per import (10,000 default, configurable).
pub const DEFAULT_MAX_ROWS: usize = 10_000;

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
    /// Custom attribute values: attribute_name -> raw value string.
    pub custom_attributes: HashMap<String, String>,
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

/// Parse and validate a CSV file from raw bytes.
///
/// Returns parsed rows, per-row errors, and total row count.
/// Does not fail the entire import for per-row errors.
pub fn parse_csv(data: &[u8]) -> Result<CsvParseResult, String> {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(true)
        .from_reader(data);

    // Parse and validate headers
    let headers: Vec<String> = reader
        .headers()
        .map_err(|e| format!("Failed to read CSV headers: {}", e))?
        .iter()
        .map(|h| h.to_string())
        .collect();

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
    let mut seen_emails: HashSet<String> = HashSet::new();
    let mut total_rows = 0usize;

    for (idx, result) in reader.records().enumerate() {
        let line_number = (idx + 2) as i32; // +2 because header=1, first data=2
        total_rows += 1;

        let record = match result {
            Ok(r) => r,
            Err(e) => {
                errors.push(RowError {
                    line_number,
                    email: None,
                    column_name: None,
                    error_type: "validation".to_string(),
                    error_message: format!("Failed to parse CSV row: {}", e),
                });
                continue;
            }
        };

        // Extract email (required)
        let email_idx = match known_columns.get("email") {
            Some(&idx) => idx,
            None => {
                errors.push(RowError {
                    line_number,
                    email: None,
                    column_name: Some("email".to_string()),
                    error_type: "validation".to_string(),
                    error_message: "Email column index not found".to_string(),
                });
                continue;
            }
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

        // Check for duplicate within file
        if seen_emails.contains(&email) {
            errors.push(RowError {
                line_number,
                email: Some(email.clone()),
                column_name: Some("email".to_string()),
                error_type: "duplicate_in_file".to_string(),
                error_message: format!("Duplicate email '{}' within CSV file", email),
            });
            continue;
        }
        seen_emails.insert(email.clone());

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
            .map(|v| matches!(v.to_lowercase().as_str(), "true" | "1" | "yes"))
            .unwrap_or(false);

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
        });
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
}
