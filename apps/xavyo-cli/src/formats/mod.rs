//! Format handling for import/export commands
//!
//! This module provides support for multiple configuration formats:
//! - YAML (default, existing behavior)
//! - JSON (full configuration round-trip)
//! - CSV (bulk agent/tool management)

use clap::ValueEnum;
use std::path::Path;

pub mod csv;
pub mod json;

/// Export format for the export command
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub enum ExportFormat {
    /// YAML format (default, existing behavior)
    #[default]
    Yaml,
    /// JSON format with pretty-printing
    Json,
    /// CSV format (requires --resource flag)
    Csv,
}

impl std::fmt::Display for ExportFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExportFormat::Yaml => write!(f, "yaml"),
            ExportFormat::Json => write!(f, "json"),
            ExportFormat::Csv => write!(f, "csv"),
        }
    }
}

/// Import format for the apply command (auto-detected or specified)
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ImportFormat {
    /// YAML configuration file
    Yaml,
    /// JSON configuration file
    Json,
    /// CSV file (requires --resource flag)
    Csv,
}

impl std::fmt::Display for ImportFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImportFormat::Yaml => write!(f, "yaml"),
            ImportFormat::Json => write!(f, "json"),
            ImportFormat::Csv => write!(f, "csv"),
        }
    }
}

/// Resource type for CSV operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ResourceType {
    /// Agent configurations
    Agents,
    /// Tool configurations
    Tools,
}

impl std::fmt::Display for ResourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResourceType::Agents => write!(f, "agents"),
            ResourceType::Tools => write!(f, "tools"),
        }
    }
}

/// Detect import format based on file extension
///
/// # Arguments
/// * `path` - Path to the file
///
/// # Returns
/// * `Ok(ImportFormat)` - Detected format
/// * `Err(String)` - Error message if format cannot be determined
pub fn detect_format(path: &Path) -> Result<ImportFormat, String> {
    match path.extension().and_then(|e| e.to_str()) {
        Some("json") => Ok(ImportFormat::Json),
        Some("csv") => Ok(ImportFormat::Csv),
        Some("yaml") | Some("yml") => Ok(ImportFormat::Yaml),
        Some(ext) => Err(format!(
            "Unknown file format '.{}' for '{}'. Use --format to specify. Supported: yaml, yml, json, csv",
            ext,
            path.display()
        )),
        None => Err(format!(
            "Cannot determine format for '{}' (no file extension). Use --format to specify.",
            path.display()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_export_format_display() {
        assert_eq!(ExportFormat::Yaml.to_string(), "yaml");
        assert_eq!(ExportFormat::Json.to_string(), "json");
        assert_eq!(ExportFormat::Csv.to_string(), "csv");
    }

    #[test]
    fn test_import_format_display() {
        assert_eq!(ImportFormat::Yaml.to_string(), "yaml");
        assert_eq!(ImportFormat::Json.to_string(), "json");
        assert_eq!(ImportFormat::Csv.to_string(), "csv");
    }

    #[test]
    fn test_resource_type_display() {
        assert_eq!(ResourceType::Agents.to_string(), "agents");
        assert_eq!(ResourceType::Tools.to_string(), "tools");
    }

    #[test]
    fn test_detect_format_json() {
        let path = PathBuf::from("config.json");
        assert_eq!(detect_format(&path).unwrap(), ImportFormat::Json);
    }

    #[test]
    fn test_detect_format_csv() {
        let path = PathBuf::from("agents.csv");
        assert_eq!(detect_format(&path).unwrap(), ImportFormat::Csv);
    }

    #[test]
    fn test_detect_format_yaml() {
        let path = PathBuf::from("config.yaml");
        assert_eq!(detect_format(&path).unwrap(), ImportFormat::Yaml);

        let path = PathBuf::from("config.yml");
        assert_eq!(detect_format(&path).unwrap(), ImportFormat::Yaml);
    }

    #[test]
    fn test_detect_format_unknown() {
        let path = PathBuf::from("config.txt");
        let result = detect_format(&path);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unknown file format"));
    }

    #[test]
    fn test_detect_format_no_extension() {
        let path = PathBuf::from("config");
        let result = detect_format(&path);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("no file extension"));
    }

    #[test]
    fn test_export_format_default() {
        assert_eq!(ExportFormat::default(), ExportFormat::Yaml);
    }
}
