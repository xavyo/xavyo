//! Diff module for comparing YAML configurations
//!
//! This module provides functionality to compare xavyo configurations
//! and produce structured diff results with colored terminal output.
//!
//! # Components
//!
//! - `result`: Diff result types (DiffResult, DiffItem, FieldChange)
//! - `engine`: Diff comparison algorithm
//! - `formatter`: Output formatting (table, JSON, YAML)

pub mod engine;
pub mod formatter;
pub mod result;

// Re-export commonly used types
pub use engine::compare_configs;
pub use formatter::{format_diff, OutputFormat};
pub use result::DiffResult;
