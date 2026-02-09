//! Attribute Transformation Engine (F-010).
//!
//! Provides attribute mapping and transformation capabilities for provisioning
//! operations. Uses Rhai scripting for flexible, tenant-isolated transformations.
//!
//! ## Features
//!
//! - **Attribute Mapping**: Map source attributes to target attributes
//! - **Built-in Functions**: Common transformations (concat, split, lowercase, etc.)
//! - **Expression Evaluation**: Evaluate Rhai expressions for dynamic values
//! - **Validation**: Validate transformation scripts before execution
//! - **Dry Run**: Test transformations without side effects
//!
//! ## Built-in Functions
//!
//! | Function | Description | Example |
//! |----------|-------------|---------|
//! | `concat(a, b, ...)` | Concatenate strings | `concat("Hello", " ", "World")` |
//! | `split(str, sep)` | Split string into array | `split("a,b,c", ",")` |
//! | `join(arr, sep)` | Join array into string | `join(["a", "b"], ",")` |
//! | `lowercase(str)` | Convert to lowercase | `lowercase("HELLO")` |
//! | `uppercase(str)` | Convert to uppercase | `uppercase("hello")` |
//! | `trim(str)` | Remove leading/trailing whitespace | `trim("  hello  ")` |
//! | `trim_start(str)` | Remove leading whitespace | `trim_start("  hello")` |
//! | `trim_end(str)` | Remove trailing whitespace | `trim_end("hello  ")` |
//! | `replace(str, from, to)` | Replace substring | `replace("hello", "l", "L")` |
//! | `substring(str, start, len)` | Extract substring | `substring("hello", 0, 3)` |
//! | `starts_with(str, prefix)` | Check prefix | `starts_with("hello", "he")` |
//! | `ends_with(str, suffix)` | Check suffix | `ends_with("hello", "lo")` |
//! | `contains(str, substr)` | Check contains | `contains("hello", "ell")` |
//! | `len(str)` | Get string length | `len("hello")` |
//! | `is_empty(str)` | Check if empty | `is_empty("")` |
//! | `default(val, default)` | Return default if nil/empty | `default(null, "N/A")` |
//! | `coalesce(a, b, ...)` | Return first non-nil value | `coalesce(null, "", "fallback")` |
//! | `format_email(user, domain)` | Format email address | `format_email("john", "example.com")` |
//! | `slugify(str)` | Convert to URL slug | `slugify("Hello World")` |
//! | `pad_left(str, len, char)` | Pad string left | `pad_left("42", 5, "0")` |
//! | `pad_right(str, len, char)` | Pad string right | `pad_right("42", 5, "0")` |

use rhai::{Dynamic, Engine, Scope};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

/// Configuration for the transformation engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransformConfig {
    /// Maximum execution time for transformations.
    pub timeout_ms: u64,
    /// Maximum number of Rhai operations.
    pub max_operations: u64,
    /// Whether to enable strict mode (fail on undefined variables).
    pub strict_mode: bool,
}

impl Default for TransformConfig {
    fn default() -> Self {
        Self {
            timeout_ms: 5000,
            max_operations: 100_000,
            strict_mode: true,
        }
    }
}

/// An attribute mapping definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributeMapping {
    /// Source attribute path (e.g., "firstName").
    pub source: String,
    /// Target attribute path (e.g., "givenName").
    pub target: String,
    /// Optional transformation expression.
    pub transform: Option<String>,
    /// Whether this mapping is required (fail if source is missing).
    pub required: bool,
    /// Default value if source is missing.
    pub default_value: Option<serde_json::Value>,
}

/// A complete mapping configuration for an object class.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MappingConfig {
    /// Object class this mapping applies to.
    pub object_class: String,
    /// Direction of the mapping (inbound/outbound).
    pub direction: MappingDirection,
    /// Individual attribute mappings.
    pub mappings: Vec<AttributeMapping>,
    /// Global transformation script applied after individual mappings.
    pub post_transform: Option<String>,
}

/// Direction of attribute mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MappingDirection {
    /// From source system to target (provisioning).
    Inbound,
    /// From target system to source (reconciliation).
    Outbound,
}

/// Result of a transformation operation.
#[derive(Debug, Clone, Serialize)]
pub struct TransformResult {
    /// Whether the transformation succeeded.
    pub success: bool,
    /// Transformed attributes.
    pub attributes: Option<serde_json::Value>,
    /// Errors encountered during transformation.
    pub errors: Vec<TransformError>,
    /// Warnings (non-fatal issues).
    pub warnings: Vec<String>,
    /// Execution time in milliseconds.
    pub duration_ms: u64,
}

/// An error during transformation.
#[derive(Debug, Clone, Serialize)]
pub struct TransformError {
    /// Attribute that failed to transform.
    pub attribute: String,
    /// Error message.
    pub message: String,
    /// Error code for programmatic handling.
    pub code: TransformErrorCode,
}

/// Error codes for transformation errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TransformErrorCode {
    /// Source attribute is missing and required.
    MissingRequired,
    /// Transformation script failed.
    ScriptError,
    /// Invalid transformation expression.
    InvalidExpression,
    /// Type conversion error.
    TypeConversion,
    /// Timeout during transformation.
    Timeout,
}

/// Transformation engine for attribute mapping.
pub struct TransformEngine {
    config: TransformConfig,
}

impl TransformEngine {
    /// Create a new transformation engine with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(TransformConfig::default())
    }

    /// Create a new transformation engine with custom configuration.
    #[must_use]
    pub fn with_config(config: TransformConfig) -> Self {
        Self { config }
    }

    /// Create a sandboxed Rhai engine with built-in transformation functions.
    fn create_engine(&self) -> Engine {
        let mut engine = Engine::new();

        // Set resource limits
        engine.set_max_operations(self.config.max_operations);
        engine.set_max_call_levels(64);
        engine.set_max_string_size(65536);
        engine.set_max_array_size(10_000);
        engine.set_max_map_size(10_000);
        engine.set_strict_variables(self.config.strict_mode);

        // Register built-in transformation functions
        Self::register_builtin_functions(&mut engine);

        engine
    }

    /// Register all built-in transformation functions.
    fn register_builtin_functions(engine: &mut Engine) {
        // String concatenation
        engine.register_fn("concat2", |a: &str, b: &str| format!("{a}{b}"));
        engine.register_fn("concat3", |a: &str, b: &str, c: &str| format!("{a}{b}{c}"));
        engine.register_fn("concat4", |a: &str, b: &str, c: &str, d: &str| {
            format!("{a}{b}{c}{d}")
        });

        // String splitting and joining
        engine.register_fn("split", |s: &str, sep: &str| -> rhai::Array {
            s.split(sep).map(|p| Dynamic::from(p.to_string())).collect()
        });

        engine.register_fn("join", |arr: rhai::Array, sep: &str| -> String {
            arr.iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<_>>()
                .join(sep)
        });

        // Case conversion
        engine.register_fn("lowercase", |s: &str| s.to_lowercase());
        engine.register_fn("uppercase", |s: &str| s.to_uppercase());
        engine.register_fn("capitalize", |s: &str| {
            let mut chars = s.chars();
            match chars.next() {
                None => String::new(),
                Some(first) => first.to_uppercase().chain(chars).collect(),
            }
        });

        // Whitespace trimming
        engine.register_fn("trim", |s: &str| s.trim().to_string());
        engine.register_fn("trim_start", |s: &str| s.trim_start().to_string());
        engine.register_fn("trim_end", |s: &str| s.trim_end().to_string());

        // String replacement
        engine.register_fn("replace", |s: &str, from: &str, to: &str| {
            s.replace(from, to)
        });
        engine.register_fn("replace_first", |s: &str, from: &str, to: &str| {
            s.replacen(from, to, 1)
        });

        // Substring operations
        engine.register_fn("substring", |s: &str, start: i64, len: i64| -> String {
            let start = start.max(0) as usize;
            let len = len.max(0) as usize;
            s.chars().skip(start).take(len).collect()
        });

        engine.register_fn("left", |s: &str, n: i64| -> String {
            let n = n.max(0) as usize;
            s.chars().take(n).collect()
        });

        engine.register_fn("right", |s: &str, n: i64| -> String {
            let n = n.max(0) as usize;
            let len = s.chars().count();
            if n >= len {
                s.to_string()
            } else {
                s.chars().skip(len - n).collect()
            }
        });

        // String predicates
        engine.register_fn("starts_with", |s: &str, prefix: &str| s.starts_with(prefix));
        engine.register_fn("ends_with", |s: &str, suffix: &str| s.ends_with(suffix));
        engine.register_fn("contains_str", |s: &str, substr: &str| s.contains(substr));
        engine.register_fn("is_empty", |s: &str| s.is_empty());
        engine.register_fn("is_blank", |s: &str| s.trim().is_empty());

        // String length
        engine.register_fn("str_len", |s: &str| s.len() as i64);
        engine.register_fn("char_count", |s: &str| s.chars().count() as i64);

        // Padding
        engine.register_fn("pad_left", |s: &str, len: i64, pad: &str| -> String {
            let len = len.max(0) as usize;
            let current_len = s.chars().count();
            if current_len >= len || pad.is_empty() {
                s.to_string()
            } else {
                let pad_char = pad.chars().next().unwrap();
                let padding: String = std::iter::repeat_n(pad_char, len - current_len).collect();
                format!("{padding}{s}")
            }
        });

        engine.register_fn("pad_right", |s: &str, len: i64, pad: &str| -> String {
            let len = len.max(0) as usize;
            let current_len = s.chars().count();
            if current_len >= len || pad.is_empty() {
                s.to_string()
            } else {
                let pad_char = pad.chars().next().unwrap();
                let padding: String = std::iter::repeat_n(pad_char, len - current_len).collect();
                format!("{s}{padding}")
            }
        });

        // Email formatting
        engine.register_fn("format_email", |user: &str, domain: &str| {
            format!(
                "{}@{}",
                user.trim().to_lowercase(),
                domain.trim().to_lowercase()
            )
        });

        // Slugify (URL-safe string)
        engine.register_fn("slugify", |s: &str| -> String {
            s.to_lowercase()
                .chars()
                .map(|c| {
                    if c.is_alphanumeric() {
                        c
                    } else if c.is_whitespace() || c == '_' {
                        '-'
                    } else {
                        ' ' // Will be filtered out
                    }
                })
                .filter(|c| c.is_alphanumeric() || *c == '-')
                .collect::<String>()
                .split('-')
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join("-")
        });

        // Default value handling
        engine.register_fn("default_str", |s: &str, default: &str| -> String {
            if s.is_empty() {
                default.to_string()
            } else {
                s.to_string()
            }
        });

        engine.register_fn("default_val", |val: Dynamic, default: Dynamic| -> Dynamic {
            if val.is_unit() || (val.is_string() && val.clone_cast::<String>().is_empty()) {
                default
            } else {
                val
            }
        });

        // Helper to check if a dynamic value is "empty" (nil or empty string)
        fn is_empty_value(v: &Dynamic) -> bool {
            v.is_unit() || (v.is_string() && v.clone_cast::<String>().is_empty())
        }

        // Coalesce (first non-empty value)
        engine.register_fn("coalesce2", |a: Dynamic, b: Dynamic| -> Dynamic {
            if is_empty_value(&a) {
                b
            } else {
                a
            }
        });

        engine.register_fn(
            "coalesce3",
            |a: Dynamic, b: Dynamic, c: Dynamic| -> Dynamic {
                if !is_empty_value(&a) {
                    a
                } else if !is_empty_value(&b) {
                    b
                } else {
                    c
                }
            },
        );

        // Array operations
        engine.register_fn("array_first", |arr: rhai::Array| -> Dynamic {
            arr.into_iter().next().unwrap_or(Dynamic::UNIT)
        });

        engine.register_fn("array_last", |arr: rhai::Array| -> Dynamic {
            arr.into_iter().last().unwrap_or(Dynamic::UNIT)
        });

        engine.register_fn("array_get", |arr: rhai::Array, idx: i64| -> Dynamic {
            let idx = idx.max(0) as usize;
            arr.get(idx).cloned().unwrap_or(Dynamic::UNIT)
        });

        engine.register_fn("array_len", |arr: rhai::Array| -> i64 { arr.len() as i64 });

        engine.register_fn("array_contains", |arr: rhai::Array, val: Dynamic| -> bool {
            let val_str = val.to_string();
            arr.iter().any(|v| v.to_string() == val_str)
        });

        engine.register_fn("array_unique", |arr: rhai::Array| -> rhai::Array {
            let mut seen = std::collections::HashSet::new();
            arr.into_iter()
                .filter(|v| seen.insert(v.to_string()))
                .collect()
        });

        // Logging (same as rhai_executor)
        engine.register_fn("log_info", |msg: &str| {
            info!(transform_log = %msg, "Transform script log");
        });

        engine.register_fn("log_warn", |msg: &str| {
            warn!(transform_log = %msg, "Transform script warning");
        });

        engine.register_fn("log_debug", |msg: &str| {
            debug!(transform_log = %msg, "Transform script debug");
        });

        // Type checking
        engine.register_fn("is_string", |val: Dynamic| val.is_string());
        engine.register_fn("is_int", |val: Dynamic| val.is_int());
        engine.register_fn("is_float", |val: Dynamic| val.is_float());
        engine.register_fn("is_bool", |val: Dynamic| val.is_bool());
        engine.register_fn("is_array", |val: Dynamic| val.is_array());
        engine.register_fn("is_map", |val: Dynamic| val.is_map());
        engine.register_fn("is_null", |val: Dynamic| val.is_unit());

        // Type conversion
        engine.register_fn("to_string", |val: Dynamic| val.to_string());
        engine.register_fn("to_int", |s: &str| -> i64 { s.parse().unwrap_or(0) });
        engine.register_fn("to_float", |s: &str| -> f64 { s.parse().unwrap_or(0.0) });
        engine.register_fn("to_bool", |s: &str| -> bool {
            matches!(s.to_lowercase().as_str(), "true" | "yes" | "1" | "on")
        });
    }

    /// Validate a transformation expression.
    #[must_use]
    pub fn validate_expression(&self, expression: &str) -> Vec<ValidationError> {
        let engine = self.create_engine();

        // Create a scope with common variables for validation
        let mut scope = Scope::new();
        scope.push("value", Dynamic::from(""));
        scope.push("source", rhai::Map::new());
        scope.push("target", rhai::Map::new());

        match engine.compile_with_scope(&scope, expression) {
            Ok(_) => vec![],
            Err(e) => {
                vec![ValidationError {
                    line: e.position().line(),
                    column: e.position().position(),
                    message: e.to_string(),
                }]
            }
        }
    }

    /// Validate a mapping configuration.
    #[must_use]
    pub fn validate_mapping(&self, mapping: &MappingConfig) -> Vec<ValidationError> {
        let mut errors = vec![];

        for attr_mapping in &mapping.mappings {
            if let Some(ref transform) = attr_mapping.transform {
                let expr_errors = self.validate_expression(transform);
                for e in expr_errors {
                    errors.push(ValidationError {
                        line: e.line,
                        column: e.column,
                        message: format!(
                            "Error in mapping '{}' -> '{}': {}",
                            attr_mapping.source, attr_mapping.target, e.message
                        ),
                    });
                }
            }
        }

        if let Some(ref post_transform) = mapping.post_transform {
            let script_errors = self.validate_expression(post_transform);
            for e in script_errors {
                errors.push(ValidationError {
                    line: e.line,
                    column: e.column,
                    message: format!("Error in post_transform: {}", e.message),
                });
            }
        }

        errors
    }

    /// Evaluate a single expression with a value.
    pub fn evaluate_expression(
        &self,
        expression: &str,
        value: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let engine = self.create_engine();

        let mut scope = Scope::new();

        // Expose the value in the scope
        if let Ok(dynamic) = rhai::serde::to_dynamic(value) {
            scope.push("value", dynamic);
        } else {
            scope.push("value", Dynamic::UNIT);
        }

        // Compile and execute
        let ast = engine
            .compile_with_scope(&scope, expression)
            .map_err(|e| format!("Compilation error: {e}"))?;

        let result: Dynamic = engine
            .eval_ast_with_scope(&mut scope, &ast)
            .map_err(|e| format!("Runtime error: {e}"))?;

        // Convert result back to JSON
        rhai::serde::from_dynamic(&result).map_err(|e| format!("Conversion error: {e}"))
    }

    /// Apply attribute mappings to transform source attributes.
    #[must_use]
    pub fn apply_mappings(
        &self,
        source: &serde_json::Value,
        mapping: &MappingConfig,
    ) -> TransformResult {
        let start = std::time::Instant::now();
        let mut errors = vec![];
        let mut warnings = vec![];
        let mut target = serde_json::Map::new();

        let engine = self.create_engine();

        // Process each attribute mapping
        for attr_mapping in &mapping.mappings {
            let source_value = self.get_attribute_value(source, &attr_mapping.source);

            match source_value {
                Some(value) => {
                    let transformed = if let Some(ref transform) = attr_mapping.transform {
                        match self.apply_transform(&engine, transform, &value, source) {
                            Ok(v) => v,
                            Err(e) => {
                                errors.push(TransformError {
                                    attribute: attr_mapping.target.clone(),
                                    message: e,
                                    code: TransformErrorCode::ScriptError,
                                });
                                continue;
                            }
                        }
                    } else {
                        value
                    };
                    target.insert(attr_mapping.target.clone(), transformed);
                }
                None => {
                    if attr_mapping.required {
                        errors.push(TransformError {
                            attribute: attr_mapping.target.clone(),
                            message: format!(
                                "Required source attribute '{}' is missing",
                                attr_mapping.source
                            ),
                            code: TransformErrorCode::MissingRequired,
                        });
                    } else if let Some(ref default) = attr_mapping.default_value {
                        target.insert(attr_mapping.target.clone(), default.clone());
                    } else {
                        warnings.push(format!(
                            "Optional attribute '{}' is missing, skipped",
                            attr_mapping.source
                        ));
                    }
                }
            }
        }

        // Apply post-transform if present
        if let Some(ref post_transform) = mapping.post_transform {
            match self.apply_post_transform(
                &engine,
                post_transform,
                &serde_json::Value::Object(target.clone()),
            ) {
                Ok(transformed) => {
                    if let serde_json::Value::Object(map) = transformed {
                        target = map;
                    }
                }
                Err(e) => {
                    errors.push(TransformError {
                        attribute: "_post_transform".to_string(),
                        message: e,
                        code: TransformErrorCode::ScriptError,
                    });
                }
            }
        }

        let duration_ms = start.elapsed().as_millis() as u64;
        let success = errors.is_empty();

        TransformResult {
            success,
            attributes: if success {
                Some(serde_json::Value::Object(target))
            } else {
                None
            },
            errors,
            warnings,
            duration_ms,
        }
    }

    /// Get an attribute value from a JSON object using dot notation.
    fn get_attribute_value(
        &self,
        source: &serde_json::Value,
        path: &str,
    ) -> Option<serde_json::Value> {
        let parts: Vec<&str> = path.split('.').collect();
        let mut current = source;

        for part in parts {
            match current {
                serde_json::Value::Object(map) => {
                    current = map.get(part)?;
                }
                serde_json::Value::Array(arr) => {
                    let idx: usize = part.parse().ok()?;
                    current = arr.get(idx)?;
                }
                _ => return None,
            }
        }

        Some(current.clone())
    }

    /// Apply a transformation expression to a value.
    fn apply_transform(
        &self,
        engine: &Engine,
        expression: &str,
        value: &serde_json::Value,
        source: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let mut scope = Scope::new();

        // Expose the current value
        if let Ok(dynamic) = rhai::serde::to_dynamic(value) {
            scope.push("value", dynamic);
        }

        // Expose the full source object
        if let Ok(dynamic) = rhai::serde::to_dynamic(source) {
            scope.push("source", dynamic);
        }

        // Compile and execute
        let ast = engine
            .compile_with_scope(&scope, expression)
            .map_err(|e| format!("Compilation error: {e}"))?;

        let result: Dynamic = engine
            .eval_ast_with_scope(&mut scope, &ast)
            .map_err(|e| format!("Runtime error: {e}"))?;

        rhai::serde::from_dynamic(&result).map_err(|e| format!("Conversion error: {e}"))
    }

    /// Apply post-transform script to the entire target object.
    fn apply_post_transform(
        &self,
        engine: &Engine,
        script: &str,
        target: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let mut scope = Scope::new();

        // Expose target as mutable
        if let Ok(dynamic) = rhai::serde::to_dynamic(target) {
            scope.push("target", dynamic);
        }

        // Compile and execute
        let ast = engine
            .compile_with_scope(&scope, script)
            .map_err(|e| format!("Compilation error: {e}"))?;

        let _ = engine
            .eval_ast_with_scope::<Dynamic>(&mut scope, &ast)
            .map_err(|e| format!("Runtime error: {e}"))?;

        // Extract modified target
        scope
            .get_value::<Dynamic>("target")
            .and_then(|d| rhai::serde::from_dynamic(&d).ok())
            .ok_or_else(|| "Failed to extract modified target".to_string())
    }
}

impl Default for TransformEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// A validation error in a transformation script.
#[derive(Debug, Clone, Serialize)]
pub struct ValidationError {
    /// Line number (if available).
    pub line: Option<usize>,
    /// Column number (if available).
    pub column: Option<usize>,
    /// Error message.
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_source() -> serde_json::Value {
        serde_json::json!({
            "firstName": "John",
            "lastName": "Doe",
            "email": "john.doe@example.com",
            "department": "Engineering",
            "employeeId": "E12345",
            "groups": ["admin", "users", "developers"],
            "custom": {
                "costCenter": "CC-100",
                "manager": "Jane Smith"
            }
        })
    }

    // ==================== Built-in Function Tests ====================

    #[test]
    fn test_concat_functions() {
        let engine = TransformEngine::new();

        let result =
            engine.evaluate_expression(r#"concat2("Hello", " World")"#, &serde_json::Value::Null);
        assert_eq!(result.unwrap(), serde_json::json!("Hello World"));

        let result =
            engine.evaluate_expression(r#"concat3("a", "b", "c")"#, &serde_json::Value::Null);
        assert_eq!(result.unwrap(), serde_json::json!("abc"));
    }

    #[test]
    fn test_split_join_functions() {
        let engine = TransformEngine::new();

        let result = engine.evaluate_expression(r#"split("a,b,c", ",")"#, &serde_json::Value::Null);
        assert_eq!(result.unwrap(), serde_json::json!(["a", "b", "c"]));

        let result =
            engine.evaluate_expression(r#"join(["a", "b", "c"], "-")"#, &serde_json::Value::Null);
        assert_eq!(result.unwrap(), serde_json::json!("a-b-c"));
    }

    #[test]
    fn test_case_conversion() {
        let engine = TransformEngine::new();

        let result = engine.evaluate_expression(r#"lowercase("HELLO")"#, &serde_json::Value::Null);
        assert_eq!(result.unwrap(), serde_json::json!("hello"));

        let result = engine.evaluate_expression(r#"uppercase("hello")"#, &serde_json::Value::Null);
        assert_eq!(result.unwrap(), serde_json::json!("HELLO"));

        let result = engine.evaluate_expression(r#"capitalize("hello")"#, &serde_json::Value::Null);
        assert_eq!(result.unwrap(), serde_json::json!("Hello"));
    }

    #[test]
    fn test_trim_functions() {
        let engine = TransformEngine::new();

        let result = engine.evaluate_expression(r#"trim("  hello  ")"#, &serde_json::Value::Null);
        assert_eq!(result.unwrap(), serde_json::json!("hello"));

        let result =
            engine.evaluate_expression(r#"trim_start("  hello")"#, &serde_json::Value::Null);
        assert_eq!(result.unwrap(), serde_json::json!("hello"));

        let result = engine.evaluate_expression(r#"trim_end("hello  ")"#, &serde_json::Value::Null);
        assert_eq!(result.unwrap(), serde_json::json!("hello"));
    }

    #[test]
    fn test_replace_functions() {
        let engine = TransformEngine::new();

        let result = engine.evaluate_expression(
            r#"replace("hello world", "world", "everyone")"#,
            &serde_json::Value::Null,
        );
        assert_eq!(result.unwrap(), serde_json::json!("hello everyone"));

        let result = engine.evaluate_expression(
            r#"replace_first("hello hello", "hello", "hi")"#,
            &serde_json::Value::Null,
        );
        assert_eq!(result.unwrap(), serde_json::json!("hi hello"));
    }

    #[test]
    fn test_substring_functions() {
        let engine = TransformEngine::new();

        let result = engine.evaluate_expression(
            r#"substring("hello world", 0, 5)"#,
            &serde_json::Value::Null,
        );
        assert_eq!(result.unwrap(), serde_json::json!("hello"));

        let result = engine.evaluate_expression(r#"left("hello", 3)"#, &serde_json::Value::Null);
        assert_eq!(result.unwrap(), serde_json::json!("hel"));

        let result = engine.evaluate_expression(r#"right("hello", 3)"#, &serde_json::Value::Null);
        assert_eq!(result.unwrap(), serde_json::json!("llo"));
    }

    #[test]
    fn test_string_predicates() {
        let engine = TransformEngine::new();

        let result =
            engine.evaluate_expression(r#"starts_with("hello", "he")"#, &serde_json::Value::Null);
        assert_eq!(result.unwrap(), serde_json::json!(true));

        let result =
            engine.evaluate_expression(r#"ends_with("hello", "lo")"#, &serde_json::Value::Null);
        assert_eq!(result.unwrap(), serde_json::json!(true));

        let result =
            engine.evaluate_expression(r#"contains_str("hello", "ell")"#, &serde_json::Value::Null);
        assert_eq!(result.unwrap(), serde_json::json!(true));

        let result = engine.evaluate_expression(r#"is_empty("")"#, &serde_json::Value::Null);
        assert_eq!(result.unwrap(), serde_json::json!(true));

        let result = engine.evaluate_expression(r#"is_blank("  ")"#, &serde_json::Value::Null);
        assert_eq!(result.unwrap(), serde_json::json!(true));
    }

    #[test]
    fn test_padding_functions() {
        let engine = TransformEngine::new();

        let result =
            engine.evaluate_expression(r#"pad_left("42", 5, "0")"#, &serde_json::Value::Null);
        assert_eq!(result.unwrap(), serde_json::json!("00042"));

        let result =
            engine.evaluate_expression(r#"pad_right("42", 5, "0")"#, &serde_json::Value::Null);
        assert_eq!(result.unwrap(), serde_json::json!("42000"));
    }

    #[test]
    fn test_format_email() {
        let engine = TransformEngine::new();

        let result = engine.evaluate_expression(
            r#"format_email("John.Doe", "Example.COM")"#,
            &serde_json::Value::Null,
        );
        assert_eq!(result.unwrap(), serde_json::json!("john.doe@example.com"));
    }

    #[test]
    fn test_slugify() {
        let engine = TransformEngine::new();

        let result = engine.evaluate_expression(
            r#"slugify("Hello World! This is a Test.")"#,
            &serde_json::Value::Null,
        );
        assert_eq!(
            result.unwrap(),
            serde_json::json!("hello-world-this-is-a-test")
        );
    }

    #[test]
    fn test_default_coalesce() {
        let engine = TransformEngine::new();

        let result =
            engine.evaluate_expression(r#"default_str("", "N/A")"#, &serde_json::Value::Null);
        assert_eq!(result.unwrap(), serde_json::json!("N/A"));

        let result =
            engine.evaluate_expression(r#"default_str("hello", "N/A")"#, &serde_json::Value::Null);
        assert_eq!(result.unwrap(), serde_json::json!("hello"));
    }

    #[test]
    fn test_array_functions() {
        let engine = TransformEngine::new();

        let result =
            engine.evaluate_expression(r#"array_first(["a", "b", "c"])"#, &serde_json::Value::Null);
        assert_eq!(result.unwrap(), serde_json::json!("a"));

        let result =
            engine.evaluate_expression(r#"array_last(["a", "b", "c"])"#, &serde_json::Value::Null);
        assert_eq!(result.unwrap(), serde_json::json!("c"));

        let result = engine
            .evaluate_expression(r#"array_get(["a", "b", "c"], 1)"#, &serde_json::Value::Null);
        assert_eq!(result.unwrap(), serde_json::json!("b"));

        let result =
            engine.evaluate_expression(r#"array_len(["a", "b", "c"])"#, &serde_json::Value::Null);
        assert_eq!(result.unwrap(), serde_json::json!(3));

        let result = engine.evaluate_expression(
            r#"array_contains(["a", "b", "c"], "b")"#,
            &serde_json::Value::Null,
        );
        assert_eq!(result.unwrap(), serde_json::json!(true));
    }

    #[test]
    fn test_type_checking() {
        let engine = TransformEngine::new();

        let result = engine.evaluate_expression(r#"is_string("hello")"#, &serde_json::Value::Null);
        assert_eq!(result.unwrap(), serde_json::json!(true));

        let result = engine.evaluate_expression(r#"is_int(42)"#, &serde_json::Value::Null);
        assert_eq!(result.unwrap(), serde_json::json!(true));

        let result = engine.evaluate_expression(r#"is_bool(true)"#, &serde_json::Value::Null);
        assert_eq!(result.unwrap(), serde_json::json!(true));
    }

    #[test]
    #[allow(clippy::approx_constant)]
    fn test_type_conversion() {
        let engine = TransformEngine::new();

        let result = engine.evaluate_expression(r#"to_int("42")"#, &serde_json::Value::Null);
        assert_eq!(result.unwrap(), serde_json::json!(42));

        let result = engine.evaluate_expression(r#"to_float("3.14")"#, &serde_json::Value::Null);
        let val = result.unwrap();
        assert!((val.as_f64().unwrap() - 3.14).abs() < 0.001);

        let result = engine.evaluate_expression(r#"to_bool("true")"#, &serde_json::Value::Null);
        assert_eq!(result.unwrap(), serde_json::json!(true));
    }

    // ==================== Validation Tests ====================

    #[test]
    fn test_validate_valid_expression() {
        let engine = TransformEngine::new();
        let errors = engine.validate_expression(r#"lowercase(value)"#);
        assert!(errors.is_empty());
    }

    #[test]
    fn test_validate_invalid_expression() {
        let engine = TransformEngine::new();
        let errors = engine.validate_expression(r#"let x = ;"#);
        assert!(!errors.is_empty());
    }

    #[test]
    fn test_validate_mapping_config() {
        let engine = TransformEngine::new();

        let mapping = MappingConfig {
            object_class: "user".to_string(),
            direction: MappingDirection::Inbound,
            mappings: vec![AttributeMapping {
                source: "firstName".to_string(),
                target: "givenName".to_string(),
                transform: Some(r#"uppercase(value)"#.to_string()),
                required: true,
                default_value: None,
            }],
            post_transform: None,
        };

        let errors = engine.validate_mapping(&mapping);
        assert!(errors.is_empty());
    }

    #[test]
    fn test_validate_invalid_mapping() {
        let engine = TransformEngine::new();

        let mapping = MappingConfig {
            object_class: "user".to_string(),
            direction: MappingDirection::Inbound,
            mappings: vec![AttributeMapping {
                source: "firstName".to_string(),
                target: "givenName".to_string(),
                transform: Some(r#"invalid_syntax ("#.to_string()),
                required: true,
                default_value: None,
            }],
            post_transform: None,
        };

        let errors = engine.validate_mapping(&mapping);
        assert!(!errors.is_empty());
    }

    // ==================== Mapping Tests ====================

    #[test]
    fn test_simple_mapping() {
        let engine = TransformEngine::new();
        let source = create_test_source();

        let mapping = MappingConfig {
            object_class: "user".to_string(),
            direction: MappingDirection::Inbound,
            mappings: vec![
                AttributeMapping {
                    source: "firstName".to_string(),
                    target: "givenName".to_string(),
                    transform: None,
                    required: true,
                    default_value: None,
                },
                AttributeMapping {
                    source: "lastName".to_string(),
                    target: "sn".to_string(),
                    transform: None,
                    required: true,
                    default_value: None,
                },
            ],
            post_transform: None,
        };

        let result = engine.apply_mappings(&source, &mapping);
        assert!(result.success);

        let attrs = result.attributes.unwrap();
        assert_eq!(attrs["givenName"], "John");
        assert_eq!(attrs["sn"], "Doe");
    }

    #[test]
    fn test_mapping_with_transform() {
        let engine = TransformEngine::new();
        let source = create_test_source();

        let mapping = MappingConfig {
            object_class: "user".to_string(),
            direction: MappingDirection::Inbound,
            mappings: vec![
                AttributeMapping {
                    source: "firstName".to_string(),
                    target: "givenName".to_string(),
                    transform: Some(r#"uppercase(value)"#.to_string()),
                    required: true,
                    default_value: None,
                },
                AttributeMapping {
                    source: "email".to_string(),
                    target: "mail".to_string(),
                    transform: Some(r#"lowercase(value)"#.to_string()),
                    required: true,
                    default_value: None,
                },
            ],
            post_transform: None,
        };

        let result = engine.apply_mappings(&source, &mapping);
        assert!(result.success, "Errors: {:?}", result.errors);

        let attrs = result.attributes.unwrap();
        assert_eq!(attrs["givenName"], "JOHN");
        assert_eq!(attrs["mail"], "john.doe@example.com");
    }

    #[test]
    fn test_mapping_with_source_access() {
        let engine = TransformEngine::new();
        let source = create_test_source();

        let mapping = MappingConfig {
            object_class: "user".to_string(),
            direction: MappingDirection::Inbound,
            mappings: vec![AttributeMapping {
                source: "firstName".to_string(),
                target: "displayName".to_string(),
                transform: Some(r#"concat3(value, " ", source["lastName"])"#.to_string()),
                required: true,
                default_value: None,
            }],
            post_transform: None,
        };

        let result = engine.apply_mappings(&source, &mapping);
        assert!(result.success, "Errors: {:?}", result.errors);

        let attrs = result.attributes.unwrap();
        assert_eq!(attrs["displayName"], "John Doe");
    }

    #[test]
    fn test_mapping_nested_attributes() {
        let engine = TransformEngine::new();
        let source = create_test_source();

        let mapping = MappingConfig {
            object_class: "user".to_string(),
            direction: MappingDirection::Inbound,
            mappings: vec![
                AttributeMapping {
                    source: "custom.costCenter".to_string(),
                    target: "costCenter".to_string(),
                    transform: None,
                    required: true,
                    default_value: None,
                },
                AttributeMapping {
                    source: "custom.manager".to_string(),
                    target: "manager".to_string(),
                    transform: None,
                    required: true,
                    default_value: None,
                },
            ],
            post_transform: None,
        };

        let result = engine.apply_mappings(&source, &mapping);
        assert!(result.success, "Errors: {:?}", result.errors);

        let attrs = result.attributes.unwrap();
        assert_eq!(attrs["costCenter"], "CC-100");
        assert_eq!(attrs["manager"], "Jane Smith");
    }

    #[test]
    fn test_mapping_missing_required() {
        let engine = TransformEngine::new();
        let source = create_test_source();

        let mapping = MappingConfig {
            object_class: "user".to_string(),
            direction: MappingDirection::Inbound,
            mappings: vec![AttributeMapping {
                source: "nonexistent".to_string(),
                target: "something".to_string(),
                transform: None,
                required: true,
                default_value: None,
            }],
            post_transform: None,
        };

        let result = engine.apply_mappings(&source, &mapping);
        assert!(!result.success);
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.errors[0].code, TransformErrorCode::MissingRequired);
    }

    #[test]
    fn test_mapping_optional_with_default() {
        let engine = TransformEngine::new();
        let source = create_test_source();

        let mapping = MappingConfig {
            object_class: "user".to_string(),
            direction: MappingDirection::Inbound,
            mappings: vec![AttributeMapping {
                source: "nonexistent".to_string(),
                target: "something".to_string(),
                transform: None,
                required: false,
                default_value: Some(serde_json::json!("default_value")),
            }],
            post_transform: None,
        };

        let result = engine.apply_mappings(&source, &mapping);
        assert!(result.success);

        let attrs = result.attributes.unwrap();
        assert_eq!(attrs["something"], "default_value");
    }

    #[test]
    fn test_mapping_with_post_transform() {
        let engine = TransformEngine::new();
        let source = create_test_source();

        let mapping = MappingConfig {
            object_class: "user".to_string(),
            direction: MappingDirection::Inbound,
            mappings: vec![
                AttributeMapping {
                    source: "firstName".to_string(),
                    target: "givenName".to_string(),
                    transform: None,
                    required: true,
                    default_value: None,
                },
                AttributeMapping {
                    source: "lastName".to_string(),
                    target: "sn".to_string(),
                    transform: None,
                    required: true,
                    default_value: None,
                },
            ],
            post_transform: Some(
                r#"
                target["cn"] = concat3(target["givenName"], " ", target["sn"]);
                target
            "#
                .to_string(),
            ),
        };

        let result = engine.apply_mappings(&source, &mapping);
        assert!(result.success, "Errors: {:?}", result.errors);

        let attrs = result.attributes.unwrap();
        assert_eq!(attrs["cn"], "John Doe");
    }

    #[test]
    fn test_evaluate_expression_with_value() {
        let engine = TransformEngine::new();

        let result = engine.evaluate_expression(r#"uppercase(value)"#, &serde_json::json!("hello"));
        assert_eq!(result.unwrap(), serde_json::json!("HELLO"));
    }

    #[test]
    fn test_complex_transformation() {
        let engine = TransformEngine::new();
        let source = create_test_source();

        let mapping = MappingConfig {
            object_class: "user".to_string(),
            direction: MappingDirection::Inbound,
            mappings: vec![
                AttributeMapping {
                    source: "email".to_string(),
                    target: "userPrincipalName".to_string(),
                    transform: None,
                    required: true,
                    default_value: None,
                },
                AttributeMapping {
                    source: "email".to_string(),
                    target: "samAccountName".to_string(),
                    transform: Some(r#"array_first(split(value, "@"))"#.to_string()),
                    required: true,
                    default_value: None,
                },
                AttributeMapping {
                    source: "employeeId".to_string(),
                    target: "employeeNumber".to_string(),
                    transform: Some(r#"pad_left(value, 10, "0")"#.to_string()),
                    required: true,
                    default_value: None,
                },
            ],
            post_transform: None,
        };

        let result = engine.apply_mappings(&source, &mapping);
        assert!(result.success, "Errors: {:?}", result.errors);

        let attrs = result.attributes.unwrap();
        assert_eq!(attrs["userPrincipalName"], "john.doe@example.com");
        assert_eq!(attrs["samAccountName"], "john.doe");
        assert_eq!(attrs["employeeNumber"], "0000E12345");
    }
}
