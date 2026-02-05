//! Expression parsing and evaluation for filter expressions.
//!
//! This module provides a complete expression language for filtering identities
//! based on their attributes, roles, and entitlements.
//!
//! # Syntax
//!
//! The expression language supports SQL-like filter syntax:
//!
//! ## Comparison Operators
//! - `=` - Equal
//! - `!=` or `<>` - Not equal
//! - `<` - Less than
//! - `>` - Greater than
//! - `<=` - Less than or equal
//! - `>=` - Greater than or equal
//! - `LIKE` - Pattern match (% for any sequence, _ for single character)
//! - `IN` - In list
//!
//! ## Logical Operators
//! - `AND` - Logical AND
//! - `OR` - Logical OR
//! - `NOT` - Logical NOT
//!
//! ## Built-in Functions
//! - `has_role('name')` - Check if user has a role
//! - `has_entitlement('name')` - Check if user has an entitlement
//! - `in_group('name')` - Check if user is in a group
//! - `today()` - Current date (YYYY-MM-DD)
//! - `now()` - Current datetime (ISO 8601)
//! - `days_since('date')` - Days since a date
//! - `days_until('date')` - Days until a date
//!
//! # Examples
//!
//! ```rust
//! use xavyo_governance::expression::{Parser, Evaluator, EvalContext};
//!
//! // Parse an expression
//! let expr = Parser::parse("department = 'engineering' AND active = true").unwrap();
//!
//! // Create evaluation context
//! let ctx = EvalContext::new()
//!     .with_attribute("department", "engineering")
//!     .with_attribute("active", true);
//!
//! // Evaluate
//! let result = Evaluator::evaluate(&expr, &ctx).unwrap();
//! assert!(result);
//! ```
//!
//! ## Complex Expressions
//!
//! ```rust
//! use xavyo_governance::expression::{Parser, Evaluator, EvalContext, FunctionContext};
//!
//! let expr = Parser::parse(
//!     "department = 'engineering' AND lifecycle_state = 'active' AND NOT has_role('developer')"
//! ).unwrap();
//!
//! let role_names = vec!["viewer".to_string()];
//! let func_ctx = FunctionContext::new().with_roles(&[], &role_names);
//! let ctx = EvalContext::new()
//!     .with_attribute("department", "engineering")
//!     .with_attribute("lifecycle_state", "active")
//!     .with_function_context(func_ctx);
//!
//! let result = Evaluator::evaluate(&expr, &ctx).unwrap();
//! assert!(result); // User doesn't have 'developer' role
//! ```

pub mod ast;
pub mod evaluator;
pub mod functions;
pub mod lexer;
pub mod parser;

// Re-export commonly used types
pub use ast::{Comparison, ComparisonOp, Expression, FunctionCall, Value};
pub use evaluator::{EvalContext, EvalError, Evaluator};
pub use functions::{FunctionContext, FunctionError, FunctionRegistry};
pub use lexer::{Lexer, LexerError, Token};
pub use parser::{ParseError, Parser};

/// Validate an expression string without fully parsing it.
///
/// Returns the list of attributes referenced in the expression.
///
/// # Errors
///
/// Returns a `ParseError` if the expression is syntactically invalid.
pub fn validate_expression(input: &str) -> Result<Vec<String>, ParseError> {
    Parser::validate(input)
}

/// Parse and evaluate an expression in one step.
///
/// # Errors
///
/// Returns an error if parsing or evaluation fails.
pub fn eval_expression(input: &str, ctx: &EvalContext<'_>) -> Result<bool, ExpressionError> {
    let expr = Parser::parse(input)?;
    let result = Evaluator::evaluate(&expr, ctx)?;
    Ok(result)
}

/// Combined error type for expression parsing and evaluation.
#[derive(Debug)]
pub enum ExpressionError {
    /// Parse error.
    Parse(ParseError),
    /// Evaluation error.
    Eval(EvalError),
}

impl std::fmt::Display for ExpressionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExpressionError::Parse(e) => write!(f, "Parse error: {e}"),
            ExpressionError::Eval(e) => write!(f, "Evaluation error: {e}"),
        }
    }
}

impl std::error::Error for ExpressionError {}

impl From<ParseError> for ExpressionError {
    fn from(err: ParseError) -> Self {
        ExpressionError::Parse(err)
    }
}

impl From<EvalError> for ExpressionError {
    fn from(err: EvalError) -> Self {
        ExpressionError::Eval(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_expression() {
        let attrs = validate_expression("department = 'eng' AND active = true").unwrap();
        assert!(attrs.contains(&"department".to_string()));
        assert!(attrs.contains(&"active".to_string()));
    }

    #[test]
    fn test_validate_invalid_expression() {
        let result = validate_expression("invalid ??? syntax");
        assert!(result.is_err());
    }

    #[test]
    fn test_eval_expression() {
        let ctx = EvalContext::new()
            .with_attribute("department", "engineering")
            .with_attribute("active", true);

        let result = eval_expression("department = 'engineering' AND active = true", &ctx).unwrap();
        assert!(result);
    }

    #[test]
    fn test_eval_expression_false() {
        let ctx = EvalContext::new()
            .with_attribute("department", "sales")
            .with_attribute("active", true);

        let result = eval_expression("department = 'engineering'", &ctx).unwrap();
        assert!(!result);
    }
}
