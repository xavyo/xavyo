//! Template Expression Service (F058).
//!
//! Parses and evaluates template expressions for computed values,
//! validations, and normalizations.
//!
//! Expression Types Supported:
//! - Path References: `${firstName}`, `${department}`
//! - Concatenation: `${firstName} + " " + ${lastName}`
//! - Conditionals: `if(${type} == "employee", "EMP-", "CTR-") + ${id}`
//! - Functions: `lowercase(${email})`, `uppercase(${code})`, `trim(${name})`
//! - Regex Match: `matches(${email}, "^[a-z]+@company\\.com$")`

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;
use thiserror::Error;
use xavyo_db::models::SUPPORTED_FUNCTIONS;

/// Errors that can occur during expression parsing or evaluation.
#[derive(Debug, Error, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExpressionError {
    #[error("Invalid expression syntax: {0}")]
    InvalidSyntax(String),

    #[error("Unknown function: {0}")]
    UnknownFunction(String),

    #[error("Unknown attribute: {0}")]
    UnknownAttribute(String),

    #[error("Invalid argument count for function {0}: expected {1}, got {2}")]
    InvalidArgumentCount(String, usize, usize),

    #[error("Type error: {0}")]
    TypeError(String),

    #[error("Regex error: {0}")]
    RegexError(String),

    #[error("Division by zero")]
    DivisionByZero,

    #[error("Circular reference detected: {0}")]
    CircularReference(String),

    #[error("Evaluation error: {0}")]
    EvaluationError(String),
}

/// Result type for expression operations.
pub type ExpressionResult<T> = Result<T, ExpressionError>;

/// A parsed expression token.
#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    /// A literal string value.
    Literal(String),
    /// A path reference like ${firstName}.
    PathRef(String),
    /// A function call like lowercase(${email}).
    FunctionCall { name: String, args: Vec<Expression> },
    /// Binary operator (e.g., +, ==, !=, <, >, <=, >=).
    BinaryOp {
        op: BinaryOperator,
        left: Box<Expression>,
        right: Box<Expression>,
    },
    /// Unary NOT operator (!).
    UnaryNot { operand: Box<Expression> },
    /// Numeric literal.
    Number(f64),
    /// Boolean literal.
    Boolean(bool),
    /// Null literal.
    Null,
}

/// Binary operators supported in expressions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryOperator {
    /// String concatenation or numeric addition.
    Add,
    /// Numeric subtraction.
    Subtract,
    /// Numeric multiplication.
    Multiply,
    /// Numeric division.
    Divide,
    /// Equality comparison.
    Equal,
    /// Inequality comparison.
    NotEqual,
    /// Less than comparison.
    LessThan,
    /// Greater than comparison.
    GreaterThan,
    /// Less than or equal comparison.
    LessOrEqual,
    /// Greater than or equal comparison.
    GreaterOrEqual,
    /// Logical AND.
    And,
    /// Logical OR.
    Or,
}

impl BinaryOperator {
    /// Parse an operator from its string representation.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "+" => Some(Self::Add),
            "-" => Some(Self::Subtract),
            "*" => Some(Self::Multiply),
            "/" => Some(Self::Divide),
            "==" => Some(Self::Equal),
            "!=" => Some(Self::NotEqual),
            "<" => Some(Self::LessThan),
            ">" => Some(Self::GreaterThan),
            "<=" => Some(Self::LessOrEqual),
            ">=" => Some(Self::GreaterOrEqual),
            "&&" => Some(Self::And),
            "||" => Some(Self::Or),
            _ => None,
        }
    }

    /// Get the precedence of this operator (higher = binds tighter).
    #[must_use]
    pub fn precedence(&self) -> u8 {
        match self {
            Self::Or => 1,
            Self::And => 2,
            Self::Equal | Self::NotEqual => 3,
            Self::LessThan | Self::GreaterThan | Self::LessOrEqual | Self::GreaterOrEqual => 4,
            Self::Add | Self::Subtract => 5,
            Self::Multiply | Self::Divide => 6,
        }
    }
}

/// A parsed expression.
#[derive(Debug, Clone, PartialEq)]
pub struct Expression {
    pub token: Token,
}

impl Expression {
    /// Create a new expression from a token.
    #[must_use]
    pub fn new(token: Token) -> Self {
        Self { token }
    }

    /// Create a literal expression.
    pub fn literal(s: impl Into<String>) -> Self {
        Self::new(Token::Literal(s.into()))
    }

    /// Create a path reference expression.
    pub fn path_ref(path: impl Into<String>) -> Self {
        Self::new(Token::PathRef(path.into()))
    }

    /// Create a function call expression.
    pub fn function_call(name: impl Into<String>, args: Vec<Expression>) -> Self {
        Self::new(Token::FunctionCall {
            name: name.into(),
            args,
        })
    }

    /// Create a binary operation expression.
    #[must_use]
    pub fn binary_op(op: BinaryOperator, left: Expression, right: Expression) -> Self {
        Self::new(Token::BinaryOp {
            op,
            left: Box::new(left),
            right: Box::new(right),
        })
    }

    /// Create a number expression.
    #[must_use]
    pub fn number(n: f64) -> Self {
        Self::new(Token::Number(n))
    }

    /// Create a boolean expression.
    #[must_use]
    pub fn boolean(b: bool) -> Self {
        Self::new(Token::Boolean(b))
    }

    /// Create a null expression.
    #[must_use]
    pub fn null() -> Self {
        Self::new(Token::Null)
    }

    /// Create a unary NOT expression.
    #[must_use]
    pub fn unary_not(operand: Expression) -> Self {
        Self::new(Token::UnaryNot {
            operand: Box::new(operand),
        })
    }

    /// Get all attribute references in this expression.
    #[must_use]
    pub fn get_references(&self) -> HashSet<String> {
        let mut refs = HashSet::new();
        self.collect_references(&mut refs);
        refs
    }

    fn collect_references(&self, refs: &mut HashSet<String>) {
        match &self.token {
            Token::PathRef(path) => {
                refs.insert(path.clone());
            }
            Token::FunctionCall { args, .. } => {
                for arg in args {
                    arg.collect_references(refs);
                }
            }
            Token::BinaryOp { left, right, .. } => {
                left.collect_references(refs);
                right.collect_references(refs);
            }
            Token::UnaryNot { operand } => {
                operand.collect_references(refs);
            }
            _ => {}
        }
    }
}

/// Regex patterns for tokenizing expressions.
static NUMBER_PATTERN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^-?\d+(\.\d+)?").unwrap());

static STRING_LITERAL_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"^"([^"\\]|\\.)*""#).unwrap());

static IDENTIFIER_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-zA-Z_][a-zA-Z0-9_]*").unwrap());

/// A simple tokenizer cursor for parsing.
struct Cursor<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(input: &'a str) -> Self {
        Self { input, pos: 0 }
    }

    fn remaining(&self) -> &'a str {
        &self.input[self.pos..]
    }

    fn skip_whitespace(&mut self) {
        let trimmed = self.remaining().trim_start();
        self.pos = self.input.len() - trimmed.len();
    }

    fn peek_char(&self) -> Option<char> {
        self.remaining().chars().next()
    }

    fn advance(&mut self, n: usize) {
        self.pos = (self.pos + n).min(self.input.len());
    }

    fn is_empty(&self) -> bool {
        self.remaining().is_empty()
    }

    fn starts_with(&self, s: &str) -> bool {
        self.remaining().starts_with(s)
    }
}

/// Template Expression Service for parsing and evaluating expressions.
pub struct TemplateExpressionService {
    /// Cache of compiled regex patterns for `matches()` function.
    regex_cache: std::sync::RwLock<HashMap<String, Regex>>,
}

impl Default for TemplateExpressionService {
    fn default() -> Self {
        Self::new()
    }
}

impl TemplateExpressionService {
    /// Create a new expression service.
    #[must_use]
    pub fn new() -> Self {
        Self {
            regex_cache: std::sync::RwLock::new(HashMap::new()),
        }
    }

    /// Parse an expression string into an Expression AST.
    pub fn parse(&self, expr: &str) -> ExpressionResult<Expression> {
        let expr = expr.trim();
        if expr.is_empty() {
            return Ok(Expression::literal(""));
        }
        let mut cursor = Cursor::new(expr);
        let result = self.parse_expression(&mut cursor, 0)?;
        cursor.skip_whitespace();
        if !cursor.is_empty() {
            return Err(ExpressionError::InvalidSyntax(format!(
                "Unexpected input remaining: {}",
                cursor.remaining()
            )));
        }
        Ok(result)
    }

    /// Parse an expression with operator precedence.
    fn parse_expression(
        &self,
        cursor: &mut Cursor,
        min_precedence: u8,
    ) -> ExpressionResult<Expression> {
        cursor.skip_whitespace();
        let mut left = self.parse_primary(cursor)?;

        loop {
            cursor.skip_whitespace();
            if cursor.is_empty() {
                break;
            }

            // Check for closing delimiters - don't consume them
            if cursor.starts_with(")") || cursor.starts_with(",") {
                break;
            }

            // Try to parse a binary operator
            let op_result = self.try_parse_operator(cursor);
            match op_result {
                Some((op, op_len)) if op.precedence() >= min_precedence => {
                    cursor.advance(op_len);
                    cursor.skip_whitespace();
                    let right = self.parse_expression(cursor, op.precedence() + 1)?;
                    left = Expression::binary_op(op, left, right);
                }
                _ => break,
            }
        }

        Ok(left)
    }

    /// Parse a primary expression (literal, path ref, function call, parenthesized).
    fn parse_primary(&self, cursor: &mut Cursor) -> ExpressionResult<Expression> {
        cursor.skip_whitespace();
        let remaining = cursor.remaining();

        // Check for unary NOT operator (!)
        if remaining.starts_with('!') && !remaining.starts_with("!=") {
            cursor.advance(1);
            cursor.skip_whitespace();
            let operand = self.parse_primary(cursor)?;
            return Ok(Expression::unary_not(operand));
        }

        // Check for null
        if let Some(after) = remaining.strip_prefix("null") {
            if after.is_empty()
                || !after
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_alphanumeric() || c == '_')
            {
                cursor.advance(4);
                return Ok(Expression::null());
            }
        }

        // Check for boolean
        if let Some(after) = remaining.strip_prefix("true") {
            if after.is_empty()
                || !after
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_alphanumeric() || c == '_')
            {
                cursor.advance(4);
                return Ok(Expression::boolean(true));
            }
        }
        if let Some(after) = remaining.strip_prefix("false") {
            if after.is_empty()
                || !after
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_alphanumeric() || c == '_')
            {
                cursor.advance(5);
                return Ok(Expression::boolean(false));
            }
        }

        // Check for number (but not if it starts with - followed by identifier)
        if let Some(c) = cursor.peek_char() {
            if c.is_ascii_digit()
                || (c == '-'
                    && remaining.len() > 1
                    && remaining
                        .chars()
                        .nth(1)
                        .is_some_and(|c2| c2.is_ascii_digit()))
            {
                if let Some(m) = NUMBER_PATTERN.find(remaining) {
                    let num_str = m.as_str();
                    let num: f64 = num_str.parse().map_err(|_| {
                        ExpressionError::InvalidSyntax(format!("Invalid number: {num_str}"))
                    })?;
                    cursor.advance(m.end());
                    return Ok(Expression::number(num));
                }
            }
        }

        // Check for string literal
        if let Some(m) = STRING_LITERAL_PATTERN.find(remaining) {
            let s = m.as_str();
            // Remove quotes and unescape
            let inner = &s[1..s.len() - 1];
            let unescaped = inner.replace("\\\"", "\"").replace("\\\\", "\\");
            cursor.advance(m.end());
            return Ok(Expression::literal(unescaped));
        }

        // Check for path reference ${...}
        if remaining.starts_with("${") {
            if let Some(end) = remaining.find('}') {
                let path = &remaining[2..end];
                if !path.chars().all(|c| c.is_alphanumeric() || c == '_') {
                    return Err(ExpressionError::InvalidSyntax(format!(
                        "Invalid path reference: {path}"
                    )));
                }
                cursor.advance(end + 1);
                return Ok(Expression::path_ref(path));
            }
            return Err(ExpressionError::InvalidSyntax(
                "Unclosed path reference".to_string(),
            ));
        }

        // Check for function call (identifier followed by '(')
        if let Some(m) = IDENTIFIER_PATTERN.find(remaining) {
            let func_name = m.as_str();
            let after_name = &remaining[m.end()..].trim_start();
            if after_name.starts_with('(') {
                if !SUPPORTED_FUNCTIONS.contains(&func_name) {
                    return Err(ExpressionError::UnknownFunction(func_name.to_string()));
                }
                cursor.advance(m.end());
                cursor.skip_whitespace();
                let args = self.parse_function_args(cursor)?;
                return Ok(Expression::function_call(func_name, args));
            }
        }

        // Check for parenthesized expression
        if remaining.starts_with('(') {
            cursor.advance(1);
            let expr = self.parse_expression(cursor, 0)?;
            cursor.skip_whitespace();
            if !cursor.starts_with(")") {
                return Err(ExpressionError::InvalidSyntax(
                    "Missing closing parenthesis".to_string(),
                ));
            }
            cursor.advance(1);
            return Ok(expr);
        }

        Err(ExpressionError::InvalidSyntax(format!(
            "Unexpected token at: {}",
            &remaining[..remaining.len().min(20)]
        )))
    }

    /// Parse function arguments (inside parentheses).
    fn parse_function_args(&self, cursor: &mut Cursor) -> ExpressionResult<Vec<Expression>> {
        cursor.skip_whitespace();
        if !cursor.starts_with("(") {
            return Err(ExpressionError::InvalidSyntax("Expected '('".to_string()));
        }
        cursor.advance(1);

        let mut args = Vec::new();
        cursor.skip_whitespace();

        // Handle empty args
        if cursor.starts_with(")") {
            cursor.advance(1);
            return Ok(args);
        }

        loop {
            cursor.skip_whitespace();
            let arg = self.parse_expression(cursor, 0)?;
            args.push(arg);

            cursor.skip_whitespace();
            if cursor.starts_with(")") {
                cursor.advance(1);
                break;
            } else if cursor.starts_with(",") {
                cursor.advance(1);
            } else {
                return Err(ExpressionError::InvalidSyntax(format!(
                    "Expected ',' or ')' in function arguments, found: {}",
                    cursor.remaining()
                )));
            }
        }

        Ok(args)
    }

    /// Try to parse a binary operator at the cursor position.
    fn try_parse_operator(&self, cursor: &Cursor) -> Option<(BinaryOperator, usize)> {
        let remaining = cursor.remaining();
        // Try two-character operators first
        for (op_str, len) in &[
            ("==", 2usize),
            ("!=", 2),
            ("<=", 2),
            (">=", 2),
            ("&&", 2),
            ("||", 2),
            ("+", 1),
            ("-", 1),
            ("*", 1),
            ("/", 1),
            ("<", 1),
            (">", 1),
        ] {
            if remaining.starts_with(op_str) {
                if let Some(op) = BinaryOperator::parse(op_str) {
                    return Some((op, *len));
                }
            }
        }
        None
    }

    /// Evaluate an expression against a context of attribute values.
    pub fn evaluate(
        &self,
        expr: &Expression,
        context: &HashMap<String, Value>,
    ) -> ExpressionResult<Value> {
        match &expr.token {
            Token::Literal(s) => Ok(Value::String(s.clone())),
            Token::Number(n) => Ok(serde_json::json!(*n)),
            Token::Boolean(b) => Ok(Value::Bool(*b)),
            Token::Null => Ok(Value::Null),
            Token::PathRef(path) => context
                .get(path)
                .cloned()
                .ok_or_else(|| ExpressionError::UnknownAttribute(path.clone())),
            Token::FunctionCall { name, args } => self.evaluate_function(name, args, context),
            Token::BinaryOp { op, left, right } => {
                let left_val = self.evaluate(left, context)?;
                let right_val = self.evaluate(right, context)?;
                self.evaluate_binary_op(*op, left_val, right_val)
            }
            Token::UnaryNot { operand } => {
                let val = self.evaluate(operand, context)?;
                let b = value_to_bool(&val)?;
                Ok(Value::Bool(!b))
            }
        }
    }

    /// Evaluate a binary operation.
    fn evaluate_binary_op(
        &self,
        op: BinaryOperator,
        left: Value,
        right: Value,
    ) -> ExpressionResult<Value> {
        match op {
            BinaryOperator::Add => {
                // String concatenation or numeric addition
                match (&left, &right) {
                    (Value::String(l), Value::String(r)) => Ok(Value::String(format!("{l}{r}"))),
                    (Value::String(l), r) => {
                        Ok(Value::String(format!("{}{}", l, value_to_string(r))))
                    }
                    (l, Value::String(r)) => {
                        Ok(Value::String(format!("{}{}", value_to_string(l), r)))
                    }
                    (Value::Number(l), Value::Number(r)) => {
                        let result = l.as_f64().unwrap_or(0.0) + r.as_f64().unwrap_or(0.0);
                        Ok(serde_json::json!(result))
                    }
                    _ => Err(ExpressionError::TypeError(format!(
                        "Cannot add {left:?} and {right:?}"
                    ))),
                }
            }
            BinaryOperator::Subtract => {
                let l = value_to_f64(&left)?;
                let r = value_to_f64(&right)?;
                Ok(serde_json::json!(l - r))
            }
            BinaryOperator::Multiply => {
                let l = value_to_f64(&left)?;
                let r = value_to_f64(&right)?;
                Ok(serde_json::json!(l * r))
            }
            BinaryOperator::Divide => {
                let l = value_to_f64(&left)?;
                let r = value_to_f64(&right)?;
                if r == 0.0 {
                    return Err(ExpressionError::DivisionByZero);
                }
                Ok(serde_json::json!(l / r))
            }
            BinaryOperator::Equal => Ok(Value::Bool(values_equal(&left, &right))),
            BinaryOperator::NotEqual => Ok(Value::Bool(!values_equal(&left, &right))),
            BinaryOperator::LessThan => {
                let l = value_to_f64(&left)?;
                let r = value_to_f64(&right)?;
                Ok(Value::Bool(l < r))
            }
            BinaryOperator::GreaterThan => {
                let l = value_to_f64(&left)?;
                let r = value_to_f64(&right)?;
                Ok(Value::Bool(l > r))
            }
            BinaryOperator::LessOrEqual => {
                let l = value_to_f64(&left)?;
                let r = value_to_f64(&right)?;
                Ok(Value::Bool(l <= r))
            }
            BinaryOperator::GreaterOrEqual => {
                let l = value_to_f64(&left)?;
                let r = value_to_f64(&right)?;
                Ok(Value::Bool(l >= r))
            }
            BinaryOperator::And => {
                let l = value_to_bool(&left)?;
                let r = value_to_bool(&right)?;
                Ok(Value::Bool(l && r))
            }
            BinaryOperator::Or => {
                let l = value_to_bool(&left)?;
                let r = value_to_bool(&right)?;
                Ok(Value::Bool(l || r))
            }
        }
    }

    /// Evaluate a function call.
    fn evaluate_function(
        &self,
        name: &str,
        args: &[Expression],
        context: &HashMap<String, Value>,
    ) -> ExpressionResult<Value> {
        match name {
            "lowercase" => {
                self.check_args(name, args, 1)?;
                let val = self.evaluate(&args[0], context)?;
                Ok(Value::String(value_to_string(&val).to_lowercase()))
            }
            "uppercase" => {
                self.check_args(name, args, 1)?;
                let val = self.evaluate(&args[0], context)?;
                Ok(Value::String(value_to_string(&val).to_uppercase()))
            }
            "trim" => {
                self.check_args(name, args, 1)?;
                let val = self.evaluate(&args[0], context)?;
                Ok(Value::String(value_to_string(&val).trim().to_string()))
            }
            "length" => {
                self.check_args(name, args, 1)?;
                let val = self.evaluate(&args[0], context)?;
                let len = match &val {
                    Value::String(s) => s.len(),
                    Value::Array(arr) => arr.len(),
                    Value::Null => 0,
                    _ => value_to_string(&val).len(),
                };
                Ok(serde_json::json!(len))
            }
            "substring" => {
                if args.len() < 2 || args.len() > 3 {
                    return Err(ExpressionError::InvalidArgumentCount(
                        name.to_string(),
                        2,
                        args.len(),
                    ));
                }
                let val = self.evaluate(&args[0], context)?;
                let s = value_to_string(&val);
                let start = value_to_f64(&self.evaluate(&args[1], context)?)? as usize;
                let end = if args.len() == 3 {
                    value_to_f64(&self.evaluate(&args[2], context)?)? as usize
                } else {
                    s.len()
                };
                let result: String = s
                    .chars()
                    .skip(start)
                    .take(end.saturating_sub(start))
                    .collect();
                Ok(Value::String(result))
            }
            "concat" => {
                let mut result = String::new();
                for arg in args {
                    let val = self.evaluate(arg, context)?;
                    result.push_str(&value_to_string(&val));
                }
                Ok(Value::String(result))
            }
            "replace" => {
                self.check_args(name, args, 3)?;
                let val = self.evaluate(&args[0], context)?;
                let from = value_to_string(&self.evaluate(&args[1], context)?);
                let to = value_to_string(&self.evaluate(&args[2], context)?);
                Ok(Value::String(value_to_string(&val).replace(&from, &to)))
            }
            "split" => {
                self.check_args(name, args, 2)?;
                let val = self.evaluate(&args[0], context)?;
                let delimiter = value_to_string(&self.evaluate(&args[1], context)?);
                let parts: Vec<Value> = value_to_string(&val)
                    .split(&delimiter)
                    .map(|s| Value::String(s.to_string()))
                    .collect();
                Ok(Value::Array(parts))
            }
            "join" => {
                self.check_args(name, args, 2)?;
                let val = self.evaluate(&args[0], context)?;
                let delimiter = value_to_string(&self.evaluate(&args[1], context)?);
                let result = match &val {
                    Value::Array(arr) => arr
                        .iter()
                        .map(value_to_string)
                        .collect::<Vec<_>>()
                        .join(&delimiter),
                    _ => value_to_string(&val),
                };
                Ok(Value::String(result))
            }
            "contains" => {
                self.check_args(name, args, 2)?;
                let val = self.evaluate(&args[0], context)?;
                let needle = value_to_string(&self.evaluate(&args[1], context)?);
                let result = match &val {
                    Value::String(s) => s.contains(&needle),
                    Value::Array(arr) => arr.iter().any(|v| value_to_string(v) == needle),
                    _ => value_to_string(&val).contains(&needle),
                };
                Ok(Value::Bool(result))
            }
            "starts_with" => {
                self.check_args(name, args, 2)?;
                let val = self.evaluate(&args[0], context)?;
                let prefix = value_to_string(&self.evaluate(&args[1], context)?);
                Ok(Value::Bool(value_to_string(&val).starts_with(&prefix)))
            }
            "ends_with" => {
                self.check_args(name, args, 2)?;
                let val = self.evaluate(&args[0], context)?;
                let suffix = value_to_string(&self.evaluate(&args[1], context)?);
                Ok(Value::Bool(value_to_string(&val).ends_with(&suffix)))
            }
            "is_empty" => {
                self.check_args(name, args, 1)?;
                let val = self.evaluate(&args[0], context)?;
                let result = match &val {
                    Value::Null => true,
                    Value::String(s) => s.is_empty(),
                    Value::Array(arr) => arr.is_empty(),
                    Value::Object(obj) => obj.is_empty(),
                    _ => false,
                };
                Ok(Value::Bool(result))
            }
            "is_null" => {
                self.check_args(name, args, 1)?;
                let val = self.evaluate(&args[0], context)?;
                Ok(Value::Bool(val.is_null()))
            }
            "coalesce" => {
                if args.is_empty() {
                    return Err(ExpressionError::InvalidArgumentCount(
                        name.to_string(),
                        1,
                        0,
                    ));
                }
                for arg in args {
                    let val = self.evaluate(arg, context)?;
                    if !val.is_null() {
                        if let Value::String(s) = &val {
                            if !s.is_empty() {
                                return Ok(val);
                            }
                        } else {
                            return Ok(val);
                        }
                    }
                }
                Ok(Value::Null)
            }
            "if" => {
                self.check_args(name, args, 3)?;
                let condition = self.evaluate(&args[0], context)?;
                let is_true = value_to_bool(&condition)?;
                if is_true {
                    self.evaluate(&args[1], context)
                } else {
                    self.evaluate(&args[2], context)
                }
            }
            "matches" => {
                self.check_args(name, args, 2)?;
                let val = self.evaluate(&args[0], context)?;
                let pattern = value_to_string(&self.evaluate(&args[1], context)?);

                let regex = self.get_or_compile_regex(&pattern)?;
                let s = value_to_string(&val);
                Ok(Value::Bool(regex.is_match(&s)))
            }
            _ => Err(ExpressionError::UnknownFunction(name.to_string())),
        }
    }

    /// Check that a function has the expected number of arguments.
    fn check_args(&self, name: &str, args: &[Expression], expected: usize) -> ExpressionResult<()> {
        if args.len() != expected {
            return Err(ExpressionError::InvalidArgumentCount(
                name.to_string(),
                expected,
                args.len(),
            ));
        }
        Ok(())
    }

    /// Get or compile a regex pattern, caching the result.
    fn get_or_compile_regex(&self, pattern: &str) -> ExpressionResult<Regex> {
        // Try read lock first
        {
            let cache = self.regex_cache.read().unwrap_or_else(|e| e.into_inner());
            if let Some(regex) = cache.get(pattern) {
                return Ok(regex.clone());
            }
        }

        // Compile and cache
        let regex = Regex::new(pattern).map_err(|e| ExpressionError::RegexError(e.to_string()))?;

        let mut cache = self.regex_cache.write().unwrap_or_else(|e| e.into_inner());
        cache.insert(pattern.to_string(), regex.clone());
        Ok(regex)
    }

    /// Validate an expression string without evaluating it.
    /// Returns the set of attribute references found in the expression.
    pub fn validate(&self, expr: &str) -> ExpressionResult<HashSet<String>> {
        let parsed = self.parse(expr)?;
        Ok(parsed.get_references())
    }

    /// Check for circular dependencies in a set of computed value expressions.
    /// Returns `Ok(ordered_attrs)` with attributes in dependency order, or Err with cycle info.
    pub fn detect_cycles(
        &self,
        expressions: &HashMap<String, String>,
    ) -> ExpressionResult<Vec<String>> {
        // Build dependency graph
        let mut deps: HashMap<String, HashSet<String>> = HashMap::new();

        for (attr, expr) in expressions {
            let refs = self.validate(expr)?;
            // Only include dependencies on other computed attributes
            let relevant_deps: HashSet<String> = refs
                .into_iter()
                .filter(|r| expressions.contains_key(r))
                .collect();
            deps.insert(attr.clone(), relevant_deps);
        }

        // Topological sort using Kahn's algorithm
        let mut in_degree: HashMap<String, usize> = HashMap::new();
        for attr in expressions.keys() {
            in_degree.insert(attr.clone(), 0);
        }
        for attr_deps in deps.values() {
            for dep in attr_deps {
                *in_degree.entry(dep.clone()).or_insert(0) += 1;
            }
        }

        let mut queue: Vec<String> = in_degree
            .iter()
            .filter(|(_, &d)| d == 0)
            .map(|(a, _)| a.clone())
            .collect();
        let mut result = Vec::new();

        while let Some(attr) = queue.pop() {
            result.push(attr.clone());
            if let Some(attr_deps) = deps.get(&attr) {
                for dep in attr_deps {
                    if let Some(d) = in_degree.get_mut(dep) {
                        *d -= 1;
                        if *d == 0 {
                            queue.push(dep.clone());
                        }
                    }
                }
            }
        }

        if result.len() != expressions.len() {
            // Find cycle - attrs not in result are part of cycle
            let cycle: Vec<String> = expressions
                .keys()
                .filter(|a| !result.contains(a))
                .cloned()
                .collect();
            return Err(ExpressionError::CircularReference(cycle.join(" -> ")));
        }

        // Reverse to get evaluation order (dependencies first)
        result.reverse();
        Ok(result)
    }
}

/// Convert a JSON value to a string representation.
fn value_to_string(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
        Value::Array(arr) => arr
            .iter()
            .map(value_to_string)
            .collect::<Vec<_>>()
            .join(","),
        Value::Object(_) => "[object]".to_string(),
    }
}

/// Convert a JSON value to a boolean.
fn value_to_bool(v: &Value) -> ExpressionResult<bool> {
    match v {
        Value::Bool(b) => Ok(*b),
        Value::Null => Ok(false),
        Value::String(s) => Ok(!s.is_empty()),
        Value::Number(n) => Ok(n.as_f64().is_some_and(|f| f != 0.0)),
        _ => Err(ExpressionError::TypeError(format!(
            "Cannot convert {v:?} to boolean"
        ))),
    }
}

/// Convert a JSON value to a float.
fn value_to_f64(v: &Value) -> ExpressionResult<f64> {
    match v {
        Value::Number(n) => n
            .as_f64()
            .ok_or_else(|| ExpressionError::TypeError("Invalid number".to_string())),
        Value::String(s) => s
            .parse()
            .map_err(|_| ExpressionError::TypeError(format!("Cannot parse '{s}' as number"))),
        _ => Err(ExpressionError::TypeError(format!(
            "Cannot convert {v:?} to number"
        ))),
    }
}

/// Check if two JSON values are equal.
fn values_equal(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Null, Value::Null) => true,
        (Value::Bool(x), Value::Bool(y)) => x == y,
        (Value::Number(x), Value::Number(y)) => {
            x.as_f64().unwrap_or(f64::NAN) == y.as_f64().unwrap_or(f64::NAN)
        }
        (Value::String(x), Value::String(y)) => x == y,
        // Loose comparison for string/number
        (Value::String(s), Value::Number(n)) | (Value::Number(n), Value::String(s)) => {
            if let Ok(parsed) = s.parse::<f64>() {
                n.as_f64().is_some_and(|f| f == parsed)
            } else {
                false
            }
        }
        _ => a == b,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service() -> TemplateExpressionService {
        TemplateExpressionService::new()
    }

    fn context() -> HashMap<String, Value> {
        let mut ctx = HashMap::new();
        ctx.insert("firstName".to_string(), Value::String("John".to_string()));
        ctx.insert("lastName".to_string(), Value::String("Doe".to_string()));
        ctx.insert(
            "email".to_string(),
            Value::String("john.doe@example.com".to_string()),
        );
        ctx.insert("age".to_string(), serde_json::json!(30));
        ctx.insert("department".to_string(), Value::Null);
        ctx.insert("type".to_string(), Value::String("employee".to_string()));
        ctx
    }

    #[test]
    fn test_parse_literal() {
        let svc = service();
        let expr = svc.parse("\"hello world\"").unwrap();
        assert_eq!(expr.token, Token::Literal("hello world".to_string()));
    }

    #[test]
    fn test_parse_path_ref() {
        let svc = service();
        let expr = svc.parse("${firstName}").unwrap();
        assert_eq!(expr.token, Token::PathRef("firstName".to_string()));
    }

    #[test]
    fn test_parse_number() {
        let svc = service();
        let expr = svc.parse("42").unwrap();
        assert_eq!(expr.token, Token::Number(42.0));

        let expr = svc.parse("-3.15").unwrap();
        assert_eq!(expr.token, Token::Number(-3.15));
    }

    #[test]
    fn test_parse_boolean() {
        let svc = service();
        let expr = svc.parse("true").unwrap();
        assert_eq!(expr.token, Token::Boolean(true));

        let expr = svc.parse("false").unwrap();
        assert_eq!(expr.token, Token::Boolean(false));
    }

    #[test]
    fn test_parse_null() {
        let svc = service();
        let expr = svc.parse("null").unwrap();
        assert_eq!(expr.token, Token::Null);
    }

    #[test]
    fn test_evaluate_path_ref() {
        let svc = service();
        let ctx = context();
        let expr = svc.parse("${firstName}").unwrap();
        let result = svc.evaluate(&expr, &ctx).unwrap();
        assert_eq!(result, Value::String("John".to_string()));
    }

    #[test]
    fn test_evaluate_concatenation() {
        let svc = service();
        let ctx = context();
        let expr = svc.parse("${firstName} + \" \" + ${lastName}").unwrap();
        let result = svc.evaluate(&expr, &ctx).unwrap();
        assert_eq!(result, Value::String("John Doe".to_string()));
    }

    #[test]
    fn test_evaluate_function_lowercase() {
        let svc = service();
        let ctx = context();
        let expr = svc.parse("lowercase(${firstName})").unwrap();
        let result = svc.evaluate(&expr, &ctx).unwrap();
        assert_eq!(result, Value::String("john".to_string()));
    }

    #[test]
    fn test_evaluate_function_uppercase() {
        let svc = service();
        let ctx = context();
        let expr = svc.parse("uppercase(${lastName})").unwrap();
        let result = svc.evaluate(&expr, &ctx).unwrap();
        assert_eq!(result, Value::String("DOE".to_string()));
    }

    #[test]
    fn test_evaluate_function_trim() {
        let svc = service();
        let mut ctx = HashMap::new();
        ctx.insert("name".to_string(), Value::String("  spaced  ".to_string()));
        let expr = svc.parse("trim(${name})").unwrap();
        let result = svc.evaluate(&expr, &ctx).unwrap();
        assert_eq!(result, Value::String("spaced".to_string()));
    }

    #[test]
    fn test_evaluate_function_concat() {
        let svc = service();
        let ctx = context();
        let expr = svc
            .parse("concat(${firstName}, \" \", ${lastName})")
            .unwrap();
        let result = svc.evaluate(&expr, &ctx).unwrap();
        assert_eq!(result, Value::String("John Doe".to_string()));
    }

    #[test]
    fn test_evaluate_function_length() {
        let svc = service();
        let ctx = context();
        let expr = svc.parse("length(${firstName})").unwrap();
        let result = svc.evaluate(&expr, &ctx).unwrap();
        assert_eq!(result, serde_json::json!(4));
    }

    #[test]
    fn test_evaluate_function_substring() {
        let svc = service();
        let ctx = context();
        let expr = svc.parse("substring(${firstName}, 0, 2)").unwrap();
        let result = svc.evaluate(&expr, &ctx).unwrap();
        assert_eq!(result, Value::String("Jo".to_string()));
    }

    #[test]
    fn test_evaluate_function_replace() {
        let svc = service();
        let ctx = context();
        let expr = svc
            .parse("replace(${email}, \"example.com\", \"company.com\")")
            .unwrap();
        let result = svc.evaluate(&expr, &ctx).unwrap();
        assert_eq!(result, Value::String("john.doe@company.com".to_string()));
    }

    #[test]
    fn test_evaluate_function_contains() {
        let svc = service();
        let ctx = context();
        let expr = svc.parse("contains(${email}, \"@\")").unwrap();
        let result = svc.evaluate(&expr, &ctx).unwrap();
        assert_eq!(result, Value::Bool(true));
    }

    #[test]
    fn test_evaluate_function_starts_with() {
        let svc = service();
        let ctx = context();
        let expr = svc.parse("starts_with(${email}, \"john\")").unwrap();
        let result = svc.evaluate(&expr, &ctx).unwrap();
        assert_eq!(result, Value::Bool(true));
    }

    #[test]
    fn test_evaluate_function_ends_with() {
        let svc = service();
        let ctx = context();
        let expr = svc.parse("ends_with(${email}, \".com\")").unwrap();
        let result = svc.evaluate(&expr, &ctx).unwrap();
        assert_eq!(result, Value::Bool(true));
    }

    #[test]
    fn test_evaluate_function_is_null() {
        let svc = service();
        let ctx = context();
        let expr = svc.parse("is_null(${department})").unwrap();
        let result = svc.evaluate(&expr, &ctx).unwrap();
        assert_eq!(result, Value::Bool(true));

        let expr = svc.parse("is_null(${firstName})").unwrap();
        let result = svc.evaluate(&expr, &ctx).unwrap();
        assert_eq!(result, Value::Bool(false));
    }

    #[test]
    fn test_evaluate_function_is_empty() {
        let svc = service();
        let mut ctx = HashMap::new();
        ctx.insert("empty".to_string(), Value::String("".to_string()));
        ctx.insert("nonempty".to_string(), Value::String("hi".to_string()));

        let expr = svc.parse("is_empty(${empty})").unwrap();
        let result = svc.evaluate(&expr, &ctx).unwrap();
        assert_eq!(result, Value::Bool(true));

        let expr = svc.parse("is_empty(${nonempty})").unwrap();
        let result = svc.evaluate(&expr, &ctx).unwrap();
        assert_eq!(result, Value::Bool(false));
    }

    #[test]
    fn test_evaluate_function_coalesce() {
        let svc = service();
        let ctx = context();
        let expr = svc
            .parse("coalesce(${department}, \"Unassigned\")")
            .unwrap();
        let result = svc.evaluate(&expr, &ctx).unwrap();
        assert_eq!(result, Value::String("Unassigned".to_string()));

        let expr = svc.parse("coalesce(${firstName}, \"Unknown\")").unwrap();
        let result = svc.evaluate(&expr, &ctx).unwrap();
        assert_eq!(result, Value::String("John".to_string()));
    }

    #[test]
    fn test_evaluate_function_if() {
        let svc = service();
        let ctx = context();
        let expr = svc
            .parse("if(${type} == \"employee\", \"EMP\", \"CTR\")")
            .unwrap();
        let result = svc.evaluate(&expr, &ctx).unwrap();
        assert_eq!(result, Value::String("EMP".to_string()));

        let mut ctx2 = ctx.clone();
        ctx2.insert("type".to_string(), Value::String("contractor".to_string()));
        let result = svc.evaluate(&expr, &ctx2).unwrap();
        assert_eq!(result, Value::String("CTR".to_string()));
    }

    #[test]
    fn test_evaluate_function_matches() {
        let svc = service();
        let ctx = context();
        let expr = svc
            .parse("matches(${email}, \"^[a-z.]+@[a-z]+\\\\.[a-z]+$\")")
            .unwrap();
        let result = svc.evaluate(&expr, &ctx).unwrap();
        assert_eq!(result, Value::Bool(true));

        let expr = svc.parse("matches(${email}, \"^admin@\")").unwrap();
        let result = svc.evaluate(&expr, &ctx).unwrap();
        assert_eq!(result, Value::Bool(false));
    }

    #[test]
    fn test_evaluate_comparison_equal() {
        let svc = service();
        let ctx = context();
        let expr = svc.parse("${firstName} == \"John\"").unwrap();
        let result = svc.evaluate(&expr, &ctx).unwrap();
        assert_eq!(result, Value::Bool(true));

        let expr = svc.parse("${age} == 30").unwrap();
        let result = svc.evaluate(&expr, &ctx).unwrap();
        assert_eq!(result, Value::Bool(true));
    }

    #[test]
    fn test_evaluate_comparison_not_equal() {
        let svc = service();
        let ctx = context();
        let expr = svc.parse("${firstName} != \"Jane\"").unwrap();
        let result = svc.evaluate(&expr, &ctx).unwrap();
        assert_eq!(result, Value::Bool(true));
    }

    #[test]
    fn test_evaluate_comparison_numeric() {
        let svc = service();
        let ctx = context();

        let expr = svc.parse("${age} > 25").unwrap();
        let result = svc.evaluate(&expr, &ctx).unwrap();
        assert_eq!(result, Value::Bool(true));

        let expr = svc.parse("${age} < 40").unwrap();
        let result = svc.evaluate(&expr, &ctx).unwrap();
        assert_eq!(result, Value::Bool(true));

        let expr = svc.parse("${age} >= 30").unwrap();
        let result = svc.evaluate(&expr, &ctx).unwrap();
        assert_eq!(result, Value::Bool(true));

        let expr = svc.parse("${age} <= 30").unwrap();
        let result = svc.evaluate(&expr, &ctx).unwrap();
        assert_eq!(result, Value::Bool(true));
    }

    #[test]
    fn test_evaluate_logical_and() {
        let svc = service();
        let ctx = context();
        let expr = svc.parse("${age} > 20 && ${age} < 40").unwrap();
        let result = svc.evaluate(&expr, &ctx).unwrap();
        assert_eq!(result, Value::Bool(true));
    }

    #[test]
    fn test_evaluate_logical_or() {
        let svc = service();
        let ctx = context();
        let expr = svc
            .parse("${type} == \"admin\" || ${type} == \"employee\"")
            .unwrap();
        let result = svc.evaluate(&expr, &ctx).unwrap();
        assert_eq!(result, Value::Bool(true));
    }

    #[test]
    fn test_evaluate_arithmetic() {
        let svc = service();
        let ctx = context();

        let expr = svc.parse("${age} + 5").unwrap();
        let result = svc.evaluate(&expr, &ctx).unwrap();
        assert_eq!(result, serde_json::json!(35.0));

        let expr = svc.parse("${age} - 10").unwrap();
        let result = svc.evaluate(&expr, &ctx).unwrap();
        assert_eq!(result, serde_json::json!(20.0));

        let expr = svc.parse("${age} * 2").unwrap();
        let result = svc.evaluate(&expr, &ctx).unwrap();
        assert_eq!(result, serde_json::json!(60.0));

        let expr = svc.parse("${age} / 3").unwrap();
        let result = svc.evaluate(&expr, &ctx).unwrap();
        assert_eq!(result, serde_json::json!(10.0));
    }

    #[test]
    fn test_evaluate_division_by_zero() {
        let svc = service();
        let ctx = context();
        let expr = svc.parse("${age} / 0").unwrap();
        let result = svc.evaluate(&expr, &ctx);
        assert!(matches!(result, Err(ExpressionError::DivisionByZero)));
    }

    #[test]
    fn test_validate_expression() {
        let svc = service();
        let refs = svc.validate("${firstName} + \" \" + ${lastName}").unwrap();
        assert!(refs.contains("firstName"));
        assert!(refs.contains("lastName"));
        assert_eq!(refs.len(), 2);
    }

    #[test]
    fn test_detect_no_cycles() {
        let svc = service();
        let mut exprs = HashMap::new();
        exprs.insert(
            "fullName".to_string(),
            "${firstName} + \" \" + ${lastName}".to_string(),
        );
        exprs.insert(
            "greeting".to_string(),
            "\"Hello, \" + ${fullName}".to_string(),
        );

        let result = svc.detect_cycles(&exprs).unwrap();
        assert_eq!(result.len(), 2);
        // fullName should come before greeting since greeting depends on fullName
        assert_eq!(result[0], "fullName");
        assert_eq!(result[1], "greeting");
    }

    #[test]
    fn test_detect_cycle() {
        let svc = service();
        let mut exprs = HashMap::new();
        exprs.insert("a".to_string(), "${b}".to_string());
        exprs.insert("b".to_string(), "${c}".to_string());
        exprs.insert("c".to_string(), "${a}".to_string());

        let result = svc.detect_cycles(&exprs);
        assert!(matches!(result, Err(ExpressionError::CircularReference(_))));
    }

    #[test]
    fn test_unknown_function_error() {
        let svc = service();
        let result = svc.parse("unknown_func(${name})");
        assert!(matches!(result, Err(ExpressionError::UnknownFunction(_))));
    }

    #[test]
    fn test_unknown_attribute_error() {
        let svc = service();
        let ctx = context();
        let expr = svc.parse("${nonexistent}").unwrap();
        let result = svc.evaluate(&expr, &ctx);
        assert!(matches!(result, Err(ExpressionError::UnknownAttribute(_))));
    }

    #[test]
    fn test_invalid_syntax_unclosed_path() {
        let svc = service();
        let result = svc.parse("${firstName");
        assert!(matches!(result, Err(ExpressionError::InvalidSyntax(_))));
    }

    #[test]
    fn test_nested_function_calls() {
        let svc = service();
        let ctx = context();
        let expr = svc.parse("uppercase(trim(${firstName}))").unwrap();
        let result = svc.evaluate(&expr, &ctx).unwrap();
        assert_eq!(result, Value::String("JOHN".to_string()));
    }

    #[test]
    fn test_complex_expression() {
        let svc = service();
        let ctx = context();
        // Complex: if employee, create email from name, else use existing
        let expr = svc.parse(
            "if(${type} == \"employee\", lowercase(${firstName}) + \".\" + lowercase(${lastName}) + \"@company.com\", ${email})"
        ).unwrap();
        let result = svc.evaluate(&expr, &ctx).unwrap();
        assert_eq!(result, Value::String("john.doe@company.com".to_string()));
    }

    #[test]
    fn test_function_split_join() {
        let svc = service();
        let mut ctx = HashMap::new();
        ctx.insert("list".to_string(), Value::String("a,b,c".to_string()));

        let expr = svc.parse("split(${list}, \",\")").unwrap();
        let result = svc.evaluate(&expr, &ctx).unwrap();
        assert_eq!(result, serde_json::json!(["a", "b", "c"]));

        ctx.insert("arr".to_string(), serde_json::json!(["x", "y", "z"]));
        let expr = svc.parse("join(${arr}, \"-\")").unwrap();
        let result = svc.evaluate(&expr, &ctx).unwrap();
        assert_eq!(result, Value::String("x-y-z".to_string()));
    }

    #[test]
    fn test_empty_expression() {
        let svc = service();
        let expr = svc.parse("").unwrap();
        let ctx = HashMap::new();
        let result = svc.evaluate(&expr, &ctx).unwrap();
        assert_eq!(result, Value::String("".to_string()));
    }

    #[test]
    fn test_unary_not_operator() {
        let svc = service();
        let ctx = context();

        // !true = false
        let expr = svc.parse("!true").unwrap();
        let result = svc.evaluate(&expr, &ctx).unwrap();
        assert_eq!(result, Value::Bool(false));

        // !false = true
        let expr = svc.parse("!false").unwrap();
        let result = svc.evaluate(&expr, &ctx).unwrap();
        assert_eq!(result, Value::Bool(true));

        // !is_null on non-null value
        let expr = svc.parse("!is_null(${firstName})").unwrap();
        let result = svc.evaluate(&expr, &ctx).unwrap();
        assert_eq!(result, Value::Bool(true));

        // !is_null on null value
        let expr = svc.parse("!is_null(${department})").unwrap();
        let result = svc.evaluate(&expr, &ctx).unwrap();
        assert_eq!(result, Value::Bool(false));

        // Complex: condition || !is_null(...)
        let expr = svc
            .parse("${type} == \"admin\" || !is_null(${firstName})")
            .unwrap();
        let result = svc.evaluate(&expr, &ctx).unwrap();
        assert_eq!(result, Value::Bool(true));
    }

    #[test]
    fn test_whitespace_handling() {
        let svc = service();
        let ctx = context();
        let expr = svc
            .parse("  ${firstName}  +  \" \"  +  ${lastName}  ")
            .unwrap();
        let result = svc.evaluate(&expr, &ctx).unwrap();
        assert_eq!(result, Value::String("John Doe".to_string()));
    }
}
