//! SCIM filter syntax parser (RFC 7644 Section 3.4.2.2).
//!
//! Implements a recursive descent parser for SCIM filter expressions
//! and generates SQL WHERE clauses.

use crate::error::{ScimError, ScimResult};

/// SCIM filter comparison operators.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompareOp {
    /// Equal
    Eq,
    /// Not equal
    Ne,
    /// Contains
    Co,
    /// Starts with
    Sw,
    /// Ends with
    Ew,
    /// Present (not null)
    Pr,
    /// Greater than
    Gt,
    /// Greater than or equal
    Ge,
    /// Less than
    Lt,
    /// Less than or equal
    Le,
}

impl CompareOp {
    fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "eq" => Some(CompareOp::Eq),
            "ne" => Some(CompareOp::Ne),
            "co" => Some(CompareOp::Co),
            "sw" => Some(CompareOp::Sw),
            "ew" => Some(CompareOp::Ew),
            "pr" => Some(CompareOp::Pr),
            "gt" => Some(CompareOp::Gt),
            "ge" => Some(CompareOp::Ge),
            "lt" => Some(CompareOp::Lt),
            "le" => Some(CompareOp::Le),
            _ => None,
        }
    }

    /// Convert the comparison operator to SQL.
    ///
    /// SECURITY: Column names are quoted with double quotes to prevent SQL injection
    /// through identifier manipulation. Even though columns come from a whitelist,
    /// quoting provides defense-in-depth.
    ///
    /// When `is_boolean` is true, the parameter is cast to `::boolean` in SQL
    /// so that string values like `"true"` / `"false"` are properly compared
    /// against PostgreSQL BOOLEAN columns.
    fn to_sql(
        &self,
        column: &str,
        value: &str,
        param_num: usize,
        is_boolean: bool,
    ) -> (String, Option<String>) {
        // SECURITY: Quote column identifier to prevent SQL injection.
        // PostgreSQL uses double quotes for identifiers.
        let quoted_col = format!("\"{}\"", column.replace('"', "\"\""));
        let param_ref = if is_boolean {
            format!("${param_num}::boolean")
        } else {
            format!("${param_num}")
        };

        match self {
            CompareOp::Eq => (
                format!("{quoted_col} = {param_ref}"),
                Some(value.to_string()),
            ),
            CompareOp::Ne => (
                format!("{quoted_col} <> {param_ref}"),
                Some(value.to_string()),
            ),
            CompareOp::Co => {
                let escaped = escape_ilike_wildcards(value);
                (
                    format!("{quoted_col} ILIKE {param_ref}"),
                    Some(format!("%{escaped}%")),
                )
            }
            CompareOp::Sw => {
                let escaped = escape_ilike_wildcards(value);
                (
                    format!("{quoted_col} ILIKE {param_ref}"),
                    Some(format!("{escaped}%")),
                )
            }
            CompareOp::Ew => {
                let escaped = escape_ilike_wildcards(value);
                (
                    format!("{quoted_col} ILIKE {param_ref}"),
                    Some(format!("%{escaped}")),
                )
            }
            CompareOp::Pr => (format!("{quoted_col} IS NOT NULL"), None),
            CompareOp::Gt => (
                format!("{quoted_col} > {param_ref}"),
                Some(value.to_string()),
            ),
            CompareOp::Ge => (
                format!("{quoted_col} >= {param_ref}"),
                Some(value.to_string()),
            ),
            CompareOp::Lt => (
                format!("{quoted_col} < {param_ref}"),
                Some(value.to_string()),
            ),
            CompareOp::Le => (
                format!("{quoted_col} <= {param_ref}"),
                Some(value.to_string()),
            ),
        }
    }
}

/// Escape ILIKE wildcard characters in a value to prevent wildcard injection.
///
/// SECURITY: Without escaping, user-supplied filter values like `%` or `_`
/// would be interpreted as PostgreSQL ILIKE wildcards, allowing broader
/// matches than intended (e.g., `userName co "%"` would match everything).
fn escape_ilike_wildcards(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

/// Logical operators.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogicalOp {
    And,
    Or,
}

/// A parsed filter expression.
#[derive(Debug, Clone)]
pub enum FilterExpr {
    /// Comparison expression: attribute op value
    Compare {
        attribute: String,
        op: CompareOp,
        value: Option<String>,
    },
    /// Logical expression: left AND/OR right
    Logical {
        left: Box<FilterExpr>,
        op: LogicalOp,
        right: Box<FilterExpr>,
    },
    /// Negation: NOT expression
    Not(Box<FilterExpr>),
    /// Grouped expression: (expression)
    Group(Box<FilterExpr>),
}

/// Maximum recursion depth for filter parsing (prevents stack overflow on malicious input).
const MAX_FILTER_DEPTH: usize = 20;

/// SCIM filter parser.
pub struct FilterParser<'a> {
    input: &'a str,
    pos: usize,
    depth: usize,
}

impl<'a> FilterParser<'a> {
    /// Create a new parser.
    #[must_use]
    pub fn new(input: &'a str) -> Self {
        Self {
            input,
            pos: 0,
            depth: 0,
        }
    }

    /// Track recursion depth, returning error if max exceeded.
    fn enter_depth(&mut self) -> ScimResult<()> {
        self.depth += 1;
        if self.depth > MAX_FILTER_DEPTH {
            return Err(ScimError::InvalidFilter(
                "Filter expression exceeds maximum nesting depth".to_string(),
            ));
        }
        Ok(())
    }

    fn exit_depth(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    /// Parse the filter expression.
    pub fn parse(&mut self) -> ScimResult<FilterExpr> {
        self.skip_whitespace();
        let expr = self.parse_or()?;
        self.skip_whitespace();
        if self.pos < self.input.len() {
            return Err(ScimError::InvalidFilter(format!(
                "Unexpected characters at position {}: '{}'",
                self.pos,
                &self.input[self.pos..]
            )));
        }
        Ok(expr)
    }

    fn parse_or(&mut self) -> ScimResult<FilterExpr> {
        let mut left = self.parse_and()?;

        loop {
            self.skip_whitespace();
            if self.try_consume_keyword("or") {
                self.skip_whitespace();
                let right = self.parse_and()?;
                left = FilterExpr::Logical {
                    left: Box::new(left),
                    op: LogicalOp::Or,
                    right: Box::new(right),
                };
            } else {
                break;
            }
        }

        Ok(left)
    }

    fn parse_and(&mut self) -> ScimResult<FilterExpr> {
        let mut left = self.parse_unary()?;

        loop {
            self.skip_whitespace();
            if self.try_consume_keyword("and") {
                self.skip_whitespace();
                let right = self.parse_unary()?;
                left = FilterExpr::Logical {
                    left: Box::new(left),
                    op: LogicalOp::And,
                    right: Box::new(right),
                };
            } else {
                break;
            }
        }

        Ok(left)
    }

    fn parse_unary(&mut self) -> ScimResult<FilterExpr> {
        self.skip_whitespace();

        if self.try_consume_keyword("not") {
            self.enter_depth()?;
            self.skip_whitespace();
            if !self.try_consume_char('(') {
                self.exit_depth();
                return Err(ScimError::InvalidFilter(
                    "Expected '(' after 'not'".to_string(),
                ));
            }
            let expr = self.parse_or()?;
            self.skip_whitespace();
            if !self.try_consume_char(')') {
                self.exit_depth();
                return Err(ScimError::InvalidFilter(
                    "Expected ')' to close 'not' expression".to_string(),
                ));
            }
            self.exit_depth();
            return Ok(FilterExpr::Not(Box::new(expr)));
        }

        self.parse_primary()
    }

    fn parse_primary(&mut self) -> ScimResult<FilterExpr> {
        self.skip_whitespace();

        // Grouped expression
        if self.try_consume_char('(') {
            self.enter_depth()?;
            let expr = self.parse_or()?;
            self.skip_whitespace();
            if !self.try_consume_char(')') {
                self.exit_depth();
                return Err(ScimError::InvalidFilter(
                    "Expected ')' to close grouped expression".to_string(),
                ));
            }
            self.exit_depth();
            return Ok(FilterExpr::Group(Box::new(expr)));
        }

        // Attribute expression
        self.parse_attr_expr()
    }

    fn parse_attr_expr(&mut self) -> ScimResult<FilterExpr> {
        let attribute = self.parse_attribute()?;
        self.skip_whitespace();

        let op_str = self.parse_operator()?;
        let op = CompareOp::from_str(&op_str)
            .ok_or_else(|| ScimError::InvalidFilter(format!("Unknown operator: {op_str}")))?;

        // 'pr' operator has no value
        if op == CompareOp::Pr {
            return Ok(FilterExpr::Compare {
                attribute,
                op,
                value: None,
            });
        }

        self.skip_whitespace();
        let value = self.parse_value()?;

        Ok(FilterExpr::Compare {
            attribute,
            op,
            value: Some(value),
        })
    }

    fn parse_attribute(&mut self) -> ScimResult<String> {
        let start = self.pos;

        while self.pos < self.input.len() {
            let c = self.current_char();
            if c.is_alphanumeric() || c == '.' || c == '_' {
                self.pos += 1;
            } else {
                break;
            }
        }

        if self.pos == start {
            return Err(ScimError::InvalidFilter(
                "Expected attribute name".to_string(),
            ));
        }

        Ok(self.input[start..self.pos].to_string())
    }

    fn parse_operator(&mut self) -> ScimResult<String> {
        let start = self.pos;

        while self.pos < self.input.len() {
            let c = self.current_char();
            if c.is_alphabetic() {
                self.pos += 1;
            } else {
                break;
            }
        }

        if self.pos == start {
            return Err(ScimError::InvalidFilter("Expected operator".to_string()));
        }

        Ok(self.input[start..self.pos].to_lowercase())
    }

    fn parse_value(&mut self) -> ScimResult<String> {
        self.skip_whitespace();

        if self.try_consume_char('"') {
            // Quoted string — collect characters, handling escape sequences
            let mut value = String::new();
            while self.pos < self.input.len() && self.current_char() != '"' {
                if self.current_char() == '\\' && self.pos + 1 < self.input.len() {
                    self.pos += 1; // Skip backslash
                    value.push(self.current_char()); // Push the escaped character
                    self.pos += 1;
                } else {
                    value.push(self.current_char());
                    self.pos += 1;
                }
            }
            if !self.try_consume_char('"') {
                return Err(ScimError::InvalidFilter("Unterminated string".to_string()));
            }
            Ok(value)
        } else {
            // Unquoted value (boolean, number)
            let start = self.pos;
            while self.pos < self.input.len() {
                let c = self.current_char();
                if c.is_alphanumeric() || c == '.' || c == '-' || c == '+' {
                    self.pos += 1;
                } else {
                    break;
                }
            }
            if self.pos == start {
                return Err(ScimError::InvalidFilter("Expected value".to_string()));
            }
            Ok(self.input[start..self.pos].to_string())
        }
    }

    fn skip_whitespace(&mut self) {
        while self.pos < self.input.len() && self.current_char().is_whitespace() {
            self.pos += 1;
        }
    }

    fn current_char(&self) -> char {
        self.input[self.pos..].chars().next().unwrap_or('\0')
    }

    fn try_consume_char(&mut self, c: char) -> bool {
        if self.pos < self.input.len() && self.current_char() == c {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn try_consume_keyword(&mut self, keyword: &str) -> bool {
        let remaining = &self.input[self.pos..];
        if remaining.to_lowercase().starts_with(keyword) {
            let after = self.pos + keyword.len();
            if after >= self.input.len() {
                self.pos = after;
                return true;
            }
            let next_char = self.input[after..].chars().next().unwrap();
            // Keyword must be followed by a non-identifier character.
            // SCIM attribute names can contain alphanumeric, '.', and '_'.
            if !next_char.is_alphanumeric() && next_char != '_' {
                self.pos = after;
                return true;
            }
        }
        false
    }
}

/// Mapping from SCIM attribute paths to SQL column names.
#[derive(Debug, Clone)]
pub struct AttributeMapper {
    mappings: Vec<(String, String)>,
    /// Column names that are boolean type in PostgreSQL.
    boolean_columns: Vec<String>,
}

impl AttributeMapper {
    /// Create a new mapper with default user mappings.
    #[must_use]
    pub fn for_users() -> Self {
        Self {
            mappings: vec![
                ("userName".to_string(), "email".to_string()),
                ("displayName".to_string(), "display_name".to_string()),
                ("active".to_string(), "is_active".to_string()),
                ("externalId".to_string(), "external_id".to_string()),
                ("name.givenName".to_string(), "first_name".to_string()),
                ("name.familyName".to_string(), "last_name".to_string()),
                ("emails.value".to_string(), "email".to_string()),
            ],
            boolean_columns: vec!["is_active".to_string()],
        }
    }

    /// Create a new mapper with default group mappings.
    #[must_use]
    pub fn for_groups() -> Self {
        Self {
            mappings: vec![
                ("displayName".to_string(), "display_name".to_string()),
                ("externalId".to_string(), "external_id".to_string()),
            ],
            boolean_columns: vec![],
        }
    }

    /// Map a SCIM attribute to a SQL column.
    #[must_use]
    pub fn map(&self, scim_attr: &str) -> Option<&str> {
        self.mappings
            .iter()
            .find(|(s, _)| s.eq_ignore_ascii_case(scim_attr))
            .map(|(_, c)| c.as_str())
    }

    /// Check if a SQL column is a boolean type.
    #[must_use]
    pub fn is_boolean(&self, column: &str) -> bool {
        self.boolean_columns.iter().any(|c| c == column)
    }
}

/// SQL filter result with WHERE clause and parameters.
#[derive(Debug, Clone)]
pub struct SqlFilter {
    /// WHERE clause (without the "WHERE" keyword).
    pub clause: String,
    /// Parameter values in order.
    pub params: Vec<String>,
}

impl SqlFilter {
    /// Generate SQL from a filter expression.
    pub fn from_expr(
        expr: &FilterExpr,
        mapper: &AttributeMapper,
        start_param: usize,
    ) -> ScimResult<Self> {
        let mut params = Vec::new();
        let clause = Self::expr_to_sql(expr, mapper, start_param, &mut params)?;
        Ok(Self { clause, params })
    }

    fn expr_to_sql(
        expr: &FilterExpr,
        mapper: &AttributeMapper,
        start_param: usize,
        params: &mut Vec<String>,
    ) -> ScimResult<String> {
        match expr {
            FilterExpr::Compare {
                attribute,
                op,
                value,
            } => {
                let column = mapper.map(attribute).ok_or_else(|| {
                    ScimError::InvalidFilter(format!("Unknown attribute: {attribute}"))
                })?;

                let param_num = start_param + params.len();
                let is_boolean = mapper.is_boolean(column);
                let (sql, param) = op.to_sql(
                    column,
                    value.as_deref().unwrap_or(""),
                    param_num,
                    is_boolean,
                );

                if let Some(p) = param {
                    params.push(p);
                }

                Ok(sql)
            }
            FilterExpr::Logical { left, op, right } => {
                let left_sql = Self::expr_to_sql(left, mapper, start_param, params)?;
                let right_sql = Self::expr_to_sql(right, mapper, start_param, params)?;
                let op_sql = match op {
                    LogicalOp::And => "AND",
                    LogicalOp::Or => "OR",
                };
                Ok(format!("({left_sql} {op_sql} {right_sql})"))
            }
            FilterExpr::Not(inner) => {
                let inner_sql = Self::expr_to_sql(inner, mapper, start_param, params)?;
                Ok(format!("NOT ({inner_sql})"))
            }
            FilterExpr::Group(inner) => {
                let inner_sql = Self::expr_to_sql(inner, mapper, start_param, params)?;
                Ok(format!("({inner_sql})"))
            }
        }
    }
}

/// Maximum allowed filter string length (bytes).
///
/// Prevents DoS via excessively long filter strings that could consume
/// CPU in parsing and generate oversized SQL queries.
const MAX_FILTER_LEN: usize = 512;

/// Parse a SCIM filter string and convert to SQL.
pub fn parse_filter(
    filter: &str,
    mapper: &AttributeMapper,
    start_param: usize,
) -> ScimResult<SqlFilter> {
    if filter.len() > MAX_FILTER_LEN {
        return Err(ScimError::InvalidFilter(format!(
            "Filter exceeds maximum length of {MAX_FILTER_LEN} characters"
        )));
    }
    let mut parser = FilterParser::new(filter);
    let expr = parser.parse()?;
    SqlFilter::from_expr(&expr, mapper, start_param)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_eq_filter() {
        let mapper = AttributeMapper::for_users();
        let result = parse_filter(r#"userName eq "john@example.com""#, &mapper, 1).unwrap();

        // Column names are now quoted for SQL injection protection
        assert_eq!(result.clause, "\"email\" = $1");
        assert_eq!(result.params, vec!["john@example.com"]);
    }

    #[test]
    fn test_contains_filter() {
        let mapper = AttributeMapper::for_users();
        let result = parse_filter(r#"displayName co "John""#, &mapper, 1).unwrap();

        assert_eq!(result.clause, "\"display_name\" ILIKE $1");
        assert_eq!(result.params, vec!["%John%"]);
    }

    #[test]
    fn test_starts_with_filter() {
        let mapper = AttributeMapper::for_users();
        let result = parse_filter(r#"userName sw "john""#, &mapper, 1).unwrap();

        assert_eq!(result.clause, "\"email\" ILIKE $1");
        assert_eq!(result.params, vec!["john%"]);
    }

    #[test]
    fn test_ilike_wildcards_escaped() {
        let mapper = AttributeMapper::for_users();
        // A filter value containing ILIKE wildcards should be escaped
        let result = parse_filter(r#"userName co "100%_done""#, &mapper, 1).unwrap();
        assert_eq!(result.clause, "\"email\" ILIKE $1");
        assert_eq!(result.params, vec!["%100\\%\\_done%"]);
    }

    #[test]
    fn test_escaped_quotes_in_value() {
        let mapper = AttributeMapper::for_users();
        // A filter value with escaped quotes: userName eq "O\"Brien"
        let result = parse_filter(r#"userName eq "O\"Brien""#, &mapper, 1).unwrap();
        assert_eq!(result.clause, "\"email\" = $1");
        assert_eq!(result.params, vec!["O\"Brien"]);
    }

    #[test]
    fn test_max_depth_exceeded() {
        let mapper = AttributeMapper::for_users();
        // Build deeply nested parenthesized expression
        let mut filter = String::new();
        for _ in 0..25 {
            filter.push('(');
        }
        filter.push_str(r#"userName eq "test""#);
        for _ in 0..25 {
            filter.push(')');
        }
        let result = parse_filter(&filter, &mapper, 1);
        assert!(result.is_err());
        if let Err(ScimError::InvalidFilter(msg)) = result {
            assert!(msg.contains("nesting depth"));
        }
    }

    #[test]
    fn test_present_filter() {
        let mapper = AttributeMapper::for_users();
        let result = parse_filter("externalId pr", &mapper, 1).unwrap();

        assert_eq!(result.clause, "\"external_id\" IS NOT NULL");
        assert!(result.params.is_empty());
    }

    #[test]
    fn test_and_filter() {
        let mapper = AttributeMapper::for_users();
        let result = parse_filter(
            r#"userName eq "john@example.com" and active eq true"#,
            &mapper,
            1,
        )
        .unwrap();

        assert_eq!(
            result.clause,
            "(\"email\" = $1 AND \"is_active\" = $2::boolean)"
        );
        assert_eq!(result.params, vec!["john@example.com", "true"]);
    }

    #[test]
    fn test_or_filter() {
        let mapper = AttributeMapper::for_users();
        let result = parse_filter(
            r#"userName eq "john@example.com" or userName eq "jane@example.com""#,
            &mapper,
            1,
        )
        .unwrap();

        assert_eq!(result.clause, "(\"email\" = $1 OR \"email\" = $2)");
        assert_eq!(result.params, vec!["john@example.com", "jane@example.com"]);
    }

    #[test]
    fn test_not_filter() {
        let mapper = AttributeMapper::for_users();
        let result = parse_filter(r#"not (active eq false)"#, &mapper, 1).unwrap();

        assert_eq!(result.clause, "NOT (\"is_active\" = $1::boolean)");
        assert_eq!(result.params, vec!["false"]);
    }

    #[test]
    fn test_complex_filter() {
        let mapper = AttributeMapper::for_users();
        let result = parse_filter(
            r#"(userName co "john" or userName co "jane") and active eq true"#,
            &mapper,
            1,
        )
        .unwrap();

        // The grouped expression gets wrapped in extra parens - this is valid SQL
        // ILIKE values have no wildcards in "john"/"jane" so escaping is a no-op
        assert_eq!(
            result.clause,
            "(((\"email\" ILIKE $1 OR \"email\" ILIKE $2)) AND \"is_active\" = $3::boolean)"
        );
        assert_eq!(result.params, vec!["%john%", "%jane%", "true"]);
    }

    #[test]
    fn test_nested_attribute() {
        let mapper = AttributeMapper::for_users();
        let result = parse_filter(r#"name.givenName eq "John""#, &mapper, 1).unwrap();

        assert_eq!(result.clause, "\"first_name\" = $1");
        assert_eq!(result.params, vec!["John"]);
    }

    #[test]
    fn test_unknown_attribute() {
        let mapper = AttributeMapper::for_users();
        let result = parse_filter(r#"unknownAttr eq "value""#, &mapper, 1);

        assert!(result.is_err());
        if let Err(ScimError::InvalidFilter(msg)) = result {
            assert!(msg.contains("Unknown attribute"));
        }
    }

    #[test]
    fn test_invalid_operator() {
        let mapper = AttributeMapper::for_users();
        let result = parse_filter(r#"userName invalidop "value""#, &mapper, 1);

        assert!(result.is_err());
    }

    #[test]
    fn test_group_filter() {
        let mapper = AttributeMapper::for_groups();
        let result = parse_filter(r#"displayName eq "Engineering""#, &mapper, 1).unwrap();

        assert_eq!(result.clause, "\"display_name\" = $1");
        assert_eq!(result.params, vec!["Engineering"]);
    }

    #[test]
    fn test_filter_length_cap() {
        let mapper = AttributeMapper::for_users();
        // Build a filter string that exceeds MAX_FILTER_LEN (512)
        let long_filter = format!(r#"userName eq "{}""#, "x".repeat(600));
        let result = parse_filter(&long_filter, &mapper, 1);
        assert!(result.is_err());
        if let Err(ScimError::InvalidFilter(msg)) = result {
            assert!(msg.contains("maximum length"));
        }
    }

    #[test]
    fn test_keyword_boundary_with_underscore() {
        let mapper = AttributeMapper::for_users();
        // "or_field" should NOT be parsed as "or" + "_field"
        // This would fail with "Unknown attribute: _field" which confirms
        // the keyword was not consumed
        let result = parse_filter(r#"userName eq "test" or_extra eq "val""#, &mapper, 1);
        // Should get "Unexpected characters" because "or_extra" is not consumed as "or"
        assert!(result.is_err());
    }

    #[test]
    fn test_column_quoting_escapes_quotes() {
        // Verify that double quotes in column names are properly escaped
        // This is defense-in-depth since columns come from a whitelist
        let column = "test\"column";
        let escaped = format!("\"{}\"", column.replace('"', "\"\""));
        assert_eq!(escaped, "\"test\"\"column\"");
    }
}
