//! Recursive descent parser for filter expressions.
//!
//! Parses tokens into an Abstract Syntax Tree (AST).

use super::ast::{Comparison, ComparisonOp, Expression, FunctionCall, Value};
use super::lexer::{Lexer, LexerError, Token};

/// Error during parsing.
#[derive(Debug, Clone, PartialEq)]
pub struct ParseError {
    /// Error message.
    pub message: String,
    /// Position in the input where the error occurred.
    pub position: usize,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} at position {}", self.message, self.position)
    }
}

impl std::error::Error for ParseError {}

impl From<LexerError> for ParseError {
    fn from(err: LexerError) -> Self {
        ParseError {
            message: err.message,
            position: err.position,
        }
    }
}

/// Parser for filter expressions.
pub struct Parser {
    tokens: Vec<Token>,
    position: usize,
}

impl Parser {
    /// Parse a filter expression string.
    pub fn parse(input: &str) -> Result<Expression, ParseError> {
        let lexer = Lexer::new(input);
        let tokens = lexer.tokenize()?;
        let mut parser = Parser {
            tokens,
            position: 0,
        };
        let expr = parser.parse_expression()?;

        // Ensure we consumed all tokens
        if !parser.is_at_end() {
            return Err(ParseError {
                message: format!(
                    "Unexpected token after expression: {}",
                    parser.current_token()
                ),
                position: parser.position,
            });
        }

        Ok(expr)
    }

    /// Validate a filter expression string without building the AST.
    pub fn validate(input: &str) -> Result<Vec<String>, ParseError> {
        let expr = Self::parse(input)?;
        Ok(expr.referenced_attributes())
    }

    fn parse_expression(&mut self) -> Result<Expression, ParseError> {
        self.parse_or()
    }

    fn parse_or(&mut self) -> Result<Expression, ParseError> {
        let mut left = self.parse_and()?;

        while self.match_token(&Token::Or) {
            let right = self.parse_and()?;
            left = Expression::Or(Box::new(left), Box::new(right));
        }

        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Expression, ParseError> {
        let mut left = self.parse_not()?;

        while self.match_token(&Token::And) {
            let right = self.parse_not()?;
            left = Expression::And(Box::new(left), Box::new(right));
        }

        Ok(left)
    }

    fn parse_not(&mut self) -> Result<Expression, ParseError> {
        if self.match_token(&Token::Not) {
            let expr = self.parse_not()?;
            return Ok(Expression::Not(Box::new(expr)));
        }

        self.parse_comparison()
    }

    fn parse_comparison(&mut self) -> Result<Expression, ParseError> {
        // Handle parenthesized expressions
        if self.match_token(&Token::LeftParen) {
            let expr = self.parse_expression()?;
            self.expect_token(&Token::RightParen)?;
            return Ok(Expression::Group(Box::new(expr)));
        }

        // Get the identifier (could be an attribute or function name)
        let identifier = self.expect_identifier()?;

        // Check if this is a function call
        if self.match_token(&Token::LeftParen) {
            return self.parse_function_call(identifier);
        }

        // Otherwise it's a comparison
        let operator = self.parse_comparison_operator()?;
        let value = self.parse_value(operator == ComparisonOp::In)?;

        Ok(Expression::Comparison(Comparison {
            attribute: identifier,
            operator,
            value,
        }))
    }

    fn parse_function_call(&mut self, name: String) -> Result<Expression, ParseError> {
        let mut arguments = Vec::new();

        if !self.check(&Token::RightParen) {
            loop {
                arguments.push(self.parse_single_value()?);
                if !self.match_token(&Token::Comma) {
                    break;
                }
            }
        }

        self.expect_token(&Token::RightParen)?;

        Ok(Expression::FunctionCall(FunctionCall { name, arguments }))
    }

    fn parse_comparison_operator(&mut self) -> Result<ComparisonOp, ParseError> {
        let token = self.advance();
        match token {
            Token::Equal => Ok(ComparisonOp::Equal),
            Token::NotEqual => Ok(ComparisonOp::NotEqual),
            Token::LessThan => Ok(ComparisonOp::LessThan),
            Token::GreaterThan => Ok(ComparisonOp::GreaterThan),
            Token::LessThanOrEqual => Ok(ComparisonOp::LessThanOrEqual),
            Token::GreaterThanOrEqual => Ok(ComparisonOp::GreaterThanOrEqual),
            Token::Like => Ok(ComparisonOp::Like),
            Token::In => Ok(ComparisonOp::In),
            _ => Err(ParseError {
                message: format!("Expected comparison operator, found {token}"),
                position: self.position,
            }),
        }
    }

    fn parse_value(&mut self, is_in_operator: bool) -> Result<Value, ParseError> {
        if is_in_operator {
            self.parse_list_value()
        } else {
            self.parse_single_value()
        }
    }

    fn parse_single_value(&mut self) -> Result<Value, ParseError> {
        let token = self.advance();
        match token {
            Token::StringLiteral(s) => Ok(Value::String(s)),
            Token::IntegerLiteral(i) => Ok(Value::Integer(i)),
            Token::FloatLiteral(f) => Ok(Value::Float(f)),
            Token::True => Ok(Value::Boolean(true)),
            Token::False => Ok(Value::Boolean(false)),
            Token::Null => Ok(Value::Null),
            Token::Identifier(s) => {
                // Check if it's a function call with no args returning a value
                // For now, treat as string for unquoted identifiers in comparisons
                // This allows things like `status = active` (though `status = 'active'` is preferred)
                Ok(Value::String(s))
            }
            _ => Err(ParseError {
                message: format!("Expected value, found {token}"),
                position: self.position,
            }),
        }
    }

    fn parse_list_value(&mut self) -> Result<Value, ParseError> {
        self.expect_token(&Token::LeftParen)?;

        let mut values = Vec::new();

        if !self.check(&Token::RightParen) {
            loop {
                values.push(self.parse_single_value()?);
                if !self.match_token(&Token::Comma) {
                    break;
                }
            }
        }

        self.expect_token(&Token::RightParen)?;

        Ok(Value::List(values))
    }

    fn expect_identifier(&mut self) -> Result<String, ParseError> {
        let token = self.advance();
        match token {
            Token::Identifier(s) => Ok(s),
            _ => Err(ParseError {
                message: format!("Expected identifier, found {token}"),
                position: self.position,
            }),
        }
    }

    fn expect_token(&mut self, expected: &Token) -> Result<(), ParseError> {
        if self.check(expected) {
            self.advance();
            Ok(())
        } else {
            Err(ParseError {
                message: format!("Expected {expected}, found {}", self.current_token()),
                position: self.position,
            })
        }
    }

    fn match_token(&mut self, token: &Token) -> bool {
        if self.check(token) {
            self.advance();
            true
        } else {
            false
        }
    }

    fn check(&self, token: &Token) -> bool {
        std::mem::discriminant(&self.current_token()) == std::mem::discriminant(token)
    }

    fn advance(&mut self) -> Token {
        if !self.is_at_end() {
            self.position += 1;
        }
        self.tokens
            .get(self.position - 1)
            .cloned()
            .unwrap_or(Token::Eof)
    }

    fn current_token(&self) -> Token {
        self.tokens
            .get(self.position)
            .cloned()
            .unwrap_or(Token::Eof)
    }

    fn is_at_end(&self) -> bool {
        matches!(self.current_token(), Token::Eof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_equality() {
        let expr = Parser::parse("department = 'engineering'").unwrap();
        assert_eq!(
            expr,
            Expression::Comparison(Comparison {
                attribute: "department".into(),
                operator: ComparisonOp::Equal,
                value: Value::String("engineering".into()),
            })
        );
    }

    #[test]
    fn test_not_equal() {
        let expr = Parser::parse("status != 'inactive'").unwrap();
        assert_eq!(
            expr,
            Expression::Comparison(Comparison {
                attribute: "status".into(),
                operator: ComparisonOp::NotEqual,
                value: Value::String("inactive".into()),
            })
        );
    }

    #[test]
    fn test_numeric_comparison() {
        let expr = Parser::parse("age > 18").unwrap();
        assert_eq!(
            expr,
            Expression::Comparison(Comparison {
                attribute: "age".into(),
                operator: ComparisonOp::GreaterThan,
                value: Value::Integer(18),
            })
        );
    }

    #[test]
    fn test_boolean_value() {
        let expr = Parser::parse("active = true").unwrap();
        assert_eq!(
            expr,
            Expression::Comparison(Comparison {
                attribute: "active".into(),
                operator: ComparisonOp::Equal,
                value: Value::Boolean(true),
            })
        );
    }

    #[test]
    fn test_and_expression() {
        let expr = Parser::parse("department = 'engineering' AND active = true").unwrap();
        match expr {
            Expression::And(left, right) => {
                assert!(matches!(*left, Expression::Comparison(_)));
                assert!(matches!(*right, Expression::Comparison(_)));
            }
            _ => panic!("Expected AND expression"),
        }
    }

    #[test]
    fn test_or_expression() {
        let expr = Parser::parse("department = 'eng' OR department = 'product'").unwrap();
        match expr {
            Expression::Or(left, right) => {
                assert!(matches!(*left, Expression::Comparison(_)));
                assert!(matches!(*right, Expression::Comparison(_)));
            }
            _ => panic!("Expected OR expression"),
        }
    }

    #[test]
    fn test_not_expression() {
        let expr = Parser::parse("NOT active = true").unwrap();
        match expr {
            Expression::Not(inner) => {
                assert!(matches!(*inner, Expression::Comparison(_)));
            }
            _ => panic!("Expected NOT expression"),
        }
    }

    #[test]
    fn test_parentheses() {
        let expr = Parser::parse("(a = 1 OR b = 2) AND c = 3").unwrap();
        match expr {
            Expression::And(left, right) => {
                assert!(matches!(*left, Expression::Group(_)));
                assert!(matches!(*right, Expression::Comparison(_)));
            }
            _ => panic!("Expected AND with grouped left side"),
        }
    }

    #[test]
    fn test_function_call_no_args() {
        let expr = Parser::parse("today()").unwrap();
        match expr {
            Expression::FunctionCall(func) => {
                assert_eq!(func.name, "today");
                assert!(func.arguments.is_empty());
            }
            _ => panic!("Expected function call"),
        }
    }

    #[test]
    fn test_function_call_with_args() {
        let expr = Parser::parse("has_role('admin')").unwrap();
        match expr {
            Expression::FunctionCall(func) => {
                assert_eq!(func.name, "has_role");
                assert_eq!(func.arguments, vec![Value::String("admin".into())]);
            }
            _ => panic!("Expected function call"),
        }
    }

    #[test]
    fn test_like_operator() {
        let expr = Parser::parse("email LIKE '%@example.com'").unwrap();
        assert_eq!(
            expr,
            Expression::Comparison(Comparison {
                attribute: "email".into(),
                operator: ComparisonOp::Like,
                value: Value::String("%@example.com".into()),
            })
        );
    }

    #[test]
    fn test_in_operator() {
        let expr = Parser::parse("status IN ('active', 'pending')").unwrap();
        assert_eq!(
            expr,
            Expression::Comparison(Comparison {
                attribute: "status".into(),
                operator: ComparisonOp::In,
                value: Value::List(vec![
                    Value::String("active".into()),
                    Value::String("pending".into()),
                ]),
            })
        );
    }

    #[test]
    fn test_complex_expression() {
        let expr = Parser::parse(
            "department = 'engineering' AND lifecycle_state = 'active' AND NOT has_role('developer')",
        )
        .unwrap();

        // Should parse as: (department = 'engineering' AND lifecycle_state = 'active') AND (NOT has_role('developer'))
        assert!(matches!(expr, Expression::And(_, _)));
    }

    #[test]
    fn test_null_value() {
        let expr = Parser::parse("manager = NULL").unwrap();
        assert_eq!(
            expr,
            Expression::Comparison(Comparison {
                attribute: "manager".into(),
                operator: ComparisonOp::Equal,
                value: Value::Null,
            })
        );
    }

    #[test]
    fn test_validate_returns_attributes() {
        let attrs = Parser::validate("department = 'eng' AND active = true").unwrap();
        assert_eq!(attrs, vec!["active", "department"]);
    }

    #[test]
    fn test_parse_error_unexpected_token() {
        let result = Parser::parse("department = ");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_error_missing_paren() {
        let result = Parser::parse("(a = 1");
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("Expected )"));
    }

    #[test]
    fn test_parse_error_invalid_operator() {
        let result = Parser::parse("a + b");
        assert!(result.is_err());
    }

    #[test]
    fn test_precedence_and_before_or() {
        // a OR b AND c should parse as a OR (b AND c)
        let expr = Parser::parse("a = 1 OR b = 2 AND c = 3").unwrap();
        match expr {
            Expression::Or(left, right) => {
                assert!(matches!(*left, Expression::Comparison(_)));
                assert!(matches!(*right, Expression::And(_, _)));
            }
            _ => panic!("Expected OR at top level"),
        }
    }

    #[test]
    fn test_float_value() {
        let expr = Parser::parse("risk_score > 3.15").unwrap();
        assert_eq!(
            expr,
            Expression::Comparison(Comparison {
                attribute: "risk_score".into(),
                operator: ComparisonOp::GreaterThan,
                value: Value::Float(3.15),
            })
        );
    }

    #[test]
    fn test_chained_and() {
        let expr = Parser::parse("a = 1 AND b = 2 AND c = 3").unwrap();
        // Should parse left-associatively: ((a = 1 AND b = 2) AND c = 3)
        match expr {
            Expression::And(left, _) => {
                assert!(matches!(*left, Expression::And(_, _)));
            }
            _ => panic!("Expected nested AND"),
        }
    }

    #[test]
    fn test_mixed_logical_with_not() {
        let expr = Parser::parse("a = 1 AND NOT b = 2 OR c = 3").unwrap();
        // Should parse as: ((a = 1 AND (NOT b = 2)) OR c = 3)
        assert!(matches!(expr, Expression::Or(_, _)));
    }
}
