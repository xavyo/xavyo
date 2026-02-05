//! Lexer/tokenizer for filter expressions.
//!
//! Converts input string into a stream of tokens.

use std::iter::Peekable;
use std::str::Chars;

/// A token in the expression.
#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    // Identifiers and literals
    /// An identifier (attribute name or keyword).
    Identifier(String),
    /// A string literal.
    StringLiteral(String),
    /// An integer literal.
    IntegerLiteral(i64),
    /// A floating-point literal.
    FloatLiteral(f64),

    // Keywords
    /// AND keyword.
    And,
    /// OR keyword.
    Or,
    /// NOT keyword.
    Not,
    /// LIKE keyword.
    Like,
    /// IN keyword.
    In,
    /// TRUE keyword.
    True,
    /// FALSE keyword.
    False,
    /// NULL keyword.
    Null,

    // Operators
    /// Equal (=).
    Equal,
    /// Not equal (!= or <>).
    NotEqual,
    /// Less than (<).
    LessThan,
    /// Greater than (>).
    GreaterThan,
    /// Less than or equal (<=).
    LessThanOrEqual,
    /// Greater than or equal (>=).
    GreaterThanOrEqual,

    // Delimiters
    /// Left parenthesis.
    LeftParen,
    /// Right parenthesis.
    RightParen,
    /// Comma.
    Comma,

    // End of input
    /// End of input.
    Eof,
}

impl std::fmt::Display for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Token::Identifier(s) => write!(f, "identifier '{s}'"),
            Token::StringLiteral(s) => write!(f, "string '{s}'"),
            Token::IntegerLiteral(i) => write!(f, "integer {i}"),
            Token::FloatLiteral(fl) => write!(f, "float {fl}"),
            Token::And => write!(f, "AND"),
            Token::Or => write!(f, "OR"),
            Token::Not => write!(f, "NOT"),
            Token::Like => write!(f, "LIKE"),
            Token::In => write!(f, "IN"),
            Token::True => write!(f, "TRUE"),
            Token::False => write!(f, "FALSE"),
            Token::Null => write!(f, "NULL"),
            Token::Equal => write!(f, "="),
            Token::NotEqual => write!(f, "!="),
            Token::LessThan => write!(f, "<"),
            Token::GreaterThan => write!(f, ">"),
            Token::LessThanOrEqual => write!(f, "<="),
            Token::GreaterThanOrEqual => write!(f, ">="),
            Token::LeftParen => write!(f, "("),
            Token::RightParen => write!(f, ")"),
            Token::Comma => write!(f, ","),
            Token::Eof => write!(f, "end of input"),
        }
    }
}

/// Error during lexical analysis.
#[derive(Debug, Clone, PartialEq)]
pub struct LexerError {
    /// Error message.
    pub message: String,
    /// Position in the input where the error occurred.
    pub position: usize,
}

impl std::fmt::Display for LexerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} at position {}", self.message, self.position)
    }
}

impl std::error::Error for LexerError {}

/// Lexer for tokenizing filter expressions.
pub struct Lexer<'a> {
    input: Peekable<Chars<'a>>,
    position: usize,
}

impl<'a> Lexer<'a> {
    /// Create a new lexer for the given input.
    #[must_use]
    pub fn new(input: &'a str) -> Self {
        Self {
            input: input.chars().peekable(),
            position: 0,
        }
    }

    /// Get all tokens from the input.
    pub fn tokenize(mut self) -> Result<Vec<Token>, LexerError> {
        let mut tokens = Vec::new();
        loop {
            let token = self.next_token()?;
            if token == Token::Eof {
                tokens.push(token);
                break;
            }
            tokens.push(token);
        }
        Ok(tokens)
    }

    /// Get the next token from the input.
    pub fn next_token(&mut self) -> Result<Token, LexerError> {
        self.skip_whitespace();

        let Some(&ch) = self.input.peek() else {
            return Ok(Token::Eof);
        };

        match ch {
            '(' => {
                self.advance();
                Ok(Token::LeftParen)
            }
            ')' => {
                self.advance();
                Ok(Token::RightParen)
            }
            ',' => {
                self.advance();
                Ok(Token::Comma)
            }
            '=' => {
                self.advance();
                Ok(Token::Equal)
            }
            '!' => {
                self.advance();
                if self.input.peek() == Some(&'=') {
                    self.advance();
                    Ok(Token::NotEqual)
                } else {
                    Err(LexerError {
                        message: "Expected '=' after '!'".to_string(),
                        position: self.position,
                    })
                }
            }
            '<' => {
                self.advance();
                if self.input.peek() == Some(&'=') {
                    self.advance();
                    Ok(Token::LessThanOrEqual)
                } else if self.input.peek() == Some(&'>') {
                    self.advance();
                    Ok(Token::NotEqual)
                } else {
                    Ok(Token::LessThan)
                }
            }
            '>' => {
                self.advance();
                if self.input.peek() == Some(&'=') {
                    self.advance();
                    Ok(Token::GreaterThanOrEqual)
                } else {
                    Ok(Token::GreaterThan)
                }
            }
            '\'' | '"' => self.read_string(),
            c if c.is_ascii_digit() || c == '-' => self.read_number(),
            c if c.is_ascii_alphabetic() || c == '_' => self.read_identifier(),
            _ => Err(LexerError {
                message: format!("Unexpected character '{ch}'"),
                position: self.position,
            }),
        }
    }

    fn advance(&mut self) -> Option<char> {
        self.position += 1;
        self.input.next()
    }

    fn skip_whitespace(&mut self) {
        while let Some(&ch) = self.input.peek() {
            if ch.is_whitespace() {
                self.advance();
            } else {
                break;
            }
        }
    }

    fn read_string(&mut self) -> Result<Token, LexerError> {
        let quote = self.advance().unwrap();
        let mut value = String::new();
        let start_pos = self.position;

        loop {
            match self.advance() {
                Some(ch) if ch == quote => {
                    // Check for escaped quote (double quote)
                    if self.input.peek() == Some(&quote) {
                        self.advance();
                        value.push(quote);
                    } else {
                        break;
                    }
                }
                Some('\\') => {
                    // Handle escape sequences
                    match self.advance() {
                        Some('n') => value.push('\n'),
                        Some('t') => value.push('\t'),
                        Some('r') => value.push('\r'),
                        Some('\\') => value.push('\\'),
                        Some(c) if c == quote => value.push(c),
                        Some(c) => {
                            value.push('\\');
                            value.push(c);
                        }
                        None => {
                            return Err(LexerError {
                                message: "Unterminated string literal".to_string(),
                                position: start_pos,
                            })
                        }
                    }
                }
                Some(ch) => value.push(ch),
                None => {
                    return Err(LexerError {
                        message: "Unterminated string literal".to_string(),
                        position: start_pos,
                    })
                }
            }
        }

        Ok(Token::StringLiteral(value))
    }

    fn read_number(&mut self) -> Result<Token, LexerError> {
        let start_pos = self.position;
        let mut value = String::new();

        // Handle negative sign
        if self.input.peek() == Some(&'-') {
            value.push(self.advance().unwrap());
        }

        // Read integer part
        while let Some(&ch) = self.input.peek() {
            if ch.is_ascii_digit() {
                value.push(self.advance().unwrap());
            } else {
                break;
            }
        }

        // Check for decimal point
        if self.input.peek() == Some(&'.') {
            value.push(self.advance().unwrap());

            // Read decimal part
            let mut has_decimal = false;
            while let Some(&ch) = self.input.peek() {
                if ch.is_ascii_digit() {
                    value.push(self.advance().unwrap());
                    has_decimal = true;
                } else {
                    break;
                }
            }

            if !has_decimal {
                return Err(LexerError {
                    message: "Expected digits after decimal point".to_string(),
                    position: self.position,
                });
            }

            value
                .parse::<f64>()
                .map(Token::FloatLiteral)
                .map_err(|_| LexerError {
                    message: "Invalid floating-point number".to_string(),
                    position: start_pos,
                })
        } else {
            value
                .parse::<i64>()
                .map(Token::IntegerLiteral)
                .map_err(|_| LexerError {
                    message: "Invalid integer number".to_string(),
                    position: start_pos,
                })
        }
    }

    fn read_identifier(&mut self) -> Result<Token, LexerError> {
        let mut value = String::new();

        while let Some(&ch) = self.input.peek() {
            if ch.is_ascii_alphanumeric() || ch == '_' {
                value.push(self.advance().unwrap());
            } else {
                break;
            }
        }

        // Check for keywords (case-insensitive)
        let token = match value.to_uppercase().as_str() {
            "AND" => Token::And,
            "OR" => Token::Or,
            "NOT" => Token::Not,
            "LIKE" => Token::Like,
            "IN" => Token::In,
            "TRUE" => Token::True,
            "FALSE" => Token::False,
            "NULL" => Token::Null,
            _ => Token::Identifier(value),
        };

        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_comparison() {
        let lexer = Lexer::new("department = 'engineering'");
        let tokens = lexer.tokenize().unwrap();
        assert_eq!(
            tokens,
            vec![
                Token::Identifier("department".into()),
                Token::Equal,
                Token::StringLiteral("engineering".into()),
                Token::Eof,
            ]
        );
    }

    #[test]
    fn test_and_expression() {
        let lexer = Lexer::new("a = 1 AND b = 2");
        let tokens = lexer.tokenize().unwrap();
        assert_eq!(
            tokens,
            vec![
                Token::Identifier("a".into()),
                Token::Equal,
                Token::IntegerLiteral(1),
                Token::And,
                Token::Identifier("b".into()),
                Token::Equal,
                Token::IntegerLiteral(2),
                Token::Eof,
            ]
        );
    }

    #[test]
    fn test_or_expression() {
        let lexer = Lexer::new("x > 10 OR y < 5");
        let tokens = lexer.tokenize().unwrap();
        assert_eq!(
            tokens,
            vec![
                Token::Identifier("x".into()),
                Token::GreaterThan,
                Token::IntegerLiteral(10),
                Token::Or,
                Token::Identifier("y".into()),
                Token::LessThan,
                Token::IntegerLiteral(5),
                Token::Eof,
            ]
        );
    }

    #[test]
    fn test_not_expression() {
        let lexer = Lexer::new("NOT active = true");
        let tokens = lexer.tokenize().unwrap();
        assert_eq!(
            tokens,
            vec![
                Token::Not,
                Token::Identifier("active".into()),
                Token::Equal,
                Token::True,
                Token::Eof,
            ]
        );
    }

    #[test]
    fn test_function_call() {
        let lexer = Lexer::new("has_role('admin')");
        let tokens = lexer.tokenize().unwrap();
        assert_eq!(
            tokens,
            vec![
                Token::Identifier("has_role".into()),
                Token::LeftParen,
                Token::StringLiteral("admin".into()),
                Token::RightParen,
                Token::Eof,
            ]
        );
    }

    #[test]
    fn test_in_operator() {
        let lexer = Lexer::new("status IN ('active', 'pending')");
        let tokens = lexer.tokenize().unwrap();
        assert_eq!(
            tokens,
            vec![
                Token::Identifier("status".into()),
                Token::In,
                Token::LeftParen,
                Token::StringLiteral("active".into()),
                Token::Comma,
                Token::StringLiteral("pending".into()),
                Token::RightParen,
                Token::Eof,
            ]
        );
    }

    #[test]
    fn test_like_operator() {
        let lexer = Lexer::new("email LIKE '%@example.com'");
        let tokens = lexer.tokenize().unwrap();
        assert_eq!(
            tokens,
            vec![
                Token::Identifier("email".into()),
                Token::Like,
                Token::StringLiteral("%@example.com".into()),
                Token::Eof,
            ]
        );
    }

    #[test]
    fn test_comparison_operators() {
        let lexer = Lexer::new("a = b != c < d > e <= f >= g");
        let tokens = lexer.tokenize().unwrap();
        assert_eq!(
            tokens,
            vec![
                Token::Identifier("a".into()),
                Token::Equal,
                Token::Identifier("b".into()),
                Token::NotEqual,
                Token::Identifier("c".into()),
                Token::LessThan,
                Token::Identifier("d".into()),
                Token::GreaterThan,
                Token::Identifier("e".into()),
                Token::LessThanOrEqual,
                Token::Identifier("f".into()),
                Token::GreaterThanOrEqual,
                Token::Identifier("g".into()),
                Token::Eof,
            ]
        );
    }

    #[test]
    fn test_float_literal() {
        let lexer = Lexer::new("risk_score > 3.14");
        let tokens = lexer.tokenize().unwrap();
        assert_eq!(
            tokens,
            vec![
                Token::Identifier("risk_score".into()),
                Token::GreaterThan,
                Token::FloatLiteral(3.14),
                Token::Eof,
            ]
        );
    }

    #[test]
    fn test_negative_number() {
        let lexer = Lexer::new("value > -10");
        let tokens = lexer.tokenize().unwrap();
        assert_eq!(
            tokens,
            vec![
                Token::Identifier("value".into()),
                Token::GreaterThan,
                Token::IntegerLiteral(-10),
                Token::Eof,
            ]
        );
    }

    #[test]
    fn test_parentheses() {
        let lexer = Lexer::new("(a = 1) AND (b = 2)");
        let tokens = lexer.tokenize().unwrap();
        assert_eq!(
            tokens,
            vec![
                Token::LeftParen,
                Token::Identifier("a".into()),
                Token::Equal,
                Token::IntegerLiteral(1),
                Token::RightParen,
                Token::And,
                Token::LeftParen,
                Token::Identifier("b".into()),
                Token::Equal,
                Token::IntegerLiteral(2),
                Token::RightParen,
                Token::Eof,
            ]
        );
    }

    #[test]
    fn test_case_insensitive_keywords() {
        let lexer = Lexer::new("and And AND or Or OR not Not NOT");
        let tokens = lexer.tokenize().unwrap();
        assert_eq!(
            tokens,
            vec![
                Token::And,
                Token::And,
                Token::And,
                Token::Or,
                Token::Or,
                Token::Or,
                Token::Not,
                Token::Not,
                Token::Not,
                Token::Eof,
            ]
        );
    }

    #[test]
    fn test_escaped_string() {
        let lexer = Lexer::new(r#"name = 'O\'Brien'"#);
        let tokens = lexer.tokenize().unwrap();
        assert_eq!(
            tokens,
            vec![
                Token::Identifier("name".into()),
                Token::Equal,
                Token::StringLiteral("O'Brien".into()),
                Token::Eof,
            ]
        );
    }

    #[test]
    fn test_double_quoted_string() {
        let lexer = Lexer::new(r#"name = "John Doe""#);
        let tokens = lexer.tokenize().unwrap();
        assert_eq!(
            tokens,
            vec![
                Token::Identifier("name".into()),
                Token::Equal,
                Token::StringLiteral("John Doe".into()),
                Token::Eof,
            ]
        );
    }

    #[test]
    fn test_null_keyword() {
        let lexer = Lexer::new("manager = NULL");
        let tokens = lexer.tokenize().unwrap();
        assert_eq!(
            tokens,
            vec![
                Token::Identifier("manager".into()),
                Token::Equal,
                Token::Null,
                Token::Eof,
            ]
        );
    }

    #[test]
    fn test_unterminated_string_error() {
        let lexer = Lexer::new("name = 'unterminated");
        let result = lexer.tokenize();
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("Unterminated"));
    }

    #[test]
    fn test_unexpected_character_error() {
        let lexer = Lexer::new("a @ b");
        let result = lexer.tokenize();
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("Unexpected"));
    }
}
