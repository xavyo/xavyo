//! Abstract Syntax Tree (AST) types for filter expressions.
//!
//! Defines the data structures representing parsed filter expressions.

use serde::{Deserialize, Serialize};

/// A complete filter expression.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Expression {
    /// A comparison between an attribute and a value.
    Comparison(Comparison),
    /// Logical AND of two expressions.
    And(Box<Expression>, Box<Expression>),
    /// Logical OR of two expressions.
    Or(Box<Expression>, Box<Expression>),
    /// Logical NOT of an expression.
    Not(Box<Expression>),
    /// A function call (e.g., has_role('admin')).
    FunctionCall(FunctionCall),
    /// A grouped expression (parentheses).
    Group(Box<Expression>),
}

/// A comparison between an attribute and a value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Comparison {
    /// The attribute name (left-hand side).
    pub attribute: String,
    /// The comparison operator.
    pub operator: ComparisonOp,
    /// The value to compare against (right-hand side).
    pub value: Value,
}

/// Comparison operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComparisonOp {
    /// Equal (=).
    Equal,
    /// Not equal (!=).
    NotEqual,
    /// Less than (<).
    LessThan,
    /// Greater than (>).
    GreaterThan,
    /// Less than or equal (<=).
    LessThanOrEqual,
    /// Greater than or equal (>=).
    GreaterThanOrEqual,
    /// Pattern match (LIKE).
    Like,
    /// In list (IN).
    In,
}

impl std::fmt::Display for ComparisonOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ComparisonOp::Equal => write!(f, "="),
            ComparisonOp::NotEqual => write!(f, "!="),
            ComparisonOp::LessThan => write!(f, "<"),
            ComparisonOp::GreaterThan => write!(f, ">"),
            ComparisonOp::LessThanOrEqual => write!(f, "<="),
            ComparisonOp::GreaterThanOrEqual => write!(f, ">="),
            ComparisonOp::Like => write!(f, "LIKE"),
            ComparisonOp::In => write!(f, "IN"),
        }
    }
}

/// A value in an expression.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Value {
    /// A string value.
    String(String),
    /// An integer value.
    Integer(i64),
    /// A floating-point value.
    Float(f64),
    /// A boolean value.
    Boolean(bool),
    /// A null value.
    Null,
    /// A list of values (for IN operator).
    List(Vec<Value>),
}

impl std::fmt::Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Value::String(s) => write!(f, "'{s}'"),
            Value::Integer(i) => write!(f, "{i}"),
            Value::Float(fl) => write!(f, "{fl}"),
            Value::Boolean(b) => write!(f, "{b}"),
            Value::Null => write!(f, "NULL"),
            Value::List(items) => {
                write!(f, "(")?;
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{item}")?;
                }
                write!(f, ")")
            }
        }
    }
}

/// A function call in an expression.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FunctionCall {
    /// The function name.
    pub name: String,
    /// The function arguments.
    pub arguments: Vec<Value>,
}

impl FunctionCall {
    /// Create a new function call.
    #[must_use]
    pub fn new(name: impl Into<String>, arguments: Vec<Value>) -> Self {
        Self {
            name: name.into(),
            arguments,
        }
    }
}

impl Expression {
    /// Create a new comparison expression.
    #[must_use]
    pub fn comparison(attribute: impl Into<String>, operator: ComparisonOp, value: Value) -> Self {
        Expression::Comparison(Comparison {
            attribute: attribute.into(),
            operator,
            value,
        })
    }

    /// Create a new AND expression.
    #[must_use]
    pub fn and(left: Expression, right: Expression) -> Self {
        Expression::And(Box::new(left), Box::new(right))
    }

    /// Create a new OR expression.
    #[must_use]
    pub fn or(left: Expression, right: Expression) -> Self {
        Expression::Or(Box::new(left), Box::new(right))
    }

    /// Create a new NOT expression.
    #[must_use]
    pub fn not(expr: Expression) -> Self {
        Expression::Not(Box::new(expr))
    }

    /// Create a new function call expression.
    #[must_use]
    pub fn function(name: impl Into<String>, arguments: Vec<Value>) -> Self {
        Expression::FunctionCall(FunctionCall::new(name, arguments))
    }

    /// Extract all attribute names referenced in the expression.
    #[must_use]
    pub fn referenced_attributes(&self) -> Vec<String> {
        let mut attrs = Vec::new();
        self.collect_attributes(&mut attrs);
        attrs.sort();
        attrs.dedup();
        attrs
    }

    fn collect_attributes(&self, attrs: &mut Vec<String>) {
        match self {
            Expression::Comparison(comp) => {
                attrs.push(comp.attribute.clone());
            }
            Expression::And(left, right) | Expression::Or(left, right) => {
                left.collect_attributes(attrs);
                right.collect_attributes(attrs);
            }
            Expression::Not(expr) | Expression::Group(expr) => {
                expr.collect_attributes(attrs);
            }
            Expression::FunctionCall(_) => {
                // Function calls don't reference attributes directly
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_comparison_display() {
        assert_eq!(ComparisonOp::Equal.to_string(), "=");
        assert_eq!(ComparisonOp::NotEqual.to_string(), "!=");
        assert_eq!(ComparisonOp::LessThan.to_string(), "<");
        assert_eq!(ComparisonOp::GreaterThan.to_string(), ">");
        assert_eq!(ComparisonOp::LessThanOrEqual.to_string(), "<=");
        assert_eq!(ComparisonOp::GreaterThanOrEqual.to_string(), ">=");
        assert_eq!(ComparisonOp::Like.to_string(), "LIKE");
        assert_eq!(ComparisonOp::In.to_string(), "IN");
    }

    #[test]
    fn test_value_display() {
        assert_eq!(Value::String("test".into()).to_string(), "'test'");
        assert_eq!(Value::Integer(42).to_string(), "42");
        assert_eq!(Value::Float(3.14).to_string(), "3.14");
        assert_eq!(Value::Boolean(true).to_string(), "true");
        assert_eq!(Value::Null.to_string(), "NULL");
        assert_eq!(
            Value::List(vec![Value::String("a".into()), Value::String("b".into())]).to_string(),
            "('a', 'b')"
        );
    }

    #[test]
    fn test_referenced_attributes() {
        let expr = Expression::and(
            Expression::comparison(
                "department",
                ComparisonOp::Equal,
                Value::String("eng".into()),
            ),
            Expression::comparison("active", ComparisonOp::Equal, Value::Boolean(true)),
        );

        let attrs = expr.referenced_attributes();
        assert_eq!(attrs, vec!["active", "department"]);
    }

    #[test]
    fn test_nested_expression_attributes() {
        let expr = Expression::or(
            Expression::and(
                Expression::comparison("a", ComparisonOp::Equal, Value::Integer(1)),
                Expression::comparison("b", ComparisonOp::Equal, Value::Integer(2)),
            ),
            Expression::not(Expression::comparison(
                "c",
                ComparisonOp::Equal,
                Value::Integer(3),
            )),
        );

        let attrs = expr.referenced_attributes();
        assert_eq!(attrs, vec!["a", "b", "c"]);
    }
}
