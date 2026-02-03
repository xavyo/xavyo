//! Input validation module for the User Management API.
//!
//! Provides comprehensive validation for:
//! - Email addresses (RFC 5322 format)
//! - Usernames (alphanumeric + underscore + hyphen, 3-64 chars)
//! - Pagination parameters (bounds checking)
//!
//! All validators return `ValidationError` for consistent error handling.

mod email;
mod error;
mod pagination;
mod username;

pub use email::validate_email;
pub use error::{ValidationError, ValidationResult};
pub use pagination::validate_pagination;
pub use username::validate_username;
