//! xavyo Core Library
//!
//! Shared types and traits for xavyo.
//!
//! # Modules
//!
//! - [`ids`] - Strongly typed identifiers (TenantId, UserId, SessionId)
//! - [`traits`] - Multi-tenant traits (TenantAware)
//! - [`error`] - Standardized error types (XavyoError)
//!
//! # Example
//!
//! ```
//! use xavyo_core::{TenantId, UserId, TenantAware, XavyoError, Result};
//!
//! // Create strongly typed IDs
//! let tenant_id = TenantId::new();
//! let user_id = UserId::new();
//!
//! // Use Result type alias
//! fn example() -> Result<()> {
//!     Err(XavyoError::Unauthorized { message: None })
//! }
//! ```

pub mod error;
pub mod ids;
pub mod traits;

// Re-export main types for convenient access
pub use error::{Result, XavyoError};
pub use ids::{SessionId, TenantId, UserId};
pub use traits::TenantAware;

/// Returns a greeting message (legacy - to be removed)
pub fn hello() -> String {
    "Hello from Xavyo Core!".to_string()
}

/// Adds two numbers (legacy - to be removed)
pub fn add(a: i32, b: i32) -> i32 {
    a + b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hello() {
        let result = hello();
        assert_eq!(result, "Hello from Xavyo Core!");
    }

    #[test]
    fn test_add() {
        assert_eq!(add(2, 3), 5);
        assert_eq!(add(-1, 1), 0);
        assert_eq!(add(0, 0), 0);
    }
}
