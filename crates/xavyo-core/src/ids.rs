//! Strongly Typed Identifiers
//!
//! This module provides type-safe identifier types for xavyo.
//! Using the newtype pattern, these types prevent accidental misuse of
//! different ID types at compile time.
//!
//! # Example
//!
//! ```
//! use xavyo_core::{TenantId, UserId};
//!
//! let tenant = TenantId::new();
//! let user = UserId::new();
//!
//! // Type safety: cannot pass UserId where TenantId is expected
//! fn requires_tenant(id: TenantId) -> String {
//!     id.to_string()
//! }
//!
//! let result = requires_tenant(tenant);
//! // requires_tenant(user); // This would not compile!
//! ```

use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use uuid::Uuid;

/// Error type for ID parsing failures
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseIdError {
    /// The type of ID that failed to parse
    pub id_type: &'static str,
    /// The underlying UUID parse error message
    pub message: String,
}

impl Display for ParseIdError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Failed to parse {}: {}", self.id_type, self.message)
    }
}

impl std::error::Error for ParseIdError {}

/// Macro to define a strongly-typed ID type
macro_rules! define_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            /// Creates a new random ID using UUID v4.
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }

            /// Creates an ID from an existing UUID.
            #[must_use]
            pub fn from_uuid(uuid: Uuid) -> Self {
                Self(uuid)
            }

            /// Returns a reference to the underlying UUID.
            #[must_use]
            pub fn as_uuid(&self) -> &Uuid {
                &self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl Display for $name {
            fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl FromStr for $name {
            type Err = ParseIdError;

            fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
                Uuid::parse_str(s)
                    .map(Self)
                    .map_err(|e| ParseIdError {
                        id_type: stringify!($name),
                        message: e.to_string(),
                    })
            }
        }
    };
}

define_id!(
    /// Strongly typed identifier for tenants.
    ///
    /// Used to identify tenants in the multi-tenant Xavyo system.
    /// Provides compile-time type safety to prevent confusion with other ID types.
    ///
    /// # Example
    ///
    /// ```
    /// use xavyo_core::TenantId;
    /// use uuid::Uuid;
    ///
    /// // Create a new random TenantId
    /// let tenant_id = TenantId::new();
    /// println!("Tenant: {}", tenant_id);
    ///
    /// // Create from existing UUID
    /// let uuid = Uuid::new_v4();
    /// let tenant_id = TenantId::from_uuid(uuid);
    /// assert_eq!(tenant_id.as_uuid(), &uuid);
    ///
    /// // Parse from string
    /// let tenant_id: TenantId = "550e8400-e29b-41d4-a716-446655440000".parse().unwrap();
    /// ```
    TenantId
);

define_id!(
    /// Strongly typed identifier for users.
    ///
    /// Used to identify users within a tenant.
    /// Provides compile-time type safety to prevent confusion with other ID types.
    ///
    /// # Example
    ///
    /// ```
    /// use xavyo_core::UserId;
    ///
    /// let user_id = UserId::new();
    /// println!("User: {}", user_id);
    /// ```
    UserId
);

define_id!(
    /// Strongly typed identifier for authentication sessions.
    ///
    /// Used to track user sessions for authentication and authorization.
    /// Provides compile-time type safety to prevent confusion with other ID types.
    ///
    /// # Example
    ///
    /// ```
    /// use xavyo_core::SessionId;
    ///
    /// let session_id = SessionId::new();
    /// println!("Session: {}", session_id);
    /// ```
    SessionId
);

#[cfg(test)]
mod tests {
    use super::*;

    // T006: TenantId creation and Display tests
    mod tenant_id_tests {
        use super::*;

        #[test]
        fn test_new_creates_valid_id() {
            let id = TenantId::new();
            let id_str = id.to_string();
            // UUID format: 8-4-4-4-12 hex digits
            assert_eq!(id_str.len(), 36);
            assert!(id_str.contains('-'));
        }

        #[test]
        fn test_from_uuid_preserves_value() {
            let uuid = Uuid::new_v4();
            let id = TenantId::from_uuid(uuid);
            assert_eq!(id.as_uuid(), &uuid);
        }

        #[test]
        fn test_display_returns_uuid_string() {
            let uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
            let id = TenantId::from_uuid(uuid);
            assert_eq!(id.to_string(), "550e8400-e29b-41d4-a716-446655440000");
        }

        #[test]
        fn test_default_creates_new_id() {
            let id1 = TenantId::default();
            let id2 = TenantId::default();
            // Default should create new random IDs
            assert_ne!(id1, id2);
        }
    }

    // T007: UserId creation and Display tests
    mod user_id_tests {
        use super::*;

        #[test]
        fn test_new_creates_valid_id() {
            let id = UserId::new();
            let id_str = id.to_string();
            assert_eq!(id_str.len(), 36);
        }

        #[test]
        fn test_from_uuid_preserves_value() {
            let uuid = Uuid::new_v4();
            let id = UserId::from_uuid(uuid);
            assert_eq!(id.as_uuid(), &uuid);
        }

        #[test]
        fn test_display_returns_uuid_string() {
            let uuid = Uuid::parse_str("123e4567-e89b-12d3-a456-426614174000").unwrap();
            let id = UserId::from_uuid(uuid);
            assert_eq!(id.to_string(), "123e4567-e89b-12d3-a456-426614174000");
        }
    }

    // T008: SessionId creation and Display tests
    mod session_id_tests {
        use super::*;

        #[test]
        fn test_new_creates_valid_id() {
            let id = SessionId::new();
            let id_str = id.to_string();
            assert_eq!(id_str.len(), 36);
        }

        #[test]
        fn test_from_uuid_preserves_value() {
            let uuid = Uuid::new_v4();
            let id = SessionId::from_uuid(uuid);
            assert_eq!(id.as_uuid(), &uuid);
        }
    }

    // T009: Serialization/deserialization round-trip tests
    mod serde_tests {
        use super::*;

        #[test]
        fn test_tenant_id_serde_roundtrip() {
            let original = TenantId::new();
            let json = serde_json::to_string(&original).unwrap();
            let deserialized: TenantId = serde_json::from_str(&json).unwrap();
            assert_eq!(original, deserialized);
        }

        #[test]
        fn test_user_id_serde_roundtrip() {
            let original = UserId::new();
            let json = serde_json::to_string(&original).unwrap();
            let deserialized: UserId = serde_json::from_str(&json).unwrap();
            assert_eq!(original, deserialized);
        }

        #[test]
        fn test_session_id_serde_roundtrip() {
            let original = SessionId::new();
            let json = serde_json::to_string(&original).unwrap();
            let deserialized: SessionId = serde_json::from_str(&json).unwrap();
            assert_eq!(original, deserialized);
        }

        #[test]
        fn test_serializes_as_plain_string() {
            let uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
            let id = TenantId::from_uuid(uuid);
            let json = serde_json::to_string(&id).unwrap();
            // Should serialize as plain quoted string, not as object
            assert_eq!(json, "\"550e8400-e29b-41d4-a716-446655440000\"");
        }
    }

    // T010: FromStr parsing tests (valid and invalid)
    mod from_str_tests {
        use super::*;

        #[test]
        fn test_parse_valid_uuid() {
            let id: TenantId = "550e8400-e29b-41d4-a716-446655440000".parse().unwrap();
            assert_eq!(id.to_string(), "550e8400-e29b-41d4-a716-446655440000");
        }

        #[test]
        fn test_parse_invalid_uuid_returns_error() {
            let result: std::result::Result<TenantId, _> = "not-a-uuid".parse();
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert_eq!(err.id_type, "TenantId");
            assert!(!err.message.is_empty());
        }

        #[test]
        fn test_parse_empty_string_returns_error() {
            let result: std::result::Result<UserId, _> = "".parse();
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert_eq!(err.id_type, "UserId");
        }

        #[test]
        fn test_error_display() {
            let result: std::result::Result<SessionId, _> = "invalid".parse();
            let err = result.unwrap_err();
            let display = err.to_string();
            assert!(display.contains("SessionId"));
            assert!(display.contains("Failed to parse"));
        }
    }

    // T011: Hash and Eq implementation tests
    mod hash_eq_tests {
        use super::*;
        use std::collections::HashMap;

        #[test]
        fn test_same_uuid_is_equal() {
            let uuid = Uuid::new_v4();
            let id1 = TenantId::from_uuid(uuid);
            let id2 = TenantId::from_uuid(uuid);
            assert_eq!(id1, id2);
        }

        #[test]
        fn test_different_uuids_are_not_equal() {
            let id1 = TenantId::new();
            let id2 = TenantId::new();
            assert_ne!(id1, id2);
        }

        #[test]
        fn test_can_use_as_hashmap_key() {
            let mut map: HashMap<TenantId, String> = HashMap::new();
            let id1 = TenantId::new();
            let id2 = TenantId::new();

            map.insert(id1, "tenant1".to_string());
            map.insert(id2, "tenant2".to_string());

            assert_eq!(map.get(&id1), Some(&"tenant1".to_string()));
            assert_eq!(map.get(&id2), Some(&"tenant2".to_string()));
        }

        #[test]
        fn test_copy_semantics() {
            let id1 = UserId::new();
            let id2 = id1; // Copy
            assert_eq!(id1, id2); // Both are still valid
        }

        #[test]
        fn test_clone_semantics() {
            let id1 = SessionId::new();
            let id2 = id1.clone();
            assert_eq!(id1, id2);
        }
    }
}
