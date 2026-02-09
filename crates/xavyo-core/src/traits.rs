//! Multi-Tenant Traits
//!
//! This module provides traits for multi-tenant entities in xavyo.
//!
//! # Example
//!
//! ```
//! use xavyo_core::{TenantId, TenantAware};
//!
//! struct User {
//!     id: uuid::Uuid,
//!     tenant_id: TenantId,
//!     email: String,
//! }
//!
//! impl TenantAware for User {
//!     fn tenant_id(&self) -> TenantId {
//!         self.tenant_id
//!     }
//! }
//!
//! // Generic function that works with any TenantAware entity
//! fn verify_tenant<T: TenantAware>(entity: &T, expected: TenantId) -> bool {
//!     entity.tenant_id() == expected
//! }
//!
//! let tenant = TenantId::new();
//! let user = User {
//!     id: uuid::Uuid::new_v4(),
//!     tenant_id: tenant,
//!     email: "user@example.com".to_string(),
//! };
//!
//! assert!(verify_tenant(&user, tenant));
//! ```

use crate::ids::TenantId;

/// Trait for entities that belong to a specific tenant.
///
/// Implementing this trait marks an entity as tenant-scoped, enabling
/// compile-time verification that tenant isolation is properly implemented.
///
/// # Object Safety
///
/// This trait is object-safe, meaning it can be used with trait objects:
/// `Box<dyn TenantAware>` or `&dyn TenantAware`.
///
/// # Example
///
/// ```
/// use xavyo_core::{TenantId, TenantAware};
///
/// struct Document {
///     tenant_id: TenantId,
///     title: String,
/// }
///
/// impl TenantAware for Document {
///     fn tenant_id(&self) -> TenantId {
///         self.tenant_id
///     }
/// }
/// ```
pub trait TenantAware {
    /// Returns the tenant ID associated with this entity.
    ///
    /// This method returns an owned `TenantId` (which is `Copy`) for convenience,
    /// allowing callers to use the value without lifetime concerns.
    fn tenant_id(&self) -> TenantId;
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test struct for TenantAware implementation
    #[allow(dead_code)]
    struct TestEntity {
        tenant_id: TenantId,
        name: String,
    }

    impl TenantAware for TestEntity {
        fn tenant_id(&self) -> TenantId {
            self.tenant_id
        }
    }

    // Another test struct to verify trait works with different types
    #[allow(dead_code)]
    struct AnotherEntity {
        id: u64,
        tenant: TenantId,
    }

    impl TenantAware for AnotherEntity {
        fn tenant_id(&self) -> TenantId {
            self.tenant
        }
    }

    // T018: TenantAware trait implementation tests
    mod tenant_aware_tests {
        use super::*;

        #[test]
        fn test_impl_returns_correct_tenant_id() {
            let tenant = TenantId::new();
            let entity = TestEntity {
                tenant_id: tenant,
                name: "Test".to_string(),
            };
            assert_eq!(entity.tenant_id(), tenant);
        }

        #[test]
        fn test_different_entities_can_have_different_tenants() {
            let tenant1 = TenantId::new();
            let tenant2 = TenantId::new();

            let entity1 = TestEntity {
                tenant_id: tenant1,
                name: "Entity 1".to_string(),
            };
            let entity2 = TestEntity {
                tenant_id: tenant2,
                name: "Entity 2".to_string(),
            };

            assert_ne!(entity1.tenant_id(), entity2.tenant_id());
        }

        #[test]
        fn test_trait_is_object_safe() {
            let tenant = TenantId::new();
            let entity = TestEntity {
                tenant_id: tenant,
                name: "Test".to_string(),
            };

            // Can use as trait object
            let dyn_entity: &dyn TenantAware = &entity;
            assert_eq!(dyn_entity.tenant_id(), tenant);
        }
    }

    // T019: Generic function with TenantAware bound tests
    mod generic_function_tests {
        use super::*;

        // Generic function that works with any TenantAware entity
        fn get_tenant_id<T: TenantAware>(entity: &T) -> TenantId {
            entity.tenant_id()
        }

        // Generic function that checks tenant isolation
        fn belongs_to_tenant<T: TenantAware>(entity: &T, tenant: TenantId) -> bool {
            entity.tenant_id() == tenant
        }

        // Generic function that works with multiple entities
        fn same_tenant<T: TenantAware, U: TenantAware>(a: &T, b: &U) -> bool {
            a.tenant_id() == b.tenant_id()
        }

        #[test]
        fn test_generic_function_extracts_tenant_id() {
            let tenant = TenantId::new();
            let entity = TestEntity {
                tenant_id: tenant,
                name: "Test".to_string(),
            };

            assert_eq!(get_tenant_id(&entity), tenant);
        }

        #[test]
        fn test_generic_function_with_different_type() {
            let tenant = TenantId::new();
            let entity = AnotherEntity { id: 42, tenant };

            assert_eq!(get_tenant_id(&entity), tenant);
        }

        #[test]
        fn test_belongs_to_tenant_returns_true() {
            let tenant = TenantId::new();
            let entity = TestEntity {
                tenant_id: tenant,
                name: "Test".to_string(),
            };

            assert!(belongs_to_tenant(&entity, tenant));
        }

        #[test]
        fn test_belongs_to_tenant_returns_false() {
            let tenant1 = TenantId::new();
            let tenant2 = TenantId::new();
            let entity = TestEntity {
                tenant_id: tenant1,
                name: "Test".to_string(),
            };

            assert!(!belongs_to_tenant(&entity, tenant2));
        }

        #[test]
        fn test_same_tenant_with_different_types() {
            let tenant = TenantId::new();
            let entity1 = TestEntity {
                tenant_id: tenant,
                name: "Test".to_string(),
            };
            let entity2 = AnotherEntity { id: 123, tenant };

            assert!(same_tenant(&entity1, &entity2));
        }

        #[test]
        fn test_different_tenants_with_different_types() {
            let tenant1 = TenantId::new();
            let tenant2 = TenantId::new();
            let entity1 = TestEntity {
                tenant_id: tenant1,
                name: "Test".to_string(),
            };
            let entity2 = AnotherEntity {
                id: 123,
                tenant: tenant2,
            };

            assert!(!same_tenant(&entity1, &entity2));
        }
    }
}
