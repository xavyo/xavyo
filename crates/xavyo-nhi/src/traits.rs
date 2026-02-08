//! Core trait for Non-Human Identity abstraction.
//!
//! This module defines the [`NhiEntity`] trait that provides a unified
//! interface for governance operations across different NHI types
//! (service accounts, agents, tools).

use crate::types::{NhiLifecycleState, NhiType};
use uuid::Uuid;

/// Uniform interface for all NHI types.
///
/// This trait defines the minimal set of accessors that every NHI entity
/// must provide, enabling unified governance workflows regardless of
/// the underlying NHI type.
///
/// # Implementing Types
///
/// Implementors combine base identity data with type-specific extensions:
/// - Service accounts (`NhiIdentity` + `NhiServiceAccount`)
/// - Agents (`NhiIdentity` + `NhiAgent`)
/// - Tools (`NhiIdentity` + `NhiTool`)
///
/// # Example
///
/// ```rust
/// use xavyo_nhi::{NhiEntity, NhiType, NhiLifecycleState};
/// use uuid::Uuid;
///
/// struct MyTool {
///     id: Uuid,
///     name: String,
///     lifecycle_state: NhiLifecycleState,
///     risk_score: Option<i32>,
/// }
///
/// impl NhiEntity for MyTool {
///     fn nhi_id(&self) -> Uuid { self.id }
///     fn nhi_type(&self) -> NhiType { NhiType::Tool }
///     fn name(&self) -> &str { &self.name }
///     fn lifecycle_state(&self) -> NhiLifecycleState { self.lifecycle_state }
///     fn risk_score(&self) -> Option<i32> { self.risk_score }
/// }
///
/// let tool = MyTool {
///     id: Uuid::new_v4(),
///     name: "my-tool".to_string(),
///     lifecycle_state: NhiLifecycleState::Active,
///     risk_score: Some(20),
/// };
///
/// assert!(tool.is_active());
/// assert!(!tool.is_terminal());
/// ```
pub trait NhiEntity: Send + Sync {
    /// Returns the unique identifier for this NHI.
    fn nhi_id(&self) -> Uuid;

    /// Returns the type discriminator for this NHI.
    fn nhi_type(&self) -> NhiType;

    /// Returns the display name for this NHI.
    fn name(&self) -> &str;

    /// Returns the current lifecycle state.
    fn lifecycle_state(&self) -> NhiLifecycleState;

    /// Returns the risk score (0-100), if computed.
    fn risk_score(&self) -> Option<i32>;

    /// Returns `true` if this NHI is in the `Active` lifecycle state.
    fn is_active(&self) -> bool {
        self.lifecycle_state() == NhiLifecycleState::Active
    }

    /// Returns `true` if this NHI is in a terminal lifecycle state (`Archived`).
    fn is_terminal(&self) -> bool {
        self.lifecycle_state().is_terminal()
    }
}

/// Blanket implementation for boxed trait objects.
impl NhiEntity for Box<dyn NhiEntity> {
    fn nhi_id(&self) -> Uuid {
        (**self).nhi_id()
    }

    fn nhi_type(&self) -> NhiType {
        (**self).nhi_type()
    }

    fn name(&self) -> &str {
        (**self).name()
    }

    fn lifecycle_state(&self) -> NhiLifecycleState {
        (**self).lifecycle_state()
    }

    fn risk_score(&self) -> Option<i32> {
        (**self).risk_score()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockNhiEntity {
        id: Uuid,
        nhi_type: NhiType,
        name: String,
        lifecycle_state: NhiLifecycleState,
        risk_score: Option<i32>,
    }

    impl Default for MockNhiEntity {
        fn default() -> Self {
            Self {
                id: Uuid::new_v4(),
                nhi_type: NhiType::ServiceAccount,
                name: "test-entity".to_string(),
                lifecycle_state: NhiLifecycleState::Active,
                risk_score: Some(25),
            }
        }
    }

    impl NhiEntity for MockNhiEntity {
        fn nhi_id(&self) -> Uuid {
            self.id
        }
        fn nhi_type(&self) -> NhiType {
            self.nhi_type
        }
        fn name(&self) -> &str {
            &self.name
        }
        fn lifecycle_state(&self) -> NhiLifecycleState {
            self.lifecycle_state
        }
        fn risk_score(&self) -> Option<i32> {
            self.risk_score
        }
    }

    #[test]
    fn test_is_active() {
        let active = MockNhiEntity {
            lifecycle_state: NhiLifecycleState::Active,
            ..Default::default()
        };
        assert!(active.is_active());

        let suspended = MockNhiEntity {
            lifecycle_state: NhiLifecycleState::Suspended,
            ..Default::default()
        };
        assert!(!suspended.is_active());

        let inactive = MockNhiEntity {
            lifecycle_state: NhiLifecycleState::Inactive,
            ..Default::default()
        };
        assert!(!inactive.is_active());
    }

    #[test]
    fn test_is_terminal() {
        let archived = MockNhiEntity {
            lifecycle_state: NhiLifecycleState::Archived,
            ..Default::default()
        };
        assert!(archived.is_terminal());

        let active = MockNhiEntity {
            lifecycle_state: NhiLifecycleState::Active,
            ..Default::default()
        };
        assert!(!active.is_terminal());

        let deprecated = MockNhiEntity {
            lifecycle_state: NhiLifecycleState::Deprecated,
            ..Default::default()
        };
        assert!(!deprecated.is_terminal());
    }

    #[test]
    fn test_nhi_type_returns_correct_type() {
        let sa = MockNhiEntity {
            nhi_type: NhiType::ServiceAccount,
            ..Default::default()
        };
        assert_eq!(sa.nhi_type(), NhiType::ServiceAccount);

        let agent = MockNhiEntity {
            nhi_type: NhiType::Agent,
            ..Default::default()
        };
        assert_eq!(agent.nhi_type(), NhiType::Agent);

        let tool = MockNhiEntity {
            nhi_type: NhiType::Tool,
            ..Default::default()
        };
        assert_eq!(tool.nhi_type(), NhiType::Tool);
    }

    #[test]
    fn test_risk_score() {
        let with_score = MockNhiEntity {
            risk_score: Some(75),
            ..Default::default()
        };
        assert_eq!(with_score.risk_score(), Some(75));

        let no_score = MockNhiEntity {
            risk_score: None,
            ..Default::default()
        };
        assert_eq!(no_score.risk_score(), None);
    }

    #[test]
    fn test_boxed_trait_object() {
        let entity = MockNhiEntity::default();
        let expected_id = entity.id;
        let boxed: Box<dyn NhiEntity> = Box::new(entity);

        assert_eq!(boxed.nhi_id(), expected_id);
        assert_eq!(boxed.nhi_type(), NhiType::ServiceAccount);
        assert_eq!(boxed.name(), "test-entity");
        assert_eq!(boxed.lifecycle_state(), NhiLifecycleState::Active);
        assert_eq!(boxed.risk_score(), Some(25));
        assert!(boxed.is_active());
        assert!(!boxed.is_terminal());
    }

    #[test]
    fn test_all_lifecycle_states_for_is_active() {
        let states = [
            (NhiLifecycleState::Active, true),
            (NhiLifecycleState::Inactive, false),
            (NhiLifecycleState::Suspended, false),
            (NhiLifecycleState::Deprecated, false),
            (NhiLifecycleState::Archived, false),
        ];
        for (state, expected) in &states {
            let entity = MockNhiEntity {
                lifecycle_state: *state,
                ..Default::default()
            };
            assert_eq!(
                entity.is_active(),
                *expected,
                "is_active() wrong for {state:?}"
            );
        }
    }

    #[test]
    fn test_all_lifecycle_states_for_is_terminal() {
        let states = [
            (NhiLifecycleState::Active, false),
            (NhiLifecycleState::Inactive, false),
            (NhiLifecycleState::Suspended, false),
            (NhiLifecycleState::Deprecated, false),
            (NhiLifecycleState::Archived, true),
        ];
        for (state, expected) in &states {
            let entity = MockNhiEntity {
                lifecycle_state: *state,
                ..Default::default()
            };
            assert_eq!(
                entity.is_terminal(),
                *expected,
                "is_terminal() wrong for {state:?}"
            );
        }
    }
}
