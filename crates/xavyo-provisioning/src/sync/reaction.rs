//! Synchronization reactions - configurable actions per sync situation.
//!
//! This module implements IGA-style synchronization reactions,
//! allowing administrators to configure specific actions for each
//! synchronization situation.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::shadow::SyncSituation;

/// Actions that can be taken in response to a sync situation.
///
/// Based on IGA's synchronization actions:
/// - <https://docs.evolveum.com/IGA/reference/synchronization/reactions>/
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncAction {
    /// Create a new identity (focus) in xavyo based on external account data.
    /// Equivalent to IGA's `addFocus`.
    AddFocus,

    /// Delete the identity (focus) from xavyo.
    /// Equivalent to IGA's `deleteFocus`.
    DeleteFocus,

    /// Inactivate (disable) the identity without deleting.
    /// Equivalent to IGA's `inactivateFocus`.
    InactivateFocus,

    /// Synchronize attributes between external account and identity.
    /// Equivalent to IGA's `synchronize`.
    Synchronize,

    /// Create a link between external account (shadow) and identity.
    /// Equivalent to IGA's `link`.
    Link,

    /// Remove the link between external account and identity.
    /// Equivalent to IGA's `unlink`.
    Unlink,

    /// Do nothing - skip processing.
    None,
}

impl SyncAction {
    /// Get string representation.
    #[must_use] 
    pub fn as_str(&self) -> &'static str {
        match self {
            SyncAction::AddFocus => "add_focus",
            SyncAction::DeleteFocus => "delete_focus",
            SyncAction::InactivateFocus => "inactivate_focus",
            SyncAction::Synchronize => "synchronize",
            SyncAction::Link => "link",
            SyncAction::Unlink => "unlink",
            SyncAction::None => "none",
        }
    }

    /// Check if this action creates or modifies the identity.
    #[must_use] 
    pub fn modifies_focus(&self) -> bool {
        matches!(
            self,
            SyncAction::AddFocus
                | SyncAction::DeleteFocus
                | SyncAction::InactivateFocus
                | SyncAction::Synchronize
        )
    }

    /// Check if this action modifies links.
    #[must_use] 
    pub fn modifies_link(&self) -> bool {
        matches!(self, SyncAction::Link | SyncAction::Unlink)
    }
}

impl std::fmt::Display for SyncAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for SyncAction {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "add_focus" | "addfocus" => Ok(SyncAction::AddFocus),
            "delete_focus" | "deletefocus" => Ok(SyncAction::DeleteFocus),
            "inactivate_focus" | "inactivatefocus" => Ok(SyncAction::InactivateFocus),
            "synchronize" | "sync" => Ok(SyncAction::Synchronize),
            "link" => Ok(SyncAction::Link),
            "unlink" => Ok(SyncAction::Unlink),
            "none" | "skip" => Ok(SyncAction::None),
            _ => Err(format!("Unknown sync action: {s}")),
        }
    }
}

/// A reaction configuration for a specific sync situation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncReaction {
    /// The situation this reaction applies to.
    pub situation: SyncSituation,
    /// Actions to execute for this situation.
    pub actions: Vec<SyncAction>,
    /// Optional condition expression (for future use).
    pub condition: Option<String>,
    /// Whether this reaction is enabled.
    pub enabled: bool,
}

impl SyncReaction {
    /// Create a new reaction.
    #[must_use] 
    pub fn new(situation: SyncSituation, actions: Vec<SyncAction>) -> Self {
        Self {
            situation,
            actions,
            condition: None,
            enabled: true,
        }
    }

    /// Create a simple reaction with a single action.
    #[must_use] 
    pub fn simple(situation: SyncSituation, action: SyncAction) -> Self {
        Self::new(situation, vec![action])
    }

    /// Set condition expression.
    pub fn with_condition(mut self, condition: impl Into<String>) -> Self {
        self.condition = Some(condition.into());
        self
    }

    /// Disable this reaction.
    #[must_use] 
    pub fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }
}

/// Configuration for synchronization reactions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncReactionConfig {
    /// Tenant ID.
    pub tenant_id: Uuid,
    /// Connector ID.
    pub connector_id: Uuid,
    /// Reactions for each situation.
    pub reactions: Vec<SyncReaction>,
}

impl SyncReactionConfig {
    /// Create a new reaction config with default reactions.
    #[must_use] 
    pub fn default_for(tenant_id: Uuid, connector_id: Uuid) -> Self {
        Self {
            tenant_id,
            connector_id,
            reactions: Self::default_reactions(),
        }
    }

    /// Get the default reactions for each situation (following IGA conventions).
    #[must_use] 
    pub fn default_reactions() -> Vec<SyncReaction> {
        vec![
            // Linked: synchronize attributes
            SyncReaction::simple(SyncSituation::Linked, SyncAction::Synchronize),
            // Deleted: unlink the shadow from identity
            SyncReaction::simple(SyncSituation::Deleted, SyncAction::Unlink),
            // Unlinked: create link (correlation found a match)
            SyncReaction::new(
                SyncSituation::Unlinked,
                vec![SyncAction::Link, SyncAction::Synchronize],
            ),
            // Unmatched: create new identity (if auto_create enabled)
            SyncReaction::new(
                SyncSituation::Unmatched,
                vec![SyncAction::AddFocus, SyncAction::Link],
            ),
            // Disputed: no action (requires manual resolution)
            SyncReaction::simple(SyncSituation::Disputed, SyncAction::None),
            // Collision: no action (error state)
            SyncReaction::simple(SyncSituation::Collision, SyncAction::None),
        ]
    }

    /// Get reaction for a specific situation.
    #[must_use] 
    pub fn get_reaction(&self, situation: SyncSituation) -> Option<&SyncReaction> {
        self.reactions
            .iter()
            .find(|r| r.situation == situation && r.enabled)
    }

    /// Get actions for a specific situation.
    #[must_use] 
    pub fn get_actions(&self, situation: SyncSituation) -> Vec<SyncAction> {
        self.get_reaction(situation).map_or_else(|| vec![SyncAction::None], |r| r.actions.clone())
    }

    /// Set reaction for a situation (replaces existing).
    pub fn set_reaction(&mut self, reaction: SyncReaction) {
        // Remove existing reaction for this situation
        self.reactions.retain(|r| r.situation != reaction.situation);
        // Add new reaction
        self.reactions.push(reaction);
    }
}

impl Default for SyncReactionConfig {
    fn default() -> Self {
        Self {
            tenant_id: Uuid::nil(),
            connector_id: Uuid::nil(),
            reactions: Self::default_reactions(),
        }
    }
}

/// Result of executing a sync action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionResult {
    /// The action that was executed.
    pub action: SyncAction,
    /// Whether the action succeeded.
    pub success: bool,
    /// Error message if failed.
    pub error: Option<String>,
    /// ID of the affected identity (if applicable).
    pub affected_identity_id: Option<Uuid>,
    /// ID of the affected shadow (if applicable).
    pub affected_shadow_id: Option<Uuid>,
}

impl ActionResult {
    /// Create a successful result.
    #[must_use] 
    pub fn success(action: SyncAction) -> Self {
        Self {
            action,
            success: true,
            error: None,
            affected_identity_id: None,
            affected_shadow_id: None,
        }
    }

    /// Create a successful result with affected identity.
    #[must_use] 
    pub fn success_with_identity(action: SyncAction, identity_id: Uuid) -> Self {
        Self {
            action,
            success: true,
            error: None,
            affected_identity_id: Some(identity_id),
            affected_shadow_id: None,
        }
    }

    /// Create a failed result.
    pub fn failed(action: SyncAction, error: impl Into<String>) -> Self {
        Self {
            action,
            success: false,
            error: Some(error.into()),
            affected_identity_id: None,
            affected_shadow_id: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_action_roundtrip() {
        for action in [
            SyncAction::AddFocus,
            SyncAction::DeleteFocus,
            SyncAction::InactivateFocus,
            SyncAction::Synchronize,
            SyncAction::Link,
            SyncAction::Unlink,
            SyncAction::None,
        ] {
            let s = action.as_str();
            let parsed: SyncAction = s.parse().unwrap();
            assert_eq!(action, parsed, "Failed for action: {:?}", action);
        }
    }

    #[test]
    fn test_sync_action_modifies() {
        assert!(SyncAction::AddFocus.modifies_focus());
        assert!(SyncAction::DeleteFocus.modifies_focus());
        assert!(SyncAction::Synchronize.modifies_focus());
        assert!(!SyncAction::Link.modifies_focus());
        assert!(!SyncAction::Unlink.modifies_focus());

        assert!(SyncAction::Link.modifies_link());
        assert!(SyncAction::Unlink.modifies_link());
        assert!(!SyncAction::AddFocus.modifies_link());
    }

    #[test]
    fn test_default_reactions() {
        let config = SyncReactionConfig::default();

        // Linked -> Synchronize
        let actions = config.get_actions(SyncSituation::Linked);
        assert_eq!(actions, vec![SyncAction::Synchronize]);

        // Deleted -> Unlink
        let actions = config.get_actions(SyncSituation::Deleted);
        assert_eq!(actions, vec![SyncAction::Unlink]);

        // Unlinked -> Link + Synchronize
        let actions = config.get_actions(SyncSituation::Unlinked);
        assert_eq!(actions, vec![SyncAction::Link, SyncAction::Synchronize]);

        // Unmatched -> AddFocus + Link
        let actions = config.get_actions(SyncSituation::Unmatched);
        assert_eq!(actions, vec![SyncAction::AddFocus, SyncAction::Link]);

        // Disputed -> None
        let actions = config.get_actions(SyncSituation::Disputed);
        assert_eq!(actions, vec![SyncAction::None]);
    }

    #[test]
    fn test_custom_reaction() {
        let mut config = SyncReactionConfig::default();

        // Override unmatched to do nothing
        config.set_reaction(SyncReaction::simple(
            SyncSituation::Unmatched,
            SyncAction::None,
        ));

        let actions = config.get_actions(SyncSituation::Unmatched);
        assert_eq!(actions, vec![SyncAction::None]);
    }

    #[test]
    fn test_disabled_reaction() {
        let mut config = SyncReactionConfig::default();

        // Disable the linked reaction
        config.set_reaction(
            SyncReaction::simple(SyncSituation::Linked, SyncAction::Synchronize).disabled(),
        );

        // Should return None since reaction is disabled
        let reaction = config.get_reaction(SyncSituation::Linked);
        assert!(reaction.is_none());

        // get_actions should return None action for disabled reaction
        let actions = config.get_actions(SyncSituation::Linked);
        assert_eq!(actions, vec![SyncAction::None]);
    }

    #[test]
    fn test_action_result() {
        let success = ActionResult::success(SyncAction::Link);
        assert!(success.success);
        assert!(success.error.is_none());

        let user_id = Uuid::new_v4();
        let with_identity = ActionResult::success_with_identity(SyncAction::AddFocus, user_id);
        assert!(with_identity.success);
        assert_eq!(with_identity.affected_identity_id, Some(user_id));

        let failed = ActionResult::failed(SyncAction::Synchronize, "Connection timeout");
        assert!(!failed.success);
        assert!(failed.error.unwrap().contains("timeout"));
    }

    #[test]
    fn test_reaction_with_condition() {
        let reaction = SyncReaction::simple(SyncSituation::Unmatched, SyncAction::AddFocus)
            .with_condition("objectClass == 'employee'");

        assert!(reaction.condition.is_some());
        assert!(reaction.condition.unwrap().contains("employee"));
    }
}
