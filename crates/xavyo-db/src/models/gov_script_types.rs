//! Provisioning Scripts type definitions (F066).
//!
//! Defines enums, newtypes, and shared types for provisioning scripts.

use serde::{Deserialize, Serialize};
use sqlx::Type;
use uuid::Uuid;

// ============================================================================
// NEWTYPE IDS
// ============================================================================

/// Unique identifier for a provisioning script.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[sqlx(transparent)]
pub struct ProvisioningScriptId(pub Uuid);

impl ProvisioningScriptId {
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    #[must_use]
    pub fn inner(&self) -> Uuid {
        self.0
    }
}

impl Default for ProvisioningScriptId {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Uuid> for ProvisioningScriptId {
    fn from(id: Uuid) -> Self {
        Self(id)
    }
}

impl From<ProvisioningScriptId> for Uuid {
    fn from(id: ProvisioningScriptId) -> Self {
        id.0
    }
}

/// Unique identifier for a script version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[sqlx(transparent)]
pub struct ScriptVersionId(pub Uuid);

impl ScriptVersionId {
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    #[must_use]
    pub fn inner(&self) -> Uuid {
        self.0
    }
}

impl Default for ScriptVersionId {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Uuid> for ScriptVersionId {
    fn from(id: Uuid) -> Self {
        Self(id)
    }
}

impl From<ScriptVersionId> for Uuid {
    fn from(id: ScriptVersionId) -> Self {
        id.0
    }
}

/// Unique identifier for a script hook binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[sqlx(transparent)]
pub struct ScriptHookBindingId(pub Uuid);

impl ScriptHookBindingId {
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    #[must_use]
    pub fn inner(&self) -> Uuid {
        self.0
    }
}

impl Default for ScriptHookBindingId {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Uuid> for ScriptHookBindingId {
    fn from(id: Uuid) -> Self {
        Self(id)
    }
}

impl From<ScriptHookBindingId> for Uuid {
    fn from(id: ScriptHookBindingId) -> Self {
        id.0
    }
}

/// Unique identifier for a script execution log entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[sqlx(transparent)]
pub struct ScriptExecutionLogId(pub Uuid);

impl ScriptExecutionLogId {
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    #[must_use]
    pub fn inner(&self) -> Uuid {
        self.0
    }
}

impl Default for ScriptExecutionLogId {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Uuid> for ScriptExecutionLogId {
    fn from(id: Uuid) -> Self {
        Self(id)
    }
}

impl From<ScriptExecutionLogId> for Uuid {
    fn from(id: ScriptExecutionLogId) -> Self {
        id.0
    }
}

/// Unique identifier for a script template.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[sqlx(transparent)]
pub struct ScriptTemplateId(pub Uuid);

impl ScriptTemplateId {
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    #[must_use]
    pub fn inner(&self) -> Uuid {
        self.0
    }
}

impl Default for ScriptTemplateId {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Uuid> for ScriptTemplateId {
    fn from(id: Uuid) -> Self {
        Self(id)
    }
}

impl From<ScriptTemplateId> for Uuid {
    fn from(id: ScriptTemplateId) -> Self {
        id.0
    }
}

/// Unique identifier for a script audit event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[sqlx(transparent)]
pub struct ScriptAuditEventId(pub Uuid);

impl ScriptAuditEventId {
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    #[must_use]
    pub fn inner(&self) -> Uuid {
        self.0
    }
}

impl Default for ScriptAuditEventId {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Uuid> for ScriptAuditEventId {
    fn from(id: Uuid) -> Self {
        Self(id)
    }
}

impl From<ScriptAuditEventId> for Uuid {
    fn from(id: ScriptAuditEventId) -> Self {
        id.0
    }
}

// ============================================================================
// ENUMS
// ============================================================================

/// Script lifecycle status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type)]
#[sqlx(type_name = "gov_script_status", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum GovScriptStatus {
    /// Script is being authored, not yet ready for production.
    Draft,
    /// Script is live and executes during provisioning.
    Active,
    /// Script is disabled, preserved for history/rollback.
    Inactive,
}

/// When the script hook should execute relative to the provisioning operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type)]
#[sqlx(type_name = "gov_hook_phase", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum GovHookPhase {
    /// Execute before the provisioning operation.
    Before,
    /// Execute after the provisioning operation completes.
    After,
}

/// The provisioning operation type that triggers script execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type)]
#[sqlx(type_name = "gov_script_operation_type", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum ScriptOperationType {
    /// User/account creation.
    Create,
    /// Attribute modification.
    Update,
    /// Account deletion.
    Delete,
    /// Account activation.
    Enable,
    /// Account deactivation.
    Disable,
}

/// What to do when a script fails during execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type)]
#[sqlx(type_name = "gov_failure_policy", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum FailurePolicy {
    /// Halt the provisioning operation and report error.
    Abort,
    /// Log the error and proceed without script modifications.
    Continue,
    /// Re-attempt script execution up to `max_retries` times.
    Retry,
}

/// Outcome of a script execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type)]
#[sqlx(type_name = "gov_execution_status", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStatus {
    /// Script executed successfully.
    Success,
    /// Script encountered a runtime error.
    Failure,
    /// Script exceeded the configured timeout.
    Timeout,
    /// Script was skipped (e.g., binding disabled).
    Skipped,
}

/// Category for script templates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type)]
#[sqlx(type_name = "gov_template_category", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum TemplateCategory {
    /// Transform or map attributes between systems.
    AttributeMapping,
    /// Generate values (usernames, IDs, passwords).
    ValueGeneration,
    /// Apply logic based on user attributes or context.
    ConditionalLogic,
    /// Format data (dates, phone numbers, addresses).
    DataFormatting,
    /// Tenant-defined custom category.
    Custom,
}

/// Type of audit action on a provisioning script.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type)]
#[sqlx(type_name = "gov_script_audit_action", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum ScriptAuditAction {
    /// Script was created.
    Created,
    /// Script metadata was updated.
    Updated,
    /// Script was deleted.
    Deleted,
    /// Script status changed to active.
    Activated,
    /// Script status changed to inactive.
    Deactivated,
    /// Script was rolled back to a previous version.
    Rollback,
    /// Script was bound to a connector.
    Bound,
    /// Script was unbound from a connector.
    Unbound,
    /// A new script version was created.
    VersionCreated,
}

// ============================================================================
// CONSTANTS
// ============================================================================

/// Maximum script body size in bytes (64KB).
pub const MAX_SCRIPT_BODY_SIZE: usize = 65536;

/// Default script execution timeout in seconds.
pub const DEFAULT_TIMEOUT_SECONDS: i32 = 30;

/// Maximum script execution timeout in seconds (5 minutes).
pub const MAX_TIMEOUT_SECONDS: i32 = 300;

/// Maximum retries for retry failure policy.
pub const MAX_RETRIES: i32 = 10;

/// Maximum bindings per connector per `hook_phase` per `operation_type`.
pub const MAX_BINDINGS_PER_HOOK: i32 = 10;

/// Default max retries.
pub const DEFAULT_MAX_RETRIES: i32 = 3;
