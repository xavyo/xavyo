//! HTTP handlers for connector API operations.

pub mod connectors;
pub mod jobs;
pub mod mappings;
pub mod operations;
pub mod reconciliation;
pub mod schemas;
pub mod sync;

pub use connectors::*;
pub use jobs::*;
pub use mappings::*;
pub use operations::*;
pub use reconciliation::*;
pub use schemas::*;
pub use sync::*;

// SCIM Outbound Provisioning Client handlers (F087)
pub mod scim_log;
pub mod scim_mappings;
pub mod scim_provisioning;
pub mod scim_sync;
pub mod scim_targets;
