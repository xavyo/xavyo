//! xavyo CLI library
//!
//! This library exposes internal modules for integration testing.
//! The main CLI binary is still in main.rs.

// Re-export error types for testing
pub mod error;

// Re-export batch result types for testing (no internal dependencies)
#[path = "batch/result.rs"]
pub mod batch_result;

// Re-export batch types at a convenient namespace
pub mod batch {
    pub use super::batch_result::*;
}

// Re-export selected model types for testing
// We can't expose the full models module because some models have internal dependencies
#[path = "models"]
pub mod models {
    pub mod agent;
    pub mod api_session;

    // Re-export types at models level for convenience
    pub use agent::{
        DryRunRotationPreview, NhiCredentialListResponse, NhiCredentialResponse,
        PlannedRotationChanges,
    };
    pub use api_session::{ApiSession, DeviceType, Location, RevokeResponse, SessionListResponse};
}
