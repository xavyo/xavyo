//! Version history management for rollback support
//!
//! This module provides functionality to save and restore configuration versions,
//! enabling users to undo apply operations by rolling back to previous states.

mod retention;
mod store;
mod version;

pub use store::VersionHistory;
pub use version::ConfigVersion;
