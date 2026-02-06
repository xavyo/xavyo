//! Interactive mode module for CLI commands.
//!
//! Provides shared utilities for interactive prompts and guided workflows.

pub mod prompts;
pub mod scopes;

pub use prompts::*;
// Note: scopes are imported explicitly via crate::interactive::scopes where needed
