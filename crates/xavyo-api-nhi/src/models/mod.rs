//! Protocol model types for MCP, A2A, and Discovery endpoints.
//!
//! These models define the request/response DTOs for the protocol handlers
//! migrated from xavyo-api-agents (Feature 205).

pub mod a2a_models;
pub mod discovery_models;
pub mod mcp_models;

// Re-export for convenience
pub use a2a_models::*;
pub use discovery_models::*;
pub use mcp_models::*;
