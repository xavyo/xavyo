//! Business logic services for unified NHI operations.
//!
//! Service modules are organized by domain:
//! - `nhi_lifecycle_service` — Uniform lifecycle transitions across all NHI types
//! - `nhi_risk_service` — Risk scoring (common + type-specific factors)
//! - `nhi_permission_service` — Tool permission management with SoD validation
//! - `nhi_inactivity_service` — Inactivity detection and grace period enforcement
//! - `mcp_service` — MCP tool discovery and invocation (Feature 205)
//! - `a2a_service` — A2A task management (Feature 205)

pub mod a2a_service;
pub mod mcp_discovery_service;
pub mod mcp_service;
pub mod nhi_inactivity_service;
pub mod nhi_lifecycle_service;
pub mod nhi_nhi_permission_service;
pub mod nhi_permission_service;
pub mod nhi_risk_service;
pub mod nhi_user_permission_service;
pub mod token_vault_service;
pub mod vault_crypto;
pub mod vault_service;
