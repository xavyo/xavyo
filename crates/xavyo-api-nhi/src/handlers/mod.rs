//! HTTP request handlers for unified NHI API.
//!
//! Handler modules are organized by domain:
//! - `unified` — Polymorphic list/get across all NHI types
//! - `tools` — Tool-specific CRUD
//! - `agents` — Agent-specific CRUD
//! - `service_accounts` — Service account-specific CRUD
//! - `lifecycle` — Lifecycle state transitions (suspend, reactivate, deprecate, archive)
//! - `permissions` — Tool permission grants and SoD validation
//! - `risk` — Risk scoring and inactivity detection
//! - `certification` — Certification campaign management
//! - `sod` — Separation of Duties validation
//! - `inactivity` — Inactivity detection and orphan management
//! - `mcp` — MCP (Model Context Protocol) tool discovery and invocation
//! - `a2a` — A2A (Agent-to-Agent) asynchronous task management
//! - `discovery` — A2A AgentCard discovery

pub mod a2a;
pub mod activity;
pub mod agents;
pub mod certification;
pub mod discovery;
pub mod inactivity;
pub mod lifecycle;
pub mod mcp;
pub mod mcp_discovery;
pub mod nhi_delegation;
pub mod nhi_permissions;
pub mod permissions;
pub mod provision;
pub mod risk;
pub mod service_accounts;
pub mod sod;
pub mod tools;
pub mod unified;
pub mod user_permissions;
pub mod vault;
