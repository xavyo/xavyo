//! AI Agent Security API for xavyo.
//!
//! This crate provides REST API endpoints for managing AI agents, tools,
//! and authorization decisions following OWASP ASI guidelines and A2A protocol.
//!
//! # Features
//!
//! - **Agent Management**: Register, update, suspend, and list AI agents (OWASP ASI03)
//! - **Tool Registry**: Register tools with JSON Schema validation (OWASP ASI02/ASI04)
//! - **Permission Management**: Grant and revoke tool permissions for agents
//! - **Real-Time Authorization**: Sub-100ms authorization decisions with rate limiting
//! - **AgentCard Discovery**: A2A protocol compatible agent discovery endpoint
//! - **Audit Trail**: Query authorization decisions for compliance
//!
//! # Example
//!
//! ```rust,ignore
//! use xavyo_api_agents::router::agents_router;
//! use axum::Router;
//!
//! let app = Router::new()
//!     .merge(agents_router(state));
//! ```
//!
//! # Endpoints
//!
//! ## Agent Management
//! - `POST /agents` - Register a new AI agent
//! - `GET /agents` - List agents for tenant
//! - `GET /agents/{id}` - Get agent details
//! - `PATCH /agents/{id}` - Update agent
//! - `DELETE /agents/{id}` - Delete agent
//! - `POST /agents/{id}/suspend` - Suspend agent
//! - `POST /agents/{id}/reactivate` - Reactivate suspended agent
//!
//! ## Tool Management
//! - `POST /tools` - Register a new tool
//! - `GET /tools` - List tools for tenant
//! - `GET /tools/{id}` - Get tool details
//! - `PATCH /tools/{id}` - Update tool
//! - `DELETE /tools/{id}` - Delete tool
//!
//! ## Permissions
//! - `POST /agents/{id}/permissions` - Grant tool permission to agent
//! - `GET /agents/{id}/permissions` - List agent's tool permissions
//! - `DELETE /agents/{id}/permissions/{tool_id}` - Revoke tool permission
//!
//! ## Authorization
//! - `POST /agents/authorize` - Real-time authorization decision (<100ms)
//!
//! ## Audit
//! - `GET /agents/{id}/audit` - Query agent's audit trail
//!
//! ## Discovery (A2A Protocol)
//! - `GET /.well-known/agents/{id}.json` - AgentCard discovery

pub mod error;
pub mod handlers;
pub mod middleware;
pub mod models;
pub mod providers;
pub mod router;
pub mod services;

// Re-export public API
pub use error::ApiAgentsError;
pub use router::{a2a_router, agents_router, discovery_router, mcp_router, AgentsState};
