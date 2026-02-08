//! Unified Non-Human Identity API for service accounts, AI agents, and tools.
//!
//! This crate provides REST API endpoints for unified NHI management,
//! operating on the `nhi_identities` base table with type-specific
//! extension tables (`nhi_agents`, `nhi_tools`, `nhi_service_accounts`).
//!
//! # Endpoint Groups
//!
//! ## Unified (polymorphic)
//! - `GET /nhi` — List all NHIs with type/state filtering
//! - `GET /nhi/{id}` — Get a specific NHI by ID
//!
//! ## Type-Specific CRUD
//! - `/nhi/tools/*` — Tool registry management
//! - `/nhi/agents/*` — AI agent management
//! - `/nhi/service-accounts/*` — Service account management
//!
//! ## Lifecycle
//! - `POST /nhi/{id}/{suspend,reactivate,deprecate,archive,deactivate,activate}`
//!
//! ## Credentials
//! - `/nhi/{id}/credentials/*` — Credential create, rotate, revoke
//!
//! ## Permissions
//! - `/nhi/agents/{id}/permissions/*` — Tool permission grants
//!
//! ## Risk & Certification
//! - `/nhi/{id}/risk` — Risk scoring
//! - `/nhi/certifications/*` — Certification campaigns

pub mod error;
pub mod handlers;
pub mod router;
pub mod services;
pub mod state;

// Re-export main entry points
pub use error::{ApiResult, ErrorResponse, NhiApiError};
pub use router::nhi_router;
pub use state::NhiState;
