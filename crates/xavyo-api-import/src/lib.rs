//! Bulk User Import & Invitation Flows (F086).
//!
//! This crate provides REST API endpoints for:
//! - CSV bulk user import with async background processing
//! - Import job tracking and per-row error reporting
//! - Email invitation flow with secure token-based password setup
//! - Self-registration via invitation link
//!
//! # Example
//!
//! ```rust,ignore
//! use xavyo_api_import::{import_router, ImportState};
//! use axum::Router;
//!
//! let state = ImportState::new(pool, email_sender);
//! let app = Router::new().merge(import_router(state));
//! ```

pub mod error;
pub mod handlers;
pub mod models;
pub mod router;
pub mod services;
pub mod validation;

// Re-export public API
pub use error::ImportError;
pub use router::{import_router, ImportState};
