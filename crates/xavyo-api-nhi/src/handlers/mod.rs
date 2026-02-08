//! HTTP request handlers for unified NHI API.
//!
//! Handler modules are organized by domain:
//! - `unified` — Polymorphic list/get across all NHI types
//! - `tools` — Tool-specific CRUD
//! - `agents` — Agent-specific CRUD
//! - `service_accounts` — Service account-specific CRUD
//! - `lifecycle` — Lifecycle state transitions (suspend, reactivate, deprecate, archive)
//! - `credentials` — Credential management (create, rotate, revoke)
//! - `permissions` — Tool permission grants and SoD validation
//! - `risk` — Risk scoring and inactivity detection
//! - `certification` — Certification campaign management
//! - `sod` — Separation of Duties validation
//! - `inactivity` — Inactivity detection and orphan management

pub mod agents;
pub mod certification;
pub mod credentials;
pub mod inactivity;
pub mod lifecycle;
pub mod permissions;
pub mod risk;
pub mod service_accounts;
pub mod sod;
pub mod tools;
pub mod unified;
