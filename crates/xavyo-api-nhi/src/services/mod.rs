//! Business logic services for unified NHI operations.
//!
//! Service modules are organized by domain:
//! - `nhi_lifecycle_service` — Uniform lifecycle transitions across all NHI types
//! - `nhi_credential_service` — Unified credential management (create, rotate, revoke)
//! - `nhi_risk_service` — Risk scoring (common + type-specific factors)
//! - `nhi_permission_service` — Tool permission management with SoD validation
//! - `nhi_inactivity_service` — Inactivity detection and grace period enforcement

pub mod nhi_credential_service;
pub mod nhi_inactivity_service;
pub mod nhi_lifecycle_service;
pub mod nhi_permission_service;
pub mod nhi_risk_service;
