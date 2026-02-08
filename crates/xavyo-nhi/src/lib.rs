//! Core types and traits for Non-Human Identity (NHI) management.
//!
//! This crate provides the [`NhiEntity`] trait that unifies service accounts,
//! AI agents, and tools under a common interface for governance operations.
//!
//! # Overview
//!
//! Non-Human Identities (NHIs) include:
//! - **Service Accounts**: Traditional machine-to-machine credentials
//! - **Agents**: AI/ML models with tool access permissions
//! - **Tools**: Invocable capabilities that agents can use
//!
//! All share common governance needs: ownership, lifecycle management,
//! risk scoring, and certification campaigns.
//!
//! # Quick Start
//!
//! ```rust
//! use xavyo_nhi::{NhiEntity, NhiType, NhiLifecycleState, NhiRiskLevel};
//! use xavyo_nhi::{RiskFactors, calculate_risk_score, calculate_risk_level};
//!
//! // Calculate risk for an NHI
//! let factors = RiskFactors {
//!     staleness_days: Some(45),       // Inactive for 45 days -> 20 pts (medium)
//!     credential_age_days: Some(50),  // Credential age 50 days -> 15 pts (medium)
//!     scope_count: Some(10),          // 10 entitlements -> 0 pts (low)
//! };
//! let score = calculate_risk_score(&factors);
//! let level = calculate_risk_level(score);
//! assert_eq!(level, NhiRiskLevel::Medium); // 35 pts = Medium
//! ```
//!
//! # Feature Flags
//!
//! | Flag | Description | Dependencies Added |
//! |------|-------------|-------------------|
//! | `sqlx` | Enable `SQLx` derives for database types | sqlx |
//! | `openapi` | Enable `utoipa::ToSchema` derives for OpenAPI | utoipa |
//!
//! # Modules
//!
//! - [`traits`]: The [`NhiEntity`] trait and implementations
//! - [`types`]: Core type definitions ([`NhiType`], [`NhiLifecycleState`], [`NhiRiskLevel`])
//! - [`risk`]: Risk score calculation utilities

/// Risk score calculation and normalization utilities.
pub mod risk;

/// Core trait for Non-Human Identity abstraction.
pub mod traits;

/// Core type definitions for Non-Human Identities.
pub mod types;

pub use risk::{calculate_risk_level, calculate_risk_score, RiskFactors};
pub use traits::NhiEntity;
pub use types::{NhiLifecycleState, NhiRiskLevel, NhiType};

// Backward-compatibility re-exports

/// Old trait name. Use [`NhiEntity`] instead.
#[deprecated(note = "use NhiEntity instead")]
pub type NonHumanIdentity = dyn NhiEntity;

/// Old status enum name. Use [`NhiLifecycleState`] instead.
#[deprecated(note = "use NhiLifecycleState instead")]
pub type NhiStatus = NhiLifecycleState;
