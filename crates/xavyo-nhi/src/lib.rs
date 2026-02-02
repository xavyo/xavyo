//! Core types and traits for Non-Human Identity (NHI) management.
//!
//! This crate provides the `NonHumanIdentity` trait that unifies
//! service accounts and AI agents under a common interface for governance operations.
//!
//! # Overview
//!
//! Non-Human Identities (NHIs) include:
//! - **Service Accounts**: Traditional machine-to-machine credentials
//! - **AI Agents**: AI/ML models with tool access permissions
//!
//! Both share common governance needs: ownership, lifecycle management,
//! risk scoring, and certification campaigns.

pub mod risk;
pub mod traits;
pub mod types;

pub use risk::{calculate_risk_level, RiskFactors};
pub use traits::NonHumanIdentity;
pub use types::{NhiRiskLevel, NhiStatus, NhiType};
