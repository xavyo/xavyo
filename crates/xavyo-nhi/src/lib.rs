//! Core types and traits for Non-Human Identity (NHI) management.
//!
//! This crate provides the [`NonHumanIdentity`] trait that unifies
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
//!
//! # Quick Start
//!
//! ```rust
//! use xavyo_nhi::{NonHumanIdentity, NhiType, NhiStatus, NhiRiskLevel};
//! use xavyo_nhi::{RiskFactors, calculate_risk_score, calculate_risk_level};
//! use uuid::Uuid;
//! use chrono::{DateTime, Utc};
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
//! # Multi-Tenant Isolation
//!
//! **CRITICAL**: Every NHI has a `tenant_id()`. All queries and operations
//! MUST be scoped by tenant to prevent cross-tenant data leakage.
//!
//! The [`NonHumanIdentity::tenant_id()`] method returns the tenant UUID that
//! MUST be used to filter all database queries and enforce isolation.
//!
//! # Feature Flags
//!
//! | Flag | Description | Dependencies Added |
//! |------|-------------|-------------------|
//! | `sqlx` | Enable SQLx derives for database types | sqlx |
//!
//! # Modules
//!
//! - [`traits`]: The [`NonHumanIdentity`] trait and implementations
//! - [`types`]: Core type definitions ([`NhiType`], [`NhiStatus`], [`NhiRiskLevel`])
//! - [`risk`]: Risk score calculation utilities

/// Risk score calculation and normalization utilities.
///
/// This module provides functions for calculating unified risk scores
/// from various factors like staleness, credential age, and access scope.
///
/// # Algorithm
///
/// Risk scores range from 0-100, composed of:
/// - **Staleness** (0-40 pts): Days since last activity
/// - **Credential Age** (0-30 pts): Days since credential rotation
/// - **Access Scope** (0-30 pts): Number of entitlements
///
/// See [`calculate_risk_score`](risk::calculate_risk_score) for details.
pub mod risk;

/// Core trait for Non-Human Identity abstraction.
///
/// This module defines the [`NonHumanIdentity`] trait that provides
/// a unified interface for governance operations across different
/// NHI types (service accounts, AI agents, etc.).
pub mod traits;

/// Core type definitions for Non-Human Identities.
///
/// This module contains the fundamental types used throughout the NHI system:
/// - [`NhiType`](types::NhiType): Discriminator for NHI categories
/// - [`NhiStatus`](types::NhiStatus): Lifecycle status values
/// - [`NhiRiskLevel`](types::NhiRiskLevel): Risk level categories
pub mod types;

pub use risk::{calculate_risk_level, calculate_risk_score, RiskFactors};
pub use traits::NonHumanIdentity;
pub use types::{NhiRiskLevel, NhiStatus, NhiType};
