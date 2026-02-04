//! Risk Assessment Service for calculating and managing user risk.
//!
//! This module provides services for:
//! - Calculating composite risk scores based on entitlements and `SoD` violations
//! - Classifying risk levels using configurable thresholds
//! - Tracking risk history for trend analysis
//!
//! # Example
//!
//! ```ignore
//! use xavyo_governance::services::risk::{
//!     RiskAssessmentService, InMemoryRiskThresholdStore, InMemoryRiskHistoryStore
//! };
//! use xavyo_governance::audit::InMemoryAuditStore;
//! use std::sync::Arc;
//!
//! let service = RiskAssessmentService::new(
//!     Arc::new(InMemoryRiskThresholdStore::new()),
//!     Arc::new(InMemoryRiskHistoryStore::new()),
//!     Arc::new(InMemoryAuditStore::new()),
//! );
//! ```

mod history_store;
mod service;
mod threshold_store;

pub use history_store::{InMemoryRiskHistoryStore, RiskHistoryStore};
pub use service::RiskAssessmentService;
pub use threshold_store::{InMemoryRiskThresholdStore, RiskThresholdStore};
