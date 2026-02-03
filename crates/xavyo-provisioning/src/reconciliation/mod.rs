//! # Reconciliation Engine
//!
//! Heavy-weight reliable comparison between xavyo and connected target systems.
//!
//! ## Overview
//!
//! The reconciliation engine provides:
//! - Full reconciliation mode comparing all accounts in target system with all identities
//! - Delta reconciliation mode processing only changes since last reconciliation
//! - Discrepancy detection (missing, orphan, mismatch, collision, unlinked, deleted)
//! - Remediation actions (create, update, delete, link, unlink, inactivate_identity)
//! - Scheduling with configurable intervals
//! - Dry-run mode for previewing changes
//! - Detailed reports with statistics
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                      ReconciliationEngine                           │
//! ├─────────────────────────────────────────────────────────────────────┤
//! │                                                                     │
//! │  ┌───────────────┐    ┌───────────────┐    ┌───────────────┐      │
//! │  │   Comparator  │───►│  Discrepancy  │───►│  Remediation  │      │
//! │  │               │    │   Detector    │    │   Executor    │      │
//! │  └───────────────┘    └───────────────┘    └───────────────┘      │
//! │          │                    │                    │               │
//! │          │                    │                    │               │
//! │          ▼                    ▼                    ▼               │
//! │  ┌───────────────┐    ┌───────────────┐    ┌───────────────┐      │
//! │  │   Checkpoint  │    │   Statistics  │    │  Audit Log    │      │
//! │  │   Manager     │    │   Tracker     │    │  (Actions)    │      │
//! │  └───────────────┘    └───────────────┘    └───────────────┘      │
//! │                                                                     │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Usage
//!
//! ```ignore
//! use xavyo_provisioning::reconciliation::{ReconciliationEngine, ReconciliationConfig};
//!
//! let engine = ReconciliationEngine::new(pool, connector_provider);
//!
//! // Trigger full reconciliation
//! let run = engine.start_reconciliation(
//!     tenant_id,
//!     connector_id,
//!     ReconciliationMode::Full,
//!     Some(user_id),
//! ).await?;
//!
//! // Monitor progress
//! let status = engine.get_run_status(tenant_id, run.id).await?;
//!
//! // Review discrepancies
//! let discrepancies = engine.list_discrepancies(tenant_id, run.id, filter).await?;
//!
//! // Execute remediation
//! let result = engine.remediate(tenant_id, discrepancy_id, action, user_id).await?;
//! ```

pub mod checkpoint;
pub mod comparator;
pub mod discrepancy;
pub mod engine;
pub mod remediation;
pub mod report;
pub mod scheduler;
pub mod statistics;
pub mod transaction;
pub mod types;

// Re-export main types
pub use checkpoint::{Checkpoint, CheckpointManager, CheckpointPhase};
pub use comparator::{AccountComparator, ComparisonResult};
pub use discrepancy::{DiscrepancyDetector, DiscrepancyInfo};
pub use engine::{
    ReconciliationConfig, ReconciliationEngine, ReconciliationError, ReconciliationResult,
};
pub use remediation::{RemediationExecutor, RemediationResult as RemediationOutcome};
pub use report::{ReconciliationReport, ReportGenerator};
pub use scheduler::{ReconciliationScheduler, ScheduleConfig};
pub use statistics::{RunStatistics, StatisticsTracker};
pub use transaction::{CompletedStep, RemediationTransaction, RollbackError, TransactionStatus};
pub use types::{
    ActionType, DiscrepancyType, ReconciliationMode, RemediationDirection, ResolutionStatus,
    RunStatus,
};
