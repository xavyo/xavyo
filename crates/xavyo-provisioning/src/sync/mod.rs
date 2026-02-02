//! Live Synchronization Module
//!
//! Provides real-time change detection and processing from external systems.
//!
//! This module implements bidirectional synchronization, allowing xavyo
//! to detect changes made directly in connected systems and propagate them
//! to the central identity repository.
//!
//! ## Key Components
//!
//! - [`ChangeListener`] - Trait for detecting changes from external systems
//! - [`SyncPipeline`] - Processes inbound changes through the sync workflow
//! - [`SyncToken`] - Tracks synchronization progress for resumable sync
//! - [`InboundMapper`] - Transforms external attributes to internal format
//! - [`ConflictDetector`] - Detects conflicts with pending outbound operations
//!
//! ## Synchronization Flow
//!
//! ```text
//! ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
//! │ Change Listener │────►│  Sync Pipeline  │────►│ Shadow Update   │
//! │ (LDAP/AD/DB)    │     │                 │     │                 │
//! └─────────────────┘     └────────┬────────┘     └─────────────────┘
//!                                  │
//!         ┌────────────────────────┼────────────────────────┐
//!         ▼                        ▼                        ▼
//! ┌───────────────┐      ┌─────────────────┐      ┌─────────────────┐
//! │  Correlation  │      │ Inbound Mapper  │      │    Conflict     │
//! │    Engine     │      │                 │      │    Detector     │
//! └───────────────┘      └─────────────────┘      └─────────────────┘
//! ```
//!
//! ## Sync Situations
//!
//! The sync engine determines the "situation" for each detected change:
//!
//! - **Linked**: Account is already connected to an identity
//! - **Unlinked**: Account exists but no link to identity (needs correlation)
//! - **Unmatched**: No correlation match found (may create new identity)
//! - **Disputed**: Multiple correlation matches (needs manual resolution)
//! - **Deleted**: Account was deleted in external system
//! - **Collision**: Account linked to multiple identities (error)
//!
//! ## Example
//!
//! ```ignore
//! use xavyo_provisioning::sync::{
//!     SyncPipeline, PollingChangeListener, SyncConfiguration,
//! };
//!
//! // Configure sync for a connector
//! let config = SyncConfiguration::new(
//!     connector_id,
//!     SyncMode::Polling,
//!     Duration::from_secs(60),
//! );
//!
//! // Create pipeline
//! let pipeline = SyncPipeline::new(pool, config)?;
//!
//! // Process changes
//! let results = pipeline.process_batch(100).await?;
//! println!("Processed {} changes", results.len());
//! ```

pub mod change;
pub mod config;
pub mod conflict;
pub mod correlator;
pub mod error;
pub mod listener;
pub mod mapper;
pub mod pipeline;
pub mod rate_limiter;
pub mod reaction;
pub mod status;
pub mod token;
pub mod types;

// Re-exports for convenience
pub use change::{
    InboundChange, InboundChangeBuilder, InboundCorrelationCandidate, InboundCorrelationResult,
};
pub use config::ConflictResolution;
pub use config::{SyncConfig, SyncMode};
pub use conflict::{SyncConflict, SyncConflictDetector};
pub use correlator::{
    DatabaseInboundCorrelator, InboundCorrelationConfig, InboundCorrelationRule, InboundCorrelator,
    InboundMatchType,
};
pub use error::{SyncError, SyncResult};
pub use listener::{ChangeListener, PollingChangeListener};
pub use mapper::{InboundMapper, MappingDirection};
pub use pipeline::{BatchSummary, ProcessedChange, SyncPipeline, SyncPipelineBuilder};
pub use rate_limiter::{RateLimiter, TokenBucket};
pub use reaction::{ActionResult, SyncAction, SyncReaction, SyncReactionConfig};
pub use status::{SyncStatus, SyncStatusManager};
pub use token::{SyncToken, SyncTokenManager, TokenType};
pub use types::{ChangeType, ProcessingStatus, ResolutionStrategy};

// Re-export SyncSituation from shadow module for convenience
pub use crate::shadow::SyncSituation;
