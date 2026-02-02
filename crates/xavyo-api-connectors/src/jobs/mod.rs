//! Background jobs for connector API operations.
//!
//! This module contains scheduled background tasks for maintenance operations.

pub mod schema_cleanup;
pub mod schema_scheduler;

pub use schema_cleanup::{SchemaCleanupJob, DEFAULT_SCHEMA_RETENTION_COUNT};
pub use schema_scheduler::{
    SchedulerError, SchemaSchedulerJob, DEFAULT_BATCH_SIZE, DEFAULT_POLL_INTERVAL_SECS,
};
