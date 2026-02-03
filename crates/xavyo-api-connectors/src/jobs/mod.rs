//! Background jobs for connector API operations.
//!
//! This module contains scheduled background tasks for maintenance operations.

pub mod job_cleanup;
pub mod schema_cleanup;
pub mod schema_scheduler;

pub use job_cleanup::{
    JobCleanupJob, DEFAULT_COMPLETED_RETENTION_DAYS, DEFAULT_FAILED_RETENTION_DAYS,
};
pub use schema_cleanup::{SchemaCleanupJob, DEFAULT_SCHEMA_RETENTION_COUNT};
pub use schema_scheduler::{
    SchedulerError, SchemaSchedulerJob, DEFAULT_BATCH_SIZE, DEFAULT_POLL_INTERVAL_SECS,
};
