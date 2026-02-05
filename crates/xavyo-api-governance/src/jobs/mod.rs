//! Background jobs for governance lifecycle features (F052, F054, F055, F064, F065).
//!
//! This module provides background job implementations for:
//! - Scheduled transitions - polls for due transitions every minute
//! - Grace period expiration - marks expired grace periods as no longer rollbackable
//! - Failed operation retry - processes retry queue with exponential backoff
//! - Escalation processing (F054) - polls for timeout escalations and warnings
//! - Micro-certification expiration (F055) - reminders, escalation, auto-revoke
//! - Bulk action processing (F-064) - processes bulk actions in batches with progress tracking
//! - Ticket sync (F064) - polls external ticketing systems for status updates
//! - SLA monitoring (F064) - monitors manual tasks for SLA warnings and breaches
//! - Ticket retry (F064) - processes retry queue for failed ticket creation
//! - License expiration (F065) - daily check for expired/expiring license pools

pub mod bulk_action_job;
pub mod escalation_job;
pub mod failed_operation_retry_job;
pub mod grace_period_job;
pub mod license_expiration_job;
pub mod micro_cert_expiration_job;
pub mod scheduled_transition_job;
pub mod sla_monitoring_job;
pub mod ticket_retry_job;
pub mod ticket_sync_job;

pub use bulk_action_job::{BulkActionJob, BulkActionJobError, BulkActionJobStats};
pub use escalation_job::{EscalationJob, EscalationJobError, EscalationStats};
pub use failed_operation_retry_job::FailedOperationRetryJob;
pub use grace_period_job::GracePeriodExpirationJob;
pub use license_expiration_job::{
    LicenseExpirationJob, LicenseExpirationJobError, LicenseExpirationStats,
};
pub use micro_cert_expiration_job::{
    MicroCertExpirationJob, MicroCertExpirationJobError, MicroCertExpirationStats,
};
pub use scheduled_transition_job::ScheduledTransitionJob;
pub use sla_monitoring_job::{SlaMonitoringJob, SlaMonitoringJobError, SlaMonitoringStats};
pub use ticket_retry_job::{TicketRetryJob, TicketRetryJobError, TicketRetryStats};
pub use ticket_sync_job::{TicketSyncJob, TicketSyncJobError, TicketSyncStats};
