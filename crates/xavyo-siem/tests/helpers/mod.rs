//! Test helpers for SIEM integration tests.
//!
//! This module provides:
//! - Mock syslog servers (TCP/TLS/UDP)
//! - Test event generators
//! - TLS certificate generation
//! - Format validators
//! - Docker infrastructure utilities (feature: docker-tests)

pub mod certificates;
pub mod mock_syslog;
pub mod test_events;
pub mod validators;

#[cfg(feature = "docker-tests")]
pub mod docker_infra;
