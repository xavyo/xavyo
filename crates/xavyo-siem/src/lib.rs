//! SIEM integration and audit log export for xavyo.
//!
//! This crate provides:
//! - Format converters (CEF v0, RFC 5424 syslog, JSON, CSV)
//! - Delivery workers (syslog TCP/TLS, syslog UDP, webhook, Splunk HEC)
//! - Pipeline orchestration (circuit breaker, retry, rate limiting)
//! - Batch export capabilities
//! - Credential encryption for auth_config
//! - SSRF protection for webhook/endpoint validation

pub mod batch;
pub mod crypto;
pub mod delivery;
pub mod format;
pub mod models;
pub mod pipeline;
pub mod validation;
