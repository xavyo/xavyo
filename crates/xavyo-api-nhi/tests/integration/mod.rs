//! Integration test module for xavyo-api-nhi.
//!
//! This module contains integration tests organized by user story:
//! - Service account lifecycle tests
//! - Credential rotation tests
//! - Unified NHI list tests
//! - Governance (risk/certification) tests
//! - Multi-tenant isolation tests

pub mod common;
pub mod fixtures;

mod credential_tests;
mod governance_tests;
mod service_account_tests;
mod tenant_isolation_tests;
mod unified_list_tests;
