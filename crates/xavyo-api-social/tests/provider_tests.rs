//! Provider Integration Tests Entry Point
//!
//! Run all provider tests:
//!   SQLX_OFFLINE=true cargo test -p xavyo-api-social --test provider_tests
//!
//! Run specific provider tests:
//!   cargo test -p xavyo-api-social google
//!   cargo test -p xavyo-api-social microsoft
//!   cargo test -p xavyo-api-social apple
//!   cargo test -p xavyo-api-social github

mod providers;

pub use providers::*;
