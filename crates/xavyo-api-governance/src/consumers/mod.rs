//! Event consumers for governance API.
//!
//! This module contains Kafka event consumers that automatically
//! trigger governance actions in response to events.
//!
//! Requires the `kafka` feature to be enabled.

#[cfg(feature = "kafka")]
pub mod micro_cert_consumer;

#[cfg(feature = "kafka")]
pub use micro_cert_consumer::{
    AssignmentCreatedConsumer, ManagerChangeConsumer, SodViolationConsumer,
};
