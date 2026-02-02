//! Alert handlers for security alert endpoints.

pub mod security_alerts;

pub use security_alerts::{acknowledge_alert, get_security_alerts};
