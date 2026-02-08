//! Configuration management for the xavyo CLI

mod paths;
mod settings;

pub use paths::ConfigPaths;
pub use settings::Config;

/// System tenant ID used for unauthenticated endpoints (signup, device code, etc.)
pub const SYSTEM_TENANT_ID: &str = "00000000-0000-0000-0000-000000000001";
