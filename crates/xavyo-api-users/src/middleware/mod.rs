//! Middleware for the User Management API.

pub mod admin_guard;

pub use admin_guard::{admin_guard, ADMIN_ROLE};
