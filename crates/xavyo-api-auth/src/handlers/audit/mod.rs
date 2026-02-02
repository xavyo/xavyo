//! Audit handlers for login history and admin audit endpoints.

pub mod admin_audit;
pub mod login_history;

pub use admin_audit::{get_admin_login_attempts, get_login_attempt_stats};
pub use login_history::get_login_history;
