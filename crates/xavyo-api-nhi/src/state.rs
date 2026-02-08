//! Application state for the unified NHI API.

use sqlx::PgPool;

/// Application state for the unified NHI API.
///
/// Contains the database pool and will hold service instances
/// as they are implemented in later phases.
#[derive(Clone)]
pub struct NhiState {
    /// Database connection pool.
    pub pool: PgPool,
    // Services will be added as they're implemented:
    // - nhi_lifecycle_service (Phase 4)
    // - nhi_credential_service (Phase 5)
    // - nhi_risk_service (Phase 8)
    // - nhi_permission_service (Phase 7)
    // - nhi_inactivity_service (Phase 8)
}

impl NhiState {
    /// Creates a new `NhiState` with the given database pool.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}
