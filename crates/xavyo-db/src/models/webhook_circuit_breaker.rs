//! Circuit breaker state persistence model.
//!
//! Stores circuit breaker state for webhook subscriptions to enable
//! recovery after service restarts.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

// Re-use the existing CircuitState from connector_health module
pub use super::connector_health::CircuitState;

/// Persisted circuit breaker state.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct WebhookCircuitBreakerState {
    pub subscription_id: Uuid,
    pub tenant_id: Uuid,
    pub state: String,
    pub failure_count: i32,
    pub last_failure_at: Option<DateTime<Utc>>,
    pub last_success_at: Option<DateTime<Utc>>,
    pub opened_at: Option<DateTime<Utc>>,
    pub recent_failures: serde_json::Value,
    pub updated_at: DateTime<Utc>,
}

/// Input for creating/updating circuit breaker state.
#[derive(Debug, Clone)]
pub struct UpsertCircuitBreakerState {
    pub subscription_id: Uuid,
    pub tenant_id: Uuid,
    pub state: CircuitState,
    pub failure_count: i32,
    pub last_failure_at: Option<DateTime<Utc>>,
    pub last_success_at: Option<DateTime<Utc>>,
    pub opened_at: Option<DateTime<Utc>>,
    pub recent_failures: serde_json::Value,
}

impl WebhookCircuitBreakerState {
    /// Get the circuit state as an enum.
    #[must_use] 
    pub fn circuit_state(&self) -> CircuitState {
        self.state.parse().unwrap_or(CircuitState::Closed)
    }

    /// Upsert circuit breaker state (insert or update).
    pub async fn upsert(
        pool: &PgPool,
        input: UpsertCircuitBreakerState,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO webhook_circuit_breaker_state (
                subscription_id, tenant_id, state, failure_count,
                last_failure_at, last_success_at, opened_at, recent_failures
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (subscription_id) DO UPDATE SET
                state = EXCLUDED.state,
                failure_count = EXCLUDED.failure_count,
                last_failure_at = EXCLUDED.last_failure_at,
                last_success_at = EXCLUDED.last_success_at,
                opened_at = EXCLUDED.opened_at,
                recent_failures = EXCLUDED.recent_failures,
                updated_at = NOW()
            RETURNING *
            ",
        )
        .bind(input.subscription_id)
        .bind(input.tenant_id)
        .bind(input.state.to_string())
        .bind(input.failure_count)
        .bind(input.last_failure_at)
        .bind(input.last_success_at)
        .bind(input.opened_at)
        .bind(&input.recent_failures)
        .fetch_one(pool)
        .await
    }

    /// Find circuit breaker state by subscription ID.
    pub async fn find_by_subscription(
        pool: &PgPool,
        tenant_id: Uuid,
        subscription_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM webhook_circuit_breaker_state
            WHERE tenant_id = $1 AND subscription_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(subscription_id)
        .fetch_optional(pool)
        .await
    }

    /// List all circuit breaker states for a tenant.
    pub async fn list_by_tenant(pool: &PgPool, tenant_id: Uuid) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM webhook_circuit_breaker_state
            WHERE tenant_id = $1
            ORDER BY updated_at DESC
            ",
        )
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// Delete circuit breaker state for a subscription.
    pub async fn delete(
        pool: &PgPool,
        tenant_id: Uuid,
        subscription_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM webhook_circuit_breaker_state
            WHERE tenant_id = $1 AND subscription_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(subscription_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_state_default() {
        assert_eq!(CircuitState::Closed.to_string(), "closed");
    }

    #[test]
    fn test_circuit_state_round_trip() {
        for state in [
            CircuitState::Closed,
            CircuitState::Open,
            CircuitState::HalfOpen,
        ] {
            let s = state.to_string();
            let parsed: CircuitState = s.parse().unwrap();
            assert_eq!(parsed, state);
        }
    }
}
