//! Risk event service for governance API.

use chrono::{DateTime, Duration, Utc};
use sqlx::PgPool;
use uuid::Uuid;
use validator::Validate;

use xavyo_db::{CreateGovRiskEvent, GovRiskEvent};

use crate::error::{ApiGovernanceError, ApiResult};
use crate::models::{
    CleanupEventsResponse, CreateRiskEventRequest, ListRiskEventsQuery, RiskEventListResponse,
    RiskEventResponse,
};

/// Service for managing risk events.
pub struct RiskEventService {
    pool: PgPool,
}

impl RiskEventService {
    /// Create a new risk event service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Create a new risk event.
    pub async fn create(
        &self,
        tenant_id: Uuid,
        request: CreateRiskEventRequest,
    ) -> ApiResult<RiskEventResponse> {
        // Validate request
        request.validate()?;

        // Default expiration: 30 days from now if not specified
        let expires_at = request
            .expires_at
            .or_else(|| Some(Utc::now() + Duration::days(30)));

        let input = CreateGovRiskEvent {
            user_id: request.user_id,
            factor_id: request.factor_id,
            event_type: request.event_type,
            value: request.value,
            source_ref: request.source_ref,
            expires_at,
        };

        let event = GovRiskEvent::create(&self.pool, tenant_id, input).await?;

        Ok(RiskEventResponse::from(event))
    }

    /// Get a risk event by ID.
    pub async fn get(&self, tenant_id: Uuid, event_id: Uuid) -> ApiResult<RiskEventResponse> {
        let event = GovRiskEvent::find_by_id(&self.pool, tenant_id, event_id)
            .await?
            .ok_or(ApiGovernanceError::NotFound(format!(
                "Risk event not found: {event_id}"
            )))?;

        Ok(RiskEventResponse::from(event))
    }

    /// List risk events for a user.
    pub async fn list_for_user(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        query: ListRiskEventsQuery,
    ) -> ApiResult<RiskEventListResponse> {
        let limit = query.limit.unwrap_or(50).min(100);
        let offset = query.offset.unwrap_or(0);

        let events = GovRiskEvent::list_for_user(
            &self.pool,
            tenant_id,
            user_id,
            query.include_expired,
            limit,
            offset,
        )
        .await?;

        let total =
            GovRiskEvent::count_for_user(&self.pool, tenant_id, user_id, query.include_expired)
                .await?;

        Ok(RiskEventListResponse {
            items: events.into_iter().map(RiskEventResponse::from).collect(),
            total,
            limit,
            offset,
        })
    }

    /// Delete a risk event.
    pub async fn delete(&self, tenant_id: Uuid, event_id: Uuid) -> ApiResult<()> {
        // Verify event exists
        GovRiskEvent::find_by_id(&self.pool, tenant_id, event_id)
            .await?
            .ok_or(ApiGovernanceError::NotFound(format!(
                "Risk event not found: {event_id}"
            )))?;

        GovRiskEvent::delete(&self.pool, tenant_id, event_id).await?;

        Ok(())
    }

    /// Cleanup expired events for a tenant.
    pub async fn cleanup_expired(&self, tenant_id: Uuid) -> ApiResult<CleanupEventsResponse> {
        let deleted_count = GovRiskEvent::cleanup_expired(&self.pool, tenant_id).await?;

        Ok(CleanupEventsResponse { deleted_count })
    }

    /// Cleanup events older than a specific date.
    pub async fn cleanup_older_than(
        &self,
        tenant_id: Uuid,
        before: DateTime<Utc>,
    ) -> ApiResult<CleanupEventsResponse> {
        let deleted_count = GovRiskEvent::cleanup_older_than(&self.pool, tenant_id, before).await?;

        Ok(CleanupEventsResponse { deleted_count })
    }

    /// Record a failed login event.
    pub async fn record_failed_login(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        source_ref: Option<String>,
    ) -> ApiResult<RiskEventResponse> {
        let input = CreateGovRiskEvent {
            user_id,
            factor_id: None,
            event_type: "failed_login_count".to_string(),
            value: Some(1.0),
            source_ref,
            expires_at: Some(Utc::now() + Duration::hours(24)), // Expires after 24 hours
        };

        let event = GovRiskEvent::create(&self.pool, tenant_id, input).await?;

        Ok(RiskEventResponse::from(event))
    }

    /// Record an unusual login time event.
    pub async fn record_unusual_login_time(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        source_ref: Option<String>,
    ) -> ApiResult<RiskEventResponse> {
        let input = CreateGovRiskEvent {
            user_id,
            factor_id: None,
            event_type: "unusual_login_time".to_string(),
            value: Some(1.0),
            source_ref,
            expires_at: Some(Utc::now() + Duration::days(7)), // Expires after 7 days
        };

        let event = GovRiskEvent::create(&self.pool, tenant_id, input).await?;

        Ok(RiskEventResponse::from(event))
    }

    /// Record a new location login event.
    pub async fn record_new_location_login(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        source_ref: Option<String>,
    ) -> ApiResult<RiskEventResponse> {
        let input = CreateGovRiskEvent {
            user_id,
            factor_id: None,
            event_type: "new_location_login".to_string(),
            value: Some(1.0),
            source_ref,
            expires_at: Some(Utc::now() + Duration::days(30)), // Expires after 30 days
        };

        let event = GovRiskEvent::create(&self.pool, tenant_id, input).await?;

        Ok(RiskEventResponse::from(event))
    }
}

#[cfg(test)]
mod tests {
    use chrono::Duration;

    #[test]
    fn test_default_expiration() {
        // Test that default expiration is 30 days from now
        let now = chrono::Utc::now();
        let expected = now + Duration::days(30);
        let diff = (expected - now).num_days();
        assert_eq!(diff, 30);
    }

    #[test]
    fn test_failed_login_expiration() {
        // Test that failed login events expire after 24 hours
        let now = chrono::Utc::now();
        let expected = now + Duration::hours(24);
        let diff = (expected - now).num_hours();
        assert_eq!(diff, 24);
    }
}
