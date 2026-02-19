//! NHI Request Service for self-service NHI provisioning workflows.
//!
//! F061 - NHI Lifecycle Management - User Story 6

use chrono::{Duration, Utc};
use sqlx::PgPool;
use std::sync::Arc;
use utoipa::ToSchema;
use uuid::Uuid;

#[cfg(feature = "kafka")]
use xavyo_events::EventProducer;

use xavyo_db::models::{
    ApproveGovNhiRequest, CreateGovNhiRequest, GovNhiRequest, NhiRequestFilter, NhiRequestStatus,
    RejectGovNhiRequest,
};
use xavyo_governance::error::{GovernanceError, Result};

use crate::models::nhi::{CreateNhiRequest, NhiRequestListResponse, NhiRequestResponse};
use crate::services::NhiService;

/// Default request expiration in days.
const DEFAULT_REQUEST_EXPIRY_DAYS: i64 = 14;

/// Default NHI expiration in days.
const DEFAULT_NHI_EXPIRY_DAYS: i64 = 365;

/// Default rotation interval in days.
const DEFAULT_ROTATION_INTERVAL_DAYS: i32 = 90;

/// Service for NHI request operations.
pub struct NhiRequestService {
    pool: PgPool,
    nhi_service: Arc<NhiService>,
    #[cfg(feature = "kafka")]
    event_producer: Option<Arc<EventProducer>>,
}

impl NhiRequestService {
    /// Create a new NHI request service.
    #[must_use]
    pub fn new(pool: PgPool, nhi_service: Arc<NhiService>) -> Self {
        Self {
            pool,
            nhi_service,
            #[cfg(feature = "kafka")]
            event_producer: None,
        }
    }

    /// Create a new NHI request service with event producer.
    #[cfg(feature = "kafka")]
    pub fn with_event_producer(
        pool: PgPool,
        nhi_service: Arc<NhiService>,
        event_producer: Arc<EventProducer>,
    ) -> Self {
        Self {
            pool,
            nhi_service,
            event_producer: Some(event_producer),
        }
    }

    /// Submit a new NHI request.
    ///
    /// Creates a request for a new NHI account that will be routed to approvers.
    pub async fn submit_request(
        &self,
        tenant_id: Uuid,
        requester_id: Uuid,
        name: String,
        purpose: String,
        requested_permissions: Vec<Uuid>,
        requested_expiration: Option<chrono::DateTime<chrono::Utc>>,
        requested_rotation_days: Option<i32>,
    ) -> Result<NhiRequestResponse> {
        // Check for duplicate pending request
        if GovNhiRequest::has_pending_request(&self.pool, tenant_id, requester_id, &name).await? {
            return Err(GovernanceError::Validation(
                "A pending request for this NHI name already exists".to_string(),
            ));
        }

        // Calculate request expiration
        let expires_at = Utc::now() + Duration::days(DEFAULT_REQUEST_EXPIRY_DAYS);

        let create_data = CreateGovNhiRequest {
            requester_id,
            requested_name: name,
            purpose,
            requested_permissions,
            requested_expiration,
            requested_rotation_days,
            expires_at,
        };

        let request = GovNhiRequest::create(&self.pool, tenant_id, create_data).await?;

        // Emit event
        #[cfg(feature = "kafka")]
        if let Some(producer) = &self.event_producer {
            use xavyo_events::events::nhi::NhiRequestSubmitted;
            let event = NhiRequestSubmitted {
                request_id: request.id,
                tenant_id,
                requester_id,
                requested_name: request.requested_name.clone(),
                submitted_at: request.created_at,
            };
            let _ = producer.send(&event).await;
        }

        Ok(request.into())
    }

    /// Get a request by ID.
    pub async fn get_request(
        &self,
        tenant_id: Uuid,
        request_id: Uuid,
    ) -> Result<NhiRequestResponse> {
        let request = GovNhiRequest::find_by_id(&self.pool, tenant_id, request_id)
            .await?
            .ok_or_else(|| GovernanceError::Validation("NHI request not found".to_string()))?;

        Ok(request.into())
    }

    /// List NHI requests with filtering.
    pub async fn list_requests(
        &self,
        tenant_id: Uuid,
        filter: NhiRequestFilter,
        limit: i64,
        offset: i64,
    ) -> Result<NhiRequestListResponse> {
        let requests = GovNhiRequest::list(&self.pool, tenant_id, &filter, limit, offset).await?;
        let total = GovNhiRequest::count(&self.pool, tenant_id, &filter).await?;

        Ok(NhiRequestListResponse {
            items: requests.into_iter().map(std::convert::Into::into).collect(),
            total,
            limit,
            offset,
        })
    }

    /// Get pending requests for a user (their own requests).
    pub async fn get_my_pending_requests(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<NhiRequestListResponse> {
        let filter = NhiRequestFilter {
            requester_id: Some(user_id),
            status: None,
            pending_only: Some(true),
        };

        self.list_requests(tenant_id, filter, limit, offset).await
    }

    /// Approve an NHI request.
    ///
    /// Creates the NHI and returns the updated request.
    pub async fn approve_request(
        &self,
        tenant_id: Uuid,
        request_id: Uuid,
        approver_id: Uuid,
        comments: Option<String>,
    ) -> Result<NhiRequestResponse> {
        // Get the request
        let request = GovNhiRequest::find_by_id(&self.pool, tenant_id, request_id)
            .await?
            .ok_or_else(|| GovernanceError::Validation("NHI request not found".to_string()))?;

        // Validate request is actionable
        if !request.is_actionable() {
            return Err(GovernanceError::Validation(
                "Request is not actionable (already decided or expired)".to_string(),
            ));
        }

        // Calculate NHI parameters
        let nhi_expiration = request
            .requested_expiration
            .unwrap_or_else(|| Utc::now() + Duration::days(DEFAULT_NHI_EXPIRY_DAYS));

        let rotation_days = request
            .requested_rotation_days
            .unwrap_or(DEFAULT_ROTATION_INTERVAL_DAYS);

        // Create the NHI request - requester becomes the owner
        let create_nhi_request = CreateNhiRequest {
            user_id: request.requester_id, // user_id is required
            name: request.requested_name.clone(),
            purpose: request.purpose.clone(),
            owner_id: request.requester_id, // owner is the requester
            backup_owner_id: None,
            expires_at: Some(nhi_expiration),
            rotation_interval_days: Some(rotation_days),
            inactivity_threshold_days: None,
        };

        // Create the NHI
        let nhi = self
            .nhi_service
            .create(tenant_id, approver_id, create_nhi_request)
            .await?;

        // Update the request as approved
        let approve_data = ApproveGovNhiRequest {
            approver_id,
            comments,
            created_nhi_id: nhi.id,
        };

        let updated_request =
            GovNhiRequest::approve(&self.pool, tenant_id, request_id, approve_data)
                .await?
                .ok_or_else(|| {
                    GovernanceError::Validation("Failed to approve request".to_string())
                })?;

        // TODO: Assign requested_permissions to the NHI if any

        // Emit event
        #[cfg(feature = "kafka")]
        if let Some(producer) = &self.event_producer {
            use xavyo_events::events::nhi::NhiRequestApproved;
            let event = NhiRequestApproved {
                request_id,
                tenant_id,
                nhi_id: nhi.id,
                approver_id,
                approved_at: updated_request.decision_at.unwrap_or_else(Utc::now),
            };
            let _ = producer.send(&event).await;
        }

        Ok(updated_request.into())
    }

    /// Reject an NHI request.
    pub async fn reject_request(
        &self,
        tenant_id: Uuid,
        request_id: Uuid,
        approver_id: Uuid,
        reason: String,
    ) -> Result<NhiRequestResponse> {
        // Get the request
        let request = GovNhiRequest::find_by_id(&self.pool, tenant_id, request_id)
            .await?
            .ok_or_else(|| GovernanceError::Validation("NHI request not found".to_string()))?;

        // Validate request is actionable
        if !request.is_actionable() {
            return Err(GovernanceError::Validation(
                "Request is not actionable (already decided or expired)".to_string(),
            ));
        }

        let reject_data = RejectGovNhiRequest {
            approver_id,
            reason: reason.clone(),
        };

        let updated_request = GovNhiRequest::reject(&self.pool, tenant_id, request_id, reject_data)
            .await?
            .ok_or_else(|| GovernanceError::Validation("Failed to reject request".to_string()))?;

        // Emit event
        #[cfg(feature = "kafka")]
        if let Some(producer) = &self.event_producer {
            use xavyo_events::events::nhi::NhiRequestRejected;
            let event = NhiRequestRejected {
                request_id,
                tenant_id,
                approver_id,
                reason,
                rejected_at: updated_request.decision_at.unwrap_or_else(Utc::now),
            };
            let _ = producer.send(&event).await;
        }

        Ok(updated_request.into())
    }

    /// Cancel an NHI request (requester only).
    pub async fn cancel_request(
        &self,
        tenant_id: Uuid,
        request_id: Uuid,
        requester_id: Uuid,
    ) -> Result<NhiRequestResponse> {
        let request = GovNhiRequest::find_by_id(&self.pool, tenant_id, request_id)
            .await?
            .ok_or_else(|| GovernanceError::Validation("NHI request not found".to_string()))?;

        // Validate requester
        if request.requester_id != requester_id {
            return Err(GovernanceError::Validation(
                "Only the requester can cancel a request".to_string(),
            ));
        }

        // Validate request is actionable
        if !request.is_actionable() {
            return Err(GovernanceError::Validation(
                "Request is not actionable (already decided or expired)".to_string(),
            ));
        }

        let updated_request =
            GovNhiRequest::cancel(&self.pool, tenant_id, request_id, requester_id)
                .await?
                .ok_or_else(|| {
                    GovernanceError::Validation("Failed to cancel request".to_string())
                })?;

        Ok(updated_request.into())
    }

    /// Expire old pending requests.
    ///
    /// This should be called by a scheduled job.
    pub async fn expire_old_requests(&self, tenant_id: Uuid) -> Result<u64> {
        let count = GovNhiRequest::expire_old_requests(&self.pool, tenant_id).await?;
        Ok(count)
    }

    /// Get request summary/stats for the tenant.
    pub async fn get_request_summary(&self, tenant_id: Uuid) -> Result<NhiRequestSummary> {
        let pending_filter = NhiRequestFilter {
            requester_id: None,
            status: Some(NhiRequestStatus::Pending),
            pending_only: Some(true),
        };
        let pending = GovNhiRequest::count(&self.pool, tenant_id, &pending_filter).await?;

        let approved_filter = NhiRequestFilter {
            requester_id: None,
            status: Some(NhiRequestStatus::Approved),
            pending_only: None,
        };
        let approved = GovNhiRequest::count(&self.pool, tenant_id, &approved_filter).await?;

        let rejected_filter = NhiRequestFilter {
            requester_id: None,
            status: Some(NhiRequestStatus::Rejected),
            pending_only: None,
        };
        let rejected = GovNhiRequest::count(&self.pool, tenant_id, &rejected_filter).await?;

        let cancelled_filter = NhiRequestFilter {
            requester_id: None,
            status: Some(NhiRequestStatus::Cancelled),
            pending_only: None,
        };
        let cancelled = GovNhiRequest::count(&self.pool, tenant_id, &cancelled_filter).await?;

        Ok(NhiRequestSummary {
            pending,
            approved,
            rejected,
            cancelled,
        })
    }
}

/// Summary of NHI requests.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, ToSchema)]
pub struct NhiRequestSummary {
    pub pending: i64,
    pub approved: i64,
    pub rejected: i64,
    pub cancelled: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_request_expiry() {
        assert_eq!(DEFAULT_REQUEST_EXPIRY_DAYS, 14);
    }

    #[test]
    fn test_default_nhi_expiry() {
        assert_eq!(DEFAULT_NHI_EXPIRY_DAYS, 365);
    }

    #[test]
    fn test_default_rotation_interval() {
        assert_eq!(DEFAULT_ROTATION_INTERVAL_DAYS, 90);
    }

    #[test]
    fn test_request_summary_default() {
        let summary = NhiRequestSummary {
            pending: 0,
            approved: 0,
            rejected: 0,
            cancelled: 0,
        };
        assert_eq!(summary.pending, 0);
        assert_eq!(summary.approved, 0);
        assert_eq!(summary.rejected, 0);
        assert_eq!(summary.cancelled, 0);
    }
}
