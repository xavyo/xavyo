//! Service account service for managing non-human identities.
//!
//! Provides CRUD operations for the service account registry.

use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::{
    CreateGovServiceAccount, GovServiceAccount, ServiceAccountFilter, UpdateGovServiceAccount,
};
use xavyo_governance::error::{GovernanceError, Result};

use crate::models::{
    ListServiceAccountsQuery, RegisterServiceAccountRequest, ServiceAccountListResponse,
    ServiceAccountResponse, ServiceAccountSummary, UpdateServiceAccountRequest,
};

/// Service for managing service accounts.
pub struct ServiceAccountService {
    pool: PgPool,
}

impl ServiceAccountService {
    /// Create a new service account service.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get the database pool reference.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// List service accounts with filtering.
    pub async fn list(
        &self,
        tenant_id: Uuid,
        query: &ListServiceAccountsQuery,
    ) -> Result<ServiceAccountListResponse> {
        let filter = ServiceAccountFilter {
            status: query.status,
            owner_id: query.owner_id,
            expiring_within_days: query.expiring_within_days,
            needs_certification: query.needs_certification,
            // NHI lifecycle filters (F061)
            backup_owner_id: None,
            inactive_days: None,
            needs_rotation: None,
        };

        let limit = query.limit.unwrap_or(50).min(100);
        let offset = query.offset.unwrap_or(0);

        let accounts = GovServiceAccount::list(&self.pool, tenant_id, &filter, limit, offset)
            .await
            .map_err(GovernanceError::Database)?;

        let total = GovServiceAccount::count(&self.pool, tenant_id, &filter)
            .await
            .map_err(GovernanceError::Database)?;

        Ok(ServiceAccountListResponse {
            items: accounts
                .into_iter()
                .map(ServiceAccountResponse::from)
                .collect(),
            total,
            limit,
            offset,
        })
    }

    /// Get a service account by ID.
    pub async fn get(&self, tenant_id: Uuid, id: Uuid) -> Result<ServiceAccountResponse> {
        let account = GovServiceAccount::find_by_id(&self.pool, tenant_id, id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::ServiceAccountNotFound(id))?;

        Ok(ServiceAccountResponse::from(account))
    }

    /// Get a service account by user ID.
    pub async fn get_by_user_id(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<ServiceAccountResponse>> {
        let account = GovServiceAccount::find_by_user_id(&self.pool, tenant_id, user_id)
            .await
            .map_err(GovernanceError::Database)?;

        Ok(account.map(ServiceAccountResponse::from))
    }

    /// Register a new service account.
    pub async fn register(
        &self,
        tenant_id: Uuid,
        request: RegisterServiceAccountRequest,
    ) -> Result<ServiceAccountResponse> {
        // Check if user is already registered as a service account
        if GovServiceAccount::is_service_account(&self.pool, tenant_id, request.user_id)
            .await
            .map_err(GovernanceError::Database)?
        {
            return Err(GovernanceError::Validation(
                "User is already registered as a service account".to_string(),
            ));
        }

        let input = CreateGovServiceAccount {
            user_id: request.user_id,
            name: request.name,
            purpose: request.purpose,
            owner_id: request.owner_id,
            expires_at: request.expires_at,
            // NHI lifecycle fields (F061)
            backup_owner_id: None,
            rotation_interval_days: None,
            inactivity_threshold_days: None,
        };

        let account = GovServiceAccount::create(&self.pool, tenant_id, input)
            .await
            .map_err(GovernanceError::Database)?;

        tracing::info!(
            tenant_id = %tenant_id,
            service_account_id = %account.id,
            user_id = %account.user_id,
            "Service account registered"
        );

        Ok(ServiceAccountResponse::from(account))
    }

    /// Update a service account.
    pub async fn update(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        request: UpdateServiceAccountRequest,
    ) -> Result<ServiceAccountResponse> {
        let update = UpdateGovServiceAccount {
            name: request.name,
            purpose: request.purpose,
            owner_id: request.owner_id,
            status: None,
            expires_at: request.expires_at,
            ..Default::default()
        };

        let updated = GovServiceAccount::update(&self.pool, tenant_id, id, update)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::ServiceAccountNotFound(id))?;

        tracing::info!(
            tenant_id = %tenant_id,
            service_account_id = %id,
            "Service account updated"
        );

        Ok(ServiceAccountResponse::from(updated))
    }

    /// Certify a service account ownership.
    pub async fn certify(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        certified_by: Uuid,
    ) -> Result<ServiceAccountResponse> {
        let certified = GovServiceAccount::certify(&self.pool, tenant_id, id, certified_by)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::ServiceAccountNotFound(id))?;

        tracing::info!(
            tenant_id = %tenant_id,
            service_account_id = %id,
            certified_by = %certified_by,
            "Service account certified"
        );

        Ok(ServiceAccountResponse::from(certified))
    }

    /// Suspend a service account.
    pub async fn suspend(&self, tenant_id: Uuid, id: Uuid) -> Result<ServiceAccountResponse> {
        let suspended = GovServiceAccount::suspend(&self.pool, tenant_id, id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::ServiceAccountNotFound(id))?;

        tracing::info!(
            tenant_id = %tenant_id,
            service_account_id = %id,
            "Service account suspended"
        );

        Ok(ServiceAccountResponse::from(suspended))
    }

    /// Reactivate a suspended service account.
    pub async fn reactivate(&self, tenant_id: Uuid, id: Uuid) -> Result<ServiceAccountResponse> {
        let reactivated = GovServiceAccount::reactivate(&self.pool, tenant_id, id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or_else(|| {
                GovernanceError::Validation(
                    "Service account not found or not in suspended status".to_string(),
                )
            })?;

        tracing::info!(
            tenant_id = %tenant_id,
            service_account_id = %id,
            "Service account reactivated"
        );

        Ok(ServiceAccountResponse::from(reactivated))
    }

    /// Unregister (delete) a service account.
    pub async fn unregister(&self, tenant_id: Uuid, id: Uuid) -> Result<()> {
        let deleted = GovServiceAccount::delete(&self.pool, tenant_id, id)
            .await
            .map_err(GovernanceError::Database)?;

        if !deleted {
            return Err(GovernanceError::ServiceAccountNotFound(id));
        }

        tracing::info!(
            tenant_id = %tenant_id,
            service_account_id = %id,
            "Service account unregistered"
        );

        Ok(())
    }

    /// Get summary statistics for service accounts.
    pub async fn get_summary(&self, tenant_id: Uuid) -> Result<ServiceAccountSummary> {
        use xavyo_db::ServiceAccountStatus;

        // Get counts by status
        let active = GovServiceAccount::count(
            &self.pool,
            tenant_id,
            &ServiceAccountFilter {
                status: Some(ServiceAccountStatus::Active),
                ..Default::default()
            },
        )
        .await
        .map_err(GovernanceError::Database)?;

        let expired = GovServiceAccount::count(
            &self.pool,
            tenant_id,
            &ServiceAccountFilter {
                status: Some(ServiceAccountStatus::Expired),
                ..Default::default()
            },
        )
        .await
        .map_err(GovernanceError::Database)?;

        let suspended = GovServiceAccount::count(
            &self.pool,
            tenant_id,
            &ServiceAccountFilter {
                status: Some(ServiceAccountStatus::Suspended),
                ..Default::default()
            },
        )
        .await
        .map_err(GovernanceError::Database)?;

        let total = active + expired + suspended;

        // Needs certification count
        let needs_certification = GovServiceAccount::count(
            &self.pool,
            tenant_id,
            &ServiceAccountFilter {
                needs_certification: Some(true),
                ..Default::default()
            },
        )
        .await
        .map_err(GovernanceError::Database)?;

        // Expiring within 30 days
        let expiring_soon = GovServiceAccount::count(
            &self.pool,
            tenant_id,
            &ServiceAccountFilter {
                expiring_within_days: Some(30),
                ..Default::default()
            },
        )
        .await
        .map_err(GovernanceError::Database)?;

        Ok(ServiceAccountSummary {
            total,
            active,
            expired,
            suspended,
            needs_certification,
            expiring_soon,
        })
    }

    /// Mark expired service accounts.
    pub async fn mark_expired(&self, tenant_id: Uuid) -> Result<u64> {
        let count = GovServiceAccount::mark_expired(&self.pool, tenant_id)
            .await
            .map_err(GovernanceError::Database)?;

        if count > 0 {
            tracing::info!(
                tenant_id = %tenant_id,
                count = count,
                "Marked service accounts as expired"
            );
        }

        Ok(count)
    }

    /// Get all service account user IDs (for orphan detection exclusion).
    pub async fn get_all_user_ids(&self, tenant_id: Uuid) -> Result<Vec<Uuid>> {
        let ids = GovServiceAccount::get_all_user_ids(&self.pool, tenant_id)
            .await
            .map_err(GovernanceError::Database)?;

        Ok(ids)
    }

    /// Check if a user is registered as a service account.
    pub async fn is_service_account(&self, tenant_id: Uuid, user_id: Uuid) -> Result<bool> {
        let is_sa = GovServiceAccount::is_service_account(&self.pool, tenant_id, user_id)
            .await
            .map_err(GovernanceError::Database)?;

        Ok(is_sa)
    }
}

#[cfg(test)]
mod tests {
    use crate::models::ServiceAccountSummary;

    #[test]
    fn test_service_account_summary_fields() {
        let summary = ServiceAccountSummary {
            total: 10,
            active: 6,
            expired: 2,
            suspended: 2,
            needs_certification: 3,
            expiring_soon: 1,
        };

        assert_eq!(summary.total, 10);
        assert_eq!(summary.active, 6);
        assert_eq!(summary.expired, 2);
        assert_eq!(summary.suspended, 2);
        assert_eq!(summary.needs_certification, 3);
        assert_eq!(summary.expiring_soon, 1);
    }

    #[test]
    fn test_service_account_summary_total_equals_statuses() {
        let summary = ServiceAccountSummary {
            total: 15,
            active: 10,
            expired: 3,
            suspended: 2,
            needs_certification: 5,
            expiring_soon: 2,
        };

        // Total should equal active + expired + suspended
        assert_eq!(
            summary.total,
            summary.active + summary.expired + summary.suspended
        );
    }

    #[test]
    fn test_service_account_summary_default() {
        let summary = ServiceAccountSummary {
            total: 0,
            active: 0,
            expired: 0,
            suspended: 0,
            needs_certification: 0,
            expiring_soon: 0,
        };

        assert_eq!(summary.total, 0);
    }
}
