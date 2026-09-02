//! Service account service for managing non-human identities.
//!
//! Provides CRUD operations for the service account registry.

use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::{
    CreateNhiIdentity, CreateNhiServiceAccount, NhiIdentity,
    NhiServiceAccount as NhiServiceAccountModel, NhiServiceAccountFilter, UpdateNhiIdentity,
    UpdateNhiServiceAccount,
};
use xavyo_governance::error::{GovernanceError, Result};
use xavyo_nhi::{NhiLifecycleState, NhiType};

use crate::models::{
    sa_status_to_lifecycle, ListServiceAccountsQuery, RegisterServiceAccountRequest,
    ServiceAccountListResponse, ServiceAccountResponse, ServiceAccountSummary,
    UpdateServiceAccountRequest,
};

/// Service for managing service accounts.
pub struct ServiceAccountService {
    pool: PgPool,
}

impl ServiceAccountService {
    /// Create a new service account service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get the database pool reference.
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// List service accounts with filtering.
    pub async fn list(
        &self,
        tenant_id: Uuid,
        query: &ListServiceAccountsQuery,
    ) -> Result<ServiceAccountListResponse> {
        let filter = NhiServiceAccountFilter {
            lifecycle_state: query.status.map(sa_status_to_lifecycle),
            owner_id: query.owner_id,
            expiring_within_days: query.expiring_within_days,
            needs_certification: query.needs_certification,
            ..Default::default()
        };

        let limit = query.limit.unwrap_or(50).min(100);
        let offset = query.offset.unwrap_or(0).max(0);

        let accounts = NhiServiceAccountModel::list(&self.pool, tenant_id, &filter, limit, offset)
            .await
            .map_err(GovernanceError::Database)?;

        let total = NhiServiceAccountModel::count(&self.pool, tenant_id, &filter)
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
        let account = NhiServiceAccountModel::find_by_nhi_id(&self.pool, tenant_id, id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::ServiceAccountNotFound(id))?;

        Ok(ServiceAccountResponse::from(account))
    }

    /// Get a service account by identity ID.
    pub async fn get_by_user_id(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<ServiceAccountResponse>> {
        let account = NhiServiceAccountModel::find_by_nhi_id(&self.pool, tenant_id, user_id)
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
        if NhiIdentity::name_exists(&self.pool, tenant_id, &request.name)
            .await
            .map_err(GovernanceError::Database)?
        {
            return Err(GovernanceError::Validation(
                "A service account with this name already exists".to_string(),
            ));
        }

        let identity = NhiIdentity::create(
            &self.pool,
            tenant_id,
            CreateNhiIdentity {
                nhi_type: NhiType::ServiceAccount,
                name: request.name.clone(),
                description: Some(request.purpose.clone()),
                owner_id: Some(request.owner_id),
                backup_owner_id: None,
                expires_at: request.expires_at,
                inactivity_threshold_days: None,
                rotation_interval_days: None,
                created_by: None,
            },
        )
        .await
        .map_err(GovernanceError::Database)?;

        NhiServiceAccountModel::create(
            &self.pool,
            CreateNhiServiceAccount {
                nhi_id: identity.id,
                purpose: request.purpose,
                environment: None,
            },
        )
        .await
        .map_err(GovernanceError::Database)?;

        let account = NhiServiceAccountModel::find_by_nhi_id(&self.pool, tenant_id, identity.id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::ServiceAccountNotFound(identity.id))?;

        tracing::info!(
            tenant_id = %tenant_id,
            service_account_id = %account.id,
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
        NhiIdentity::update(
            &self.pool,
            tenant_id,
            id,
            UpdateNhiIdentity {
                name: request.name.clone(),
                description: request.purpose.clone(),
                owner_id: request.owner_id.map(Some),
                expires_at: request.expires_at.map(Some),
                ..Default::default()
            },
        )
        .await
        .map_err(GovernanceError::Database)?
        .ok_or(GovernanceError::ServiceAccountNotFound(id))?;

        if request.purpose.is_some() {
            NhiServiceAccountModel::update(
                &self.pool,
                tenant_id,
                id,
                UpdateNhiServiceAccount {
                    purpose: request.purpose.clone(),
                    environment: None,
                },
            )
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::ServiceAccountNotFound(id))?;
        }

        let updated = NhiServiceAccountModel::find_by_nhi_id(&self.pool, tenant_id, id)
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
        let certified_ok = NhiIdentity::update_certification(
            &self.pool,
            tenant_id,
            id,
            certified_by,
            Some(Utc::now() + chrono::Duration::days(365)),
        )
        .await
        .map_err(GovernanceError::Database)?;
        if !certified_ok {
            return Err(GovernanceError::ServiceAccountNotFound(id));
        }

        let certified = NhiServiceAccountModel::find_by_nhi_id(&self.pool, tenant_id, id)
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
        NhiIdentity::update_lifecycle_state(
            &self.pool,
            tenant_id,
            id,
            NhiLifecycleState::Suspended,
            Some("manual".to_string()),
        )
        .await
        .map_err(GovernanceError::Database)?
        .ok_or(GovernanceError::ServiceAccountNotFound(id))?;

        let suspended = NhiServiceAccountModel::find_by_nhi_id(&self.pool, tenant_id, id)
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
        let existing = NhiServiceAccountModel::find_by_nhi_id(&self.pool, tenant_id, id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::ServiceAccountNotFound(id))?;

        if existing.lifecycle_state != NhiLifecycleState::Suspended {
            return Err(GovernanceError::Validation(
                "Service account not found or not in suspended status".to_string(),
            ));
        }

        NhiIdentity::update_lifecycle_state(
            &self.pool,
            tenant_id,
            id,
            NhiLifecycleState::Active,
            None,
        )
        .await
        .map_err(GovernanceError::Database)?
        .ok_or(GovernanceError::ServiceAccountNotFound(id))?;

        let reactivated = NhiServiceAccountModel::find_by_nhi_id(&self.pool, tenant_id, id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::ServiceAccountNotFound(id))?;

        tracing::info!(
            tenant_id = %tenant_id,
            service_account_id = %id,
            "Service account reactivated"
        );

        Ok(ServiceAccountResponse::from(reactivated))
    }

    /// Unregister (delete) a service account.
    pub async fn unregister(&self, tenant_id: Uuid, id: Uuid) -> Result<()> {
        let deleted = NhiIdentity::delete(&self.pool, tenant_id, id)
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
        let active = NhiServiceAccountModel::count(
            &self.pool,
            tenant_id,
            &NhiServiceAccountFilter {
                lifecycle_state: Some(NhiLifecycleState::Active),
                ..Default::default()
            },
        )
        .await
        .map_err(GovernanceError::Database)?;

        let expired = NhiServiceAccountModel::count(
            &self.pool,
            tenant_id,
            &NhiServiceAccountFilter {
                lifecycle_state: Some(NhiLifecycleState::Inactive),
                ..Default::default()
            },
        )
        .await
        .map_err(GovernanceError::Database)?;

        let suspended = NhiServiceAccountModel::count(
            &self.pool,
            tenant_id,
            &NhiServiceAccountFilter {
                lifecycle_state: Some(NhiLifecycleState::Suspended),
                ..Default::default()
            },
        )
        .await
        .map_err(GovernanceError::Database)?;

        let total = active + expired + suspended;

        let needs_certification = NhiServiceAccountModel::count(
            &self.pool,
            tenant_id,
            &NhiServiceAccountFilter {
                needs_certification: Some(true),
                ..Default::default()
            },
        )
        .await
        .map_err(GovernanceError::Database)?;

        let expiring_soon = NhiServiceAccountModel::count(
            &self.pool,
            tenant_id,
            &NhiServiceAccountFilter {
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
        let count = NhiIdentity::mark_expired(&self.pool, tenant_id)
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

    /// Unified NHIs are not users; there is no linked user_id to exclude.
    pub async fn get_all_user_ids(&self, _tenant_id: Uuid) -> Result<Vec<Uuid>> {
        Ok(Vec::new())
    }

    /// Check if an identity is a service account.
    pub async fn is_service_account(&self, tenant_id: Uuid, user_id: Uuid) -> Result<bool> {
        let account = NhiServiceAccountModel::find_by_nhi_id(&self.pool, tenant_id, user_id)
            .await
            .map_err(GovernanceError::Database)?;
        Ok(account.is_some())
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

    #[test]
    fn service_account_crud_queries_unified_nhi_identities() {
        let src = include_str!("service_account_service.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            production.contains("NhiServiceAccountModel::list")
                && production.contains("NhiServiceAccountModel::find_by_nhi_id")
                && production.contains("NhiIdentity::create")
                && production.contains("NhiIdentity::update")
                && production.contains("NhiIdentity::delete")
                && !production.contains("GovServiceAccount")
                && !production.contains("gov_service_accounts"),
            "GET/POST/PUT/DELETE /governance/service-accounts must use nhi_identities, not the dropped gov_service_accounts table"
        );
    }

    #[test]
    fn register_service_account_does_not_advertise_unused_user_id() {
        let src = include_str!("service_account_service.rs");
        let production = src.split("mod tests").next().expect("production source");
        let register = production
            .split("pub async fn register(")
            .nth(1)
            .and_then(|s| s.split("    /// Update a service account.").next())
            .expect("register");
        assert!(
            !register.contains("request.user_id") && !register.contains("user_id:"),
            "POST /governance/service-accounts must not require or store a linked user_id after NHI unification"
        );
        let dto = include_str!("../models/service_account.rs");
        let create_dto = dto
            .split("pub struct RegisterServiceAccountRequest")
            .nth(1)
            .and_then(|s| s.split("pub struct UpdateServiceAccountRequest").next())
            .expect("RegisterServiceAccountRequest");
        assert!(
            !create_dto.contains("user_id"),
            "RegisterServiceAccountRequest must not advertise user_id; unified NHIs are not linked users"
        );
    }

    #[test]
    fn get_service_account_does_not_advertise_linked_user_id() {
        let dto = include_str!("../models/service_account.rs");
        let response_dto = dto
            .split("pub struct ServiceAccountResponse")
            .nth(1)
            .and_then(|s| s.split("impl From<NhiServiceAccountWithIdentity>").next())
            .expect("ServiceAccountResponse");
        assert!(
            !response_dto.contains("user_id"),
            "GET /governance/service-accounts must not advertise user_id as a distinct linked user"
        );
        let from_impl = dto
            .split("impl From<NhiServiceAccountWithIdentity> for ServiceAccountResponse")
            .nth(1)
            .and_then(|s| s.split("pub struct RegisterServiceAccountRequest").next())
            .expect("ServiceAccountResponse From");
        assert!(
            !from_impl.contains("user_id:"),
            "ServiceAccountResponse must not alias owner_id as a distinct linked user_id"
        );
        assert!(
            from_impl.contains("owner_id: account.owner_id")
                && !from_impl.contains("unwrap_or(account.id)")
                && !from_impl.contains("linked_user_id"),
            "GET /governance/service-accounts owner_id must stay null when no owner is assigned"
        );
    }
}
