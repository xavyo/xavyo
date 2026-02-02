//! License Pool Service (F065).
//!
//! Provides business logic for managing license pools including CRUD operations,
//! capacity management, and audit logging.

use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::models::{
    CreateGovLicensePool, GovLicensePool, LicensePoolFilter, LicensePoolStatus,
    UpdateGovLicensePool,
};
use xavyo_governance::error::{GovernanceError, Result};

use super::license_audit_service::LicenseAuditService;
use crate::models::license::{
    CreateLicensePoolRequest, LicensePoolListResponse, LicensePoolResponse, ListLicensePoolsParams,
    UpdateLicensePoolRequest,
};

// ============================================================================
// Pure Business Logic Functions
// ============================================================================

/// Validate that a create request has a positive total capacity.
///
/// Returns `Err` if `total_capacity <= 0`.
pub(crate) fn validate_create_request(request: &CreateLicensePoolRequest) -> Result<()> {
    if request.total_capacity <= 0 {
        return Err(GovernanceError::Validation(
            "Total capacity must be greater than zero".to_string(),
        ));
    }
    Ok(())
}

/// Validate that a capacity update does not reduce capacity below the current
/// allocated count.
///
/// Returns `Err(GovernanceError::LicenseCapacityReductionInvalid)` when the
/// requested new capacity is smaller than the number of licenses already
/// allocated.
pub(crate) fn validate_capacity_update(new_capacity: i32, allocated_count: i32) -> Result<()> {
    if new_capacity < allocated_count {
        return Err(GovernanceError::LicenseCapacityReductionInvalid(
            allocated_count,
        ));
    }
    Ok(())
}

/// Detect which fields changed between an existing pool and an update request.
///
/// This is a pure comparison -- it does **not** check name-uniqueness (which
/// requires a database lookup).  The caller is responsible for checking name
/// uniqueness separately and prepending `"name"` to the returned vec when
/// appropriate.
///
/// Returns a `Vec<String>` of changed field names.
pub(crate) fn detect_changed_fields(
    existing: &GovLicensePool,
    request: &UpdateLicensePoolRequest,
) -> Vec<String> {
    let mut changed = Vec::new();

    if let Some(ref new_name) = request.name {
        if new_name != &existing.name {
            changed.push("name".to_string());
        }
    }

    if let Some(new_capacity) = request.total_capacity {
        if new_capacity != existing.total_capacity {
            changed.push("total_capacity".to_string());
        }
    }

    if request.description.is_some() {
        changed.push("description".to_string());
    }

    if request.cost_per_license.is_some() && request.cost_per_license != existing.cost_per_license {
        changed.push("cost_per_license".to_string());
    }

    if request.expiration_date.is_some() && request.expiration_date != existing.expiration_date {
        changed.push("expiration_date".to_string());
    }

    if let Some(policy) = request.expiration_policy {
        if policy != existing.expiration_policy {
            changed.push("expiration_policy".to_string());
        }
    }

    if let Some(days) = request.warning_days {
        if days != existing.warning_days {
            changed.push("warning_days".to_string());
        }
    }

    if let Some(ref new_vendor) = request.vendor {
        if new_vendor != &existing.vendor {
            changed.push("vendor".to_string());
        }
    }

    if let Some(ref new_currency) = request.currency {
        if new_currency != &existing.currency {
            changed.push("currency".to_string());
        }
    }

    if let Some(new_billing) = request.billing_period {
        if new_billing != existing.billing_period {
            changed.push("billing_period".to_string());
        }
    }

    changed
}

/// Validate that a pool can be archived.
///
/// A pool that is already `Archived` cannot be archived again.
pub(crate) fn validate_archive_status(status: LicensePoolStatus, pool_id: Uuid) -> Result<()> {
    if matches!(status, LicensePoolStatus::Archived) {
        return Err(GovernanceError::LicensePoolArchived(pool_id));
    }
    Ok(())
}

/// Validate that a pool can be deleted.
///
/// A pool with active assignments (`allocated_count > 0`) cannot be deleted.
pub(crate) fn validate_delete_preconditions(allocated_count: i32) -> Result<()> {
    if allocated_count > 0 {
        return Err(GovernanceError::LicensePoolHasAssignments(allocated_count));
    }
    Ok(())
}

/// Enforce sane pagination limits.
///
/// - `limit` is clamped to `[1, 100]`.
/// - `offset` is clamped to `>= 0`.
pub(crate) fn enforce_list_limits(limit: i64, offset: i64) -> (i64, i64) {
    (limit.clamp(1, 100), offset.max(0))
}

/// Check whether a pool has available capacity for a new assignment.
///
/// A pool has capacity when it is `Active` **and** `available_count > 0`.
pub(crate) fn check_pool_has_capacity(available_count: i32, status: LicensePoolStatus) -> bool {
    available_count > 0 && status == LicensePoolStatus::Active
}

// ============================================================================
// Service
// ============================================================================

/// Service for license pool operations.
pub struct LicensePoolService {
    pool: PgPool,
    audit_service: LicenseAuditService,
}

/// Result of creating a license pool.
#[derive(Debug)]
pub struct CreatePoolResult {
    pub pool: LicensePoolResponse,
    pub created: bool,
}

/// Result of updating a license pool.
#[derive(Debug)]
pub struct UpdatePoolResult {
    pub pool: LicensePoolResponse,
    pub changed_fields: Vec<String>,
}

impl LicensePoolService {
    /// Create a new license pool service.
    pub fn new(pool: PgPool) -> Self {
        Self {
            audit_service: LicenseAuditService::new(pool.clone()),
            pool,
        }
    }

    /// Create a new license pool.
    ///
    /// Validates that the pool name is unique within the tenant and creates
    /// the pool with initial capacity tracking.
    pub async fn create(
        &self,
        tenant_id: Uuid,
        actor_id: Uuid,
        request: CreateLicensePoolRequest,
    ) -> Result<CreatePoolResult> {
        // Validate name uniqueness
        if let Some(_existing) =
            GovLicensePool::find_by_name(&self.pool, tenant_id, &request.name).await?
        {
            return Err(GovernanceError::LicensePoolNameExists(request.name.clone()));
        }

        // Validate total capacity
        validate_create_request(&request)?;

        // Create the pool
        let input = CreateGovLicensePool {
            name: request.name.clone(),
            vendor: request.vendor,
            description: request.description,
            total_capacity: request.total_capacity,
            cost_per_license: request.cost_per_license,
            currency: request.currency,
            billing_period: request.billing_period,
            license_type: request.license_type,
            expiration_date: request.expiration_date,
            expiration_policy: request.expiration_policy,
            warning_days: request.warning_days,
            created_by: actor_id,
        };

        let created_pool = GovLicensePool::create(&self.pool, tenant_id, input).await?;

        // Log audit event
        self.audit_service
            .log_pool_created(tenant_id, created_pool.id, &created_pool.name, actor_id)
            .await?;

        Ok(CreatePoolResult {
            pool: LicensePoolResponse::from(created_pool),
            created: true,
        })
    }

    /// Get a license pool by ID.
    pub async fn get(&self, tenant_id: Uuid, pool_id: Uuid) -> Result<Option<LicensePoolResponse>> {
        let pool = GovLicensePool::find_by_id(&self.pool, tenant_id, pool_id).await?;
        Ok(pool.map(LicensePoolResponse::from))
    }

    /// Get a license pool by ID, returning an error if not found.
    pub async fn get_required(
        &self,
        tenant_id: Uuid,
        pool_id: Uuid,
    ) -> Result<LicensePoolResponse> {
        self.get(tenant_id, pool_id)
            .await?
            .ok_or_else(|| GovernanceError::LicensePoolNotFound(pool_id))
    }

    /// List license pools with filtering and pagination.
    pub async fn list(
        &self,
        tenant_id: Uuid,
        params: ListLicensePoolsParams,
    ) -> Result<LicensePoolListResponse> {
        // Enforce reasonable limits
        let (limit, offset) = enforce_list_limits(params.limit, params.offset);

        let filter = LicensePoolFilter {
            vendor: params.vendor,
            status: params.status,
            license_type: params.license_type,
        };

        let pools =
            GovLicensePool::list_by_tenant(&self.pool, tenant_id, &filter, limit, offset).await?;
        let total = GovLicensePool::count_by_tenant(&self.pool, tenant_id, &filter).await?;

        Ok(LicensePoolListResponse {
            items: pools.into_iter().map(LicensePoolResponse::from).collect(),
            total,
            limit,
            offset,
        })
    }

    /// Update a license pool.
    ///
    /// Validates that capacity changes don't leave allocated_count > total_capacity.
    pub async fn update(
        &self,
        tenant_id: Uuid,
        pool_id: Uuid,
        actor_id: Uuid,
        request: UpdateLicensePoolRequest,
    ) -> Result<UpdatePoolResult> {
        // Fetch the existing pool
        let existing = GovLicensePool::find_by_id(&self.pool, tenant_id, pool_id)
            .await?
            .ok_or_else(|| GovernanceError::LicensePoolNotFound(pool_id))?;

        // Validate capacity change
        if let Some(new_capacity) = request.total_capacity {
            validate_capacity_update(new_capacity, existing.allocated_count)?;
        }

        // Validate name uniqueness if changing name
        if let Some(ref new_name) = request.name {
            if new_name != &existing.name {
                if let Some(_other) =
                    GovLicensePool::find_by_name(&self.pool, tenant_id, new_name).await?
                {
                    return Err(GovernanceError::LicensePoolNameExists(new_name.clone()));
                }
            }
        }

        // Detect changed fields
        let changed_fields = detect_changed_fields(&existing, &request);

        // Build update input
        let update = UpdateGovLicensePool {
            name: request.name,
            vendor: request.vendor,
            description: request.description,
            total_capacity: request.total_capacity,
            cost_per_license: request.cost_per_license,
            currency: request.currency,
            billing_period: request.billing_period,
            expiration_date: request.expiration_date,
            expiration_policy: request.expiration_policy,
            warning_days: request.warning_days,
        };

        let updated = GovLicensePool::update(&self.pool, tenant_id, pool_id, update)
            .await?
            .ok_or_else(|| GovernanceError::LicensePoolNotFound(pool_id))?;

        // Log audit event with changes
        if !changed_fields.is_empty() {
            self.audit_service
                .log_pool_updated(
                    tenant_id,
                    pool_id,
                    serde_json::json!({ "changed_fields": changed_fields }),
                    actor_id,
                )
                .await?;
        }

        Ok(UpdatePoolResult {
            pool: LicensePoolResponse::from(updated),
            changed_fields,
        })
    }

    /// Archive a license pool (soft delete).
    ///
    /// Archived pools can still have their assignments viewed but cannot
    /// accept new assignments.
    pub async fn archive(
        &self,
        tenant_id: Uuid,
        pool_id: Uuid,
        actor_id: Uuid,
    ) -> Result<LicensePoolResponse> {
        // Fetch existing to verify it exists and isn't already archived
        let existing = GovLicensePool::find_by_id(&self.pool, tenant_id, pool_id)
            .await?
            .ok_or_else(|| GovernanceError::LicensePoolNotFound(pool_id))?;

        validate_archive_status(existing.status, pool_id)?;

        let archived = GovLicensePool::archive(&self.pool, tenant_id, pool_id)
            .await?
            .ok_or_else(|| GovernanceError::LicensePoolNotFound(pool_id))?;

        // Log audit event
        self.audit_service
            .log_pool_archived(tenant_id, pool_id, actor_id)
            .await?;

        Ok(LicensePoolResponse::from(archived))
    }

    /// Delete a license pool permanently.
    ///
    /// Only allowed if there are no active assignments (allocated_count == 0).
    pub async fn delete(&self, tenant_id: Uuid, pool_id: Uuid, actor_id: Uuid) -> Result<bool> {
        // Fetch existing to verify and get name for audit
        let existing = GovLicensePool::find_by_id(&self.pool, tenant_id, pool_id)
            .await?
            .ok_or_else(|| GovernanceError::LicensePoolNotFound(pool_id))?;

        validate_delete_preconditions(existing.allocated_count)?;

        let deleted = GovLicensePool::delete(&self.pool, tenant_id, pool_id).await?;

        if deleted {
            // Log audit event
            self.audit_service
                .log_pool_deleted(tenant_id, pool_id, &existing.name, actor_id)
                .await?;
        }

        Ok(deleted)
    }

    /// List all active pools for a tenant.
    pub async fn list_active(&self, tenant_id: Uuid) -> Result<Vec<LicensePoolResponse>> {
        let pools = GovLicensePool::list_active(&self.pool, tenant_id).await?;
        Ok(pools.into_iter().map(LicensePoolResponse::from).collect())
    }

    /// List pools by vendor.
    pub async fn list_by_vendor(
        &self,
        tenant_id: Uuid,
        vendor: &str,
    ) -> Result<Vec<LicensePoolResponse>> {
        let pools = GovLicensePool::list_by_vendor(&self.pool, tenant_id, vendor).await?;
        Ok(pools.into_iter().map(LicensePoolResponse::from).collect())
    }

    /// Get pools that are expiring within a given number of days.
    pub async fn get_expiring(
        &self,
        tenant_id: Uuid,
        days: i32,
    ) -> Result<Vec<LicensePoolResponse>> {
        let pools = GovLicensePool::find_expiring(&self.pool, tenant_id, days).await?;
        Ok(pools.into_iter().map(LicensePoolResponse::from).collect())
    }

    /// Check if a pool has available capacity.
    pub async fn has_capacity(&self, tenant_id: Uuid, pool_id: Uuid) -> Result<bool> {
        let pool = self.get_required(tenant_id, pool_id).await?;
        Ok(check_pool_has_capacity(pool.available_count, pool.status))
    }

    /// Get the underlying database pool reference.
    pub fn db_pool(&self) -> &PgPool {
        &self.pool
    }

    /// Get the audit service reference.
    pub fn audit_service(&self) -> &LicenseAuditService {
        &self.audit_service
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::license::{CreateLicensePoolRequest, ListLicensePoolsParams};
    use chrono::{Duration, Utc};
    use rust_decimal::Decimal;
    use xavyo_db::models::{LicenseBillingPeriod, LicenseExpirationPolicy, LicenseType};

    // ========================================================================
    // Helper: build a GovLicensePool for testing
    // ========================================================================

    fn make_existing_pool() -> GovLicensePool {
        GovLicensePool {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "Microsoft 365 E3".to_string(),
            vendor: "Microsoft".to_string(),
            description: Some("Enterprise E3 licenses".to_string()),
            total_capacity: 100,
            allocated_count: 75,
            cost_per_license: Some(Decimal::from(36)),
            currency: "USD".to_string(),
            billing_period: LicenseBillingPeriod::Monthly,
            license_type: LicenseType::Named,
            expiration_date: None,
            expiration_policy: LicenseExpirationPolicy::BlockNew,
            warning_days: 60,
            status: LicensePoolStatus::Active,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: Uuid::new_v4(),
        }
    }

    fn make_update_request_empty() -> UpdateLicensePoolRequest {
        UpdateLicensePoolRequest {
            name: None,
            vendor: None,
            description: None,
            total_capacity: None,
            cost_per_license: None,
            currency: None,
            billing_period: None,
            expiration_date: None,
            expiration_policy: None,
            warning_days: None,
        }
    }

    // ========================================================================
    // validate_create_request
    // ========================================================================

    #[test]
    fn test_validate_create_request_positive_capacity_succeeds() {
        let request = CreateLicensePoolRequest {
            name: "Pool".to_string(),
            vendor: "Vendor".to_string(),
            description: None,
            total_capacity: 100,
            cost_per_license: None,
            currency: "USD".to_string(),
            billing_period: LicenseBillingPeriod::Monthly,
            license_type: LicenseType::Named,
            expiration_date: None,
            expiration_policy: LicenseExpirationPolicy::BlockNew,
            warning_days: 60,
        };
        assert!(validate_create_request(&request).is_ok());
    }

    #[test]
    fn test_validate_create_request_zero_capacity_fails() {
        let request = CreateLicensePoolRequest {
            name: "Pool".to_string(),
            vendor: "Vendor".to_string(),
            description: None,
            total_capacity: 0,
            cost_per_license: None,
            currency: "USD".to_string(),
            billing_period: LicenseBillingPeriod::Monthly,
            license_type: LicenseType::Named,
            expiration_date: None,
            expiration_policy: LicenseExpirationPolicy::BlockNew,
            warning_days: 60,
        };
        let err = validate_create_request(&request).unwrap_err();
        assert!(
            matches!(err, GovernanceError::Validation(ref msg) if msg.contains("greater than zero")),
            "Expected Validation error for zero capacity, got: {:?}",
            err
        );
    }

    #[test]
    fn test_validate_create_request_negative_capacity_fails() {
        let request = CreateLicensePoolRequest {
            name: "Pool".to_string(),
            vendor: "Vendor".to_string(),
            description: None,
            total_capacity: -1,
            cost_per_license: None,
            currency: "USD".to_string(),
            billing_period: LicenseBillingPeriod::Monthly,
            license_type: LicenseType::Named,
            expiration_date: None,
            expiration_policy: LicenseExpirationPolicy::BlockNew,
            warning_days: 60,
        };
        let err = validate_create_request(&request).unwrap_err();
        assert!(
            matches!(err, GovernanceError::Validation(ref msg) if msg.contains("greater than zero")),
            "Expected Validation error, got: {:?}",
            err
        );
    }

    // ========================================================================
    // validate_capacity_update
    // ========================================================================

    #[test]
    fn test_validate_capacity_reduction_below_allocated_fails() {
        // 75 allocated, try to reduce to 50 -- must fail
        let result = validate_capacity_update(50, 75);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::LicenseCapacityReductionInvalid(75)
        ));
    }

    #[test]
    fn test_validate_capacity_reduction_above_allocated_succeeds() {
        // 75 allocated, reduce to 80 -- should succeed
        assert!(validate_capacity_update(80, 75).is_ok());
    }

    #[test]
    fn test_validate_capacity_increase_succeeds() {
        // 75 allocated, increase to 200 -- should succeed
        assert!(validate_capacity_update(200, 75).is_ok());
    }

    #[test]
    fn test_validate_capacity_equal_to_allocated_succeeds() {
        // Exact match: 75 allocated, set to exactly 75 -- should succeed
        assert!(validate_capacity_update(75, 75).is_ok());
    }

    #[test]
    fn test_validate_capacity_reduction_to_zero_with_zero_allocated_succeeds() {
        assert!(validate_capacity_update(0, 0).is_ok());
    }

    #[test]
    fn test_validate_capacity_reduction_to_zero_with_allocations_fails() {
        let result = validate_capacity_update(0, 10);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::LicenseCapacityReductionInvalid(10)
        ));
    }

    // ========================================================================
    // detect_changed_fields
    // ========================================================================

    #[test]
    fn test_detect_changed_fields_no_changes() {
        let existing = make_existing_pool();
        let request = make_update_request_empty();
        let changed = detect_changed_fields(&existing, &request);
        assert!(changed.is_empty());
    }

    #[test]
    fn test_detect_changed_fields_name_changed() {
        let existing = make_existing_pool();
        let mut request = make_update_request_empty();
        request.name = Some("New Name".to_string());
        let changed = detect_changed_fields(&existing, &request);
        assert!(changed.contains(&"name".to_string()));
    }

    #[test]
    fn test_detect_changed_fields_name_same_value_not_detected() {
        let existing = make_existing_pool();
        let mut request = make_update_request_empty();
        request.name = Some(existing.name.clone());
        let changed = detect_changed_fields(&existing, &request);
        assert!(!changed.contains(&"name".to_string()));
    }

    #[test]
    fn test_detect_changed_fields_capacity_changed() {
        let existing = make_existing_pool();
        let mut request = make_update_request_empty();
        request.total_capacity = Some(200);
        let changed = detect_changed_fields(&existing, &request);
        assert!(changed.contains(&"total_capacity".to_string()));
    }

    #[test]
    fn test_detect_changed_fields_capacity_same_value_not_detected() {
        let existing = make_existing_pool();
        let mut request = make_update_request_empty();
        request.total_capacity = Some(existing.total_capacity);
        let changed = detect_changed_fields(&existing, &request);
        assert!(!changed.contains(&"total_capacity".to_string()));
    }

    #[test]
    fn test_detect_changed_fields_description_always_detected_when_present() {
        // Any description value in the request counts as a change because we
        // cannot distinguish "set to same" without comparing Option<String>.
        let existing = make_existing_pool();
        let mut request = make_update_request_empty();
        request.description = Some("Same or different".to_string());
        let changed = detect_changed_fields(&existing, &request);
        assert!(changed.contains(&"description".to_string()));
    }

    #[test]
    fn test_detect_changed_fields_vendor_changed() {
        let existing = make_existing_pool();
        let mut request = make_update_request_empty();
        request.vendor = Some("Google".to_string());
        let changed = detect_changed_fields(&existing, &request);
        assert!(changed.contains(&"vendor".to_string()));
    }

    #[test]
    fn test_detect_changed_fields_vendor_same_value_not_detected() {
        let existing = make_existing_pool();
        let mut request = make_update_request_empty();
        request.vendor = Some(existing.vendor.clone());
        let changed = detect_changed_fields(&existing, &request);
        assert!(!changed.contains(&"vendor".to_string()));
    }

    #[test]
    fn test_detect_changed_fields_currency_changed() {
        let existing = make_existing_pool();
        let mut request = make_update_request_empty();
        request.currency = Some("EUR".to_string());
        let changed = detect_changed_fields(&existing, &request);
        assert!(changed.contains(&"currency".to_string()));
    }

    #[test]
    fn test_detect_changed_fields_billing_period_changed() {
        let existing = make_existing_pool();
        let mut request = make_update_request_empty();
        request.billing_period = Some(LicenseBillingPeriod::Annual);
        let changed = detect_changed_fields(&existing, &request);
        assert!(changed.contains(&"billing_period".to_string()));
    }

    #[test]
    fn test_detect_changed_fields_expiration_policy_changed() {
        let existing = make_existing_pool();
        let mut request = make_update_request_empty();
        request.expiration_policy = Some(LicenseExpirationPolicy::RevokeAll);
        let changed = detect_changed_fields(&existing, &request);
        assert!(changed.contains(&"expiration_policy".to_string()));
    }

    #[test]
    fn test_detect_changed_fields_warning_days_changed() {
        let existing = make_existing_pool();
        let mut request = make_update_request_empty();
        request.warning_days = Some(90);
        let changed = detect_changed_fields(&existing, &request);
        assert!(changed.contains(&"warning_days".to_string()));
    }

    #[test]
    fn test_detect_changed_fields_warning_days_same_value_not_detected() {
        let existing = make_existing_pool();
        let mut request = make_update_request_empty();
        request.warning_days = Some(existing.warning_days);
        let changed = detect_changed_fields(&existing, &request);
        assert!(!changed.contains(&"warning_days".to_string()));
    }

    #[test]
    fn test_detect_changed_fields_multiple_changes() {
        let existing = make_existing_pool();
        let mut request = make_update_request_empty();
        request.name = Some("New Pool Name".to_string());
        request.total_capacity = Some(200);
        request.vendor = Some("Oracle".to_string());
        request.warning_days = Some(30);

        let changed = detect_changed_fields(&existing, &request);
        assert_eq!(changed.len(), 4);
        assert!(changed.contains(&"name".to_string()));
        assert!(changed.contains(&"total_capacity".to_string()));
        assert!(changed.contains(&"vendor".to_string()));
        assert!(changed.contains(&"warning_days".to_string()));
    }

    #[test]
    fn test_detect_changed_fields_cost_changed() {
        let existing = make_existing_pool();
        let mut request = make_update_request_empty();
        request.cost_per_license = Some(Decimal::from(99));
        let changed = detect_changed_fields(&existing, &request);
        assert!(changed.contains(&"cost_per_license".to_string()));
    }

    #[test]
    fn test_detect_changed_fields_cost_same_value_not_detected() {
        let existing = make_existing_pool();
        let mut request = make_update_request_empty();
        request.cost_per_license = existing.cost_per_license;
        let changed = detect_changed_fields(&existing, &request);
        assert!(!changed.contains(&"cost_per_license".to_string()));
    }

    #[test]
    fn test_detect_changed_fields_expiration_date_changed() {
        let existing = make_existing_pool();
        let mut request = make_update_request_empty();
        request.expiration_date = Some(Utc::now() + Duration::days(365));
        let changed = detect_changed_fields(&existing, &request);
        assert!(changed.contains(&"expiration_date".to_string()));
    }

    // ========================================================================
    // validate_archive_status
    // ========================================================================

    #[test]
    fn test_validate_archive_active_pool_succeeds() {
        let pool_id = Uuid::new_v4();
        assert!(validate_archive_status(LicensePoolStatus::Active, pool_id).is_ok());
    }

    #[test]
    fn test_validate_archive_expired_pool_succeeds() {
        let pool_id = Uuid::new_v4();
        assert!(validate_archive_status(LicensePoolStatus::Expired, pool_id).is_ok());
    }

    #[test]
    fn test_validate_archive_already_archived_pool_fails() {
        let pool_id = Uuid::new_v4();
        let result = validate_archive_status(LicensePoolStatus::Archived, pool_id);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::LicensePoolArchived(id) if id == pool_id
        ));
    }

    // ========================================================================
    // validate_delete_preconditions
    // ========================================================================

    #[test]
    fn test_validate_delete_zero_allocated_succeeds() {
        assert!(validate_delete_preconditions(0).is_ok());
    }

    #[test]
    fn test_validate_delete_with_allocations_fails() {
        let result = validate_delete_preconditions(5);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::LicensePoolHasAssignments(5)
        ));
    }

    #[test]
    fn test_validate_delete_with_one_allocation_fails() {
        let result = validate_delete_preconditions(1);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::LicensePoolHasAssignments(1)
        ));
    }

    #[test]
    fn test_validate_delete_large_allocation_count_fails() {
        let result = validate_delete_preconditions(10_000);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::LicensePoolHasAssignments(10_000)
        ));
    }

    // ========================================================================
    // enforce_list_limits
    // ========================================================================

    #[test]
    fn test_enforce_list_limits_zero_becomes_one() {
        let (limit, _) = enforce_list_limits(0, 0);
        assert_eq!(limit, 1);
    }

    #[test]
    fn test_enforce_list_limits_large_becomes_100() {
        let (limit, _) = enforce_list_limits(500, 0);
        assert_eq!(limit, 100);
    }

    #[test]
    fn test_enforce_list_limits_within_range_unchanged() {
        let (limit, _) = enforce_list_limits(50, 0);
        assert_eq!(limit, 50);
    }

    #[test]
    fn test_enforce_list_limits_negative_limit_becomes_one() {
        let (limit, _) = enforce_list_limits(-10, 0);
        assert_eq!(limit, 1);
    }

    #[test]
    fn test_enforce_list_limits_exact_boundary_one() {
        let (limit, _) = enforce_list_limits(1, 0);
        assert_eq!(limit, 1);
    }

    #[test]
    fn test_enforce_list_limits_exact_boundary_100() {
        let (limit, _) = enforce_list_limits(100, 0);
        assert_eq!(limit, 100);
    }

    #[test]
    fn test_enforce_list_limits_negative_offset_becomes_zero() {
        let (_, offset) = enforce_list_limits(20, -10);
        assert_eq!(offset, 0);
    }

    #[test]
    fn test_enforce_list_limits_positive_offset_unchanged() {
        let (_, offset) = enforce_list_limits(20, 40);
        assert_eq!(offset, 40);
    }

    #[test]
    fn test_enforce_list_limits_zero_offset_unchanged() {
        let (_, offset) = enforce_list_limits(20, 0);
        assert_eq!(offset, 0);
    }

    // ========================================================================
    // check_pool_has_capacity
    // ========================================================================

    #[test]
    fn test_check_pool_has_capacity_active_with_available() {
        assert!(check_pool_has_capacity(25, LicensePoolStatus::Active));
    }

    #[test]
    fn test_check_pool_has_capacity_active_with_zero_available() {
        assert!(!check_pool_has_capacity(0, LicensePoolStatus::Active));
    }

    #[test]
    fn test_check_pool_has_capacity_archived_with_available() {
        assert!(!check_pool_has_capacity(25, LicensePoolStatus::Archived));
    }

    #[test]
    fn test_check_pool_has_capacity_expired_with_available() {
        assert!(!check_pool_has_capacity(25, LicensePoolStatus::Expired));
    }

    #[test]
    fn test_check_pool_has_capacity_archived_with_zero_available() {
        assert!(!check_pool_has_capacity(0, LicensePoolStatus::Archived));
    }

    #[test]
    fn test_check_pool_has_capacity_expired_with_zero_available() {
        assert!(!check_pool_has_capacity(0, LicensePoolStatus::Expired));
    }

    #[test]
    fn test_check_pool_has_capacity_active_with_large_available() {
        assert!(check_pool_has_capacity(100_000, LicensePoolStatus::Active));
    }

    // ========================================================================
    // List Parameters Deserialization Tests (kept -- they test serde defaults)
    // ========================================================================

    #[test]
    fn test_list_params_from_json_defaults() {
        let json = r#"{}"#;
        let params: ListLicensePoolsParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.limit, 20); // default_limit() function
        assert_eq!(params.offset, 0);
    }

    #[test]
    fn test_list_params_with_filters() {
        let json = r#"{"vendor": "Microsoft", "status": "active", "limit": 50, "offset": 10}"#;
        let params: ListLicensePoolsParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.vendor, Some("Microsoft".to_string()));
        assert_eq!(params.status, Some(LicensePoolStatus::Active));
        assert_eq!(params.limit, 50);
        assert_eq!(params.offset, 10);
    }

    #[test]
    fn test_list_params_with_license_type_filter() {
        let json = r#"{"license_type": "named"}"#;
        let params: ListLicensePoolsParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.license_type, Some(LicenseType::Named));
    }
}
