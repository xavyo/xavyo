//! License Pool model (F065).
//!
//! Represents a purchased software license package with capacity tracking.

use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use super::gov_license_types::{
    LicenseBillingPeriod, LicenseExpirationPolicy, LicensePoolStatus, LicenseType,
};

/// A license pool representing a purchased software license package.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovLicensePool {
    /// Unique identifier for the pool.
    pub id: Uuid,

    /// The tenant this pool belongs to.
    pub tenant_id: Uuid,

    /// Pool display name (e.g., "Microsoft 365 E3").
    pub name: String,

    /// Vendor name (e.g., "Microsoft").
    pub vendor: String,

    /// Optional description.
    pub description: Option<String>,

    /// Total number of licenses purchased.
    pub total_capacity: i32,

    /// Current number of licenses assigned.
    pub allocated_count: i32,

    /// Cost per license unit.
    pub cost_per_license: Option<Decimal>,

    /// ISO 4217 currency code.
    pub currency: String,

    /// Billing period (monthly, annual, perpetual).
    pub billing_period: LicenseBillingPeriod,

    /// License type (named or concurrent).
    pub license_type: LicenseType,

    /// When the license expires.
    pub expiration_date: Option<DateTime<Utc>>,

    /// Policy to enforce when pool expires.
    pub expiration_policy: LicenseExpirationPolicy,

    /// Days before expiration to start sending alerts.
    pub warning_days: i32,

    /// Pool lifecycle status.
    pub status: LicensePoolStatus,

    /// When the pool was created.
    pub created_at: DateTime<Utc>,

    /// When the pool was last updated.
    pub updated_at: DateTime<Utc>,

    /// Who created this pool.
    pub created_by: Uuid,
}

impl GovLicensePool {
    /// Get the number of available (unallocated) licenses.
    pub fn available_count(&self) -> i32 {
        self.total_capacity - self.allocated_count
    }

    /// Check if the pool has available capacity.
    pub fn has_capacity(&self) -> bool {
        self.available_count() > 0
    }

    /// Check if the pool is active.
    pub fn is_active(&self) -> bool {
        matches!(self.status, LicensePoolStatus::Active)
    }

    /// Check if the pool is expired.
    pub fn is_expired(&self) -> bool {
        matches!(self.status, LicensePoolStatus::Expired)
    }

    /// Check if new allocations are blocked (expired with block_new policy or no capacity).
    pub fn is_allocation_blocked(&self) -> bool {
        if self.is_expired() && self.expiration_policy == LicenseExpirationPolicy::BlockNew {
            return true;
        }
        !self.has_capacity()
    }

    /// Get utilization percentage.
    pub fn utilization_percent(&self) -> f64 {
        if self.total_capacity == 0 {
            return 0.0;
        }
        (self.allocated_count as f64 / self.total_capacity as f64) * 100.0
    }

    /// Calculate monthly cost based on allocated licenses.
    pub fn monthly_allocated_cost(&self) -> Option<Decimal> {
        self.cost_per_license.map(|cost| {
            let count = Decimal::from(self.allocated_count);
            match self.billing_period {
                LicenseBillingPeriod::Monthly => cost * count,
                LicenseBillingPeriod::Annual => (cost * count) / Decimal::from(12),
                LicenseBillingPeriod::Perpetual => Decimal::ZERO,
            }
        })
    }

    /// Check if expiration warning should be shown.
    pub fn should_show_expiration_warning(&self) -> bool {
        if let Some(expiration) = self.expiration_date {
            let now = Utc::now();
            let warning_threshold = expiration - chrono::Duration::days(self.warning_days as i64);
            now >= warning_threshold && now < expiration
        } else {
            false
        }
    }

    /// Find a pool by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_license_pools
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find a pool by name within a tenant.
    pub async fn find_by_name(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        name: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_license_pools
            WHERE tenant_id = $1 AND name = $2
            "#,
        )
        .bind(tenant_id)
        .bind(name)
        .fetch_optional(pool)
        .await
    }

    /// List pools for a tenant with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &LicensePoolFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT * FROM gov_license_pools
            WHERE tenant_id = $1
            "#,
        );
        let mut param_count = 1;

        if filter.vendor.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND vendor = ${}", param_count));
        }
        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${}", param_count));
        }
        if filter.license_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND license_type = ${}", param_count));
        }

        query.push_str(&format!(
            " ORDER BY created_at DESC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, GovLicensePool>(&query).bind(tenant_id);

        if let Some(ref vendor) = filter.vendor {
            q = q.bind(vendor);
        }
        if let Some(status) = filter.status {
            q = q.bind(status);
        }
        if let Some(license_type) = filter.license_type {
            q = q.bind(license_type);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count pools in a tenant with filtering.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &LicensePoolFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT COUNT(*) FROM gov_license_pools
            WHERE tenant_id = $1
            "#,
        );
        let mut param_count = 1;

        if filter.vendor.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND vendor = ${}", param_count));
        }
        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${}", param_count));
        }
        if filter.license_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND license_type = ${}", param_count));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(ref vendor) = filter.vendor {
            q = q.bind(vendor);
        }
        if let Some(status) = filter.status {
            q = q.bind(status);
        }
        if let Some(license_type) = filter.license_type {
            q = q.bind(license_type);
        }

        q.fetch_one(pool).await
    }

    /// Create a new license pool.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateGovLicensePool,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r#"
            INSERT INTO gov_license_pools (
                tenant_id, name, vendor, description, total_capacity,
                cost_per_license, currency, billing_period, license_type,
                expiration_date, expiration_policy, warning_days, created_by
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(&input.name)
        .bind(&input.vendor)
        .bind(&input.description)
        .bind(input.total_capacity)
        .bind(input.cost_per_license)
        .bind(&input.currency)
        .bind(input.billing_period)
        .bind(input.license_type)
        .bind(input.expiration_date)
        .bind(input.expiration_policy)
        .bind(input.warning_days)
        .bind(input.created_by)
        .fetch_one(pool)
        .await
    }

    /// Update a license pool.
    pub async fn update(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateGovLicensePool,
    ) -> Result<Option<Self>, sqlx::Error> {
        let mut updates = vec!["updated_at = NOW()".to_string()];
        let mut param_idx = 3;

        if input.name.is_some() {
            updates.push(format!("name = ${}", param_idx));
            param_idx += 1;
        }
        if input.vendor.is_some() {
            updates.push(format!("vendor = ${}", param_idx));
            param_idx += 1;
        }
        if input.description.is_some() {
            updates.push(format!("description = ${}", param_idx));
            param_idx += 1;
        }
        if input.total_capacity.is_some() {
            updates.push(format!("total_capacity = ${}", param_idx));
            param_idx += 1;
        }
        if input.cost_per_license.is_some() {
            updates.push(format!("cost_per_license = ${}", param_idx));
            param_idx += 1;
        }
        if input.currency.is_some() {
            updates.push(format!("currency = ${}", param_idx));
            param_idx += 1;
        }
        if input.billing_period.is_some() {
            updates.push(format!("billing_period = ${}", param_idx));
            param_idx += 1;
        }
        if input.expiration_date.is_some() {
            updates.push(format!("expiration_date = ${}", param_idx));
            param_idx += 1;
        }
        if input.expiration_policy.is_some() {
            updates.push(format!("expiration_policy = ${}", param_idx));
            param_idx += 1;
        }
        if input.warning_days.is_some() {
            updates.push(format!("warning_days = ${}", param_idx));
            let _ = param_idx;
        }

        let query = format!(
            "UPDATE gov_license_pools SET {} WHERE id = $1 AND tenant_id = $2 RETURNING *",
            updates.join(", ")
        );

        let mut q = sqlx::query_as::<_, GovLicensePool>(&query)
            .bind(id)
            .bind(tenant_id);

        if let Some(ref name) = input.name {
            q = q.bind(name);
        }
        if let Some(ref vendor) = input.vendor {
            q = q.bind(vendor);
        }
        if let Some(ref description) = input.description {
            q = q.bind(description);
        }
        if let Some(total_capacity) = input.total_capacity {
            q = q.bind(total_capacity);
        }
        if let Some(cost_per_license) = input.cost_per_license {
            q = q.bind(cost_per_license);
        }
        if let Some(ref currency) = input.currency {
            q = q.bind(currency);
        }
        if let Some(billing_period) = input.billing_period {
            q = q.bind(billing_period);
        }
        if let Some(expiration_date) = input.expiration_date {
            q = q.bind(expiration_date);
        }
        if let Some(expiration_policy) = input.expiration_policy {
            q = q.bind(expiration_policy);
        }
        if let Some(warning_days) = input.warning_days {
            q = q.bind(warning_days);
        }

        q.fetch_optional(pool).await
    }

    /// Archive a license pool (soft delete).
    pub async fn archive(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_license_pools
            SET status = 'archived', updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Delete a license pool. Only allowed if no active assignments.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM gov_license_pools
            WHERE id = $1 AND tenant_id = $2 AND allocated_count = 0
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Increment allocated count atomically. Returns the updated pool or None if no capacity.
    /// Uses FOR UPDATE SKIP LOCKED to handle concurrent requests.
    pub async fn increment_allocated(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_license_pools
            SET allocated_count = allocated_count + 1, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
              AND allocated_count < total_capacity
              AND status = 'active'
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Decrement allocated count atomically.
    pub async fn decrement_allocated(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_license_pools
            SET allocated_count = allocated_count - 1, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND allocated_count > 0
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Set pool status to expired.
    pub async fn set_expired(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_license_pools
            SET status = 'expired', updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find pools that are expiring within the given number of days.
    pub async fn find_expiring(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        days: i32,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_license_pools
            WHERE tenant_id = $1
              AND status = 'active'
              AND expiration_date IS NOT NULL
              AND expiration_date <= NOW() + INTERVAL '1 day' * $2
              AND expiration_date > NOW()
            ORDER BY expiration_date ASC
            "#,
        )
        .bind(tenant_id)
        .bind(days)
        .fetch_all(pool)
        .await
    }

    /// Find pools that have expired but haven't been marked as expired yet.
    pub async fn find_newly_expired(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_license_pools
            WHERE tenant_id = $1
              AND status = 'active'
              AND expiration_date IS NOT NULL
              AND expiration_date <= NOW()
            "#,
        )
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// Get all active pools for a tenant.
    pub async fn list_active(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_license_pools
            WHERE tenant_id = $1 AND status = 'active'
            ORDER BY name ASC
            "#,
        )
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// Get pools by vendor.
    pub async fn list_by_vendor(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        vendor: &str,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_license_pools
            WHERE tenant_id = $1 AND vendor = $2
            ORDER BY name ASC
            "#,
        )
        .bind(tenant_id)
        .bind(vendor)
        .fetch_all(pool)
        .await
    }
}

/// Request to create a new license pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovLicensePool {
    pub name: String,
    pub vendor: String,
    pub description: Option<String>,
    pub total_capacity: i32,
    pub cost_per_license: Option<Decimal>,
    #[serde(default = "default_currency")]
    pub currency: String,
    pub billing_period: LicenseBillingPeriod,
    #[serde(default)]
    pub license_type: LicenseType,
    pub expiration_date: Option<DateTime<Utc>>,
    #[serde(default)]
    pub expiration_policy: LicenseExpirationPolicy,
    #[serde(default = "default_warning_days")]
    pub warning_days: i32,
    pub created_by: Uuid,
}

fn default_currency() -> String {
    "USD".to_string()
}

fn default_warning_days() -> i32 {
    60
}

/// Request to update a license pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateGovLicensePool {
    pub name: Option<String>,
    pub vendor: Option<String>,
    pub description: Option<String>,
    pub total_capacity: Option<i32>,
    pub cost_per_license: Option<Decimal>,
    pub currency: Option<String>,
    pub billing_period: Option<LicenseBillingPeriod>,
    pub expiration_date: Option<DateTime<Utc>>,
    pub expiration_policy: Option<LicenseExpirationPolicy>,
    pub warning_days: Option<i32>,
}

/// Filter options for listing license pools.
#[derive(Debug, Clone, Default)]
pub struct LicensePoolFilter {
    pub vendor: Option<String>,
    pub status: Option<LicensePoolStatus>,
    pub license_type: Option<LicenseType>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_available_count() {
        let pool = GovLicensePool {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "Test".to_string(),
            vendor: "Vendor".to_string(),
            description: None,
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
        };

        assert_eq!(pool.available_count(), 25);
        assert!(pool.has_capacity());
        assert!(pool.is_active());
        assert!(!pool.is_expired());
    }

    #[test]
    fn test_utilization_percent() {
        let pool = GovLicensePool {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "Test".to_string(),
            vendor: "Vendor".to_string(),
            description: None,
            total_capacity: 100,
            allocated_count: 85,
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
        };

        assert_eq!(pool.utilization_percent(), 85.0);
    }

    #[test]
    fn test_no_capacity() {
        let pool = GovLicensePool {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "Test".to_string(),
            vendor: "Vendor".to_string(),
            description: None,
            total_capacity: 100,
            allocated_count: 100,
            cost_per_license: None,
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
        };

        assert_eq!(pool.available_count(), 0);
        assert!(!pool.has_capacity());
        assert!(pool.is_allocation_blocked());
    }

    #[test]
    fn test_create_request_defaults() {
        let json = r#"{
            "name": "Test Pool",
            "vendor": "Microsoft",
            "total_capacity": 100,
            "billing_period": "monthly",
            "created_by": "00000000-0000-0000-0000-000000000001"
        }"#;

        let request: CreateGovLicensePool = serde_json::from_str(json).unwrap();
        assert_eq!(request.currency, "USD");
        assert_eq!(request.license_type, LicenseType::Named);
        assert_eq!(request.expiration_policy, LicenseExpirationPolicy::BlockNew);
        assert_eq!(request.warning_days, 60);
    }
}
