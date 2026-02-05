//! Governance Entitlement model.
//!
//! Represents granular access rights within an application.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// GDPR data protection classification for entitlements (F-067).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(
    type_name = "data_protection_classification",
    rename_all = "snake_case"
)]
#[serde(rename_all = "snake_case")]
pub enum DataProtectionClassification {
    /// No personal data involved.
    #[default]
    None,
    /// Contains personal data (GDPR Art. 4).
    Personal,
    /// Contains sensitive personal data (GDPR Art. 9).
    Sensitive,
    /// Special category data requiring explicit consent.
    SpecialCategory,
}

/// GDPR legal basis for data processing (F-067).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gdpr_legal_basis", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum GdprLegalBasis {
    /// Data subject has given consent (Art. 6(1)(a)).
    Consent,
    /// Processing necessary for contract performance (Art. 6(1)(b)).
    Contract,
    /// Processing necessary for legal obligation (Art. 6(1)(c)).
    LegalObligation,
    /// Processing necessary to protect vital interests (Art. 6(1)(d)).
    VitalInterest,
    /// Processing necessary for public interest task (Art. 6(1)(e)).
    PublicTask,
    /// Processing necessary for legitimate interests (Art. 6(1)(f)).
    LegitimateInterest,
}

/// Risk level classification for entitlements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_risk_level", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum GovRiskLevel {
    /// Low risk entitlement.
    Low,
    /// Medium risk entitlement.
    Medium,
    /// High risk entitlement.
    High,
    /// Critical risk entitlement requiring extra scrutiny.
    Critical,
}

/// Entitlement status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_entitlement_status", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum GovEntitlementStatus {
    /// Entitlement is active and can be assigned.
    Active,
    /// Entitlement is inactive; no new assignments allowed.
    Inactive,
    /// Entitlement is temporarily suspended.
    Suspended,
}

/// A governance entitlement representing a granular access right.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovEntitlement {
    /// Unique identifier for the entitlement.
    pub id: Uuid,

    /// The tenant this entitlement belongs to.
    pub tenant_id: Uuid,

    /// The application this entitlement belongs to.
    pub application_id: Uuid,

    /// Entitlement display name.
    pub name: String,

    /// Entitlement description.
    pub description: Option<String>,

    /// Risk level classification.
    pub risk_level: GovRiskLevel,

    /// Entitlement status.
    pub status: GovEntitlementStatus,

    /// Entitlement owner (user ID).
    pub owner_id: Option<Uuid>,

    /// External system reference ID.
    pub external_id: Option<String>,

    /// Extensible metadata as JSON.
    pub metadata: Option<serde_json::Value>,

    /// Whether this entitlement can be delegated (F053).
    /// Only delegable entitlements appear in deputy work items.
    pub is_delegable: bool,

    /// GDPR data protection classification (F-067).
    pub data_protection_classification: DataProtectionClassification,

    /// GDPR legal basis for processing personal data (F-067).
    pub legal_basis: Option<GdprLegalBasis>,

    /// Data retention period in days (F-067).
    pub retention_period_days: Option<i32>,

    /// Name of the data controller organization (F-067).
    pub data_controller: Option<String>,

    /// Name of the data processor organization (F-067).
    pub data_processor: Option<String>,

    /// Processing purpose labels (F-067).
    pub purposes: Option<Vec<String>>,

    /// When the entitlement was created.
    pub created_at: DateTime<Utc>,

    /// When the entitlement was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Request to create a new entitlement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovEntitlement {
    pub application_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub risk_level: GovRiskLevel,
    pub owner_id: Option<Uuid>,
    pub external_id: Option<String>,
    pub metadata: Option<serde_json::Value>,
    /// Whether this entitlement can be delegated. Defaults to true.
    #[serde(default = "default_delegable")]
    pub is_delegable: bool,
    /// GDPR data protection classification. Defaults to None.
    #[serde(default)]
    pub data_protection_classification: DataProtectionClassification,
    /// GDPR legal basis for processing personal data.
    pub legal_basis: Option<GdprLegalBasis>,
    /// Data retention period in days.
    pub retention_period_days: Option<i32>,
    /// Name of the data controller organization.
    pub data_controller: Option<String>,
    /// Name of the data processor organization.
    pub data_processor: Option<String>,
    /// Processing purpose labels.
    pub purposes: Option<Vec<String>>,
}

fn default_delegable() -> bool {
    true
}

/// Request to update an entitlement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateGovEntitlement {
    pub name: Option<String>,
    pub description: Option<String>,
    pub risk_level: Option<GovRiskLevel>,
    pub status: Option<GovEntitlementStatus>,
    pub owner_id: Option<Uuid>,
    pub external_id: Option<String>,
    pub metadata: Option<serde_json::Value>,
    /// Whether this entitlement can be delegated.
    pub is_delegable: Option<bool>,
    /// GDPR data protection classification.
    pub data_protection_classification: Option<DataProtectionClassification>,
    /// GDPR legal basis for processing personal data.
    pub legal_basis: Option<GdprLegalBasis>,
    /// Data retention period in days.
    pub retention_period_days: Option<i32>,
    /// Name of the data controller organization.
    pub data_controller: Option<String>,
    /// Name of the data processor organization.
    pub data_processor: Option<String>,
    /// Processing purpose labels.
    pub purposes: Option<Vec<String>>,
}

/// Filter options for listing entitlements.
#[derive(Debug, Clone, Default)]
pub struct EntitlementFilter {
    pub application_id: Option<Uuid>,
    pub status: Option<GovEntitlementStatus>,
    pub risk_level: Option<GovRiskLevel>,
    pub owner_id: Option<Uuid>,
    /// Filter by delegable flag.
    pub is_delegable: Option<bool>,
    /// Filter by GDPR data protection classification (F-067).
    pub data_protection_classification: Option<DataProtectionClassification>,
}

impl GovEntitlement {
    /// Find an entitlement by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_entitlements
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find an entitlement by name within an application.
    pub async fn find_by_name(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        application_id: Uuid,
        name: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_entitlements
            WHERE tenant_id = $1 AND application_id = $2 AND name = $3
            ",
        )
        .bind(tenant_id)
        .bind(application_id)
        .bind(name)
        .fetch_optional(pool)
        .await
    }

    /// List entitlements for a tenant with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &EntitlementFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT * FROM gov_entitlements
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.application_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND application_id = ${param_count}"));
        }
        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${param_count}"));
        }
        if filter.risk_level.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND risk_level = ${param_count}"));
        }
        if filter.owner_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND owner_id = ${param_count}"));
        }
        if filter.is_delegable.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND is_delegable = ${param_count}"));
        }
        if filter.data_protection_classification.is_some() {
            param_count += 1;
            query.push_str(&format!(
                " AND data_protection_classification = ${param_count}"
            ));
        }

        query.push_str(&format!(
            " ORDER BY name LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, GovEntitlement>(&query).bind(tenant_id);

        if let Some(app_id) = filter.application_id {
            q = q.bind(app_id);
        }
        if let Some(status) = filter.status {
            q = q.bind(status);
        }
        if let Some(risk_level) = filter.risk_level {
            q = q.bind(risk_level);
        }
        if let Some(owner_id) = filter.owner_id {
            q = q.bind(owner_id);
        }
        if let Some(is_delegable) = filter.is_delegable {
            q = q.bind(is_delegable);
        }
        if let Some(classification) = filter.data_protection_classification {
            q = q.bind(classification);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count entitlements in a tenant with filtering.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &EntitlementFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT COUNT(*) FROM gov_entitlements
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.application_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND application_id = ${param_count}"));
        }
        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${param_count}"));
        }
        if filter.risk_level.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND risk_level = ${param_count}"));
        }
        if filter.owner_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND owner_id = ${param_count}"));
        }
        if filter.is_delegable.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND is_delegable = ${param_count}"));
        }
        if filter.data_protection_classification.is_some() {
            param_count += 1;
            query.push_str(&format!(
                " AND data_protection_classification = ${param_count}"
            ));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(app_id) = filter.application_id {
            q = q.bind(app_id);
        }
        if let Some(status) = filter.status {
            q = q.bind(status);
        }
        if let Some(risk_level) = filter.risk_level {
            q = q.bind(risk_level);
        }
        if let Some(owner_id) = filter.owner_id {
            q = q.bind(owner_id);
        }
        if let Some(is_delegable) = filter.is_delegable {
            q = q.bind(is_delegable);
        }
        if let Some(classification) = filter.data_protection_classification {
            q = q.bind(classification);
        }

        q.fetch_one(pool).await
    }

    /// Create a new entitlement.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateGovEntitlement,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO gov_entitlements (tenant_id, application_id, name, description, risk_level, owner_id, external_id, metadata, is_delegable, data_protection_classification, legal_basis, retention_period_days, data_controller, data_processor, purposes)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(input.application_id)
        .bind(&input.name)
        .bind(&input.description)
        .bind(input.risk_level)
        .bind(input.owner_id)
        .bind(&input.external_id)
        .bind(&input.metadata)
        .bind(input.is_delegable)
        .bind(input.data_protection_classification)
        .bind(input.legal_basis)
        .bind(input.retention_period_days)
        .bind(&input.data_controller)
        .bind(&input.data_processor)
        .bind(&input.purposes)
        .fetch_one(pool)
        .await
    }

    /// Update an entitlement.
    pub async fn update(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateGovEntitlement,
    ) -> Result<Option<Self>, sqlx::Error> {
        let mut updates = vec!["updated_at = NOW()".to_string()];
        let mut param_idx = 3;

        if input.name.is_some() {
            updates.push(format!("name = ${param_idx}"));
            param_idx += 1;
        }
        if input.description.is_some() {
            updates.push(format!("description = ${param_idx}"));
            param_idx += 1;
        }
        if input.risk_level.is_some() {
            updates.push(format!("risk_level = ${param_idx}"));
            param_idx += 1;
        }
        if input.status.is_some() {
            updates.push(format!("status = ${param_idx}"));
            param_idx += 1;
        }
        if input.owner_id.is_some() {
            updates.push(format!("owner_id = ${param_idx}"));
            param_idx += 1;
        }
        if input.external_id.is_some() {
            updates.push(format!("external_id = ${param_idx}"));
            param_idx += 1;
        }
        if input.metadata.is_some() {
            updates.push(format!("metadata = ${param_idx}"));
            param_idx += 1;
        }
        if input.is_delegable.is_some() {
            updates.push(format!("is_delegable = ${param_idx}"));
            param_idx += 1;
        }
        if input.data_protection_classification.is_some() {
            updates.push(format!("data_protection_classification = ${param_idx}"));
            param_idx += 1;
        }
        if input.legal_basis.is_some() {
            updates.push(format!("legal_basis = ${param_idx}"));
            param_idx += 1;
        }
        if input.retention_period_days.is_some() {
            updates.push(format!("retention_period_days = ${param_idx}"));
            param_idx += 1;
        }
        if input.data_controller.is_some() {
            updates.push(format!("data_controller = ${param_idx}"));
            param_idx += 1;
        }
        if input.data_processor.is_some() {
            updates.push(format!("data_processor = ${param_idx}"));
            param_idx += 1;
        }
        if input.purposes.is_some() {
            updates.push(format!("purposes = ${param_idx}"));
            // param_idx += 1;
        }

        let query = format!(
            "UPDATE gov_entitlements SET {} WHERE id = $1 AND tenant_id = $2 RETURNING *",
            updates.join(", ")
        );

        let mut q = sqlx::query_as::<_, GovEntitlement>(&query)
            .bind(id)
            .bind(tenant_id);

        if let Some(ref name) = input.name {
            q = q.bind(name);
        }
        if let Some(ref description) = input.description {
            q = q.bind(description);
        }
        if let Some(risk_level) = input.risk_level {
            q = q.bind(risk_level);
        }
        if let Some(status) = input.status {
            q = q.bind(status);
        }
        if let Some(owner_id) = input.owner_id {
            q = q.bind(owner_id);
        }
        if let Some(ref external_id) = input.external_id {
            q = q.bind(external_id);
        }
        if let Some(ref metadata) = input.metadata {
            q = q.bind(metadata);
        }
        if let Some(is_delegable) = input.is_delegable {
            q = q.bind(is_delegable);
        }
        if let Some(classification) = input.data_protection_classification {
            q = q.bind(classification);
        }
        if let Some(legal_basis) = input.legal_basis {
            q = q.bind(legal_basis);
        }
        if let Some(retention_period_days) = input.retention_period_days {
            q = q.bind(retention_period_days);
        }
        if let Some(ref data_controller) = input.data_controller {
            q = q.bind(data_controller);
        }
        if let Some(ref data_processor) = input.data_processor {
            q = q.bind(data_processor);
        }
        if let Some(ref purposes) = input.purposes {
            q = q.bind(purposes);
        }

        q.fetch_optional(pool).await
    }

    /// Delete an entitlement.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_entitlements
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Set owner for an entitlement.
    pub async fn set_owner(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        owner_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_entitlements
            SET owner_id = $3, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(owner_id)
        .fetch_optional(pool)
        .await
    }

    /// Remove owner from an entitlement.
    pub async fn remove_owner(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_entitlements
            SET owner_id = NULL, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Count assignments for this entitlement.
    pub async fn count_assignments(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        entitlement_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM gov_entitlement_assignments
            WHERE entitlement_id = $1 AND tenant_id = $2
            ",
        )
        .bind(entitlement_id)
        .bind(tenant_id)
        .fetch_one(pool)
        .await
    }

    /// List entitlements by owner.
    pub async fn list_by_owner(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        owner_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_entitlements
            WHERE tenant_id = $1 AND owner_id = $2
            ORDER BY name
            LIMIT $3 OFFSET $4
            ",
        )
        .bind(tenant_id)
        .bind(owner_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

    /// Check if entitlement is active.
    #[must_use]
    pub fn is_active(&self) -> bool {
        matches!(self.status, GovEntitlementStatus::Active)
    }

    /// List all active entitlements for a tenant (used by role mining).
    pub async fn list_all(pool: &sqlx::PgPool, tenant_id: Uuid) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_entitlements
            WHERE tenant_id = $1 AND status = 'active'
            ORDER BY name
            ",
        )
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_entitlement_request() {
        let request = CreateGovEntitlement {
            application_id: Uuid::new_v4(),
            name: "Admin Access".to_string(),
            description: Some("Full administrative access".to_string()),
            risk_level: GovRiskLevel::Critical,
            owner_id: Some(Uuid::new_v4()),
            external_id: None,
            metadata: None,
            is_delegable: true,
            data_protection_classification: DataProtectionClassification::default(),
            legal_basis: None,
            retention_period_days: None,
            data_controller: None,
            data_processor: None,
            purposes: None,
        };

        assert_eq!(request.name, "Admin Access");
        assert_eq!(request.risk_level, GovRiskLevel::Critical);
        assert!(request.is_delegable);
    }

    #[test]
    fn test_risk_level_serialization() {
        let critical = GovRiskLevel::Critical;
        let json = serde_json::to_string(&critical).unwrap();
        assert_eq!(json, "\"critical\"");
    }

    #[test]
    fn test_entitlement_status_serialization() {
        let active = GovEntitlementStatus::Active;
        let json = serde_json::to_string(&active).unwrap();
        assert_eq!(json, "\"active\"");
    }
}
