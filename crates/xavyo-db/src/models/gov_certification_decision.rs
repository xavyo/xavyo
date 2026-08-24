//! Governance Certification Decision model.
//!
//! Represents the reviewer's action on a certification item.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Decision type for certification items.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "cert_decision_type", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum CertDecisionType {
    /// Access was approved to continue.
    Approved,
    /// Access was revoked.
    Revoked,
}

impl CertDecisionType {
    /// Check if this is a revocation decision.
    #[must_use]
    pub fn is_revoked(&self) -> bool {
        matches!(self, Self::Revoked)
    }
}

/// A certification decision record.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovCertificationDecision {
    /// Unique identifier for the decision.
    pub id: Uuid,

    /// The certification item this decision is for (unique).
    pub item_id: Uuid,

    /// The decision type.
    pub decision_type: CertDecisionType,

    /// Justification (required for revocations).
    pub justification: Option<String>,

    /// User who made the decision.
    pub decided_by: Uuid,

    /// When the decision was made.
    pub decided_at: DateTime<Utc>,

    /// When the record was created.
    pub created_at: DateTime<Utc>,
}

/// Request to create a certification decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateCertificationDecision {
    pub item_id: Uuid,
    pub decision_type: CertDecisionType,
    pub justification: Option<String>,
    pub decided_by: Uuid,
}

impl GovCertificationDecision {
    /// Find a decision by ID within a tenant (via the parent item).
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT d.* FROM gov_certification_decisions d
            INNER JOIN gov_certification_items i ON i.id = d.item_id
            WHERE d.id = $1 AND i.tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find a decision by item ID within a tenant.
    pub async fn find_by_item_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        item_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT d.* FROM gov_certification_decisions d
            INNER JOIN gov_certification_items i ON i.id = d.item_id
            WHERE d.item_id = $1 AND i.tenant_id = $2
            ",
        )
        .bind(item_id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Check if a decision exists for an item within a tenant.
    pub async fn exists_for_item(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        item_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let count: i64 = sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM gov_certification_decisions d
            INNER JOIN gov_certification_items i ON i.id = d.item_id
            WHERE d.item_id = $1 AND i.tenant_id = $2
            ",
        )
        .bind(item_id)
        .bind(tenant_id)
        .fetch_one(pool)
        .await?;

        Ok(count > 0)
    }

    /// List decisions for a campaign (via item join).
    pub async fn list_by_campaign(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        campaign_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT d.* FROM gov_certification_decisions d
            JOIN gov_certification_items i ON d.item_id = i.id
            WHERE i.tenant_id = $1 AND i.campaign_id = $2
            ORDER BY d.decided_at DESC
            LIMIT $3 OFFSET $4
            ",
        )
        .bind(tenant_id)
        .bind(campaign_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

    /// List decisions made by a specific user within a tenant.
    pub async fn list_by_decided_by(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        decided_by: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT d.* FROM gov_certification_decisions d
            INNER JOIN gov_certification_items i ON i.id = d.item_id
            WHERE d.decided_by = $1 AND i.tenant_id = $2
            ORDER BY d.decided_at DESC
            LIMIT $3 OFFSET $4
            ",
        )
        .bind(decided_by)
        .bind(tenant_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

    /// Count decisions for a campaign.
    pub async fn count_by_campaign(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        campaign_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM gov_certification_decisions d
            JOIN gov_certification_items i ON d.item_id = i.id
            WHERE i.tenant_id = $1 AND i.campaign_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(campaign_id)
        .fetch_one(pool)
        .await
    }

    /// Count revocations for a campaign.
    pub async fn count_revocations_by_campaign(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        campaign_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM gov_certification_decisions d
            JOIN gov_certification_items i ON d.item_id = i.id
            WHERE i.tenant_id = $1 AND i.campaign_id = $2 AND d.decision_type = 'revoked'
            ",
        )
        .bind(tenant_id)
        .bind(campaign_id)
        .fetch_one(pool)
        .await
    }

    /// Create a new certification decision.
    pub async fn create(
        pool: &sqlx::PgPool,
        input: CreateCertificationDecision,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO gov_certification_decisions (
                item_id, decision_type, justification, decided_by
            )
            VALUES ($1, $2, $3, $4)
            RETURNING *
            ",
        )
        .bind(input.item_id)
        .bind(input.decision_type)
        .bind(&input.justification)
        .bind(input.decided_by)
        .fetch_one(pool)
        .await
    }

    /// Check if this is a revocation decision.
    #[must_use]
    pub fn is_revoked(&self) -> bool {
        self.decision_type.is_revoked()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decision_type_is_revoked() {
        assert!(CertDecisionType::Revoked.is_revoked());
        assert!(!CertDecisionType::Approved.is_revoked());
    }

    #[test]
    fn test_decision_type_serialization() {
        let approved = CertDecisionType::Approved;
        let json = serde_json::to_string(&approved).unwrap();
        assert_eq!(json, "\"approved\"");

        let revoked = CertDecisionType::Revoked;
        let json = serde_json::to_string(&revoked).unwrap();
        assert_eq!(json, "\"revoked\"");
    }

    #[test]
    fn test_create_decision_request() {
        let request = CreateCertificationDecision {
            item_id: Uuid::new_v4(),
            decision_type: CertDecisionType::Revoked,
            justification: Some("User no longer needs access to this system.".to_string()),
            decided_by: Uuid::new_v4(),
        };

        assert!(request.decision_type.is_revoked());
        assert!(request.justification.is_some());
    }

    #[test]
    fn decision_lookups_join_item_tenant() {
        let src = include_str!("gov_certification_decision.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            production.contains("INNER JOIN gov_certification_items i ON i.id = d.item_id"),
            "decision lookups must join certification items"
        );
        assert!(
            production.contains("AND i.tenant_id = $2"),
            "decision lookups must filter item tenant_id"
        );
        assert!(
            !production
                .contains("FROM gov_certification_decisions\n            WHERE item_id = $1"),
            "must not look up decisions by item_id alone"
        );
        assert!(
            !production.contains("FROM gov_certification_decisions\n            WHERE id = $1"),
            "must not look up decisions by id alone"
        );
        assert!(
            !production
                .contains("FROM gov_certification_decisions\n            WHERE decided_by = $1"),
            "must not list decisions by decided_by alone"
        );
    }

    #[test]
    fn test_create_approval_decision() {
        let request = CreateCertificationDecision {
            item_id: Uuid::new_v4(),
            decision_type: CertDecisionType::Approved,
            justification: None,
            decided_by: Uuid::new_v4(),
        };

        assert!(!request.decision_type.is_revoked());
        assert!(request.justification.is_none());
    }
}
