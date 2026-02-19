//! Identity Provider Domain model for Home Realm Discovery.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Identity Provider Domain entity for HRD.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct IdentityProviderDomain {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub identity_provider_id: Uuid,
    pub domain: String,
    pub priority: i32,
    pub created_at: DateTime<Utc>,
}

/// Input for creating a new domain mapping.
#[derive(Debug, Clone)]
pub struct CreateDomain {
    pub tenant_id: Uuid,
    pub identity_provider_id: Uuid,
    pub domain: String,
    pub priority: i32,
}

impl IdentityProviderDomain {
    /// Validate domain format.
    #[must_use]
    pub fn validate_domain(domain: &str) -> bool {
        // Domain must start and end with alphanumeric, contain only alphanumeric, dots, and hyphens
        let domain = domain.to_lowercase();
        if domain.len() < 3 || domain.len() > 255 {
            return false;
        }

        let chars: Vec<char> = domain.chars().collect();

        // Must start with alphanumeric
        if !chars[0].is_ascii_alphanumeric() {
            return false;
        }

        // Must end with alphanumeric
        if !chars[chars.len() - 1].is_ascii_alphanumeric() {
            return false;
        }

        // All characters must be alphanumeric, dot, or hyphen
        for c in &chars {
            if !c.is_ascii_alphanumeric() && *c != '.' && *c != '-' {
                return false;
            }
        }

        // No consecutive dots
        if domain.contains("..") {
            return false;
        }

        true
    }

    /// Create a new domain mapping.
    pub async fn create(pool: &sqlx::PgPool, input: CreateDomain) -> Result<Self, sqlx::Error> {
        let domain = input.domain.to_lowercase();
        sqlx::query_as(
            r"
            INSERT INTO identity_provider_domains (
                tenant_id, identity_provider_id, domain, priority
            )
            VALUES ($1, $2, $3, $4)
            RETURNING *
            ",
        )
        .bind(input.tenant_id)
        .bind(input.identity_provider_id)
        .bind(&domain)
        .bind(input.priority)
        .fetch_one(pool)
        .await
    }

    /// Find domain by ID with tenant isolation.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as("SELECT * FROM identity_provider_domains WHERE id = $1 AND tenant_id = $2")
            .bind(id)
            .bind(tenant_id)
            .fetch_optional(pool)
            .await
    }

    /// Find all domains for an identity provider within a tenant.
    pub async fn list_by_idp(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        identity_provider_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM identity_provider_domains
            WHERE tenant_id = $1 AND identity_provider_id = $2
            ORDER BY priority DESC, domain ASC
            ",
        )
        .bind(tenant_id)
        .bind(identity_provider_id)
        .fetch_all(pool)
        .await
    }

    /// Find identity provider for a domain (Home Realm Discovery).
    /// Returns the `IdP` with highest priority for the given domain.
    pub async fn find_idp_for_domain(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        domain: &str,
    ) -> Result<Option<Uuid>, sqlx::Error> {
        let domain = domain.to_lowercase();
        let result: Option<(Uuid,)> = sqlx::query_as(
            r"
            SELECT ipd.identity_provider_id
            FROM identity_provider_domains ipd
            JOIN tenant_identity_providers tip ON ipd.identity_provider_id = tip.id
            WHERE ipd.tenant_id = $1
              AND ipd.domain = $2
              AND tip.is_enabled = true
            ORDER BY ipd.priority DESC
            LIMIT 1
            ",
        )
        .bind(tenant_id)
        .bind(&domain)
        .fetch_optional(pool)
        .await?;

        Ok(result.map(|r| r.0))
    }

    /// Find domain entry by tenant and domain name (Home Realm Discovery).
    /// Returns the domain entry with highest priority.
    pub async fn find_by_domain(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        domain: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        let domain = domain.to_lowercase();
        sqlx::query_as(
            r"
            SELECT * FROM identity_provider_domains
            WHERE tenant_id = $1 AND domain = $2
            ORDER BY priority DESC
            LIMIT 1
            ",
        )
        .bind(tenant_id)
        .bind(&domain)
        .fetch_optional(pool)
        .await
    }

    /// Check if domain exists for this `IdP` within a tenant.
    pub async fn domain_exists_for_idp(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        identity_provider_id: Uuid,
        domain: &str,
    ) -> Result<bool, sqlx::Error> {
        let domain = domain.to_lowercase();
        let result: (bool,) = sqlx::query_as(
            r"
            SELECT EXISTS(
                SELECT 1 FROM identity_provider_domains
                WHERE tenant_id = $1 AND identity_provider_id = $2 AND domain = $3
            )
            ",
        )
        .bind(tenant_id)
        .bind(identity_provider_id)
        .bind(&domain)
        .fetch_one(pool)
        .await?;
        Ok(result.0)
    }

    /// Delete a domain mapping.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result =
            sqlx::query("DELETE FROM identity_provider_domains WHERE id = $1 AND tenant_id = $2")
                .bind(id)
                .bind(tenant_id)
                .execute(pool)
                .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Delete all domains for an `IdP`.
    pub async fn delete_by_idp(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        identity_provider_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            "DELETE FROM identity_provider_domains WHERE identity_provider_id = $1 AND tenant_id = $2",
        )
        .bind(identity_provider_id)
        .bind(tenant_id)
        .execute(pool)
        .await?;
        Ok(result.rows_affected())
    }
}
