//! Request Cart model for Self-Service Request Catalog (F-062).
//!
//! Persistent shopping cart for access requests.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// A request cart for collecting items before submission.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RequestCart {
    /// Unique identifier for the cart.
    pub id: Uuid,

    /// The tenant this cart belongs to.
    pub tenant_id: Uuid,

    /// User creating the request (requester).
    pub requester_id: Uuid,

    /// Target user for the request (NULL = self).
    pub beneficiary_id: Option<Uuid>,

    /// When the cart was created.
    pub created_at: DateTime<Utc>,

    /// When the cart was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Request to create a new cart.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreateRequestCart {
    /// User creating the request.
    pub requester_id: Uuid,

    /// Target user for the request (NULL = self).
    pub beneficiary_id: Option<Uuid>,
}

impl RequestCart {
    /// Find a cart by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM request_carts
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find a cart by requester and beneficiary.
    /// This is used to implement the "one cart per pair" constraint.
    pub async fn find_by_pair(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        requester_id: Uuid,
        beneficiary_id: Option<Uuid>,
    ) -> Result<Option<Self>, sqlx::Error> {
        if let Some(ben_id) = beneficiary_id {
            sqlx::query_as(
                r"
                SELECT * FROM request_carts
                WHERE tenant_id = $1 AND requester_id = $2 AND beneficiary_id = $3
                ",
            )
            .bind(tenant_id)
            .bind(requester_id)
            .bind(ben_id)
            .fetch_optional(pool)
            .await
        } else {
            sqlx::query_as(
                r"
                SELECT * FROM request_carts
                WHERE tenant_id = $1 AND requester_id = $2 AND beneficiary_id IS NULL
                ",
            )
            .bind(tenant_id)
            .bind(requester_id)
            .fetch_optional(pool)
            .await
        }
    }

    /// Get or create a cart for a requester/beneficiary pair.
    pub async fn get_or_create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        requester_id: Uuid,
        beneficiary_id: Option<Uuid>,
    ) -> Result<Self, sqlx::Error> {
        // First try to find existing cart
        if let Some(cart) =
            Self::find_by_pair(pool, tenant_id, requester_id, beneficiary_id).await?
        {
            return Ok(cart);
        }

        // Create new cart
        Self::create(
            pool,
            tenant_id,
            CreateRequestCart {
                requester_id,
                beneficiary_id,
            },
        )
        .await
    }

    /// List carts for a requester.
    pub async fn list_by_requester(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        requester_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM request_carts
            WHERE tenant_id = $1 AND requester_id = $2
            ORDER BY created_at DESC
            ",
        )
        .bind(tenant_id)
        .bind(requester_id)
        .fetch_all(pool)
        .await
    }

    /// Create a new cart.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateRequestCart,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO request_carts (tenant_id, requester_id, beneficiary_id)
            VALUES ($1, $2, $3)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(input.requester_id)
        .bind(input.beneficiary_id)
        .fetch_one(pool)
        .await
    }

    /// Delete a cart.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM request_carts
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Delete a cart by requester/beneficiary pair.
    pub async fn delete_by_pair(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        requester_id: Uuid,
        beneficiary_id: Option<Uuid>,
    ) -> Result<bool, sqlx::Error> {
        let result = if let Some(ben_id) = beneficiary_id {
            sqlx::query(
                r"
                DELETE FROM request_carts
                WHERE tenant_id = $1 AND requester_id = $2 AND beneficiary_id = $3
                ",
            )
            .bind(tenant_id)
            .bind(requester_id)
            .bind(ben_id)
            .execute(pool)
            .await?
        } else {
            sqlx::query(
                r"
                DELETE FROM request_carts
                WHERE tenant_id = $1 AND requester_id = $2 AND beneficiary_id IS NULL
                ",
            )
            .bind(tenant_id)
            .bind(requester_id)
            .execute(pool)
            .await?
        };

        Ok(result.rows_affected() > 0)
    }

    /// Touch the cart (update timestamp).
    pub async fn touch(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE request_carts
            SET updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Count items in this cart.
    pub async fn count_items(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        cart_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM request_cart_items
            WHERE tenant_id = $1 AND cart_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(cart_id)
        .fetch_one(pool)
        .await
    }

    /// Check if cart is empty.
    pub async fn is_empty(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        cart_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let count = Self::count_items(pool, tenant_id, cart_id).await?;
        Ok(count == 0)
    }

    /// Clear all items from a cart.
    pub async fn clear_items(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        cart_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM request_cart_items
            WHERE tenant_id = $1 AND cart_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(cart_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Check if this is a self-request cart.
    #[must_use]
    pub fn is_self_request(&self) -> bool {
        self.beneficiary_id.is_none()
    }

    /// Get the effective beneficiary ID (self if None).
    #[must_use]
    pub fn effective_beneficiary_id(&self) -> Uuid {
        self.beneficiary_id.unwrap_or(self.requester_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_cart_request() {
        let request = CreateRequestCart {
            requester_id: Uuid::new_v4(),
            beneficiary_id: None,
        };

        assert!(request.beneficiary_id.is_none());
    }

    #[test]
    fn test_cart_serialization() {
        let cart = RequestCart {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            requester_id: Uuid::new_v4(),
            beneficiary_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let json = serde_json::to_string(&cart).unwrap();
        assert!(json.contains("requester_id"));
    }

    #[test]
    fn test_is_self_request() {
        let self_cart = RequestCart {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            requester_id: Uuid::new_v4(),
            beneficiary_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        assert!(self_cart.is_self_request());

        let other_cart = RequestCart {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            requester_id: Uuid::new_v4(),
            beneficiary_id: Some(Uuid::new_v4()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        assert!(!other_cart.is_self_request());
    }

    #[test]
    fn test_effective_beneficiary_id() {
        let requester_id = Uuid::new_v4();
        let beneficiary_id = Uuid::new_v4();

        let self_cart = RequestCart {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            requester_id,
            beneficiary_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        assert_eq!(self_cart.effective_beneficiary_id(), requester_id);

        let other_cart = RequestCart {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            requester_id,
            beneficiary_id: Some(beneficiary_id),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        assert_eq!(other_cart.effective_beneficiary_id(), beneficiary_id);
    }
}
