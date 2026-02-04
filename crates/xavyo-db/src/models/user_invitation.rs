//! User invitation model (F086, F-ADMIN-INVITE).
//!
//! Represents an invitation sent to a user to set their password.
//! Supports both bulk import invitations (F086) and admin invitations (F-ADMIN-INVITE).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

/// A user invitation for password setup.
///
/// When users are imported via CSV or invited by an admin, they receive an email invitation
/// containing a secure, time-limited link to set their password and activate their account.
///
/// For bulk imports (F086): `job_id` is set, `user_id` points to existing user.
/// For admin invites (F-ADMIN-INVITE): `job_id` is NULL, `invited_by_user_id` is set,
/// `user_id` may be NULL (user created on acceptance).
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UserInvitation {
    /// Unique invitation identifier.
    pub id: Uuid,

    /// Tenant this invitation belongs to.
    pub tenant_id: Uuid,

    /// Invited user (NULL for admin invites where user doesn't exist yet).
    pub user_id: Option<Uuid>,

    /// Import job that created this (NULL if manual/admin invite).
    pub job_id: Option<Uuid>,

    /// SHA-256 hex hash of invitation token.
    pub token_hash: String,

    /// Invitation lifecycle state: pending, sent, accepted, expired, cancelled.
    pub status: String,

    /// Token expiry timestamp.
    pub expires_at: DateTime<Utc>,

    /// When email was successfully sent.
    pub sent_at: Option<DateTime<Utc>>,

    /// When user set password.
    pub accepted_at: Option<DateTime<Utc>>,

    /// IP of acceptance request (audit).
    pub ip_address: Option<String>,

    /// User-Agent of acceptance request (audit).
    pub user_agent: Option<String>,

    /// Record creation timestamp.
    pub created_at: DateTime<Utc>,

    /// Last update timestamp.
    pub updated_at: DateTime<Utc>,

    // F-ADMIN-INVITE extensions
    /// Admin user who created this invitation (NULL for bulk import).
    pub invited_by_user_id: Option<Uuid>,

    /// Role template to assign on acceptance (NULL for default role).
    pub role_template_id: Option<Uuid>,

    /// Invitee email address (for admin invites where user doesn't exist yet).
    pub email: Option<String>,
}

/// Data required to create a new invitation (F086 bulk import).
#[derive(Debug)]
pub struct CreateInvitation {
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub job_id: Option<Uuid>,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
}

/// Data required to create an admin invitation (F-ADMIN-INVITE).
#[derive(Debug)]
pub struct CreateAdminInvitation {
    pub tenant_id: Uuid,
    pub email: String,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub invited_by_user_id: Uuid,
    pub role_template_id: Option<Uuid>,
}

impl UserInvitation {
    /// Create a new invitation record (F086 bulk import).
    pub async fn create(pool: &PgPool, data: &CreateInvitation) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO user_invitations
                (tenant_id, user_id, job_id, token_hash, expires_at)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
            ",
        )
        .bind(data.tenant_id)
        .bind(data.user_id)
        .bind(data.job_id)
        .bind(&data.token_hash)
        .bind(data.expires_at)
        .fetch_one(pool)
        .await
    }

    /// Create an admin invitation (F-ADMIN-INVITE).
    ///
    /// Unlike bulk import invitations, admin invitations don't have a `user_id`
    /// initially - the user is created when the invitation is accepted.
    pub async fn create_admin_invitation(
        pool: &PgPool,
        data: &CreateAdminInvitation,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO user_invitations
                (tenant_id, email, token_hash, expires_at, invited_by_user_id, role_template_id)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING *
            ",
        )
        .bind(data.tenant_id)
        .bind(&data.email)
        .bind(&data.token_hash)
        .bind(data.expires_at)
        .bind(data.invited_by_user_id)
        .bind(data.role_template_id)
        .fetch_one(pool)
        .await
    }

    /// Find a pending invitation by email (for duplicate check).
    pub async fn find_by_email_pending(
        pool: &PgPool,
        tenant_id: Uuid,
        email: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM user_invitations
            WHERE tenant_id = $1 AND email = $2 AND status IN ('pending', 'sent')
            ORDER BY created_at DESC
            LIMIT 1
            ",
        )
        .bind(tenant_id)
        .bind(email)
        .fetch_optional(pool)
        .await
    }

    /// Find an invitation by ID within a tenant.
    pub async fn find_by_id(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM user_invitations
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Count pending invitations for a tenant (for rate limiting).
    pub async fn count_pending_by_tenant(
        pool: &PgPool,
        tenant_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        let row: (i64,) = sqlx::query_as(
            r"
            SELECT COUNT(*) FROM user_invitations
            WHERE tenant_id = $1 AND status IN ('pending', 'sent')
            ",
        )
        .bind(tenant_id)
        .fetch_one(pool)
        .await?;
        Ok(row.0)
    }

    /// List invitations for a tenant with optional filters.
    pub async fn list_by_tenant(
        pool: &PgPool,
        tenant_id: Uuid,
        status_filter: Option<&str>,
        email_search: Option<&str>,
        limit: i32,
        offset: i32,
    ) -> Result<Vec<Self>, sqlx::Error> {
        // Build dynamic query based on filters
        let mut query = String::from(
            r"
            SELECT * FROM user_invitations
            WHERE tenant_id = $1
            ",
        );

        let mut param_index = 2;

        if status_filter.is_some() {
            query.push_str(&format!(" AND status = ${param_index}"));
            param_index += 1;
        }

        if email_search.is_some() {
            query.push_str(&format!(" AND email ILIKE ${param_index}"));
            param_index += 1;
        }

        query.push_str(&format!(
            " ORDER BY created_at DESC LIMIT ${} OFFSET ${}",
            param_index,
            param_index + 1
        ));

        let mut q = sqlx::query_as::<_, Self>(&query).bind(tenant_id);

        if let Some(status) = status_filter {
            q = q.bind(status);
        }

        if let Some(email) = email_search {
            q = q.bind(format!("%{email}%"));
        }

        q = q.bind(limit).bind(offset);

        q.fetch_all(pool).await
    }

    /// Count invitations for a tenant with optional filters (for pagination).
    pub async fn count_by_tenant(
        pool: &PgPool,
        tenant_id: Uuid,
        status_filter: Option<&str>,
        email_search: Option<&str>,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT COUNT(*) FROM user_invitations
            WHERE tenant_id = $1
            ",
        );

        let mut param_index = 2;

        if status_filter.is_some() {
            query.push_str(&format!(" AND status = ${param_index}"));
            param_index += 1;
        }

        if email_search.is_some() {
            query.push_str(&format!(" AND email ILIKE ${param_index}"));
        }

        let mut q = sqlx::query_as::<_, (i64,)>(&query).bind(tenant_id);

        if let Some(status) = status_filter {
            q = q.bind(status);
        }

        if let Some(email) = email_search {
            q = q.bind(format!("%{email}%"));
        }

        let row = q.fetch_one(pool).await?;
        Ok(row.0)
    }

    /// Mark an invitation as cancelled.
    pub async fn mark_cancelled(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE user_invitations
            SET status = 'cancelled', updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status IN ('pending', 'sent')
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Update `user_id` after user creation on acceptance.
    pub async fn set_user_id(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE user_invitations
            SET user_id = $3, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(user_id)
        .fetch_optional(pool)
        .await
    }

    /// Invalidate all previous active invitations for an email (for resend).
    pub async fn invalidate_previous_by_email(
        pool: &PgPool,
        tenant_id: Uuid,
        email: &str,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE user_invitations
            SET status = 'expired', updated_at = NOW()
            WHERE tenant_id = $1 AND email = $2 AND status IN ('pending', 'sent')
            ",
        )
        .bind(tenant_id)
        .bind(email)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Refresh expiration for an invitation (for resend).
    pub async fn refresh_expiration(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
        new_token_hash: &str,
        new_expires_at: DateTime<Utc>,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE user_invitations
            SET token_hash = $3, expires_at = $4, status = 'pending', sent_at = NULL, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status IN ('pending', 'sent')
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(new_token_hash)
        .bind(new_expires_at)
        .fetch_optional(pool)
        .await
    }

    /// Find an invitation by token hash (for token validation/acceptance).
    pub async fn find_by_token_hash(
        pool: &PgPool,
        token_hash: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM user_invitations
            WHERE token_hash = $1
            ",
        )
        .bind(token_hash)
        .fetch_optional(pool)
        .await
    }

    /// Find the most recent active invitation for a user.
    pub async fn find_by_user_id(
        pool: &PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM user_invitations
            WHERE tenant_id = $1 AND user_id = $2
            ORDER BY created_at DESC
            LIMIT 1
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_optional(pool)
        .await
    }

    /// List invitations for an import job with optional status filter.
    pub async fn list_by_job(
        pool: &PgPool,
        tenant_id: Uuid,
        job_id: Uuid,
        status_filter: Option<&[&str]>,
    ) -> Result<Vec<Self>, sqlx::Error> {
        match status_filter {
            Some(statuses) if !statuses.is_empty() => {
                // Build IN clause for status filter
                let placeholders: Vec<String> = statuses
                    .iter()
                    .enumerate()
                    .map(|(i, _)| format!("${}", i + 3))
                    .collect();
                let in_clause = placeholders.join(", ");
                let query = format!(
                    r"
                    SELECT * FROM user_invitations
                    WHERE tenant_id = $1 AND job_id = $2 AND status IN ({in_clause})
                    ORDER BY created_at ASC
                    "
                );

                let mut q = sqlx::query_as::<_, Self>(&query)
                    .bind(tenant_id)
                    .bind(job_id);

                for status in statuses {
                    q = q.bind(*status);
                }

                q.fetch_all(pool).await
            }
            _ => {
                sqlx::query_as(
                    r"
                    SELECT * FROM user_invitations
                    WHERE tenant_id = $1 AND job_id = $2
                    ORDER BY created_at ASC
                    ",
                )
                .bind(tenant_id)
                .bind(job_id)
                .fetch_all(pool)
                .await
            }
        }
    }

    /// Mark an invitation as sent (email delivered).
    pub async fn mark_sent(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE user_invitations
            SET status = 'sent', sent_at = NOW(), updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Mark an invitation as accepted (user set password).
    ///
    /// Uses atomic WHERE clause with `status != 'accepted'` to prevent
    /// concurrent double-acceptance race conditions.
    pub async fn mark_accepted(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
        ip_address: Option<&str>,
        user_agent_str: Option<&str>,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE user_invitations
            SET status = 'accepted', accepted_at = NOW(), ip_address = $3, user_agent = $4, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status != 'accepted'
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(ip_address)
        .bind(user_agent_str)
        .fetch_optional(pool)
        .await
    }

    /// Invalidate all previous active invitations for a user (for resend).
    pub async fn invalidate_previous(
        pool: &PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE user_invitations
            SET status = 'expired', updated_at = NOW()
            WHERE tenant_id = $1 AND user_id = $2 AND status IN ('pending', 'sent')
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }
}
