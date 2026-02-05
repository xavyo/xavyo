//! User management service.
//!
//! Handles CRUD operations for users within a tenant context.

use crate::error::{ApiUsersError, FieldValidationError};
use crate::models::{
    CreateUserRequest, CustomAttributeFilter, FilterOperator, LifecycleStateInfo, ListUsersQuery,
    PaginationMeta, UpdateUserRequest, UserListResponse, UserResponse,
};
use crate::validation::{validate_email, validate_username};
use sqlx::PgPool;
use xavyo_auth::PasswordHasher;
use xavyo_core::{TenantId, UserId};
use xavyo_db::User;

/// Service for user management operations.
///
/// All operations are scoped to a tenant, enforcing multi-tenant isolation.
#[derive(Clone)]
pub struct UserService {
    pool: PgPool,
    password_hasher: PasswordHasher,
}

impl UserService {
    /// Create a new user service.
    ///
    /// # Arguments
    ///
    /// * `pool` - Database connection pool
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            password_hasher: PasswordHasher::default(),
        }
    }

    /// Get the database pool reference.
    ///
    /// This is useful for testing and direct database operations.
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// List users for a tenant with pagination, optional email filter, and custom attribute filters.
    ///
    /// # Arguments
    ///
    /// * `tenant_id` - The tenant to list users for
    /// * `query` - Query parameters (offset, limit, email filter)
    /// * `custom_attr_filters` - Optional custom attribute filters parsed from query string
    ///
    /// # Returns
    ///
    /// A `UserListResponse` containing the users and pagination metadata.
    ///
    /// # Errors
    ///
    /// Returns `ApiUsersError::Database` if the database query fails.
    /// Returns `ApiUsersError::Validation` if a custom attribute filter name is invalid.
    pub async fn list_users(
        &self,
        tenant_id: TenantId,
        query: &ListUsersQuery,
        custom_attr_filters: &[CustomAttributeFilter],
    ) -> Result<UserListResponse, ApiUsersError> {
        let offset = query.offset();
        let limit = query.limit();

        // Validate custom attribute filter names to prevent SQL injection.
        // Attribute names must match the DB constraint: ^[a-z][a-z0-9_]{0,63}$
        // SECURITY: Compile regex once using LazyLock to avoid panic on every request
        use std::sync::LazyLock;
        static ATTR_NAME_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
            regex::Regex::new(r"^[a-z][a-z0-9_]{0,63}$")
                .expect("ATTR_NAME_RE is a valid regex pattern")
        });
        for f in custom_attr_filters {
            if !ATTR_NAME_RE.is_match(&f.attribute_name) {
                return Err(ApiUsersError::Validation(format!(
                    "Invalid custom attribute filter name: '{}'. Must be lowercase alphanumeric with underscores.",
                    f.attribute_name
                )));
            }
        }

        // Build dynamic WHERE clause fragments for custom attribute filters.
        // Since attribute names are validated against a strict regex, they are safe
        // to interpolate. Values are bound as parameters.
        let custom_attr_clauses = build_custom_attr_filter_clauses(custom_attr_filters);

        // Build count query dynamically
        let total_count: i64 = {
            let mut sql = String::from("SELECT COUNT(*) FROM users WHERE tenant_id = $1");
            let mut param_idx: usize = 2;

            if query.email.is_some() {
                sql.push_str(&format!(" AND LOWER(email) LIKE ${param_idx}"));
                param_idx += 1;
            }

            for clause in &custom_attr_clauses {
                sql.push_str(&format!(" AND {}", clause.sql_fragment(param_idx)));
                param_idx += 1;
            }

            let mut q = sqlx::query_scalar::<_, i64>(&sql).bind(tenant_id.as_uuid());

            if let Some(email_filter) = &query.email {
                let pattern = format!("%{}%", email_filter.to_lowercase());
                q = q.bind(pattern);
            }

            for clause in &custom_attr_clauses {
                q = clause.bind_value(q);
            }

            q.fetch_one(&self.pool).await?
        };

        // Build data query dynamically
        let users: Vec<User> = {
            let mut sql = String::from("SELECT * FROM users WHERE tenant_id = $1");
            let mut param_idx: usize = 2;

            if query.email.is_some() {
                sql.push_str(&format!(" AND LOWER(email) LIKE ${param_idx}"));
                param_idx += 1;
            }

            for clause in &custom_attr_clauses {
                sql.push_str(&format!(" AND {}", clause.sql_fragment(param_idx)));
                param_idx += 1;
            }

            sql.push_str(&format!(
                " ORDER BY created_at DESC LIMIT ${param_idx} OFFSET ${}",
                param_idx + 1
            ));

            let mut q = sqlx::query_as::<_, User>(&sql).bind(tenant_id.as_uuid());

            if let Some(email_filter) = &query.email {
                let pattern = format!("%{}%", email_filter.to_lowercase());
                q = q.bind(pattern);
            }

            for clause in &custom_attr_clauses {
                q = clause.bind_value_query_as(q);
            }

            q = q.bind(limit).bind(offset);

            q.fetch_all(&self.pool).await?
        };

        // Fetch roles for all users in a single query to avoid N+1
        let user_ids: Vec<uuid::Uuid> = users.iter().map(|u| u.id).collect();
        let all_roles: Vec<(uuid::Uuid, String)> = if user_ids.is_empty() {
            Vec::new()
        } else {
            sqlx::query_as(
                r"
                SELECT user_id, role_name FROM user_roles
                WHERE user_id = ANY($1)
                ORDER BY user_id, role_name
                ",
            )
            .bind(&user_ids)
            .fetch_all(&self.pool)
            .await?
        };

        // Group roles by user_id
        let mut roles_map: std::collections::HashMap<uuid::Uuid, Vec<String>> =
            std::collections::HashMap::new();
        for (user_id, role_name) in all_roles {
            roles_map.entry(user_id).or_default().push(role_name);
        }

        // Fetch lifecycle states for users that have them (F052)
        let lifecycle_state_ids: Vec<uuid::Uuid> =
            users.iter().filter_map(|u| u.lifecycle_state_id).collect();
        let lifecycle_states: Vec<(uuid::Uuid, String, bool)> = if lifecycle_state_ids.is_empty() {
            Vec::new()
        } else {
            sqlx::query_as(
                r"
                SELECT id, name, is_terminal
                FROM gov_lifecycle_states
                WHERE id = ANY($1)
                ",
            )
            .bind(&lifecycle_state_ids)
            .fetch_all(&self.pool)
            .await
            .unwrap_or_default()
        };

        // Build lifecycle state map
        let lifecycle_map: std::collections::HashMap<uuid::Uuid, LifecycleStateInfo> =
            lifecycle_states
                .into_iter()
                .map(|(id, name, is_terminal)| {
                    (
                        id,
                        LifecycleStateInfo {
                            id,
                            name,
                            is_terminal,
                        },
                    )
                })
                .collect();

        // Build responses
        let user_responses: Vec<UserResponse> = users
            .iter()
            .map(|user| {
                let roles = roles_map.remove(&user.id).unwrap_or_default();
                let lifecycle_state = user
                    .lifecycle_state_id
                    .and_then(|id| lifecycle_map.get(&id).cloned());
                user_to_response(user, roles, lifecycle_state)
            })
            .collect();

        let pagination = PaginationMeta::new(total_count, offset, limit);

        tracing::debug!(
            tenant_id = %tenant_id,
            total_count = total_count,
            returned = user_responses.len(),
            offset = offset,
            limit = limit,
            "Listed users"
        );

        Ok(UserListResponse {
            users: user_responses,
            pagination,
        })
    }

    /// Create a new user in the tenant.
    ///
    /// # Arguments
    ///
    /// * `tenant_id` - The tenant to create the user in
    /// * `request` - The create user request containing email, password, and roles
    ///
    /// # Returns
    ///
    /// The created user as a `UserResponse`.
    ///
    /// # Errors
    ///
    /// - `ApiUsersError::Validation` if email or password is invalid
    /// - `ApiUsersError::EmailConflict` if email already exists in tenant
    /// - `ApiUsersError::Database` if the database operation fails
    pub async fn create_user(
        &self,
        tenant_id: TenantId,
        request: &CreateUserRequest,
    ) -> Result<UserResponse, ApiUsersError> {
        // Collect all validation errors
        let mut validation_errors = Vec::new();

        // Validate email using RFC 5322 compliant validator
        let email = request.email.trim().to_lowercase();
        if let Err(err) = validate_email(&email) {
            validation_errors.push(FieldValidationError::from(err));
        }

        // Validate username if provided
        if let Some(ref username) = request.username {
            if let Err(err) = validate_username(username) {
                validation_errors.push(FieldValidationError::from(err));
            }
        }

        // Validate password
        if request.password.len() < 8 {
            validation_errors.push(FieldValidationError {
                field: "password".to_string(),
                code: "too_short".to_string(),
                message: "Password must be at least 8 characters".to_string(),
                constraints: Some(
                    serde_json::json!({"min_length": 8, "actual": request.password.len()}),
                ),
            });
        }

        // Validate roles
        if request.roles.is_empty() {
            validation_errors.push(FieldValidationError {
                field: "roles".to_string(),
                code: "required".to_string(),
                message: "At least one role is required".to_string(),
                constraints: None,
            });
        }
        for (i, role) in request.roles.iter().enumerate() {
            if role.is_empty() {
                validation_errors.push(FieldValidationError {
                    field: format!("roles[{i}]"),
                    code: "empty".to_string(),
                    message: "Role name cannot be empty".to_string(),
                    constraints: None,
                });
            } else if role.len() > 50 {
                validation_errors.push(FieldValidationError {
                    field: format!("roles[{i}]"),
                    code: "too_long".to_string(),
                    message: "Role name must not exceed 50 characters".to_string(),
                    constraints: Some(serde_json::json!({"max_length": 50, "actual": role.len()})),
                });
            }
        }

        // Return all validation errors at once
        if !validation_errors.is_empty() {
            return Err(ApiUsersError::ValidationErrors {
                errors: validation_errors,
            });
        }

        // Check if email already exists in tenant
        let exists: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE tenant_id = $1 AND email = $2")
                .bind(tenant_id.as_uuid())
                .bind(&email)
                .fetch_one(&self.pool)
                .await?;

        if exists > 0 {
            return Err(ApiUsersError::EmailConflict);
        }

        // Hash password
        let password_hash = self
            .password_hasher
            .hash(&request.password)
            .map_err(|e| ApiUsersError::Internal(format!("Password hashing failed: {e}")))?;

        // Create user in transaction
        let mut tx = self.pool.begin().await?;

        // Set tenant context for RLS defense-in-depth
        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(tenant_id.as_uuid().to_string())
            .execute(&mut *tx)
            .await?;

        let user_id = uuid::Uuid::new_v4();
        let now = chrono::Utc::now();

        sqlx::query(
            r"
            INSERT INTO users (id, tenant_id, email, password_hash, is_active, email_verified, created_at, updated_at)
            VALUES ($1, $2, $3, $4, true, false, $5, $5)
            ",
        )
        .bind(user_id)
        .bind(tenant_id.as_uuid())
        .bind(&email)
        .bind(&password_hash)
        .bind(now)
        .execute(&mut *tx)
        .await?;

        // Insert roles
        for role in &request.roles {
            sqlx::query(
                r"
                INSERT INTO user_roles (user_id, role_name, created_at)
                VALUES ($1, $2, $3)
                ON CONFLICT (user_id, role_name) DO NOTHING
                ",
            )
            .bind(user_id)
            .bind(role)
            .bind(now)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;

        tracing::info!(
            user_id = %user_id,
            tenant_id = %tenant_id,
            email = %email,
            roles = ?request.roles,
            "User created"
        );

        Ok(UserResponse {
            id: user_id,
            email,
            is_active: true,
            email_verified: false,
            roles: request.roles.clone(),
            created_at: now,
            updated_at: now,
            lifecycle_state: None,
            custom_attributes: serde_json::json!({}),
        })
    }

    /// Get a user by ID within a tenant.
    ///
    /// # Arguments
    ///
    /// * `tenant_id` - The tenant to search in
    /// * `user_id` - The user ID to look up
    ///
    /// # Returns
    ///
    /// The user as a `UserResponse`.
    ///
    /// # Errors
    ///
    /// - `ApiUsersError::NotFound` if user doesn't exist or belongs to different tenant
    /// - `ApiUsersError::Database` if the database query fails
    pub async fn get_user(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> Result<UserResponse, ApiUsersError> {
        let user: Option<User> = sqlx::query_as(
            r"
            SELECT *
            FROM users
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(user_id.as_uuid())
        .bind(tenant_id.as_uuid())
        .fetch_optional(&self.pool)
        .await?;

        let user = user.ok_or(ApiUsersError::NotFound)?;

        // Fetch roles
        let roles: Vec<String> = sqlx::query_scalar(
            r"
            SELECT role_name FROM user_roles
            WHERE user_id = $1
            ORDER BY role_name
            ",
        )
        .bind(user.id)
        .fetch_all(&self.pool)
        .await?;

        // Fetch lifecycle state if present (F052)
        let lifecycle_state = if let Some(state_id) = user.lifecycle_state_id {
            let state: Option<(uuid::Uuid, String, bool)> = sqlx::query_as(
                r"
                SELECT id, name, is_terminal
                FROM gov_lifecycle_states
                WHERE id = $1
                ",
            )
            .bind(state_id)
            .fetch_optional(&self.pool)
            .await
            .ok()
            .flatten();
            state.map(|(id, name, is_terminal)| LifecycleStateInfo {
                id,
                name,
                is_terminal,
            })
        } else {
            None
        };

        tracing::debug!(
            user_id = %user_id,
            tenant_id = %tenant_id,
            "Fetched user"
        );

        Ok(user_to_response(&user, roles, lifecycle_state))
    }

    /// Update a user's email, roles, or active status.
    ///
    /// # Arguments
    ///
    /// * `tenant_id` - The tenant the user belongs to
    /// * `user_id` - The user ID to update
    /// * `request` - The update request with optional fields
    ///
    /// # Returns
    ///
    /// The updated user as a `UserResponse`.
    ///
    /// # Errors
    ///
    /// - `ApiUsersError::NotFound` if user doesn't exist or belongs to different tenant
    /// - `ApiUsersError::Validation` if new email is invalid
    /// - `ApiUsersError::EmailConflict` if new email already exists in tenant
    /// - `ApiUsersError::Database` if the database operation fails
    pub async fn update_user(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        request: &UpdateUserRequest,
    ) -> Result<UserResponse, ApiUsersError> {
        // Check user exists in tenant
        let user: Option<User> = sqlx::query_as(
            r"
            SELECT *
            FROM users
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(user_id.as_uuid())
        .bind(tenant_id.as_uuid())
        .fetch_optional(&self.pool)
        .await?;

        let mut user = user.ok_or(ApiUsersError::NotFound)?;

        let mut tx = self.pool.begin().await?;

        // Set tenant context for RLS defense-in-depth
        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(tenant_id.as_uuid().to_string())
            .execute(&mut *tx)
            .await?;

        let now = chrono::Utc::now();
        let mut updated = false;

        // Validate all provided fields first
        let mut validation_errors = Vec::new();

        // Validate email if provided
        if let Some(ref new_email) = request.email {
            let email_trimmed = new_email.trim().to_lowercase();
            if let Err(err) = validate_email(&email_trimmed) {
                validation_errors.push(FieldValidationError::from(err));
            }
        }

        // Validate username if provided
        if let Some(ref username) = request.username {
            if let Err(err) = validate_username(username) {
                validation_errors.push(FieldValidationError::from(err));
            }
        }

        // Validate roles if provided
        if let Some(ref new_roles) = request.roles {
            if new_roles.is_empty() {
                validation_errors.push(FieldValidationError {
                    field: "roles".to_string(),
                    code: "required".to_string(),
                    message: "At least one role is required".to_string(),
                    constraints: None,
                });
            }
            for (i, role) in new_roles.iter().enumerate() {
                if role.is_empty() {
                    validation_errors.push(FieldValidationError {
                        field: format!("roles[{i}]"),
                        code: "empty".to_string(),
                        message: "Role name cannot be empty".to_string(),
                        constraints: None,
                    });
                } else if role.len() > 50 {
                    validation_errors.push(FieldValidationError {
                        field: format!("roles[{i}]"),
                        code: "too_long".to_string(),
                        message: "Role name must not exceed 50 characters".to_string(),
                        constraints: Some(
                            serde_json::json!({"max_length": 50, "actual": role.len()}),
                        ),
                    });
                }
            }
        }

        // Return all validation errors at once
        if !validation_errors.is_empty() {
            return Err(ApiUsersError::ValidationErrors {
                errors: validation_errors,
            });
        }

        // Update email if provided
        if let Some(ref new_email) = request.email {
            let email = new_email.trim().to_lowercase();

            // Check if email is different and not already taken
            if email != user.email {
                let exists: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM users WHERE tenant_id = $1 AND email = $2 AND id != $3",
                )
                .bind(tenant_id.as_uuid())
                .bind(&email)
                .bind(user_id.as_uuid())
                .fetch_one(&mut *tx)
                .await?;

                if exists > 0 {
                    return Err(ApiUsersError::EmailConflict);
                }

                sqlx::query(
                    "UPDATE users SET email = $1, updated_at = $2 WHERE id = $3 AND tenant_id = $4",
                )
                .bind(&email)
                .bind(now)
                .bind(user_id.as_uuid())
                .bind(tenant_id.as_uuid())
                .execute(&mut *tx)
                .await?;

                user.email = email;
                updated = true;
            }
        }

        // Update is_active if provided
        if let Some(is_active) = request.is_active {
            if is_active != user.is_active {
                sqlx::query("UPDATE users SET is_active = $1, updated_at = $2 WHERE id = $3 AND tenant_id = $4")
                    .bind(is_active)
                    .bind(now)
                    .bind(user_id.as_uuid())
                    .bind(tenant_id.as_uuid())
                    .execute(&mut *tx)
                    .await?;

                user.is_active = is_active;
                updated = true;
            }
        }

        // Update roles if provided (validation done upfront)
        let roles = if let Some(ref new_roles) = request.roles {
            // Delete existing roles and insert new ones
            sqlx::query("DELETE FROM user_roles WHERE user_id = $1")
                .bind(user_id.as_uuid())
                .execute(&mut *tx)
                .await?;

            for role in new_roles {
                sqlx::query(
                    r"
                    INSERT INTO user_roles (user_id, role_name, created_at)
                    VALUES ($1, $2, $3)
                    ",
                )
                .bind(user_id.as_uuid())
                .bind(role)
                .bind(now)
                .execute(&mut *tx)
                .await?;
            }

            // Update timestamp
            sqlx::query("UPDATE users SET updated_at = $1 WHERE id = $2 AND tenant_id = $3")
                .bind(now)
                .bind(user_id.as_uuid())
                .bind(tenant_id.as_uuid())
                .execute(&mut *tx)
                .await?;

            new_roles.clone()
        } else {
            // Fetch current roles
            sqlx::query_scalar(
                "SELECT role_name FROM user_roles WHERE user_id = $1 ORDER BY role_name",
            )
            .bind(user_id.as_uuid())
            .fetch_all(&mut *tx)
            .await?
        };

        tx.commit().await?;

        if updated || request.roles.is_some() {
            user.updated_at = now;
        }

        // Fetch lifecycle state if present (F052)
        let lifecycle_state = if let Some(state_id) = user.lifecycle_state_id {
            let state: Option<(uuid::Uuid, String, bool)> = sqlx::query_as(
                r"
                SELECT id, name, is_terminal
                FROM gov_lifecycle_states
                WHERE id = $1
                ",
            )
            .bind(state_id)
            .fetch_optional(&self.pool)
            .await
            .ok()
            .flatten();
            state.map(|(id, name, is_terminal)| LifecycleStateInfo {
                id,
                name,
                is_terminal,
            })
        } else {
            None
        };

        tracing::info!(
            user_id = %user_id,
            tenant_id = %tenant_id,
            "User updated"
        );

        Ok(user_to_response(&user, roles, lifecycle_state))
    }

    /// Deactivate a user (soft delete).
    ///
    /// Sets the user's `is_active` flag to false.
    /// This is idempotent - succeeds even if user is already deactivated.
    ///
    /// # Arguments
    ///
    /// * `tenant_id` - The tenant the user belongs to
    /// * `user_id` - The user ID to deactivate
    ///
    /// # Errors
    ///
    /// - `ApiUsersError::NotFound` if user doesn't exist or belongs to different tenant
    /// - `ApiUsersError::Database` if the database operation fails
    pub async fn deactivate_user(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> Result<(), ApiUsersError> {
        let result = sqlx::query(
            r"
            UPDATE users SET is_active = false, updated_at = $1
            WHERE id = $2 AND tenant_id = $3
            ",
        )
        .bind(chrono::Utc::now())
        .bind(user_id.as_uuid())
        .bind(tenant_id.as_uuid())
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(ApiUsersError::NotFound);
        }

        tracing::info!(
            user_id = %user_id,
            tenant_id = %tenant_id,
            "User deactivated"
        );

        Ok(())
    }
}

// ── Custom attribute filter helpers (US3) ──

/// A prepared SQL clause for a custom attribute filter.
///
/// Attribute names are validated before reaching this struct, so they are safe
/// to interpolate into SQL. Values are bound as parameters.
struct FilterClause {
    /// The validated attribute name.
    attribute_name: String,
    /// SQL comparison operator.
    sql_operator: &'static str,
    /// The string value to compare against.
    value: String,
}

impl FilterClause {
    /// Generate the SQL fragment using the given parameter index for the value.
    ///
    /// For equality, uses JSONB containment: `custom_attributes @> $N::jsonb`
    /// For range operators, casts the JSONB text value for comparison:
    /// `(custom_attributes->>'{name}') {op} $N`
    fn sql_fragment(&self, param_idx: usize) -> String {
        if self.sql_operator == "=" {
            // Equality uses JSONB containment operator for GIN index efficiency
            format!("custom_attributes @> ${param_idx}::jsonb")
        } else {
            // Range operators compare extracted text value
            format!(
                "(custom_attributes->>'{}') {} ${param_idx}",
                self.attribute_name, self.sql_operator
            )
        }
    }

    /// Bind the filter value for a `query_scalar` (count query).
    fn bind_value<'q>(
        &'q self,
        q: sqlx::query::QueryScalar<'q, sqlx::Postgres, i64, sqlx::postgres::PgArguments>,
    ) -> sqlx::query::QueryScalar<'q, sqlx::Postgres, i64, sqlx::postgres::PgArguments> {
        if self.sql_operator == "=" {
            // Build containment JSON: {"attr_name": "value"}
            let json_val = serde_json::json!({ &self.attribute_name: &self.value });
            q.bind(json_val)
        } else {
            q.bind(self.value.clone())
        }
    }

    /// Bind the filter value for a `query_as<User>` (data query).
    fn bind_value_query_as<'q>(
        &'q self,
        q: sqlx::query::QueryAs<'q, sqlx::Postgres, User, sqlx::postgres::PgArguments>,
    ) -> sqlx::query::QueryAs<'q, sqlx::Postgres, User, sqlx::postgres::PgArguments> {
        if self.sql_operator == "=" {
            let json_val = serde_json::json!({ &self.attribute_name: &self.value });
            q.bind(json_val)
        } else {
            q.bind(self.value.clone())
        }
    }
}

/// Build filter clauses from parsed custom attribute filters.
fn build_custom_attr_filter_clauses(filters: &[CustomAttributeFilter]) -> Vec<FilterClause> {
    filters
        .iter()
        .map(|f| {
            let sql_operator = match f.operator {
                FilterOperator::Eq => "=",
                FilterOperator::Lt => "<",
                FilterOperator::Gt => ">",
                FilterOperator::Lte => "<=",
                FilterOperator::Gte => ">=",
            };
            FilterClause {
                attribute_name: f.attribute_name.clone(),
                sql_operator,
                value: f.value.clone(),
            }
        })
        .collect()
}

/// Convert a User entity and roles to a `UserResponse`.
///
/// This is a helper function to build API responses from database entities.
#[must_use]
pub fn user_to_response(
    user: &User,
    roles: Vec<String>,
    lifecycle_state: Option<LifecycleStateInfo>,
) -> UserResponse {
    UserResponse {
        id: user.id,
        email: user.email.clone(),
        is_active: user.is_active,
        email_verified: user.email_verified,
        roles,
        created_at: user.created_at,
        updated_at: user.updated_at,
        lifecycle_state,
        custom_attributes: user.custom_attributes.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_user_to_response() {
        let user = User {
            id: uuid::Uuid::new_v4(),
            tenant_id: uuid::Uuid::new_v4(),
            email: "test@example.com".to_string(),
            password_hash: "hash".to_string(),
            display_name: Some("Test User".to_string()),
            is_active: true,
            email_verified: false,
            email_verified_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            external_id: None,
            first_name: None,
            last_name: None,
            scim_provisioned: false,
            scim_last_sync: None,
            // Lockout tracking fields (F024)
            failed_login_count: 0,
            last_failed_login_at: None,
            locked_at: None,
            locked_until: None,
            lockout_reason: None,
            // Password expiration tracking fields (F024)
            password_changed_at: None,
            password_expires_at: None,
            must_change_password: false,
            // Self-service profile fields (F027)
            avatar_url: None,
            // Object Lifecycle States (F052)
            lifecycle_state_id: None,
            // Manager hierarchy (F054)
            manager_id: None,
            // Custom attributes (F070)
            custom_attributes: serde_json::json!({}),
        };

        let roles = vec!["admin".to_string(), "user".to_string()];
        let response = user_to_response(&user, roles.clone(), None);

        assert_eq!(response.id, user.id);
        assert_eq!(response.email, user.email);
        assert_eq!(response.is_active, user.is_active);
        assert_eq!(response.email_verified, user.email_verified);
        assert_eq!(response.roles, roles);
        assert!(response.lifecycle_state.is_none());
    }

    #[test]
    fn test_user_to_response_with_lifecycle_state() {
        let user = User {
            id: uuid::Uuid::new_v4(),
            tenant_id: uuid::Uuid::new_v4(),
            email: "test@example.com".to_string(),
            password_hash: "hash".to_string(),
            display_name: Some("Test User".to_string()),
            is_active: true,
            email_verified: false,
            email_verified_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            external_id: None,
            first_name: None,
            last_name: None,
            scim_provisioned: false,
            scim_last_sync: None,
            failed_login_count: 0,
            last_failed_login_at: None,
            locked_at: None,
            locked_until: None,
            lockout_reason: None,
            password_changed_at: None,
            password_expires_at: None,
            must_change_password: false,
            avatar_url: None,
            lifecycle_state_id: Some(uuid::Uuid::new_v4()),
            // Manager hierarchy (F054)
            manager_id: None,
            // Custom attributes (F070)
            custom_attributes: serde_json::json!({}),
        };

        let roles = vec!["user".to_string()];
        let state_id = uuid::Uuid::new_v4();
        let lifecycle_state = Some(LifecycleStateInfo {
            id: state_id,
            name: "Active".to_string(),
            is_terminal: false,
        });
        let response = user_to_response(&user, roles.clone(), lifecycle_state.clone());

        assert_eq!(response.lifecycle_state.as_ref().unwrap().id, state_id);
        assert_eq!(
            response.lifecycle_state.as_ref().unwrap().name,
            "Active".to_string()
        );
        assert!(!response.lifecycle_state.as_ref().unwrap().is_terminal);
    }
}
