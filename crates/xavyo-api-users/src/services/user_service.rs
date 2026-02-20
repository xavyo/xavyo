//! User management service.
//!
//! Handles CRUD operations for users within a tenant context.

use crate::error::{ApiUsersError, FieldValidationError};
use crate::models::{
    CreateUserRequest, CustomAttributeFilter, FilterOperator, LifecycleStateInfo, ListUsersQuery,
    PaginationMeta, UpdateUserRequest, UserListResponse, UserResponse,
};
use crate::validation::validate_email;
use sqlx::PgPool;
use xavyo_auth::PasswordHasher;
use xavyo_core::{TenantId, UserId};
use xavyo_db::{TenantPasswordPolicy, User};

/// Allowed role names that can be assigned to users.
const ALLOWED_ROLES: &[&str] = &["user", "member", "admin", "super_admin"];

/// Special characters recognised by the password policy.
/// Kept in sync with `PasswordPolicyService::SPECIAL_CHARS` in xavyo-api-auth.
const SPECIAL_CHARS: &str = "!@#$%^&*()_+-=[]{}|;:,.<>?";

/// Validate a password against the tenant's `TenantPasswordPolicy`.
///
/// Returns a list of `FieldValidationError`s (empty if valid).
fn validate_password_against_policy(
    password: &str,
    policy: &TenantPasswordPolicy,
) -> Vec<FieldValidationError> {
    let mut errors = Vec::new();
    let len = password.chars().count();

    if len < policy.min_length as usize {
        errors.push(FieldValidationError {
            field: "password".to_string(),
            code: "too_short".to_string(),
            message: format!("Password must be at least {} characters", policy.min_length),
            constraints: Some(serde_json::json!({"min_length": policy.min_length})),
        });
    }
    if len > policy.max_length as usize {
        errors.push(FieldValidationError {
            field: "password".to_string(),
            code: "too_long".to_string(),
            message: format!("Password must not exceed {} characters", policy.max_length),
            constraints: Some(serde_json::json!({"max_length": policy.max_length})),
        });
    }
    if policy.require_uppercase && !password.chars().any(|c| c.is_ascii_uppercase()) {
        errors.push(FieldValidationError {
            field: "password".to_string(),
            code: "missing_uppercase".to_string(),
            message: "Password must contain at least one uppercase letter".to_string(),
            constraints: None,
        });
    }
    if policy.require_lowercase && !password.chars().any(|c| c.is_ascii_lowercase()) {
        errors.push(FieldValidationError {
            field: "password".to_string(),
            code: "missing_lowercase".to_string(),
            message: "Password must contain at least one lowercase letter".to_string(),
            constraints: None,
        });
    }
    if policy.require_digit && !password.chars().any(|c| c.is_ascii_digit()) {
        errors.push(FieldValidationError {
            field: "password".to_string(),
            code: "missing_digit".to_string(),
            message: "Password must contain at least one digit".to_string(),
            constraints: None,
        });
    }
    if policy.require_special && !password.chars().any(|c| SPECIAL_CHARS.contains(c)) {
        errors.push(FieldValidationError {
            field: "password".to_string(),
            code: "missing_special".to_string(),
            message: "Password must contain at least one special character".to_string(),
            constraints: None,
        });
    }
    errors
}

/// Validate a list of roles and collect errors.
///
/// Checks: non-empty, max 20, each role non-empty/<=50 chars, all in allowlist.
fn validate_roles(roles: &[String]) -> Vec<FieldValidationError> {
    let mut errors = Vec::new();

    if roles.len() > 20 {
        errors.push(FieldValidationError {
            field: "roles".to_string(),
            code: "too_many".to_string(),
            message: "Cannot assign more than 20 roles".to_string(),
            constraints: Some(serde_json::json!({"max_count": 20})),
        });
    }
    if roles.is_empty() {
        errors.push(FieldValidationError {
            field: "roles".to_string(),
            code: "required".to_string(),
            message: "At least one role is required".to_string(),
            constraints: None,
        });
    }
    for (i, role) in roles.iter().enumerate() {
        if role.is_empty() {
            errors.push(FieldValidationError {
                field: format!("roles[{i}]"),
                code: "empty".to_string(),
                message: "Role name cannot be empty".to_string(),
                constraints: None,
            });
        } else if role.len() > 50 {
            errors.push(FieldValidationError {
                field: format!("roles[{i}]"),
                code: "too_long".to_string(),
                message: "Role name must not exceed 50 characters".to_string(),
                constraints: Some(serde_json::json!({"max_length": 50})),
            });
        } else if !ALLOWED_ROLES.contains(&role.as_str()) {
            errors.push(FieldValidationError {
                field: format!("roles[{i}]"),
                code: "invalid_role".to_string(),
                message: format!(
                    "Invalid role '{}'. Allowed roles: {}",
                    role,
                    ALLOWED_ROLES.join(", ")
                ),
                constraints: None,
            });
        }
    }

    errors
}

/// A-1: Escape ILIKE special characters (`%`, `_`, `\`) in a search pattern.
///
/// Returns a lowercased, escaped string suitable for use in `LOWER(col) LIKE $N`.
fn escape_ilike(input: &str) -> String {
    input
        .to_lowercase()
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

/// Check whether `caller_roles` are allowed to assign `target_roles`.
///
/// A caller without `super_admin` cannot assign `super_admin` to anyone.
fn check_role_assignment_privilege(
    caller_roles: &[String],
    target_roles: &[String],
) -> Result<(), ApiUsersError> {
    let caller_is_super = caller_roles.iter().any(|r| r == "super_admin");
    if !caller_is_super && target_roles.iter().any(|r| r == "super_admin") {
        return Err(ApiUsersError::Forbidden);
    }
    Ok(())
}

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

        // M-7: Cap email filter length to prevent DoS via huge LIKE patterns (RFC 5321 max = 254)
        if let Some(ref email) = query.email {
            if email.len() > 254 {
                return Err(ApiUsersError::Validation(
                    "Email filter too long (maximum 254 characters)".to_string(),
                ));
            }
        }

        // A-7: Cap the number of custom attribute filters to prevent DoS via large SQL
        if custom_attr_filters.len() > 20 {
            return Err(ApiUsersError::Validation(
                "Too many custom attribute filters (maximum 20)".to_string(),
            ));
        }

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

            // L3: Optional is_active filter
            if query.is_active.is_some() {
                sql.push_str(&format!(" AND is_active = ${param_idx}"));
                param_idx += 1;
            }

            if query.email.is_some() {
                sql.push_str(&format!(" AND LOWER(email) LIKE ${param_idx}"));
                param_idx += 1;
            }

            for clause in &custom_attr_clauses {
                sql.push_str(&format!(" AND {}", clause.sql_fragment(param_idx)));
                param_idx += 1;
            }

            let mut q = sqlx::query_scalar::<_, i64>(&sql).bind(tenant_id.as_uuid());

            if let Some(is_active) = query.is_active {
                q = q.bind(is_active);
            }

            if let Some(email_filter) = &query.email {
                let pattern = format!("%{}%", escape_ilike(email_filter));
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

            // L3: Optional is_active filter
            if query.is_active.is_some() {
                sql.push_str(&format!(" AND is_active = ${param_idx}"));
                param_idx += 1;
            }

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

            if let Some(is_active) = query.is_active {
                q = q.bind(is_active);
            }

            if let Some(email_filter) = &query.email {
                let pattern = format!("%{}%", escape_ilike(email_filter));
                q = q.bind(pattern);
            }

            for clause in &custom_attr_clauses {
                q = clause.bind_value_query_as(q);
            }

            q = q.bind(limit).bind(offset);

            q.fetch_all(&self.pool).await?
        };

        // H-4: Fetch roles for all users with tenant JOIN for cross-tenant safety
        let user_ids: Vec<uuid::Uuid> = users.iter().map(|u| u.id).collect();
        let all_roles: Vec<(uuid::Uuid, String)> = if user_ids.is_empty() {
            Vec::new()
        } else {
            sqlx::query_as(
                r"
                SELECT ur.user_id, ur.role_name FROM user_roles ur
                JOIN users u ON ur.user_id = u.id AND u.tenant_id = $2
                WHERE ur.user_id = ANY($1)
                ORDER BY ur.user_id, ur.role_name
                ",
            )
            .bind(&user_ids)
            .bind(tenant_id.as_uuid())
            .fetch_all(&self.pool)
            .await?
        };

        // Group roles by user_id
        let mut roles_map: std::collections::HashMap<uuid::Uuid, Vec<String>> =
            std::collections::HashMap::new();
        for (user_id, role_name) in all_roles {
            roles_map.entry(user_id).or_default().push(role_name);
        }

        // M-6: Fetch lifecycle states with tenant_id filter for tenant isolation
        let lifecycle_state_ids: Vec<uuid::Uuid> =
            users.iter().filter_map(|u| u.lifecycle_state_id).collect();
        let lifecycle_states: Vec<(uuid::Uuid, String, bool)> = if lifecycle_state_ids.is_empty() {
            Vec::new()
        } else {
            sqlx::query_as(
                r"
                SELECT id, name, is_terminal
                FROM gov_lifecycle_states
                WHERE id = ANY($1) AND tenant_id = $2
                ",
            )
            .bind(&lifecycle_state_ids)
            .bind(tenant_id.as_uuid())
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
        caller_roles: &[String],
    ) -> Result<UserResponse, ApiUsersError> {
        // Collect all validation errors
        let mut validation_errors = Vec::new();

        // Validate email using RFC 5322 compliant validator
        let email = request.email.trim().to_lowercase();
        if let Err(err) = validate_email(&email) {
            validation_errors.push(FieldValidationError::from(err));
        }

        // H2: Validate password against the tenant's password policy (length, character classes).
        // Fetch the policy from the DB; fall back to defaults if none is configured.
        let password_policy =
            TenantPasswordPolicy::get_or_default(&self.pool, *tenant_id.as_uuid())
                .await
                .unwrap_or_else(|_| TenantPasswordPolicy::default_for_tenant(*tenant_id.as_uuid()));
        validation_errors.extend(validate_password_against_policy(
            &request.password,
            &password_policy,
        ));

        // Validate roles (A1: shared helper; H1: allowlist enforced)
        validation_errors.extend(validate_roles(&request.roles));

        // Return all validation errors at once
        if !validation_errors.is_empty() {
            return Err(ApiUsersError::ValidationErrors {
                errors: validation_errors,
            });
        }

        // H1: Enforce role assignment hierarchy — non-super_admin cannot assign super_admin
        check_role_assignment_privilege(caller_roles, &request.roles)?;

        // Hash password before transaction to keep the lock short
        let password_hash = self
            .password_hasher
            .hash(&request.password)
            .map_err(|e| ApiUsersError::Internal(format!("Password hashing failed: {e}")))?;

        // L4: All DB operations in one transaction to prevent TOCTOU on email conflict
        let mut tx = self.pool.begin().await?;

        // Set tenant context for RLS defense-in-depth
        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(tenant_id.as_uuid().to_string())
            .execute(&mut *tx)
            .await?;

        // Check if email already exists in tenant (inside transaction for atomicity)
        let exists: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE tenant_id = $1 AND email = $2")
                .bind(tenant_id.as_uuid())
                .bind(&email)
                .fetch_one(&mut *tx)
                .await?;

        if exists > 0 {
            return Err(ApiUsersError::EmailConflict);
        }

        let now = chrono::Utc::now();

        // A4: Use RETURNING * to get the authoritative row from the database,
        // capturing any DB-level defaults (e.g., generated UUID, timestamps).
        let user: User = sqlx::query_as(
            r"
            INSERT INTO users (tenant_id, email, password_hash, is_active, email_verified, created_at, updated_at)
            VALUES ($1, $2, $3, true, false, $4, $4)
            RETURNING *
            ",
        )
        .bind(tenant_id.as_uuid())
        .bind(&email)
        .bind(&password_hash)
        .bind(now)
        .fetch_one(&mut *tx)
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
            .bind(user.id)
            .bind(role)
            .bind(now)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;

        // L7: Log user_id and tenant_id at INFO; email at DEBUG to avoid PII in production logs
        tracing::info!(
            user_id = %user.id,
            tenant_id = %tenant_id,
            roles = ?request.roles,
            "User created"
        );

        // M-3: Fetch roles from DB after insertion to avoid returning duplicates
        // that were silently dropped by ON CONFLICT DO NOTHING.
        let stored_roles: Vec<String> = sqlx::query_scalar(
            r"SELECT ur.role_name FROM user_roles ur
            JOIN users u ON ur.user_id = u.id AND u.tenant_id = $2
            WHERE ur.user_id = $1
            ORDER BY ur.role_name",
        )
        .bind(user.id)
        .bind(tenant_id.as_uuid())
        .fetch_all(&self.pool)
        .await
        .unwrap_or_else(|_| request.roles.clone());

        Ok(user_to_response(&user, stored_roles, None))
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

        // C-1: Fetch roles with tenant JOIN for cross-tenant safety
        let roles: Vec<String> = sqlx::query_scalar(
            r"
            SELECT ur.role_name FROM user_roles ur
            JOIN users u ON ur.user_id = u.id AND u.tenant_id = $2
            WHERE ur.user_id = $1
            ORDER BY ur.role_name
            ",
        )
        .bind(user.id)
        .bind(tenant_id.as_uuid())
        .fetch_all(&self.pool)
        .await?;

        // M-6: Fetch lifecycle state with tenant_id filter for tenant isolation
        let lifecycle_state = if let Some(state_id) = user.lifecycle_state_id {
            let state: Option<(uuid::Uuid, String, bool)> = sqlx::query_as(
                r"
                SELECT id, name, is_terminal
                FROM gov_lifecycle_states
                WHERE id = $1 AND tenant_id = $2
                ",
            )
            .bind(state_id)
            .bind(tenant_id.as_uuid())
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
        caller_roles: &[String],
    ) -> Result<UserResponse, ApiUsersError> {
        // M2: All DB operations in one transaction to prevent TOCTOU on user state
        let mut tx = self.pool.begin().await?;

        // Set tenant context for RLS defense-in-depth
        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(tenant_id.as_uuid().to_string())
            .execute(&mut *tx)
            .await?;

        // Check user exists in tenant (inside transaction for consistency)
        let user: Option<User> = sqlx::query_as(
            r"
            SELECT *
            FROM users
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(user_id.as_uuid())
        .bind(tenant_id.as_uuid())
        .fetch_optional(&mut *tx)
        .await?;

        let mut user = user.ok_or(ApiUsersError::NotFound)?;

        let now = chrono::Utc::now();
        let mut updated = false;
        // M-1/M-2/H-5: Track identity-affecting changes for token revocation
        let mut email_changed = false;
        let mut roles_changed = false;
        let mut deactivated = false;

        // Validate all provided fields first
        let mut validation_errors = Vec::new();

        // Validate email if provided
        if let Some(ref new_email) = request.email {
            let email_trimmed = new_email.trim().to_lowercase();
            if let Err(err) = validate_email(&email_trimmed) {
                validation_errors.push(FieldValidationError::from(err));
            }
        }

        // Validate roles if provided (A1: shared helper; H1: allowlist enforced)
        if let Some(ref new_roles) = request.roles {
            validation_errors.extend(validate_roles(new_roles));
        }

        // Return all validation errors at once
        if !validation_errors.is_empty() {
            return Err(ApiUsersError::ValidationErrors {
                errors: validation_errors,
            });
        }

        // H1: Enforce role assignment hierarchy
        if let Some(ref new_roles) = request.roles {
            check_role_assignment_privilege(caller_roles, new_roles)?;
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

                // C2: Reset email_verified when admin changes email — the new address is unverified
                sqlx::query(
                    "UPDATE users SET email = $1, email_verified = false, email_verified_at = NULL, updated_at = $2 WHERE id = $3 AND tenant_id = $4",
                )
                .bind(&email)
                .bind(now)
                .bind(user_id.as_uuid())
                .bind(tenant_id.as_uuid())
                .execute(&mut *tx)
                .await?;

                user.email = email;
                user.email_verified = false;
                updated = true;
                email_changed = true;
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

                // H-5: Track deactivation for token revocation
                if !is_active {
                    deactivated = true;
                }
                user.is_active = is_active;
                updated = true;
            }
        }

        // Update roles if provided (validation done upfront)
        let roles = if let Some(ref new_roles) = request.roles {
            // H-3: Delete existing roles with tenant JOIN for defense-in-depth
            sqlx::query(
                r"DELETE FROM user_roles ur
                USING users u
                WHERE ur.user_id = $1 AND u.id = ur.user_id AND u.tenant_id = $2",
            )
            .bind(user_id.as_uuid())
            .bind(tenant_id.as_uuid())
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

            roles_changed = true;
            new_roles.clone()
        } else {
            // C-3: Fetch current roles with tenant JOIN for cross-tenant safety
            sqlx::query_scalar(
                r"SELECT ur.role_name FROM user_roles ur
                JOIN users u ON ur.user_id = u.id AND u.tenant_id = $2
                WHERE ur.user_id = $1
                ORDER BY ur.role_name",
            )
            .bind(user_id.as_uuid())
            .bind(tenant_id.as_uuid())
            .fetch_all(&mut *tx)
            .await?
        };

        tx.commit().await?;

        if updated || request.roles.is_some() {
            user.updated_at = now;
        }

        // M-1/M-2: Revoke all refresh tokens when email or roles change.
        // This forces re-authentication so the user's JWT reflects the new
        // identity (email) or permissions (roles). Best-effort — don't fail
        // the update if revocation fails.
        if email_changed || roles_changed || deactivated {
            let revoke_result = sqlx::query(
                "UPDATE refresh_tokens SET revoked_at = NOW() WHERE user_id = $1 AND tenant_id = $2 AND revoked_at IS NULL",
            )
            .bind(user_id.as_uuid())
            .bind(tenant_id.as_uuid())
            .execute(&self.pool)
            .await;

            match revoke_result {
                Ok(result) if result.rows_affected() > 0 => {
                    tracing::info!(
                        user_id = %user_id,
                        tenant_id = %tenant_id,
                        revoked = result.rows_affected(),
                        email_changed,
                        roles_changed,
                        "Revoked refresh tokens after identity change"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        user_id = %user_id,
                        tenant_id = %tenant_id,
                        error = %e,
                        "Failed to revoke refresh tokens after identity change"
                    );
                }
                _ => {}
            }
        }

        // M-6: Fetch lifecycle state with tenant_id filter for tenant isolation
        let lifecycle_state = if let Some(state_id) = user.lifecycle_state_id {
            let state: Option<(uuid::Uuid, String, bool)> = sqlx::query_as(
                r"
                SELECT id, name, is_terminal
                FROM gov_lifecycle_states
                WHERE id = $1 AND tenant_id = $2
                ",
            )
            .bind(state_id)
            .bind(tenant_id.as_uuid())
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
        caller_user_id: uuid::Uuid,
    ) -> Result<(), ApiUsersError> {
        // C4: Prevent self-deactivation
        if *user_id.as_uuid() == caller_user_id {
            return Err(ApiUsersError::Validation(
                "Cannot deactivate your own account".to_string(),
            ));
        }

        // H-2: Wrap the entire check-and-deactivate in a transaction with
        // SELECT FOR UPDATE to prevent the TOCTOU race where two concurrent
        // requests both pass the "last admin" check and lock out the tenant.
        let mut tx = self.pool.begin().await?;

        // Set tenant context for RLS defense-in-depth
        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(tenant_id.as_uuid().to_string())
            .execute(&mut *tx)
            .await?;

        // Lock the target user row to serialize concurrent deactivation attempts
        let user: Option<(bool,)> = sqlx::query_as(
            "SELECT is_active FROM users WHERE id = $1 AND tenant_id = $2 FOR UPDATE",
        )
        .bind(user_id.as_uuid())
        .bind(tenant_id.as_uuid())
        .fetch_optional(&mut *tx)
        .await?;

        let _user = user.ok_or(ApiUsersError::NotFound)?;

        // C-2: Fetch roles with tenant JOIN for cross-tenant safety
        let target_roles: Vec<String> = sqlx::query_scalar(
            r"SELECT ur.role_name FROM user_roles ur
            JOIN users u ON ur.user_id = u.id AND u.tenant_id = $2
            WHERE ur.user_id = $1",
        )
        .bind(user_id.as_uuid())
        .bind(tenant_id.as_uuid())
        .fetch_all(&mut *tx)
        .await?;

        let is_admin = target_roles
            .iter()
            .any(|r| r == "admin" || r == "super_admin");

        if is_admin {
            // Count other active admins in tenant (inside the same transaction)
            let other_admins: i64 = sqlx::query_scalar(
                r"
                SELECT COUNT(DISTINCT ur.user_id) FROM user_roles ur
                JOIN users u ON ur.user_id = u.id AND u.tenant_id = $1
                WHERE u.is_active = true
                  AND ur.role_name IN ('admin', 'super_admin')
                  AND ur.user_id != $2
                ",
            )
            .bind(tenant_id.as_uuid())
            .bind(user_id.as_uuid())
            .fetch_one(&mut *tx)
            .await?;

            if other_admins == 0 {
                return Err(ApiUsersError::Validation(
                    "Cannot deactivate the last admin in a tenant".to_string(),
                ));
            }
        }

        sqlx::query(
            "UPDATE users SET is_active = false, updated_at = $1 WHERE id = $2 AND tenant_id = $3",
        )
        .bind(chrono::Utc::now())
        .bind(user_id.as_uuid())
        .bind(tenant_id.as_uuid())
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        // Revoke all refresh tokens for the deactivated user so they cannot
        // obtain new access tokens. Best-effort — don't fail the deactivation.
        let revoke_result = sqlx::query(
            "UPDATE refresh_tokens SET revoked_at = NOW() WHERE user_id = $1 AND tenant_id = $2 AND revoked_at IS NULL",
        )
        .bind(user_id.as_uuid())
        .bind(tenant_id.as_uuid())
        .execute(&self.pool)
        .await;

        if let Err(e) = &revoke_result {
            tracing::warn!(
                user_id = %user_id,
                tenant_id = %tenant_id,
                error = %e,
                "Failed to revoke refresh tokens on deactivation"
            );
        } else if let Ok(r) = &revoke_result {
            if r.rows_affected() > 0 {
                tracing::info!(
                    user_id = %user_id,
                    tenant_id = %tenant_id,
                    revoked = r.rows_affected(),
                    "Revoked refresh tokens on deactivation"
                );
            }
        }

        tracing::info!(
            user_id = %user_id,
            tenant_id = %tenant_id,
            "User deactivated"
        );

        Ok(())
    }

    /// Record an admin audit event for user CRUD operations (A6).
    ///
    /// Best-effort: logs a warning and continues if the INSERT fails, so that
    /// audit failures never block the primary operation.
    pub async fn record_audit_event(
        &self,
        tenant_id: TenantId,
        actor_id: uuid::Uuid,
        action: &str,
        resource_id: uuid::Uuid,
        details: serde_json::Value,
    ) {
        let result = sqlx::query(
            r"
            INSERT INTO admin_audit_events (tenant_id, actor_id, action, resource_type, resource_id, details)
            VALUES ($1, $2, $3, 'user', $4, $5)
            ",
        )
        .bind(tenant_id.as_uuid())
        .bind(actor_id)
        .bind(action)
        .bind(resource_id)
        .bind(&details)
        .execute(&self.pool)
        .await;

        if let Err(e) = result {
            tracing::warn!(
                tenant_id = %tenant_id,
                actor_id = %actor_id,
                action = action,
                resource_id = %resource_id,
                error = %e,
                "Failed to record admin audit event"
            );
        }
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
        display_name: user.display_name.clone(),
        first_name: user.first_name.clone(),
        last_name: user.last_name.clone(),
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
            // Archetype fields (F058)
            archetype_id: None,
            archetype_custom_attrs: serde_json::json!({}),
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
            // Archetype fields (F058)
            archetype_id: None,
            archetype_custom_attrs: serde_json::json!({}),
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
