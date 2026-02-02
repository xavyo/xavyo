//! Attribute audit service for finding users missing required custom attributes (F070).

use crate::error::ApiUsersError;
use crate::models::{MissingAttributeAuditResponse, PaginationMeta, UserMissingAttributes};
use sqlx::PgPool;
use std::sync::LazyLock;
use uuid::Uuid;
use xavyo_db::models::TenantAttributeDefinition;

/// Service for auditing custom attribute compliance.
pub struct AttributeAuditService {
    pool: PgPool,
}

impl AttributeAuditService {
    /// Create a new attribute audit service.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Audit users missing required custom attributes.
    ///
    /// Returns users who are missing one or more required custom attribute values.
    /// Optionally filters to a single attribute by name.
    pub async fn audit_missing_required(
        &self,
        tenant_id: Uuid,
        attribute_name_filter: Option<&str>,
        offset: i64,
        limit: i64,
    ) -> Result<MissingAttributeAuditResponse, ApiUsersError> {
        // Load required active definitions
        let definitions =
            TenantAttributeDefinition::list_required_active(&self.pool, tenant_id).await?;

        // Filter to specific attribute if requested
        let target_defs: Vec<&TenantAttributeDefinition> = if let Some(name) = attribute_name_filter
        {
            definitions.iter().filter(|d| d.name == name).collect()
        } else {
            definitions.iter().collect()
        };

        if target_defs.is_empty() {
            return Ok(MissingAttributeAuditResponse {
                users: Vec::new(),
                pagination: PaginationMeta::new(0, offset, limit),
                total_missing_count: 0,
            });
        }

        // Build the required attribute names list
        let required_names: Vec<&str> = target_defs.iter().map(|d| d.name.as_str()).collect();

        // Defense-in-depth: validate attribute names before interpolating into SQL.
        // Names are validated on insert via CHECK(name ~ '^[a-z][a-z0-9_]{0,63}$'), but
        // we re-validate here to prevent SQL injection if the DB constraint is ever bypassed.
        // SECURITY: Compile regex once using LazyLock to avoid panic on every request
        static NAME_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
            regex::Regex::new(r"^[a-z][a-z0-9_]{0,63}$").expect("NAME_RE is a valid regex pattern")
        });
        for name in &required_names {
            if !NAME_RE.is_match(name) {
                tracing::error!(
                    attribute_name = %name,
                    "Attribute name failed safety validation — skipping audit"
                );
                return Ok(MissingAttributeAuditResponse {
                    users: Vec::new(),
                    pagination: PaginationMeta::new(0, offset, limit),
                    total_missing_count: 0,
                });
            }
        }

        // Query users who are missing any of the required attributes.
        // A user is "missing" an attribute if:
        // 1. custom_attributes does not contain the key at all (NOT custom_attributes ? 'key')
        // 2. OR custom_attributes contains the key but with a null value
        //
        // Attribute names are validated above against ^[a-z][a-z0-9_]{0,63}$,
        // making them safe for the jsonb ? operator.
        let mut conditions = Vec::new();
        for name in &required_names {
            conditions.push(format!(
                "NOT (u.custom_attributes ? '{name}') OR u.custom_attributes->>'{name}' IS NULL"
            ));
        }

        // Count total users missing any required attribute
        let count_sql = format!(
            "SELECT COUNT(DISTINCT u.id) FROM users u WHERE u.tenant_id = $1 AND ({})",
            conditions.join(" OR ")
        );

        let total_missing_count: i64 = sqlx::query_scalar(&count_sql)
            .bind(tenant_id)
            .fetch_one(&self.pool)
            .await?;

        // Get paginated user list
        let data_sql = format!(
            "SELECT u.id, u.email FROM users u WHERE u.tenant_id = $1 AND ({}) ORDER BY u.email LIMIT $2 OFFSET $3",
            conditions.join(" OR ")
        );

        let rows: Vec<(Uuid, String)> = sqlx::query_as(&data_sql)
            .bind(tenant_id)
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.pool)
            .await?;

        // For each returned user, determine which attributes are missing
        let mut users: Vec<UserMissingAttributes> = Vec::with_capacity(rows.len());
        if !rows.is_empty() {
            let user_ids: Vec<Uuid> = rows.iter().map(|(id, _)| *id).collect();

            // Fetch custom_attributes for all matched users
            let attr_rows: Vec<(Uuid, serde_json::Value)> = sqlx::query_as(
                r#"
                SELECT id, custom_attributes FROM users
                WHERE tenant_id = $1 AND id = ANY($2)
                "#,
            )
            .bind(tenant_id)
            .bind(&user_ids)
            .fetch_all(&self.pool)
            .await?;

            let attr_map: std::collections::HashMap<Uuid, serde_json::Value> =
                attr_rows.into_iter().collect();

            for (user_id, email) in &rows {
                let custom_attrs = attr_map
                    .get(user_id)
                    .cloned()
                    .unwrap_or(serde_json::json!({}));
                let obj = custom_attrs.as_object();

                let mut missing = Vec::new();
                for name in &required_names {
                    let has_value = obj
                        .and_then(|o| o.get(*name))
                        .map(|v| !v.is_null())
                        .unwrap_or(false);
                    if !has_value {
                        missing.push(name.to_string());
                    }
                }

                if !missing.is_empty() {
                    users.push(UserMissingAttributes {
                        user_id: *user_id,
                        email: email.clone(),
                        missing_attributes: missing,
                    });
                }
            }
        }

        Ok(MissingAttributeAuditResponse {
            users,
            pagination: PaginationMeta::new(total_missing_count, offset, limit),
            total_missing_count,
        })
    }
}
