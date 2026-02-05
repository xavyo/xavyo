//! ModifyAttribute action executor for F-064: Bulk Action Engine.
//!
//! Modifies a custom attribute on a user, stored in the custom_attributes JSONB column.

use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

use super::{ActionExecutor, ExecutionContext, ExecutionResult};

/// Executor for modify_attribute action.
pub struct ModifyAttributeExecutor;

/// List of immutable attributes that cannot be modified via bulk actions.
const IMMUTABLE_ATTRIBUTES: &[&str] = &[
    "id",
    "tenant_id",
    "email",
    "password_hash",
    "created_at",
    "updated_at",
];

impl ModifyAttributeExecutor {
    /// Create a new modify attribute executor.
    pub fn new() -> Self {
        Self
    }

    /// Check if the attribute is immutable.
    fn is_immutable(attribute: &str) -> bool {
        IMMUTABLE_ATTRIBUTES.contains(&attribute)
    }

    /// Get the current value of the attribute.
    async fn get_attribute_value(
        pool: &PgPool,
        user_id: Uuid,
        attribute: &str,
    ) -> Result<Option<serde_json::Value>, sqlx::Error> {
        let result: Option<(serde_json::Value,)> =
            sqlx::query_as("SELECT custom_attributes FROM users WHERE id = $1")
                .bind(user_id)
                .fetch_optional(pool)
                .await?;

        Ok(result.and_then(|(attrs,)| {
            if let serde_json::Value::Object(map) = attrs {
                map.get(attribute).cloned()
            } else {
                None
            }
        }))
    }

    /// Set the attribute value.
    async fn set_attribute_value(
        pool: &PgPool,
        user_id: Uuid,
        attribute: &str,
        value: &serde_json::Value,
    ) -> Result<bool, sqlx::Error> {
        // Use jsonb_set to update the specific attribute within custom_attributes
        let result = sqlx::query(
            r#"
            UPDATE users
            SET custom_attributes = jsonb_set(
                COALESCE(custom_attributes, '{}'::jsonb),
                $2::text[],
                $3::jsonb,
                true
            ),
            updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(user_id)
        .bind(vec![attribute.to_string()])
        .bind(value)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }
}

impl Default for ModifyAttributeExecutor {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ActionExecutor for ModifyAttributeExecutor {
    async fn execute(
        &self,
        pool: &PgPool,
        _ctx: &ExecutionContext,
        target_user_id: Uuid,
        params: &serde_json::Value,
    ) -> ExecutionResult {
        // Extract attribute and value from params
        let attribute = match params.get("attribute").and_then(|v| v.as_str()) {
            Some(attr) => attr,
            None => return ExecutionResult::failure("Missing 'attribute' parameter"),
        };

        let new_value = match params.get("value") {
            Some(val) => val.clone(),
            None => return ExecutionResult::failure("Missing 'value' parameter"),
        };

        // Check if attribute is immutable
        if Self::is_immutable(attribute) {
            return ExecutionResult::failure(format!(
                "Attribute '{}' is immutable and cannot be modified",
                attribute
            ));
        }

        // Get current value
        let current_value = match Self::get_attribute_value(pool, target_user_id, attribute).await {
            Ok(val) => val,
            Err(e) => return ExecutionResult::failure(format!("Failed to get current value: {e}")),
        };

        // Check if value would change
        if current_value.as_ref() == Some(&new_value) {
            return ExecutionResult::skipped(serde_json::json!({
                "attribute": attribute,
                "current_value": current_value
            }));
        }

        // Set the new value
        match Self::set_attribute_value(pool, target_user_id, attribute, &new_value).await {
            Ok(true) => ExecutionResult::success(
                serde_json::json!({
                    "attribute": attribute,
                    "value": current_value
                }),
                serde_json::json!({
                    "attribute": attribute,
                    "value": new_value
                }),
            ),
            Ok(false) => ExecutionResult::failure("User not found"),
            Err(e) => ExecutionResult::failure(format!("Failed to set attribute: {e}")),
        }
    }

    async fn would_change(
        &self,
        pool: &PgPool,
        _ctx: &ExecutionContext,
        target_user_id: Uuid,
        params: &serde_json::Value,
    ) -> (bool, Option<serde_json::Value>, Option<serde_json::Value>) {
        let attribute = match params.get("attribute").and_then(|v| v.as_str()) {
            Some(attr) => attr,
            None => return (false, None, None),
        };

        let new_value = match params.get("value") {
            Some(val) => val.clone(),
            None => return (false, None, None),
        };

        // Check if attribute is immutable
        if Self::is_immutable(attribute) {
            return (false, None, None);
        }

        // Get current value
        match Self::get_attribute_value(pool, target_user_id, attribute).await {
            Ok(current) => {
                if current.as_ref() == Some(&new_value) {
                    (
                        false,
                        Some(serde_json::json!({"attribute": attribute, "value": current})),
                        None,
                    )
                } else {
                    (
                        true,
                        Some(serde_json::json!({"attribute": attribute, "value": current})),
                        Some(serde_json::json!({"attribute": attribute, "value": new_value})),
                    )
                }
            }
            Err(_) => (false, None, None),
        }
    }

    fn action_type(&self) -> &'static str {
        "modify_attribute"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_executor_action_type() {
        let executor = ModifyAttributeExecutor::new();
        assert_eq!(executor.action_type(), "modify_attribute");
    }

    #[test]
    fn test_immutable_attributes() {
        assert!(ModifyAttributeExecutor::is_immutable("id"));
        assert!(ModifyAttributeExecutor::is_immutable("tenant_id"));
        assert!(ModifyAttributeExecutor::is_immutable("email"));
        assert!(ModifyAttributeExecutor::is_immutable("password_hash"));
        assert!(!ModifyAttributeExecutor::is_immutable("department"));
        assert!(!ModifyAttributeExecutor::is_immutable("custom_field"));
    }
}
