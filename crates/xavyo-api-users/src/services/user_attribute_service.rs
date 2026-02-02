//! User attribute service for storing and retrieving custom attributes (F070/F081).

use crate::error::{ApiUsersError, AttributeFieldError};
use crate::models::attribute_definitions::{
    BulkUpdateFailure, BulkUpdateRequest, BulkUpdateResponse, PatchCustomAttributesRequest,
    SetCustomAttributesRequest, UserCustomAttributesResponse,
};
use crate::services::attribute_validation_service::AttributeValidationService;
use serde_json::Value;
use sqlx::PgPool;
#[cfg(feature = "kafka")]
use std::sync::Arc;
use std::sync::LazyLock;
use uuid::Uuid;
use xavyo_db::models::TenantAttributeDefinition;
#[cfg(feature = "kafka")]
use xavyo_events::EventProducer;

/// Service for managing user custom attributes.
pub struct UserAttributeService {
    pool: PgPool,
    #[cfg(feature = "kafka")]
    event_producer: Option<Arc<EventProducer>>,
}

impl UserAttributeService {
    /// Create a new user attribute service.
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            #[cfg(feature = "kafka")]
            event_producer: None,
        }
    }

    /// Create a new user attribute service with event producer.
    #[cfg(feature = "kafka")]
    pub fn with_event_producer(pool: PgPool, event_producer: Arc<EventProducer>) -> Self {
        Self {
            pool,
            event_producer: Some(event_producer),
        }
    }

    /// Set the event producer for publishing attribute change events.
    #[cfg(feature = "kafka")]
    pub fn set_event_producer(&mut self, producer: Arc<EventProducer>) {
        self.event_producer = Some(producer);
    }

    /// Get a user's custom attributes.
    pub async fn get_custom_attributes(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<UserCustomAttributesResponse, ApiUsersError> {
        let row: Option<(Value,)> = sqlx::query_as(
            r#"
            SELECT custom_attributes FROM users
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(user_id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some((custom_attributes,)) => Ok(UserCustomAttributesResponse {
                user_id,
                custom_attributes,
            }),
            None => Err(ApiUsersError::NotFound),
        }
    }

    /// Set (full replace) a user's custom attributes.
    pub async fn set_custom_attributes(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        _actor_id: Option<Uuid>,
        request: SetCustomAttributesRequest,
    ) -> Result<UserCustomAttributesResponse, ApiUsersError> {
        // Capture old values for audit event (F081)
        let _old_attrs: Option<Value> = {
            let row: Option<(Value,)> = sqlx::query_as(
                r#"
                SELECT custom_attributes FROM users
                WHERE id = $1 AND tenant_id = $2
                "#,
            )
            .bind(user_id)
            .bind(tenant_id)
            .fetch_optional(&self.pool)
            .await?;
            row.map(|(v,)| v)
        };

        // Load active attribute definitions for validation
        let definitions =
            TenantAttributeDefinition::list_by_tenant(&self.pool, tenant_id, Some(true), None)
                .await?;

        // Apply defaults for missing optional attributes
        let mut attrs = request.attributes;
        if let Some(obj) = attrs.as_object_mut() {
            for def in &definitions {
                if !obj.contains_key(&def.name) {
                    if let Some(default_val) = &def.default_value {
                        obj.insert(def.name.clone(), default_val.clone());
                    }
                }
            }
        }

        // Validate all attributes (full replace checks required fields)
        if let Err(validation_errors) =
            AttributeValidationService::validate_attributes(&definitions, &attrs, true)
        {
            return Err(ApiUsersError::AttributeValidationFailed {
                errors: validation_errors
                    .into_iter()
                    .map(|e| AttributeFieldError {
                        attribute: e.attribute,
                        error: e.error,
                    })
                    .collect(),
            });
        }

        // Update the user's custom attributes
        let row: Option<(Value,)> = sqlx::query_as(
            r#"
            UPDATE users
            SET custom_attributes = $3,
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING custom_attributes
            "#,
        )
        .bind(user_id)
        .bind(tenant_id)
        .bind(&attrs)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some((custom_attributes,)) => {
                // Emit audit event (F081)
                #[cfg(feature = "kafka")]
                self.emit_attributes_changed(
                    tenant_id,
                    user_id,
                    actor_id,
                    _old_attrs.as_ref(),
                    &custom_attributes,
                )
                .await;

                Ok(UserCustomAttributesResponse {
                    user_id,
                    custom_attributes,
                })
            }
            None => Err(ApiUsersError::NotFound),
        }
    }

    /// Patch (merge) a user's custom attributes.
    pub async fn patch_custom_attributes(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        _actor_id: Option<Uuid>,
        request: PatchCustomAttributesRequest,
    ) -> Result<UserCustomAttributesResponse, ApiUsersError> {
        // Load current attributes
        let current_row: Option<(Value,)> = sqlx::query_as(
            r#"
            SELECT custom_attributes FROM users
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(user_id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?;

        let (current_attrs,) = current_row.ok_or(ApiUsersError::NotFound)?;

        let mut merged = current_attrs.clone();
        let merged_obj = merged.as_object_mut().ok_or_else(|| {
            ApiUsersError::Internal("custom_attributes column is not a JSON object".to_string())
        })?;

        // Apply set operations
        if let Some(set_values) = &request.set {
            if let Some(set_obj) = set_values.as_object() {
                for (key, value) in set_obj {
                    merged_obj.insert(key.clone(), value.clone());
                }
            }
        }

        // Apply unset operations
        if let Some(unset_keys) = &request.unset {
            for key in unset_keys {
                merged_obj.remove(key);
            }
        }

        // Load active attribute definitions for validation
        let definitions =
            TenantAttributeDefinition::list_by_tenant(&self.pool, tenant_id, Some(true), None)
                .await?;

        // Validate merged result (patch mode — don't check required for unchanged fields)
        if let Err(validation_errors) =
            AttributeValidationService::validate_attributes(&definitions, &merged, false)
        {
            return Err(ApiUsersError::AttributeValidationFailed {
                errors: validation_errors
                    .into_iter()
                    .map(|e| AttributeFieldError {
                        attribute: e.attribute,
                        error: e.error,
                    })
                    .collect(),
            });
        }

        // Update the user's custom attributes
        let row: Option<(Value,)> = sqlx::query_as(
            r#"
            UPDATE users
            SET custom_attributes = $3,
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING custom_attributes
            "#,
        )
        .bind(user_id)
        .bind(tenant_id)
        .bind(&merged)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some((custom_attributes,)) => {
                // Emit audit event (F081)
                #[cfg(feature = "kafka")]
                self.emit_attributes_changed(
                    tenant_id,
                    user_id,
                    actor_id,
                    Some(&current_attrs),
                    &custom_attributes,
                )
                .await;

                Ok(UserCustomAttributesResponse {
                    user_id,
                    custom_attributes,
                })
            }
            None => Err(ApiUsersError::NotFound),
        }
    }

    /// Bulk update a custom attribute across multiple users.
    ///
    /// Supports filtering by current_value (JSONB containment) or explicit user_ids.
    /// Processes in batches of 500 to avoid long-running transactions.
    pub async fn bulk_update(
        &self,
        tenant_id: Uuid,
        _actor_id: Option<Uuid>,
        request: BulkUpdateRequest,
    ) -> Result<BulkUpdateResponse, ApiUsersError> {
        let attr_name = &request.attribute_name;

        // Validate attribute name pattern
        // SECURITY: Compile regex once using LazyLock to avoid panic on every request
        static NAME_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
            regex::Regex::new(r"^[a-z][a-z0-9_]{0,63}$").expect("NAME_RE is a valid regex pattern")
        });
        if !NAME_RE.is_match(attr_name) {
            return Err(ApiUsersError::Validation(format!(
                "Invalid attribute name: '{attr_name}'"
            )));
        }

        // Verify the attribute definition exists and is active
        let definition =
            TenantAttributeDefinition::get_by_name(&self.pool, tenant_id, attr_name).await?;
        let definition = definition.ok_or(ApiUsersError::AttributeDefinitionNotFound)?;
        if !definition.is_active {
            return Err(ApiUsersError::AttributeDefinitionNotFound);
        }

        // Validate the new value against the definition
        let test_attrs = serde_json::json!({ attr_name: &request.new_value });
        if let Err(validation_errors) =
            AttributeValidationService::validate_attributes(&[definition], &test_attrs, false)
        {
            return Err(ApiUsersError::AttributeValidationFailed {
                errors: validation_errors
                    .into_iter()
                    .map(|e| AttributeFieldError {
                        attribute: e.attribute,
                        error: e.error,
                    })
                    .collect(),
            });
        }

        // Find matching users based on filter criteria
        let matching_user_ids: Vec<Uuid> = if let Some(ref user_ids) = request.filter.user_ids {
            // Filter by explicit user IDs
            sqlx::query_scalar(
                r#"
                SELECT id FROM users
                WHERE tenant_id = $1 AND id = ANY($2)
                "#,
            )
            .bind(tenant_id)
            .bind(user_ids)
            .fetch_all(&self.pool)
            .await?
        } else if let Some(ref current_value) = request.filter.current_value {
            // Filter by current attribute value using JSONB containment
            let containment = serde_json::json!({ attr_name: current_value });
            sqlx::query_scalar(
                r#"
                SELECT id FROM users
                WHERE tenant_id = $1 AND custom_attributes @> $2::jsonb
                "#,
            )
            .bind(tenant_id)
            .bind(&containment)
            .fetch_all(&self.pool)
            .await?
        } else {
            // No filter means all users in tenant
            sqlx::query_scalar(
                r#"
                SELECT id FROM users
                WHERE tenant_id = $1
                "#,
            )
            .bind(tenant_id)
            .fetch_all(&self.pool)
            .await?
        };

        let total_matched = matching_user_ids.len() as i64;
        let mut total_updated: i64 = 0;
        let mut total_failed: i64 = 0;
        let mut failures: Vec<BulkUpdateFailure> = Vec::new();

        // Process in batches of 500
        let batch_size = 500;
        for batch in matching_user_ids.chunks(batch_size) {
            let batch_vec: Vec<Uuid> = batch.to_vec();

            // Use jsonb_set to update the specific attribute key
            let result = sqlx::query(
                r#"
                UPDATE users
                SET custom_attributes = jsonb_set(
                    COALESCE(custom_attributes, '{}'::jsonb),
                    $3::text[],
                    $4::jsonb
                ),
                updated_at = NOW()
                WHERE tenant_id = $1 AND id = ANY($2)
                "#,
            )
            .bind(tenant_id)
            .bind(&batch_vec)
            .bind(&[attr_name.as_str()] as &[&str])
            .bind(&request.new_value)
            .execute(&self.pool)
            .await;

            match result {
                Ok(r) => {
                    total_updated += r.rows_affected() as i64;
                }
                Err(e) => {
                    // If batch fails, record failures for each user in the batch
                    let error_msg = e.to_string();
                    for user_id in batch {
                        total_failed += 1;
                        failures.push(BulkUpdateFailure {
                            user_id: *user_id,
                            error: error_msg.clone(),
                        });
                    }
                }
            }
        }

        tracing::info!(
            tenant_id = %tenant_id,
            attribute_name = %attr_name,
            total_matched = total_matched,
            total_updated = total_updated,
            total_failed = total_failed,
            "Bulk attribute update completed"
        );

        // Emit a bulk audit event for the attribute change (F081)
        #[cfg(feature = "kafka")]
        if total_updated > 0 {
            if let Some(ref producer) = self.event_producer {
                let event = xavyo_events::events::user_attributes::BulkAttributeUpdateCompleted {
                    attribute_name: attr_name.clone(),
                    new_value: request.new_value.clone(),
                    total_matched,
                    total_updated,
                    total_failed,
                    initiated_by: actor_id,
                };
                if let Err(e) = producer.publish(event, tenant_id, actor_id).await {
                    tracing::warn!(
                        attribute_name = %attr_name,
                        error = %e,
                        "Failed to publish BulkAttributeUpdateCompleted event"
                    );
                }
            }
        }

        Ok(BulkUpdateResponse {
            total_matched,
            total_updated,
            total_failed,
            failures,
        })
    }

    /// Compare old and new attribute values and emit a CustomAttributesUpdated event.
    #[cfg(feature = "kafka")]
    async fn emit_attributes_changed(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        actor_id: Option<Uuid>,
        old_attrs: Option<&Value>,
        new_attrs: &Value,
    ) {
        let Some(ref producer) = self.event_producer else {
            return;
        };

        let empty = serde_json::json!({});
        let old_obj = old_attrs.unwrap_or(&empty);

        let old_map = old_obj.as_object();
        let new_map = new_attrs.as_object();

        let (Some(old_map), Some(new_map)) = (old_map, new_map) else {
            return;
        };

        let mut changed_attributes = Vec::new();
        let mut old_values = std::collections::HashMap::new();
        let mut new_values = std::collections::HashMap::new();

        // Check for changed or added keys
        for (key, new_val) in new_map {
            let old_val = old_map.get(key);
            if old_val != Some(new_val) {
                changed_attributes.push(key.clone());
                if let Some(ov) = old_val {
                    old_values.insert(key.clone(), ov.clone());
                }
                new_values.insert(key.clone(), new_val.clone());
            }
        }

        // Check for removed keys
        for (key, old_val) in old_map {
            if !new_map.contains_key(key) {
                changed_attributes.push(key.clone());
                old_values.insert(key.clone(), old_val.clone());
            }
        }

        if changed_attributes.is_empty() {
            return;
        }

        let event = xavyo_events::events::user_attributes::CustomAttributesUpdated {
            user_id,
            changed_attributes,
            old_values,
            new_values,
            changed_by: actor_id,
        };

        if let Err(e) = producer.publish(event, tenant_id, actor_id).await {
            tracing::warn!(
                user_id = %user_id,
                error = %e,
                "Failed to publish CustomAttributesUpdated event"
            );
        }
    }
}
