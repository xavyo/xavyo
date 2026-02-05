//! Attribute definition service for managing tenant custom attribute schemas (F070/F081).

use crate::error::ApiUsersError;
use crate::models::attribute_definitions::{
    AttributeDefinitionListResponse, AttributeDefinitionResponse, CreateAttributeDefinitionRequest,
    SeedWellKnownResponse, SeededAttribute, SkippedAttribute, UpdateAttributeDefinitionRequest,
};
use sqlx::PgPool;
#[cfg(feature = "kafka")]
use std::sync::Arc;
use uuid::Uuid;
use xavyo_db::models::TenantAttributeDefinition;
#[cfg(feature = "kafka")]
use xavyo_events::EventProducer;

/// Maximum number of attribute definitions per tenant.
const MAX_DEFINITIONS_PER_TENANT: i64 = 100;

/// Valid data types for custom attributes.
const VALID_DATA_TYPES: &[&str] = &["string", "number", "boolean", "date", "json", "enum"];

/// Attribute name validation pattern.
const NAME_PATTERN: &str = r"^[a-z][a-z0-9_]{0,63}$";

/// A well-known attribute entry in the catalog.
struct WellKnownEntry {
    slug: &'static str,
    display_label: &'static str,
    data_type: &'static str,
    validation_rules: Option<serde_json::Value>,
}

/// The 13 well-known enterprise attributes available for seeding (F081).
fn well_known_catalog() -> Vec<WellKnownEntry> {
    vec![
        WellKnownEntry {
            slug: "department",
            display_label: "Department",
            data_type: "string",
            validation_rules: None,
        },
        WellKnownEntry {
            slug: "title",
            display_label: "Job Title",
            data_type: "string",
            validation_rules: None,
        },
        WellKnownEntry {
            slug: "job_code",
            display_label: "Job Code",
            data_type: "string",
            validation_rules: None,
        },
        WellKnownEntry {
            slug: "cost_center",
            display_label: "Cost Center",
            data_type: "string",
            validation_rules: None,
        },
        WellKnownEntry {
            slug: "hire_date",
            display_label: "Hire Date",
            data_type: "date",
            validation_rules: None,
        },
        WellKnownEntry {
            slug: "termination_date",
            display_label: "Termination Date",
            data_type: "date",
            validation_rules: None,
        },
        WellKnownEntry {
            slug: "employee_id",
            display_label: "Employee ID",
            data_type: "string",
            validation_rules: None,
        },
        WellKnownEntry {
            slug: "employee_type",
            display_label: "Employee Type",
            data_type: "enum",
            validation_rules: Some(serde_json::json!({
                "allowed_values": ["full_time", "contractor", "intern", "temporary"]
            })),
        },
        WellKnownEntry {
            slug: "manager_id",
            display_label: "Manager ID",
            data_type: "string",
            validation_rules: None,
        },
        WellKnownEntry {
            slug: "location",
            display_label: "Location",
            data_type: "string",
            validation_rules: None,
        },
        WellKnownEntry {
            slug: "office_code",
            display_label: "Office Code",
            data_type: "string",
            validation_rules: None,
        },
        WellKnownEntry {
            slug: "phone_number",
            display_label: "Phone Number",
            data_type: "string",
            validation_rules: None,
        },
        WellKnownEntry {
            slug: "timezone",
            display_label: "Timezone",
            data_type: "string",
            validation_rules: None,
        },
    ]
}

/// Service for managing tenant attribute definitions.
pub struct AttributeDefinitionService {
    pool: PgPool,
    #[cfg(feature = "kafka")]
    event_producer: Option<Arc<EventProducer>>,
}

impl AttributeDefinitionService {
    /// Create a new attribute definition service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            #[cfg(feature = "kafka")]
            event_producer: None,
        }
    }

    /// Create a new attribute definition service with event producer.
    #[cfg(feature = "kafka")]
    pub fn with_event_producer(pool: PgPool, event_producer: Arc<EventProducer>) -> Self {
        Self {
            pool,
            event_producer: Some(event_producer),
        }
    }

    /// Set the event producer for publishing attribute definition events.
    #[cfg(feature = "kafka")]
    pub fn set_event_producer(&mut self, producer: Arc<EventProducer>) {
        self.event_producer = Some(producer);
    }

    /// Create a new attribute definition.
    pub async fn create(
        &self,
        tenant_id: Uuid,
        _actor_id: Option<Uuid>,
        request: CreateAttributeDefinitionRequest,
    ) -> Result<AttributeDefinitionResponse, ApiUsersError> {
        // Validate name pattern
        let name_re = regex::Regex::new(NAME_PATTERN)
            .map_err(|e| ApiUsersError::Internal(format!("Regex error: {e}")))?;
        let name = request.name.to_lowercase();
        if !name_re.is_match(&name) {
            return Err(ApiUsersError::Validation(format!(
                "Attribute name '{name}' is invalid. Must match pattern: lowercase letter followed by lowercase letters, digits, or underscores (1-64 chars)"
            )));
        }

        // Validate data type
        if !VALID_DATA_TYPES.contains(&request.data_type.as_str()) {
            return Err(ApiUsersError::Validation(format!(
                "Invalid data type '{}'. Must be one of: {}",
                request.data_type,
                VALID_DATA_TYPES.join(", ")
            )));
        }

        // Validate enum type requires non-empty allowed_values in validation_rules
        if request.data_type == "enum" {
            let has_valid_allowed_values = request
                .validation_rules
                .as_ref()
                .and_then(|r| r.get("allowed_values"))
                .and_then(|v| v.as_array())
                .is_some_and(|arr| !arr.is_empty());
            if !has_valid_allowed_values {
                return Err(ApiUsersError::Validation(
                    "Enum data type requires 'validation_rules' with a non-empty 'allowed_values' array".to_string(),
                ));
            }
        }

        // Check definition count limit
        let count = TenantAttributeDefinition::count_by_tenant(&self.pool, tenant_id).await?;
        if count >= MAX_DEFINITIONS_PER_TENANT {
            return Err(ApiUsersError::AttributeDefinitionLimitExceeded);
        }

        // Check uniqueness
        if TenantAttributeDefinition::get_by_name(&self.pool, tenant_id, &name)
            .await?
            .is_some()
        {
            return Err(ApiUsersError::AttributeDefinitionConflict);
        }

        // Create the definition
        let def = TenantAttributeDefinition::create(
            &self.pool,
            tenant_id,
            &name,
            &request.display_label,
            &request.data_type,
            request.required,
            request.validation_rules,
            request.default_value,
            request.sort_order,
        )
        .await?;

        // Emit audit event (F081)
        #[cfg(feature = "kafka")]
        if let Some(ref producer) = self.event_producer {
            let event = xavyo_events::events::user_attributes::AttributeDefinitionCreated {
                definition_id: def.id,
                name: def.name.clone(),
                display_label: def.display_label.clone(),
                data_type: def.data_type.clone(),
                required: def.required,
                is_well_known: def.is_well_known,
                well_known_slug: def.well_known_slug.clone(),
                created_by: actor_id,
            };
            if let Err(e) = producer.publish(event, tenant_id, actor_id).await {
                tracing::warn!(
                    definition_id = %def.id,
                    error = %e,
                    "Failed to publish AttributeDefinitionCreated event"
                );
            }
        }

        Ok(def.into())
    }

    /// Get an attribute definition by ID.
    pub async fn get(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<AttributeDefinitionResponse, ApiUsersError> {
        let def = TenantAttributeDefinition::get_by_id(&self.pool, tenant_id, id)
            .await?
            .ok_or(ApiUsersError::AttributeDefinitionNotFound)?;

        Ok(def.into())
    }

    /// List attribute definitions for a tenant.
    pub async fn list(
        &self,
        tenant_id: Uuid,
        is_active: Option<bool>,
        data_type: Option<&str>,
    ) -> Result<AttributeDefinitionListResponse, ApiUsersError> {
        let definitions =
            TenantAttributeDefinition::list_by_tenant(&self.pool, tenant_id, is_active, data_type)
                .await?;

        let total_count = definitions.len() as i64;
        let definitions: Vec<AttributeDefinitionResponse> = definitions
            .into_iter()
            .map(std::convert::Into::into)
            .collect();

        Ok(AttributeDefinitionListResponse {
            definitions,
            total_count,
        })
    }

    /// Update an attribute definition.
    pub async fn update(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        _actor_id: Option<Uuid>,
        request: UpdateAttributeDefinitionRequest,
    ) -> Result<AttributeDefinitionResponse, ApiUsersError> {
        // Verify definition exists
        let _existing = TenantAttributeDefinition::get_by_id(&self.pool, tenant_id, id)
            .await?
            .ok_or(ApiUsersError::AttributeDefinitionNotFound)?;

        // Flatten Option<Option<Value>> for the DB update call
        let validation_rules = request
            .validation_rules
            .map(|opt| opt.unwrap_or(serde_json::Value::Null));
        let default_value = request
            .default_value
            .map(|opt| opt.unwrap_or(serde_json::Value::Null));

        let updated = TenantAttributeDefinition::update(
            &self.pool,
            tenant_id,
            id,
            request.display_label.as_deref(),
            request.required,
            validation_rules,
            default_value,
            request.sort_order,
            request.is_active,
        )
        .await?
        .ok_or(ApiUsersError::AttributeDefinitionNotFound)?;

        // Emit audit event (F081)
        #[cfg(feature = "kafka")]
        if let Some(ref producer) = self.event_producer {
            let mut changes = std::collections::HashMap::new();
            if request.display_label.is_some() {
                changes.insert(
                    "display_label".to_string(),
                    serde_json::json!(updated.display_label),
                );
            }
            if request.required.is_some() {
                changes.insert("required".to_string(), serde_json::json!(updated.required));
            }
            if request.is_active.is_some() {
                changes.insert(
                    "is_active".to_string(),
                    serde_json::json!(updated.is_active),
                );
            }
            if !changes.is_empty() {
                let event = xavyo_events::events::user_attributes::AttributeDefinitionUpdated {
                    definition_id: updated.id,
                    name: updated.name.clone(),
                    changes,
                    updated_by: actor_id,
                };
                if let Err(e) = producer.publish(event, tenant_id, actor_id).await {
                    tracing::warn!(
                        definition_id = %updated.id,
                        error = %e,
                        "Failed to publish AttributeDefinitionUpdated event"
                    );
                }
            }
        }

        Ok(updated.into())
    }

    /// Seed well-known enterprise attributes for a tenant (F081).
    ///
    /// Idempotent: existing attributes with matching slugs are skipped.
    /// Returns a summary of what was seeded and what was skipped.
    pub async fn seed_wellknown(
        &self,
        tenant_id: Uuid,
    ) -> Result<SeedWellKnownResponse, ApiUsersError> {
        let catalog = well_known_catalog();
        let mut seeded = Vec::new();
        let mut skipped = Vec::new();

        // Fetch count once and track locally to avoid N+1 queries
        let mut current_count =
            TenantAttributeDefinition::count_by_tenant(&self.pool, tenant_id).await?;

        for (idx, entry) in catalog.iter().enumerate() {
            // Check if this well-known slug already exists for the tenant (by name)
            let existing =
                TenantAttributeDefinition::get_by_name(&self.pool, tenant_id, entry.slug).await?;

            if existing.is_some() {
                skipped.push(SkippedAttribute {
                    slug: entry.slug.to_string(),
                    reason: "Already exists".to_string(),
                });
                continue;
            }

            // Check count limit
            if current_count >= MAX_DEFINITIONS_PER_TENANT {
                skipped.push(SkippedAttribute {
                    slug: entry.slug.to_string(),
                    reason: "Tenant definition limit reached".to_string(),
                });
                continue;
            }

            let def = TenantAttributeDefinition::create_well_known(
                &self.pool,
                tenant_id,
                entry.slug,
                entry.display_label,
                entry.data_type,
                false, // well-known attributes default to optional
                entry.validation_rules.clone(),
                None, // no default value
                idx as i32,
                entry.slug,
            )
            .await?;

            current_count += 1;
            seeded.push(SeededAttribute {
                id: def.id,
                slug: entry.slug.to_string(),
                display_label: entry.display_label.to_string(),
                data_type: entry.data_type.to_string(),
            });
        }

        let total_seeded = seeded.len();
        let total_skipped = skipped.len();

        Ok(SeedWellKnownResponse {
            seeded,
            skipped,
            total_seeded,
            total_skipped,
        })
    }

    /// Delete an attribute definition.
    pub async fn delete(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        force: bool,
        _actor_id: Option<Uuid>,
    ) -> Result<(), ApiUsersError> {
        // Verify definition exists
        let def = TenantAttributeDefinition::get_by_id(&self.pool, tenant_id, id)
            .await?
            .ok_or(ApiUsersError::AttributeDefinitionNotFound)?;

        // Check if user data exists for this attribute
        if !force {
            let has_data =
                TenantAttributeDefinition::has_user_data(&self.pool, tenant_id, &def.name).await?;
            if has_data {
                return Err(ApiUsersError::AttributeDefinitionInUse);
            }
        }

        let deleted = TenantAttributeDefinition::delete(&self.pool, tenant_id, id).await?;
        if !deleted {
            return Err(ApiUsersError::AttributeDefinitionNotFound);
        }

        // Emit audit event (F081)
        #[cfg(feature = "kafka")]
        if let Some(ref producer) = self.event_producer {
            let event = xavyo_events::events::user_attributes::AttributeDefinitionDeactivated {
                definition_id: id,
                name: def.name.clone(),
                hard_delete: true,
                deactivated_by: actor_id,
            };
            if let Err(e) = producer.publish(event, tenant_id, actor_id).await {
                tracing::warn!(
                    definition_id = %id,
                    error = %e,
                    "Failed to publish AttributeDefinitionDeactivated event"
                );
            }
        }

        Ok(())
    }
}
