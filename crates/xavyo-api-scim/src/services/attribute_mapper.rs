//! SCIM to Xavyo attribute mapping service.

use std::collections::HashMap;
use uuid::Uuid;
use xavyo_db::models::{ScimAttributeMapping, User};

use crate::error::{ScimError, ScimResult};
use crate::models::{CreateScimUserRequest, ScimEmail, ScimName, ScimUser, ScimUserGroup};

/// Service for mapping SCIM attributes to Xavyo user fields.
pub struct AttributeMapperService {
    mappings: HashMap<String, ScimAttributeMapping>,
}

impl AttributeMapperService {
    /// Create a mapper from a list of mappings.
    #[must_use]
    pub fn new(mappings: Vec<ScimAttributeMapping>) -> Self {
        let map = mappings
            .into_iter()
            .map(|m| (m.scim_path.clone(), m))
            .collect();
        Self { mappings: map }
    }

    /// Create a mapper with default enterprise extension mappings (F081).
    ///
    /// Maps standard SCIM Enterprise User extension attributes to well-known
    /// custom attribute slugs, enabling out-of-the-box SCIM provisioning
    /// without explicit tenant-level mapping configuration.
    #[must_use]
    pub fn with_defaults() -> Self {
        let enterprise_uri = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
        let defaults = [
            ("department", "custom.department"),
            ("costCenter", "custom.cost_center"),
            ("employeeNumber", "custom.employee_id"),
            ("organization", "custom.department"),
            ("division", "custom.division"),
        ];

        let mappings = defaults
            .into_iter()
            .map(|(scim_field, xavyo_field)| {
                let scim_path = format!("{enterprise_uri}.{scim_field}");
                let mapping = ScimAttributeMapping {
                    id: Uuid::nil(),
                    tenant_id: Uuid::nil(),
                    scim_path: scim_path.clone(),
                    xavyo_field: xavyo_field.to_string(),
                    transform: None,
                    required: false,
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                };
                (scim_path, mapping)
            })
            .collect();

        Self { mappings }
    }

    /// Get the Xavyo field for a SCIM path.
    #[allow(dead_code)]
    fn get_xavyo_field(&self, scim_path: &str) -> Option<&str> {
        self.mappings.get(scim_path).map(|m| m.xavyo_field.as_str())
    }

    /// Apply transform if configured.
    fn apply_transform(&self, scim_path: &str, value: &str) -> String {
        if let Some(mapping) = self.mappings.get(scim_path) {
            mapping.apply_transform(value)
        } else {
            value.to_string()
        }
    }

    /// Check if an attribute is required.
    fn is_required(&self, scim_path: &str) -> bool {
        self.mappings.get(scim_path).is_some_and(|m| m.required)
    }

    /// Extract user data from a SCIM user request.
    pub fn extract_user_data(
        &self,
        request: &CreateScimUserRequest,
    ) -> ScimResult<ExtractedUserData> {
        // userName is always required and maps to email
        let email = self.apply_transform("userName", &request.user_name);

        // Validate required fields
        if self.is_required("userName") && email.is_empty() {
            return Err(ScimError::Validation("userName is required".to_string()));
        }

        // Extract display name
        let display_name = request
            .display_name
            .as_ref()
            .map(|d| self.apply_transform("displayName", d));

        // Extract name components
        let (first_name, last_name) = if let Some(ref name) = request.name {
            (
                name.given_name
                    .as_ref()
                    .map(|n| self.apply_transform("name.givenName", n)),
                name.family_name
                    .as_ref()
                    .map(|n| self.apply_transform("name.familyName", n)),
            )
        } else {
            (None, None)
        };

        // Extract external ID
        let external_id = request.external_id.clone();

        // Active status
        let is_active = request.active;

        // Extract custom attributes from SCIM extension data (F070).
        // Look for mappings where xavyo_field starts with "custom." and extract
        // values from the SCIM request's extension schemas.
        let mut custom_attributes = serde_json::Map::new();
        for mapping in self.mappings.values() {
            if let Some(custom_attr_name) = mapping.xavyo_field.strip_prefix("custom.") {
                if custom_attr_name.is_empty() {
                    continue;
                }
                // The scim_path might be a dotted path like
                // "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User.department"
                // We split on the first dot to get the schema URI and the field name.
                if let Some(value) =
                    extract_extension_value(&request.extensions, &mapping.scim_path)
                {
                    let transformed = mapping.apply_transform(
                        &value
                            .as_str()
                            .map_or_else(|| value.to_string(), std::string::ToString::to_string),
                    );
                    custom_attributes.insert(
                        custom_attr_name.to_string(),
                        serde_json::Value::String(transformed),
                    );
                }
            }
        }

        // Handle enterprise extension manager.value → manager_id (F081).
        // The manager attribute is a complex type: { "value": "uuid", "displayName": "..." }
        let enterprise_uri = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
        if let Some(ext) = request.extensions.get(enterprise_uri) {
            if let Some(mgr) = ext.get("manager") {
                if let Some(mgr_val) = mgr.get("value") {
                    custom_attributes.insert("manager_id".to_string(), mgr_val.clone());
                }
            }
        }

        Ok(ExtractedUserData {
            email,
            display_name,
            first_name,
            last_name,
            external_id,
            is_active,
            custom_attributes,
        })
    }

    /// Convert a Xavyo User to a SCIM User response.
    #[must_use]
    pub fn to_scim_user(
        &self,
        user: &User,
        groups: Vec<ScimUserGroup>,
        base_url: &str,
    ) -> ScimUser {
        let mut scim_user = ScimUser::new(&user.email);

        scim_user.id = Some(user.id);
        scim_user.external_id = user.external_id.clone();
        scim_user.display_name = user.display_name.clone();
        scim_user.active = user.is_active;

        // Set name if available
        if user.first_name.is_some() || user.last_name.is_some() {
            scim_user.name = Some(ScimName {
                given_name: user.first_name.clone(),
                family_name: user.last_name.clone(),
                formatted: match (&user.first_name, &user.last_name) {
                    (Some(f), Some(l)) => Some(format!("{f} {l}")),
                    (Some(f), None) => Some(f.clone()),
                    (None, Some(l)) => Some(l.clone()),
                    (None, None) => None,
                },
                ..Default::default()
            });
        }

        // Set email
        scim_user.emails = vec![ScimEmail {
            value: user.email.clone(),
            email_type: Some("work".to_string()),
            primary: true,
        }];

        // Set groups
        scim_user.groups = groups;

        // Set metadata
        scim_user = scim_user.with_meta(user.id, base_url, user.created_at, user.updated_at);

        // Include custom attributes in the SCIM response as an extension schema (F070).
        // Mappings with `custom.*` xavyo_field are reversed: custom_attributes → extension schema.
        if let Some(obj) = user.custom_attributes.as_object() {
            if !obj.is_empty() {
                let mut reverse_map: serde_json::Map<String, serde_json::Value> =
                    serde_json::Map::new();
                for mapping in self.mappings.values() {
                    if let Some(custom_attr_name) = mapping.xavyo_field.strip_prefix("custom.") {
                        if let Some(value) = obj.get(custom_attr_name) {
                            // Place the value at the SCIM path location
                            if let Some((schema_uri, field_name)) =
                                mapping.scim_path.rsplit_once('.')
                            {
                                let schema_entry =
                                    reverse_map.entry(schema_uri.to_string()).or_insert_with(
                                        || serde_json::Value::Object(serde_json::Map::new()),
                                    );
                                if let Some(schema_obj) = schema_entry.as_object_mut() {
                                    schema_obj.insert(field_name.to_string(), value.clone());
                                }
                            }
                        }
                    }
                }
                // Handle manager_id → enterprise manager complex attribute (F081)
                if let Some(manager_val) = obj.get("manager_id") {
                    let enterprise_uri =
                        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
                    let schema_entry = reverse_map
                        .entry(enterprise_uri.to_string())
                        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
                    if let Some(schema_obj) = schema_entry.as_object_mut() {
                        schema_obj.insert(
                            "manager".to_string(),
                            serde_json::json!({ "value": manager_val }),
                        );
                    }
                }

                // Merge extension schemas into the SCIM user's extensions
                for (key, value) in &reverse_map {
                    scim_user.extensions.insert(key.clone(), value.clone());
                    // Add schema URN to schemas array if not already present (F081)
                    if !scim_user.schemas.contains(key) {
                        scim_user.schemas.push(key.clone());
                    }
                }
            }
        }

        scim_user
    }
}

/// Extract a value from SCIM extension data using a dotted path.
///
/// The path can be:
/// - A simple key like `"department"` (looked up in all extension schemas)
/// - A dotted path like `"urn:...:enterprise:2.0:User.department"` (looked up in
///   the specific extension schema, then the field within it)
fn extract_extension_value(
    extensions: &serde_json::Map<String, serde_json::Value>,
    scim_path: &str,
) -> Option<serde_json::Value> {
    // Try dotted path: "schemaUri.fieldName"
    if let Some((schema_uri, field_name)) = scim_path.rsplit_once('.') {
        // Check if the schema URI part exists in extensions
        if let Some(schema_obj) = extensions.get(schema_uri) {
            if let Some(obj) = schema_obj.as_object() {
                return obj.get(field_name).cloned();
            }
        }
    }

    // Fallback: try as a top-level key in any extension schema
    for (_schema, schema_value) in extensions {
        if let Some(obj) = schema_value.as_object() {
            if let Some(value) = obj.get(scim_path) {
                return Some(value.clone());
            }
        }
    }

    None
}

/// Extracted user data from SCIM request.
#[derive(Debug, Clone)]
pub struct ExtractedUserData {
    pub email: String,
    pub display_name: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub external_id: Option<String>,
    pub is_active: bool,
    /// Custom attributes extracted from SCIM extension data (F070).
    /// Maps custom attribute names (without `custom.` prefix) to their values.
    pub custom_attributes: serde_json::Map<String, serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_user_data() {
        let mapper = AttributeMapperService::with_defaults();

        let request = CreateScimUserRequest {
            schemas: vec![ScimUser::SCHEMA.to_string()],
            user_name: "john@example.com".to_string(),
            external_id: Some("azure-12345".to_string()),
            name: Some(ScimName {
                given_name: Some("John".to_string()),
                family_name: Some("Doe".to_string()),
                ..Default::default()
            }),
            display_name: Some("John Doe".to_string()),
            active: true,
            emails: vec![],
            extensions: serde_json::Map::new(),
        };

        let data = mapper.extract_user_data(&request).unwrap();

        assert_eq!(data.email, "john@example.com");
        assert_eq!(data.display_name, Some("John Doe".to_string()));
        assert_eq!(data.first_name, Some("John".to_string()));
        assert_eq!(data.last_name, Some("Doe".to_string()));
        assert_eq!(data.external_id, Some("azure-12345".to_string()));
        assert!(data.is_active);
        assert!(data.custom_attributes.is_empty());
    }

    #[test]
    fn test_default_enterprise_extension_inbound() {
        // F081: Default mapper should extract enterprise extension attributes
        let mapper = AttributeMapperService::with_defaults();

        let enterprise_uri = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";

        let mut extensions = serde_json::Map::new();
        let mut enterprise_attrs = serde_json::Map::new();
        enterprise_attrs.insert("department".to_string(), serde_json::json!("Engineering"));
        enterprise_attrs.insert("costCenter".to_string(), serde_json::json!("CC-1234"));
        enterprise_attrs.insert("employeeNumber".to_string(), serde_json::json!("EMP-5678"));
        extensions.insert(
            enterprise_uri.to_string(),
            serde_json::Value::Object(enterprise_attrs),
        );

        let request = CreateScimUserRequest {
            schemas: vec![ScimUser::SCHEMA.to_string(), enterprise_uri.to_string()],
            user_name: "jane@example.com".to_string(),
            external_id: None,
            name: None,
            display_name: Some("Jane Doe".to_string()),
            active: true,
            emails: vec![],
            extensions,
        };

        let data = mapper.extract_user_data(&request).unwrap();

        assert_eq!(
            data.custom_attributes.get("department"),
            Some(&serde_json::json!("Engineering"))
        );
        assert_eq!(
            data.custom_attributes.get("cost_center"),
            Some(&serde_json::json!("CC-1234"))
        );
        assert_eq!(
            data.custom_attributes.get("employee_id"),
            Some(&serde_json::json!("EMP-5678"))
        );
    }

    #[test]
    fn test_default_enterprise_extension_outbound() {
        use chrono::Utc;

        // F081: Outbound SCIM GET should include enterprise extension attributes
        let mapper = AttributeMapperService::with_defaults();

        let enterprise_uri = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";

        let user = User {
            id: uuid::Uuid::new_v4(),
            tenant_id: uuid::Uuid::new_v4(),
            email: "jane@example.com".to_string(),
            password_hash: "".to_string(),
            display_name: Some("Jane Doe".to_string()),
            is_active: true,
            email_verified: true,
            email_verified_at: Some(Utc::now()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            external_id: None,
            first_name: Some("Jane".to_string()),
            last_name: Some("Doe".to_string()),
            scim_provisioned: true,
            scim_last_sync: Some(Utc::now()),
            failed_login_count: 0,
            last_failed_login_at: None,
            locked_at: None,
            locked_until: None,
            lockout_reason: None,
            password_changed_at: None,
            password_expires_at: None,
            must_change_password: false,
            avatar_url: None,
            lifecycle_state_id: None,
            manager_id: None,
            custom_attributes: serde_json::json!({
                "department": "Engineering",
                "cost_center": "CC-1234",
                "employee_id": "EMP-5678"
            }),
            // Archetype fields (F058)
            archetype_id: None,
            archetype_custom_attrs: serde_json::json!({}),
        };

        let scim_user = mapper.to_scim_user(&user, vec![], "https://idp.xavyo.com");

        // Verify enterprise extension schema is in schemas array
        assert!(
            scim_user.schemas.contains(&enterprise_uri.to_string()),
            "schemas should include enterprise extension URI"
        );

        // Verify extension data is present
        let ext = scim_user
            .extensions
            .get(enterprise_uri)
            .expect("enterprise extension should be in extensions");
        let ext_obj = ext.as_object().unwrap();
        assert_eq!(
            ext_obj.get("department"),
            Some(&serde_json::json!("Engineering"))
        );
        assert_eq!(
            ext_obj.get("costCenter"),
            Some(&serde_json::json!("CC-1234"))
        );
        assert_eq!(
            ext_obj.get("employeeNumber"),
            Some(&serde_json::json!("EMP-5678"))
        );
    }

    #[test]
    fn test_default_mapper_unmapped_extension_ignored() {
        // F081: Extension attributes without a mapping should be silently ignored
        let mapper = AttributeMapperService::with_defaults();

        let enterprise_uri = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";

        let mut extensions = serde_json::Map::new();
        let mut enterprise_attrs = serde_json::Map::new();
        // "customField123" has no default mapping
        enterprise_attrs.insert(
            "customField123".to_string(),
            serde_json::json!("some_value"),
        );
        extensions.insert(
            enterprise_uri.to_string(),
            serde_json::Value::Object(enterprise_attrs),
        );

        let request = CreateScimUserRequest {
            schemas: vec![ScimUser::SCHEMA.to_string()],
            user_name: "test@example.com".to_string(),
            external_id: None,
            name: None,
            display_name: None,
            active: true,
            emails: vec![],
            extensions,
        };

        let data = mapper.extract_user_data(&request).unwrap();

        // Only the mapped fields should appear — customField123 is not in defaults,
        // but it will appear if its scim_path happens to match. In our default setup,
        // we don't have a mapping for "customField123" so it should NOT be extracted.
        assert!(!data.custom_attributes.contains_key("customField123"));
    }

    #[test]
    fn test_to_scim_user() {
        use chrono::Utc;

        let mapper = AttributeMapperService::with_defaults();

        let user = User {
            id: uuid::Uuid::new_v4(),
            tenant_id: uuid::Uuid::new_v4(),
            email: "john@example.com".to_string(),
            password_hash: "".to_string(),
            display_name: Some("John Doe".to_string()),
            is_active: true,
            email_verified: true,
            email_verified_at: Some(Utc::now()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            external_id: Some("azure-12345".to_string()),
            first_name: Some("John".to_string()),
            last_name: Some("Doe".to_string()),
            scim_provisioned: true,
            scim_last_sync: Some(Utc::now()),
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

        let scim_user = mapper.to_scim_user(&user, vec![], "https://idp.xavyo.com");

        assert_eq!(scim_user.user_name, "john@example.com");
        assert_eq!(scim_user.display_name, Some("John Doe".to_string()));
        assert!(scim_user.active);
        assert_eq!(scim_user.emails.len(), 1);
        assert!(scim_user.meta.is_some());
    }
}
