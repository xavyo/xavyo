//! Idempotency service for preventing duplicate operations.
//!
//! Generates deterministic keys based on operation content and checks
//! for existing operations with the same key.

use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

/// Errors that can occur during idempotency operations.
#[derive(Debug, Error)]
pub enum IdempotencyError {
    /// A duplicate operation was detected.
    #[error("Duplicate operation detected: existing operation {existing_id}")]
    DuplicateOperation {
        /// The ID of the existing operation with the same idempotency key.
        existing_id: Uuid,
    },

    /// Database error during idempotency check.
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    /// Serialization error when generating key.
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// Result type for idempotency operations.
pub type IdempotencyResult<T> = Result<T, IdempotencyError>;

/// Service for generating and checking idempotency keys.
///
/// The idempotency key is a SHA256 hash of:
/// - `tenant_id`
/// - `connector_id`
/// - `user_id` (optional)
/// - `operation_type`
/// - payload hash (canonical JSON)
///
/// This ensures that identical operations produce the same key,
/// allowing duplicate detection.
#[derive(Debug, Clone)]
pub struct IdempotencyService;

impl IdempotencyService {
    /// Create a new idempotency service.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Generate an idempotency key for an operation.
    ///
    /// The key is a 64-character hex string (256 bits) derived from
    /// the operation's identifying attributes.
    ///
    /// # Arguments
    ///
    /// * `tenant_id` - The tenant ID
    /// * `connector_id` - The connector ID
    /// * `user_id` - Optional user ID (for user-related operations)
    /// * `operation_type` - The type of operation (create, update, delete, etc.)
    /// * `payload` - The operation payload as JSON
    ///
    /// # Returns
    ///
    /// A 64-character hex string that uniquely identifies this operation.
    pub fn generate_key(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
        user_id: Option<Uuid>,
        operation_type: &str,
        payload: &serde_json::Value,
    ) -> IdempotencyResult<String> {
        // Canonicalize the payload (sorted keys, no whitespace)
        let canonical_payload = self.canonicalize_json(payload)?;
        let payload_hash = self.hash_string(&canonical_payload);

        // Build the composite string to hash
        let mut composite = format!("{tenant_id}:{connector_id}:{operation_type}:{payload_hash}");

        if let Some(uid) = user_id {
            composite = format!("{tenant_id}:{connector_id}:{uid}:{operation_type}:{payload_hash}");
        }

        // Generate final hash
        Ok(self.hash_string(&composite))
    }

    /// Generate an idempotency key with explicit target entity.
    ///
    /// Use this when the target entity is known (e.g., update/delete operations).
    pub fn generate_key_for_entity(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
        entity_type: &str,
        entity_id: &str,
        operation_type: &str,
        payload: &serde_json::Value,
    ) -> IdempotencyResult<String> {
        let canonical_payload = self.canonicalize_json(payload)?;
        let payload_hash = self.hash_string(&canonical_payload);

        let composite = format!(
            "{tenant_id}:{connector_id}:{entity_type}:{entity_id}:{operation_type}:{payload_hash}"
        );

        Ok(self.hash_string(&composite))
    }

    /// Check if an operation with the given idempotency key already exists.
    ///
    /// # Arguments
    ///
    /// * `pool` - Database connection pool
    /// * `tenant_id` - The tenant ID
    /// * `idempotency_key` - The key to check
    ///
    /// # Returns
    ///
    /// - `Ok(None)` if no duplicate exists
    /// - `Ok(Some(existing_id))` if a duplicate exists
    /// - `Err(...)` on database error
    pub async fn check_duplicate(
        &self,
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        idempotency_key: &str,
    ) -> IdempotencyResult<Option<Uuid>> {
        let result: Option<(Uuid,)> = sqlx::query_as(
            r"
            SELECT id FROM provisioning_operations
            WHERE tenant_id = $1 AND idempotency_key = $2
            LIMIT 1
            ",
        )
        .bind(tenant_id)
        .bind(idempotency_key)
        .fetch_optional(pool)
        .await?;

        Ok(result.map(|(id,)| id))
    }

    /// Check for duplicate and return error if found.
    ///
    /// Convenience method that returns `IdempotencyError::DuplicateOperation`
    /// if a duplicate is detected.
    pub async fn ensure_unique(
        &self,
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        idempotency_key: &str,
    ) -> IdempotencyResult<()> {
        if let Some(existing_id) = self
            .check_duplicate(pool, tenant_id, idempotency_key)
            .await?
        {
            return Err(IdempotencyError::DuplicateOperation { existing_id });
        }
        Ok(())
    }

    /// Mark an operation as completed with idempotency protection.
    ///
    /// This is used to ensure that re-execution of the same operation
    /// is detected as a duplicate.
    pub async fn mark_completed(
        &self,
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        operation_id: Uuid,
        idempotency_key: &str,
    ) -> IdempotencyResult<()> {
        sqlx::query(
            r"
            UPDATE provisioning_operations
            SET idempotency_key = $3
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(operation_id)
        .bind(tenant_id)
        .bind(idempotency_key)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Canonicalize JSON for consistent hashing.
    ///
    /// Sorts object keys and removes whitespace to ensure identical
    /// payloads produce identical hashes.
    fn canonicalize_json(&self, value: &serde_json::Value) -> IdempotencyResult<String> {
        // serde_json serialization with sorted keys
        let canonical = self.sort_json_keys(value);
        Ok(serde_json::to_string(&canonical)?)
    }

    /// Recursively sort JSON object keys for canonical representation.
    fn sort_json_keys(&self, value: &serde_json::Value) -> serde_json::Value {
        match value {
            serde_json::Value::Object(map) => {
                let sorted: serde_json::Map<String, serde_json::Value> = map
                    .iter()
                    .map(|(k, v)| (k.clone(), self.sort_json_keys(v)))
                    .collect();
                serde_json::Value::Object(sorted)
            }
            serde_json::Value::Array(arr) => {
                serde_json::Value::Array(arr.iter().map(|v| self.sort_json_keys(v)).collect())
            }
            other => other.clone(),
        }
    }

    /// Generate SHA256 hash of a string, returning hex-encoded result.
    fn hash_string(&self, input: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        let result = hasher.finalize();
        hex::encode(result)
    }
}

impl Default for IdempotencyService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_key_deterministic() {
        let service = IdempotencyService::new();
        let tenant_id = Uuid::parse_str("12345678-1234-1234-1234-123456789abc").unwrap();
        let connector_id = Uuid::parse_str("87654321-4321-4321-4321-987654321cba").unwrap();
        let user_id = Some(Uuid::parse_str("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap());
        let payload = serde_json::json!({
            "firstName": "John",
            "lastName": "Doe",
            "email": "john@example.com"
        });

        let key1 = service
            .generate_key(tenant_id, connector_id, user_id, "create", &payload)
            .unwrap();
        let key2 = service
            .generate_key(tenant_id, connector_id, user_id, "create", &payload)
            .unwrap();

        assert_eq!(key1, key2);
        assert_eq!(key1.len(), 64); // SHA256 hex = 64 chars
    }

    #[test]
    fn test_generate_key_different_for_different_inputs() {
        let service = IdempotencyService::new();
        let tenant_id = Uuid::parse_str("12345678-1234-1234-1234-123456789abc").unwrap();
        let connector_id = Uuid::parse_str("87654321-4321-4321-4321-987654321cba").unwrap();
        let payload = serde_json::json!({"name": "test"});

        let key1 = service
            .generate_key(tenant_id, connector_id, None, "create", &payload)
            .unwrap();
        let key2 = service
            .generate_key(tenant_id, connector_id, None, "update", &payload)
            .unwrap();

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_json_key_order_independent() {
        let service = IdempotencyService::new();
        let tenant_id = Uuid::parse_str("12345678-1234-1234-1234-123456789abc").unwrap();
        let connector_id = Uuid::parse_str("87654321-4321-4321-4321-987654321cba").unwrap();

        // Same data, different key order
        let payload1 = serde_json::json!({
            "a": 1,
            "b": 2,
            "c": 3
        });
        let payload2 = serde_json::json!({
            "c": 3,
            "a": 1,
            "b": 2
        });

        let key1 = service
            .generate_key(tenant_id, connector_id, None, "create", &payload1)
            .unwrap();
        let key2 = service
            .generate_key(tenant_id, connector_id, None, "create", &payload2)
            .unwrap();

        assert_eq!(key1, key2);
    }

    #[test]
    fn test_generate_key_for_entity() {
        let service = IdempotencyService::new();
        let tenant_id = Uuid::parse_str("12345678-1234-1234-1234-123456789abc").unwrap();
        let connector_id = Uuid::parse_str("87654321-4321-4321-4321-987654321cba").unwrap();
        let payload = serde_json::json!({"status": "disabled"});

        let key = service
            .generate_key_for_entity(
                tenant_id,
                connector_id,
                "user",
                "cn=john,dc=example,dc=com",
                "update",
                &payload,
            )
            .unwrap();

        assert_eq!(key.len(), 64);
    }

    #[test]
    fn test_nested_json_canonicalization() {
        let service = IdempotencyService::new();
        let tenant_id = Uuid::new_v4();
        let connector_id = Uuid::new_v4();

        let payload1 = serde_json::json!({
            "user": {
                "z": 1,
                "a": 2
            },
            "meta": {
                "b": [3, 2, 1]
            }
        });

        let payload2 = serde_json::json!({
            "meta": {
                "b": [3, 2, 1]
            },
            "user": {
                "a": 2,
                "z": 1
            }
        });

        let key1 = service
            .generate_key(tenant_id, connector_id, None, "create", &payload1)
            .unwrap();
        let key2 = service
            .generate_key(tenant_id, connector_id, None, "create", &payload2)
            .unwrap();

        assert_eq!(key1, key2);
    }
}
