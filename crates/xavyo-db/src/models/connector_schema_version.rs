//! Connector Schema Version model.
//!
//! Represents versioned snapshots of discovered schemas for diff comparison.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// How the schema discovery was triggered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "VARCHAR", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum TriggeredBy {
    /// Manually triggered by a user.
    #[default]
    Manual,
    /// Triggered by a scheduled job.
    Scheduled,
    /// Triggered via API.
    Api,
}

impl TriggeredBy {
    /// Get the string representation.
    #[must_use] 
    pub fn as_str(&self) -> &'static str {
        match self {
            TriggeredBy::Manual => "manual",
            TriggeredBy::Scheduled => "scheduled",
            TriggeredBy::Api => "api",
        }
    }

    /// Parse from string.
    #[must_use] 
    pub fn parse_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "manual" => Some(TriggeredBy::Manual),
            "scheduled" => Some(TriggeredBy::Scheduled),
            "api" => Some(TriggeredBy::Api),
            _ => None,
        }
    }
}

impl std::fmt::Display for TriggeredBy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A versioned snapshot of a discovered schema.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct ConnectorSchemaVersion {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant this schema belongs to.
    pub tenant_id: Uuid,

    /// Connector this schema was discovered from.
    pub connector_id: Uuid,

    /// Version number (auto-increment per connector, starts at 1).
    pub version: i32,

    /// Complete schema snapshot (JSON).
    pub schema_data: serde_json::Value,

    /// Number of object classes in this schema.
    pub object_class_count: i32,

    /// Total number of attributes across all classes.
    pub attribute_count: i32,

    /// When the schema was discovered.
    pub discovered_at: DateTime<Utc>,

    /// How long the discovery took in milliseconds.
    pub discovery_duration_ms: i64,

    /// How the discovery was triggered.
    pub triggered_by: String,

    /// User who triggered (if manual).
    pub triggered_by_user: Option<Uuid>,

    /// When the record was created.
    pub created_at: DateTime<Utc>,
}

/// Input for creating a new schema version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSchemaVersion {
    /// Complete schema snapshot.
    pub schema_data: serde_json::Value,
    /// Number of object classes.
    pub object_class_count: i32,
    /// Total attribute count.
    pub attribute_count: i32,
    /// Discovery duration in milliseconds.
    pub discovery_duration_ms: i64,
    /// How discovery was triggered.
    pub triggered_by: TriggeredBy,
    /// User who triggered (if manual).
    pub triggered_by_user: Option<Uuid>,
}

/// Summary of a schema version (for listing).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaVersionSummary {
    /// Version number.
    pub version: i32,
    /// When discovered.
    pub discovered_at: DateTime<Utc>,
    /// Discovery duration.
    pub discovery_duration_ms: i64,
    /// Object class count.
    pub object_class_count: i32,
    /// Attribute count.
    pub attribute_count: i32,
    /// How triggered.
    pub triggered_by: String,
    /// Who triggered.
    pub triggered_by_user: Option<Uuid>,
}

impl ConnectorSchemaVersion {
    /// Get the latest version number for a connector.
    pub async fn get_latest_version(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> Result<Option<i32>, sqlx::Error> {
        let result: Option<(i32,)> = sqlx::query_as(
            r"
            SELECT version FROM connector_schema_versions
            WHERE connector_id = $1 AND tenant_id = $2
            ORDER BY version DESC
            LIMIT 1
            ",
        )
        .bind(connector_id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await?;

        Ok(result.map(|(v,)| v))
    }

    /// Get the next version number for a connector.
    pub async fn get_next_version(
        pool: &sqlx::PgPool,
        connector_id: Uuid,
    ) -> Result<i32, sqlx::Error> {
        let result: (i32,) = sqlx::query_as(r"SELECT get_next_schema_version($1)")
            .bind(connector_id)
            .fetch_one(pool)
            .await?;

        Ok(result.0)
    }

    /// Create a new schema version.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
        input: &CreateSchemaVersion,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO connector_schema_versions (
                tenant_id, connector_id, version, schema_data,
                object_class_count, attribute_count, discovered_at,
                discovery_duration_ms, triggered_by, triggered_by_user
            )
            VALUES (
                $1, $2, get_next_schema_version($2), $3,
                $4, $5, NOW(),
                $6, $7, $8
            )
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .bind(&input.schema_data)
        .bind(input.object_class_count)
        .bind(input.attribute_count)
        .bind(input.discovery_duration_ms)
        .bind(input.triggered_by.as_str())
        .bind(input.triggered_by_user)
        .fetch_one(pool)
        .await
    }

    /// Find a specific version.
    pub async fn find_by_version(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
        version: i32,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM connector_schema_versions
            WHERE connector_id = $1 AND tenant_id = $2 AND version = $3
            ",
        )
        .bind(connector_id)
        .bind(tenant_id)
        .bind(version)
        .fetch_optional(pool)
        .await
    }

    /// Get the latest version.
    pub async fn find_latest(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM connector_schema_versions
            WHERE connector_id = $1 AND tenant_id = $2
            ORDER BY version DESC
            LIMIT 1
            ",
        )
        .bind(connector_id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List all versions for a connector with pagination.
    pub async fn list_versions(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
        limit: i32,
        offset: i32,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM connector_schema_versions
            WHERE connector_id = $1 AND tenant_id = $2
            ORDER BY version DESC
            LIMIT $3 OFFSET $4
            ",
        )
        .bind(connector_id)
        .bind(tenant_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

    /// Count total versions for a connector.
    pub async fn count_versions(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        let result: (i64,) = sqlx::query_as(
            r"
            SELECT COUNT(*) FROM connector_schema_versions
            WHERE connector_id = $1 AND tenant_id = $2
            ",
        )
        .bind(connector_id)
        .bind(tenant_id)
        .fetch_one(pool)
        .await?;

        Ok(result.0)
    }

    /// Delete old versions (keep last N).
    pub async fn cleanup_old_versions(
        pool: &sqlx::PgPool,
        connector_id: Uuid,
        keep_count: i32,
    ) -> Result<u64, sqlx::Error> {
        let result: (i32,) = sqlx::query_as(r"SELECT cleanup_old_schema_versions($1, $2)")
            .bind(connector_id)
            .bind(keep_count)
            .fetch_one(pool)
            .await?;

        Ok(result.0 as u64)
    }

    /// Delete all versions for a connector.
    pub async fn delete_by_connector(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM connector_schema_versions
            WHERE connector_id = $1 AND tenant_id = $2
            ",
        )
        .bind(connector_id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Convert to summary.
    #[must_use] 
    pub fn to_summary(&self) -> SchemaVersionSummary {
        SchemaVersionSummary {
            version: self.version,
            discovered_at: self.discovered_at,
            discovery_duration_ms: self.discovery_duration_ms,
            object_class_count: self.object_class_count,
            attribute_count: self.attribute_count,
            triggered_by: self.triggered_by.clone(),
            triggered_by_user: self.triggered_by_user,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_triggered_by_conversion() {
        assert_eq!(TriggeredBy::Manual.as_str(), "manual");
        assert_eq!(TriggeredBy::Scheduled.as_str(), "scheduled");
        assert_eq!(TriggeredBy::Api.as_str(), "api");

        assert_eq!(TriggeredBy::parse_str("manual"), Some(TriggeredBy::Manual));
        assert_eq!(
            TriggeredBy::parse_str("SCHEDULED"),
            Some(TriggeredBy::Scheduled)
        );
        assert_eq!(TriggeredBy::parse_str("Api"), Some(TriggeredBy::Api));
        assert_eq!(TriggeredBy::parse_str("unknown"), None);
    }

    #[test]
    fn test_create_schema_version_input() {
        let input = CreateSchemaVersion {
            schema_data: serde_json::json!({
                "object_classes": []
            }),
            object_class_count: 5,
            attribute_count: 50,
            discovery_duration_ms: 1500,
            triggered_by: TriggeredBy::Manual,
            triggered_by_user: Some(Uuid::new_v4()),
        };

        assert_eq!(input.object_class_count, 5);
        assert_eq!(input.attribute_count, 50);
        assert_eq!(input.discovery_duration_ms, 1500);
    }

    #[test]
    fn test_schema_version_summary() {
        let summary = SchemaVersionSummary {
            version: 3,
            discovered_at: Utc::now(),
            discovery_duration_ms: 2500,
            object_class_count: 10,
            attribute_count: 100,
            triggered_by: "scheduled".to_string(),
            triggered_by_user: None,
        };

        assert_eq!(summary.version, 3);
        assert_eq!(summary.triggered_by, "scheduled");
    }
}
