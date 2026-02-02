//! SIEM Destination model (F078).
//!
//! Represents configured SIEM export destinations for audit log delivery.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// A configured SIEM destination.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct SiemDestination {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub destination_type: String,
    pub endpoint_host: String,
    pub endpoint_port: Option<i32>,
    pub export_format: String,
    /// Encrypted auth configuration (tokens, passwords, certs).
    pub auth_config: Option<Vec<u8>>,
    /// Event types to export (JSON array of category strings).
    pub event_type_filter: serde_json::Value,
    pub rate_limit_per_second: i32,
    pub queue_buffer_size: i32,
    pub circuit_breaker_threshold: i32,
    pub circuit_breaker_cooldown_secs: i32,
    pub circuit_state: String,
    pub circuit_last_failure_at: Option<DateTime<Utc>>,
    pub enabled: bool,
    /// Splunk-specific: source field.
    pub splunk_source: Option<String>,
    /// Splunk-specific: sourcetype field.
    pub splunk_sourcetype: Option<String>,
    /// Splunk-specific: index name.
    pub splunk_index: Option<String>,
    /// Splunk-specific: indexer acknowledgment.
    pub splunk_ack_enabled: bool,
    /// Syslog facility code (0-23).
    pub syslog_facility: i16,
    /// Whether to verify TLS certificates.
    pub tls_verify_cert: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: Uuid,
}

/// Request to create a new SIEM destination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSiemDestination {
    pub name: String,
    pub destination_type: String,
    pub endpoint_host: String,
    pub endpoint_port: Option<i32>,
    pub export_format: String,
    pub auth_config: Option<Vec<u8>>,
    #[serde(default = "default_event_filter")]
    pub event_type_filter: serde_json::Value,
    #[serde(default = "default_rate_limit")]
    pub rate_limit_per_second: i32,
    #[serde(default = "default_queue_buffer")]
    pub queue_buffer_size: i32,
    #[serde(default = "default_circuit_threshold")]
    pub circuit_breaker_threshold: i32,
    #[serde(default = "default_circuit_cooldown")]
    pub circuit_breaker_cooldown_secs: i32,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub splunk_source: Option<String>,
    pub splunk_sourcetype: Option<String>,
    pub splunk_index: Option<String>,
    #[serde(default)]
    pub splunk_ack_enabled: bool,
    #[serde(default = "default_syslog_facility")]
    pub syslog_facility: i16,
    #[serde(default = "default_true")]
    pub tls_verify_cert: bool,
}

fn default_event_filter() -> serde_json::Value {
    serde_json::json!([])
}
fn default_rate_limit() -> i32 {
    1000
}
fn default_queue_buffer() -> i32 {
    10000
}
fn default_circuit_threshold() -> i32 {
    5
}
fn default_circuit_cooldown() -> i32 {
    60
}
fn default_true() -> bool {
    true
}
fn default_syslog_facility() -> i16 {
    10
}

/// Request to update a SIEM destination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateSiemDestination {
    pub name: Option<String>,
    pub endpoint_host: Option<String>,
    pub endpoint_port: Option<i32>,
    pub export_format: Option<String>,
    pub auth_config: Option<Vec<u8>>,
    pub event_type_filter: Option<serde_json::Value>,
    pub rate_limit_per_second: Option<i32>,
    pub queue_buffer_size: Option<i32>,
    pub circuit_breaker_threshold: Option<i32>,
    pub circuit_breaker_cooldown_secs: Option<i32>,
    pub enabled: Option<bool>,
    pub splunk_source: Option<String>,
    pub splunk_sourcetype: Option<String>,
    pub splunk_index: Option<String>,
    pub splunk_ack_enabled: Option<bool>,
    pub syslog_facility: Option<i16>,
    pub tls_verify_cert: Option<bool>,
}

impl SiemDestination {
    /// Find a destination by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM siem_destinations
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find a destination by name within a tenant.
    pub async fn find_by_name(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        name: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM siem_destinations
            WHERE tenant_id = $1 AND name = $2
            "#,
        )
        .bind(tenant_id)
        .bind(name)
        .fetch_optional(pool)
        .await
    }

    /// List all destinations for a tenant with pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        enabled_only: Option<bool>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT * FROM siem_destinations
            WHERE tenant_id = $1
            "#,
        );
        let mut param_count = 1;

        if enabled_only.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND enabled = ${}", param_count));
        }

        query.push_str(&format!(
            " ORDER BY name LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, SiemDestination>(&query).bind(tenant_id);

        if let Some(enabled) = enabled_only {
            q = q.bind(enabled);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// List all enabled destinations for a tenant (used by pipeline).
    pub async fn list_enabled(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM siem_destinations
            WHERE tenant_id = $1 AND enabled = true
            ORDER BY name
            "#,
        )
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// Count destinations in a tenant.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        enabled_only: Option<bool>,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT COUNT(*) FROM siem_destinations
            WHERE tenant_id = $1
            "#,
        );
        let mut param_count = 1;

        if enabled_only.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND enabled = ${}", param_count));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(enabled) = enabled_only {
            q = q.bind(enabled);
        }

        q.fetch_one(pool).await
    }

    /// Create a new SIEM destination.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        created_by: Uuid,
        input: CreateSiemDestination,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r#"
            INSERT INTO siem_destinations (
                tenant_id, name, destination_type, endpoint_host, endpoint_port,
                export_format, auth_config, event_type_filter,
                rate_limit_per_second, queue_buffer_size,
                circuit_breaker_threshold, circuit_breaker_cooldown_secs,
                enabled, splunk_source, splunk_sourcetype, splunk_index,
                splunk_ack_enabled, syslog_facility, tls_verify_cert, created_by
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(&input.name)
        .bind(&input.destination_type)
        .bind(&input.endpoint_host)
        .bind(input.endpoint_port)
        .bind(&input.export_format)
        .bind(&input.auth_config)
        .bind(&input.event_type_filter)
        .bind(input.rate_limit_per_second)
        .bind(input.queue_buffer_size)
        .bind(input.circuit_breaker_threshold)
        .bind(input.circuit_breaker_cooldown_secs)
        .bind(input.enabled)
        .bind(&input.splunk_source)
        .bind(&input.splunk_sourcetype)
        .bind(&input.splunk_index)
        .bind(input.splunk_ack_enabled)
        .bind(input.syslog_facility)
        .bind(input.tls_verify_cert)
        .bind(created_by)
        .fetch_one(pool)
        .await
    }

    /// Update a SIEM destination.
    pub async fn update(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateSiemDestination,
    ) -> Result<Option<Self>, sqlx::Error> {
        let mut updates = vec!["updated_at = NOW()".to_string()];
        let mut param_idx = 3; // $1=id, $2=tenant_id

        if input.name.is_some() {
            updates.push(format!("name = ${}", param_idx));
            param_idx += 1;
        }
        if input.endpoint_host.is_some() {
            updates.push(format!("endpoint_host = ${}", param_idx));
            param_idx += 1;
        }
        if input.endpoint_port.is_some() {
            updates.push(format!("endpoint_port = ${}", param_idx));
            param_idx += 1;
        }
        if input.export_format.is_some() {
            updates.push(format!("export_format = ${}", param_idx));
            param_idx += 1;
        }
        if input.auth_config.is_some() {
            updates.push(format!("auth_config = ${}", param_idx));
            param_idx += 1;
        }
        if input.event_type_filter.is_some() {
            updates.push(format!("event_type_filter = ${}", param_idx));
            param_idx += 1;
        }
        if input.rate_limit_per_second.is_some() {
            updates.push(format!("rate_limit_per_second = ${}", param_idx));
            param_idx += 1;
        }
        if input.queue_buffer_size.is_some() {
            updates.push(format!("queue_buffer_size = ${}", param_idx));
            param_idx += 1;
        }
        if input.circuit_breaker_threshold.is_some() {
            updates.push(format!("circuit_breaker_threshold = ${}", param_idx));
            param_idx += 1;
        }
        if input.circuit_breaker_cooldown_secs.is_some() {
            updates.push(format!("circuit_breaker_cooldown_secs = ${}", param_idx));
            param_idx += 1;
        }
        if input.enabled.is_some() {
            updates.push(format!("enabled = ${}", param_idx));
            param_idx += 1;
        }
        if input.splunk_source.is_some() {
            updates.push(format!("splunk_source = ${}", param_idx));
            param_idx += 1;
        }
        if input.splunk_sourcetype.is_some() {
            updates.push(format!("splunk_sourcetype = ${}", param_idx));
            param_idx += 1;
        }
        if input.splunk_index.is_some() {
            updates.push(format!("splunk_index = ${}", param_idx));
            param_idx += 1;
        }
        if input.splunk_ack_enabled.is_some() {
            updates.push(format!("splunk_ack_enabled = ${}", param_idx));
            param_idx += 1;
        }
        if input.syslog_facility.is_some() {
            updates.push(format!("syslog_facility = ${}", param_idx));
            param_idx += 1;
        }
        if input.tls_verify_cert.is_some() {
            updates.push(format!("tls_verify_cert = ${}", param_idx));
            let _ = param_idx;
        }

        let query = format!(
            "UPDATE siem_destinations SET {} WHERE id = $1 AND tenant_id = $2 RETURNING *",
            updates.join(", ")
        );

        let mut q = sqlx::query_as::<_, SiemDestination>(&query)
            .bind(id)
            .bind(tenant_id);

        if let Some(ref name) = input.name {
            q = q.bind(name);
        }
        if let Some(ref endpoint_host) = input.endpoint_host {
            q = q.bind(endpoint_host);
        }
        if let Some(endpoint_port) = input.endpoint_port {
            q = q.bind(endpoint_port);
        }
        if let Some(ref export_format) = input.export_format {
            q = q.bind(export_format);
        }
        if let Some(ref auth_config) = input.auth_config {
            q = q.bind(auth_config);
        }
        if let Some(ref event_type_filter) = input.event_type_filter {
            q = q.bind(event_type_filter);
        }
        if let Some(rate_limit) = input.rate_limit_per_second {
            q = q.bind(rate_limit);
        }
        if let Some(queue_buffer) = input.queue_buffer_size {
            q = q.bind(queue_buffer);
        }
        if let Some(threshold) = input.circuit_breaker_threshold {
            q = q.bind(threshold);
        }
        if let Some(cooldown) = input.circuit_breaker_cooldown_secs {
            q = q.bind(cooldown);
        }
        if let Some(enabled) = input.enabled {
            q = q.bind(enabled);
        }
        if let Some(ref splunk_source) = input.splunk_source {
            q = q.bind(splunk_source);
        }
        if let Some(ref splunk_sourcetype) = input.splunk_sourcetype {
            q = q.bind(splunk_sourcetype);
        }
        if let Some(ref splunk_index) = input.splunk_index {
            q = q.bind(splunk_index);
        }
        if let Some(splunk_ack) = input.splunk_ack_enabled {
            q = q.bind(splunk_ack);
        }
        if let Some(facility) = input.syslog_facility {
            q = q.bind(facility);
        }
        if let Some(tls_verify) = input.tls_verify_cert {
            q = q.bind(tls_verify);
        }

        q.fetch_optional(pool).await
    }

    /// Update circuit breaker state for a destination.
    pub async fn update_circuit_state(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        state: &str,
        last_failure_at: Option<DateTime<Utc>>,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r#"
            UPDATE siem_destinations
            SET circuit_state = $3, circuit_last_failure_at = $4, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(state)
        .bind(last_failure_at)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Delete a destination.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM siem_destinations
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_destination_request() {
        let request = CreateSiemDestination {
            name: "Production SIEM".to_string(),
            destination_type: "syslog_tcp_tls".to_string(),
            endpoint_host: "siem.example.com".to_string(),
            endpoint_port: Some(6514),
            export_format: "cef".to_string(),
            auth_config: None,
            event_type_filter: serde_json::json!(["authentication", "security"]),
            rate_limit_per_second: 1000,
            queue_buffer_size: 10000,
            circuit_breaker_threshold: 5,
            circuit_breaker_cooldown_secs: 60,
            enabled: true,
            splunk_source: None,
            splunk_sourcetype: None,
            splunk_index: None,
            splunk_ack_enabled: false,
            syslog_facility: 10,
            tls_verify_cert: true,
        };

        assert_eq!(request.name, "Production SIEM");
        assert_eq!(request.destination_type, "syslog_tcp_tls");
        assert_eq!(request.rate_limit_per_second, 1000);
        assert!(request.tls_verify_cert);
    }

    #[test]
    fn test_create_splunk_destination() {
        let request = CreateSiemDestination {
            name: "Splunk Cloud".to_string(),
            destination_type: "splunk_hec".to_string(),
            endpoint_host: "input-prd.splunkcloud.com".to_string(),
            endpoint_port: Some(8088),
            export_format: "json".to_string(),
            auth_config: Some(vec![1, 2, 3]),
            event_type_filter: serde_json::json!([]),
            rate_limit_per_second: 500,
            queue_buffer_size: 5000,
            circuit_breaker_threshold: 3,
            circuit_breaker_cooldown_secs: 120,
            enabled: true,
            splunk_source: Some("xavyo".to_string()),
            splunk_sourcetype: Some("xavyo:audit".to_string()),
            splunk_index: Some("security".to_string()),
            splunk_ack_enabled: true,
            syslog_facility: 10,
            tls_verify_cert: true,
        };

        assert_eq!(request.destination_type, "splunk_hec");
        assert!(request.splunk_ack_enabled);
        assert_eq!(request.splunk_index, Some("security".to_string()));
    }

    #[test]
    fn test_update_destination_request() {
        let update = UpdateSiemDestination {
            name: Some("Updated SIEM".to_string()),
            endpoint_host: None,
            endpoint_port: None,
            export_format: None,
            auth_config: None,
            event_type_filter: Some(serde_json::json!(["authentication"])),
            rate_limit_per_second: None,
            queue_buffer_size: None,
            circuit_breaker_threshold: None,
            circuit_breaker_cooldown_secs: None,
            enabled: Some(false),
            splunk_source: None,
            splunk_sourcetype: None,
            splunk_index: None,
            splunk_ack_enabled: None,
            syslog_facility: None,
            tls_verify_cert: None,
        };

        assert_eq!(update.name, Some("Updated SIEM".to_string()));
        assert_eq!(update.enabled, Some(false));
    }

    #[test]
    fn test_default_values_via_serde() {
        let json = r#"{"name":"Test","destination_type":"webhook","endpoint_host":"hook.example.com","export_format":"json"}"#;
        let dest: CreateSiemDestination = serde_json::from_str(json).unwrap();
        assert_eq!(dest.rate_limit_per_second, 1000);
        assert_eq!(dest.queue_buffer_size, 10000);
        assert_eq!(dest.circuit_breaker_threshold, 5);
        assert_eq!(dest.circuit_breaker_cooldown_secs, 60);
        assert!(dest.enabled);
        assert!(dest.tls_verify_cert);
        assert_eq!(dest.syslog_facility, 10);
        assert!(!dest.splunk_ack_enabled);
    }
}
