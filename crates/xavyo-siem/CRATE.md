# xavyo-siem

> SIEM integration and audit log export for compliance and security monitoring.

## Purpose

Exports audit logs to external SIEM systems for compliance, security monitoring, and threat detection. Supports multiple formats (CEF v0, RFC 5424 syslog, JSON, CSV) and delivery methods (syslog TCP/TLS, syslog UDP, webhook, Splunk HEC). Includes circuit breaker patterns, rate limiting, and batch export capabilities.

## Layer

domain

## Dependencies

### Internal (xavyo)
- `xavyo-db` - Audit log storage

### External (key)
- `tokio` - Async runtime, TCP/UDP sockets
- `tokio-native-tls` - TLS for syslog
- `reqwest` - Webhook/Splunk HEC delivery
- `governor` - Rate limiting
- `csv` - CSV export

## Public API

### Types

```rust
/// Export format types
pub enum ExportFormat {
    Cef,      // Common Event Format v0
    Syslog,   // RFC 5424
    Json,     // JSON lines
    Csv,      // CSV with headers
}

/// Delivery types
pub enum DeliveryType {
    SyslogTcp,   // RFC 5424 over TCP
    SyslogTls,   // RFC 5424 over TLS
    SyslogUdp,   // RFC 5424 over UDP
    Webhook,     // HTTP POST
    SplunkHec,   // Splunk HTTP Event Collector
}

/// SIEM destination configuration
pub struct SiemDestination {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub delivery_type: DeliveryType,
    pub format: ExportFormat,
    pub endpoint: String,
    pub auth_config: Option<Vec<u8>>,  // Encrypted
    pub enabled: bool,
}

/// Batch export job
pub struct BatchExportJob {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub destination_id: Uuid,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub status: JobStatus,
}

/// Delivery health metrics
pub struct DeliveryHealth {
    pub destination_id: Uuid,
    pub success_count: i64,
    pub failure_count: i64,
    pub last_success: Option<DateTime<Utc>>,
    pub circuit_state: CircuitState,
}
```

### Modules

```rust
/// Format converters
pub mod format {
    pub fn to_cef(event: &AuditEvent) -> String;
    pub fn to_syslog(event: &AuditEvent) -> String;
    pub fn to_json(event: &AuditEvent) -> String;
}

/// Delivery workers
pub mod delivery {
    pub struct SyslogTcpWorker { ... }
    pub struct SyslogUdpWorker { ... }
    pub struct WebhookWorker { ... }
    pub struct SplunkHecWorker { ... }
}

/// Pipeline orchestration
pub mod pipeline {
    pub struct ExportPipeline { ... }
    pub struct CircuitBreaker { ... }
}

/// Batch export
pub mod batch {
    pub struct BatchExporter { ... }
}
```

## Usage Example

```rust
use xavyo_siem::{
    format::{to_cef, to_syslog},
    delivery::SyslogTcpWorker,
    pipeline::ExportPipeline,
};

// Format an audit event
let cef_line = to_cef(&audit_event);
// CEF:0|xavyo|idp|1.0|USER_LOGIN|User Login|5|src=192.168.1.1 ...

let syslog_line = to_syslog(&audit_event);
// <134>1 2024-01-15T10:30:00Z xavyo idp - - - {...}

// Create export pipeline
let pipeline = ExportPipeline::new(pool.clone(), config);
pipeline.start(shutdown_token).await;

// Run batch export
let batch_exporter = BatchExporter::new(pool.clone());
batch_exporter.export(BatchExportJob {
    tenant_id,
    destination_id,
    start_time: Utc::now() - Duration::days(1),
    end_time: Utc::now(),
    ..Default::default()
}).await?;
```

## Integration Points

- **Consumed by**: `xavyo-api-governance` (audit endpoints)
- **Exports to**: Splunk, QRadar, Sentinel, generic syslog
- **Reads from**: `xavyo-db` audit tables

## Feature Flags

None - all features are enabled by default.

## Anti-Patterns

- Never export audit logs without tenant context
- Never skip TLS verification in production
- Never store auth credentials unencrypted
- Never bypass rate limiting for "priority" events

## Related Crates

- `xavyo-webhooks` - Real-time event delivery (different purpose)
- `xavyo-events` - Kafka events (different mechanism)
- `xavyo-db` - Audit log storage
