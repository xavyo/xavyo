//! Audit log API client for the xavyo CLI
//!
//! This module provides functions for interacting with the audit log API,
//! including listing audit entries and streaming real-time audit events.

use crate::api::ApiClient;
use crate::error::{CliError, CliResult};
use crate::models::audit::{AuditEntry, AuditFilter, AuditListResponse};
use futures_util::StreamExt;
use reqwest_eventsource::{Event, EventSource};

impl ApiClient {
    /// List audit log entries with optional filtering
    pub async fn list_audit_logs(&self, filter: &AuditFilter) -> CliResult<AuditListResponse> {
        let url = format!(
            "{}/audit?{}",
            self.config().api_url,
            filter.to_query_string()
        );

        let response = self.get_authenticated(&url).await?;

        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            Err(CliError::NotAuthenticated)
        } else if response.status() == reqwest::StatusCode::FORBIDDEN {
            Err(CliError::AuthorizationDenied)
        } else if response.status() == reqwest::StatusCode::BAD_REQUEST {
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Validation(body))
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }
}

/// Stream audit log events in real-time via SSE
#[allow(dead_code)]
///
/// # Arguments
/// * `api_client` - The API client to use for authentication
/// * `action_filter` - Optional action type to filter events
///
/// # Returns
/// An EventSource that yields audit events
pub async fn stream_audit_logs(
    api_client: &ApiClient,
    action_filter: Option<&str>,
) -> CliResult<EventSource> {
    let mut url = format!("{}/audit/stream", api_client.config().api_url);

    if let Some(action) = action_filter {
        url = format!("{}?action={}", url, action);
    }

    // Get the token for authentication
    let token = api_client.get_access_token().await?;

    // Create the event source with authentication header
    let client = reqwest::Client::new();
    let request = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", token))
        .header("Accept", "text/event-stream");

    let es = EventSource::new(request).map_err(|e| CliError::Network(e.to_string()))?;

    Ok(es)
}

/// Parse an SSE event into an AuditEntry
#[allow(dead_code)]
pub fn parse_audit_event(event: &Event) -> Option<AuditEntry> {
    match event {
        Event::Message(msg) => {
            // Parse the data as JSON
            serde_json::from_str(&msg.data).ok()
        }
        Event::Open => None,
    }
}

/// Helper function to consume stream events
#[allow(dead_code)]
pub async fn consume_stream_event(es: &mut EventSource) -> Option<Result<AuditEntry, CliError>> {
    loop {
        match es.next().await {
            Some(Ok(event)) => {
                if let Some(entry) = parse_audit_event(&event) {
                    return Some(Ok(entry));
                }
                // Continue if we got an open event or unparseable message
            }
            Some(Err(e)) => {
                return Some(Err(CliError::Network(e.to_string())));
            }
            None => {
                // Stream ended
                return None;
            }
        }
    }
}

// ============================================================================
// Public API Functions
// ============================================================================

/// List audit logs using the provided API client
#[allow(dead_code)]
pub async fn list_audit_logs(
    client: &ApiClient,
    filter: &AuditFilter,
) -> CliResult<AuditListResponse> {
    client.list_audit_logs(filter).await
}
