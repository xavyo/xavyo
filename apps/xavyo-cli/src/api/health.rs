//! Health check API

use crate::api::ApiClient;
use crate::error::{CliError, CliResult};
use crate::models::{HealthResponse, HealthStatus};

/// Check API health
pub async fn check_health(client: &ApiClient, url: &str) -> CliResult<HealthResponse> {
    let response = client.get_unauthenticated(url).await;

    match response {
        Ok(resp) if resp.status().is_success() => resp
            .json()
            .await
            .map_err(|e| CliError::Server(format!("Invalid health response: {}", e))),
        Ok(resp) => {
            // Non-success status but we got a response
            Err(CliError::Server(format!(
                "Health check returned status: {}",
                resp.status()
            )))
        }
        Err(e) => {
            // Connection failed - return unhealthy status
            Err(CliError::ConnectionFailed(e.to_string()))
        }
    }
}

/// Check health and return a result suitable for display
pub async fn check_health_display(client: &ApiClient, url: &str) -> (HealthStatus, Option<String>) {
    match check_health(client, url).await {
        Ok(health) => (health.status, health.version),
        Err(_) => (HealthStatus::Unhealthy, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_response_parsing() {
        let json = r#"{"status": "healthy", "version": "1.0.0"}"#;
        let response: HealthResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.status, HealthStatus::Healthy);
    }
}
