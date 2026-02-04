//! Tenant provisioning API

use crate::api::ApiClient;
use crate::error::{CliError, CliResult};
use crate::models::{ProvisionRequest, ProvisionResponse};

/// Provision a new tenant
pub async fn provision_tenant(
    client: &ApiClient,
    request: &ProvisionRequest,
) -> CliResult<ProvisionResponse> {
    let url = client.config().provision_url();

    let response = client.post_json(&url, request).await?;

    if response.status().is_success() {
        let provision_response: ProvisionResponse = response
            .json()
            .await
            .map_err(|e| CliError::Server(format!("Invalid provision response: {e}")))?;
        return Ok(provision_response);
    }

    // Handle error responses
    let status = response.status();

    if status == reqwest::StatusCode::CONFLICT {
        // Try to extract the slug from the error response
        if let Ok(body) = response.text().await {
            if body.contains("slug") {
                return Err(CliError::TenantExists(
                    "A tenant with this name already exists".to_string(),
                ));
            }
        }
        return Err(CliError::TenantExists("Tenant already exists".to_string()));
    }

    if status == reqwest::StatusCode::BAD_REQUEST {
        let body = response.text().await.unwrap_or_default();
        return Err(CliError::Validation(format!(
            "Invalid organization name: {body}"
        )));
    }

    if status == reqwest::StatusCode::UNAUTHORIZED {
        return Err(CliError::NotAuthenticated);
    }

    let body = response.text().await.unwrap_or_default();
    Err(CliError::Server(format!(
        "Failed to provision tenant: {status} - {body}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provision_request_serialization() {
        let request = ProvisionRequest::new("Test Org".to_string());
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("Test Org"));
    }
}
