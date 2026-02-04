//! Tenant API operations (provisioning, listing, switching)

use crate::api::ApiClient;
use crate::error::{CliError, CliResult};
use crate::models::{
    ProvisionRequest, ProvisionResponse, TenantListResponse, TenantSwitchRequest,
    TenantSwitchResponse,
};
use uuid::Uuid;

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
            .map_err(|e| CliError::Server(format!("Invalid provision response: {}", e)))?;
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
            "Invalid organization name: {}",
            body
        )));
    }

    if status == reqwest::StatusCode::UNAUTHORIZED {
        return Err(CliError::NotAuthenticated);
    }

    let body = response.text().await.unwrap_or_default();
    Err(CliError::Server(format!(
        "Failed to provision tenant: {} - {}",
        status, body
    )))
}

/// List tenants the user has access to
pub async fn list_tenants(
    client: &ApiClient,
    limit: Option<u32>,
    cursor: Option<&str>,
) -> CliResult<TenantListResponse> {
    let mut url = format!("{}/users/me/tenants", client.config().api_url);

    // Add query parameters
    let mut params = vec![];
    if let Some(l) = limit {
        params.push(format!("limit={}", l));
    }
    if let Some(c) = cursor {
        params.push(format!("cursor={}", c));
    }
    if !params.is_empty() {
        url.push('?');
        url.push_str(&params.join("&"));
    }

    let response = client.get_authenticated(&url).await?;

    if response.status().is_success() {
        let tenant_response: TenantListResponse = response
            .json()
            .await
            .map_err(|e| CliError::Server(format!("Invalid tenant list response: {}", e)))?;
        return Ok(tenant_response);
    }

    let status = response.status();

    if status == reqwest::StatusCode::UNAUTHORIZED {
        return Err(CliError::NotAuthenticated);
    }

    let body = response.text().await.unwrap_or_default();
    Err(CliError::Server(format!(
        "Failed to list tenants: {} - {}",
        status, body
    )))
}

/// Switch the active tenant context
pub async fn switch_tenant(client: &ApiClient, tenant_id: Uuid) -> CliResult<TenantSwitchResponse> {
    let url = format!("{}/users/me/tenant", client.config().api_url);
    let request = TenantSwitchRequest { tenant_id };

    let response = client.post_json(&url, &request).await?;

    if response.status().is_success() {
        let switch_response: TenantSwitchResponse = response
            .json()
            .await
            .map_err(|e| CliError::Server(format!("Invalid switch response: {}", e)))?;
        return Ok(switch_response);
    }

    let status = response.status();

    if status == reqwest::StatusCode::NOT_FOUND {
        return Err(CliError::TenantNotFound(tenant_id.to_string()));
    }

    if status == reqwest::StatusCode::FORBIDDEN {
        return Err(CliError::TenantAccessDenied(tenant_id.to_string()));
    }

    if status == reqwest::StatusCode::UNAUTHORIZED {
        return Err(CliError::NotAuthenticated);
    }

    let body = response.text().await.unwrap_or_default();
    Err(CliError::Server(format!(
        "Failed to switch tenant: {} - {}",
        status, body
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
