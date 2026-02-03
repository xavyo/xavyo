//! Integration tests for multi-cloud endpoint support.

#![cfg(feature = "integration")]

use xavyo_connector_entra::EntraCloudEnvironment;

/// Tests that Commercial cloud uses correct endpoints.
#[test]
fn test_commercial_cloud_endpoints() {
    let env = EntraCloudEnvironment::Commercial;

    assert_eq!(env.login_endpoint(), "https://login.microsoftonline.com");
    assert_eq!(env.graph_endpoint(), "https://graph.microsoft.com");
}

/// Tests that US Government cloud uses correct endpoints.
#[test]
fn test_us_government_gcc_endpoints() {
    let env = EntraCloudEnvironment::UsGovernment;

    // GCC and GCC-High use different endpoints
    // Note: GCC uses commercial endpoints, GCC-High uses .us
    assert_eq!(env.login_endpoint(), "https://login.microsoftonline.us");
    assert_eq!(env.graph_endpoint(), "https://graph.microsoft.us");
}

/// Tests that China cloud uses correct endpoints.
#[test]
fn test_china_cloud_endpoints() {
    let env = EntraCloudEnvironment::China;

    assert_eq!(env.login_endpoint(), "https://login.chinacloudapi.cn");
    assert_eq!(env.graph_endpoint(), "https://microsoftgraph.chinacloudapi.cn");
}

/// Tests that Germany cloud uses correct endpoints.
#[test]
fn test_germany_cloud_endpoints() {
    let env = EntraCloudEnvironment::Germany;

    assert_eq!(env.login_endpoint(), "https://login.microsoftonline.de");
    assert_eq!(env.graph_endpoint(), "https://graph.microsoft.de");
}

/// Tests that endpoint URLs are properly constructed.
#[test]
fn test_endpoint_url_construction() {
    let env = EntraCloudEnvironment::Commercial;

    // Graph endpoint should be a valid URL
    let graph = env.graph_endpoint();
    assert!(graph.starts_with("https://"));
    assert!(!graph.ends_with("/"));

    // Login endpoint should be a valid URL
    let login = env.login_endpoint();
    assert!(login.starts_with("https://"));
    assert!(!login.ends_with("/"));
}

/// Tests token endpoint construction per cloud.
#[test]
fn test_token_endpoint_per_cloud() {
    let tenant_id = "test-tenant-id";

    // Commercial
    let commercial = EntraCloudEnvironment::Commercial;
    let token_url = format!("{}/{}/oauth2/v2.0/token", commercial.login_endpoint(), tenant_id);
    assert_eq!(
        token_url,
        "https://login.microsoftonline.com/test-tenant-id/oauth2/v2.0/token"
    );

    // US Government
    let us_gov = EntraCloudEnvironment::UsGovernment;
    let token_url = format!("{}/{}/oauth2/v2.0/token", us_gov.login_endpoint(), tenant_id);
    assert_eq!(
        token_url,
        "https://login.microsoftonline.us/test-tenant-id/oauth2/v2.0/token"
    );

    // China
    let china = EntraCloudEnvironment::China;
    let token_url = format!("{}/{}/oauth2/v2.0/token", china.login_endpoint(), tenant_id);
    assert_eq!(
        token_url,
        "https://login.chinacloudapi.cn/test-tenant-id/oauth2/v2.0/token"
    );
}

/// Tests that all environments have distinct endpoints.
#[test]
fn test_all_environments_distinct() {
    let environments = vec![
        EntraCloudEnvironment::Commercial,
        EntraCloudEnvironment::UsGovernment,
        EntraCloudEnvironment::China,
        EntraCloudEnvironment::Germany,
    ];

    let login_endpoints: Vec<_> = environments.iter().map(|e| e.login_endpoint()).collect();
    let graph_endpoints: Vec<_> = environments.iter().map(|e| e.graph_endpoint()).collect();

    // All login endpoints should be unique
    let unique_logins: std::collections::HashSet<_> = login_endpoints.iter().collect();
    assert_eq!(unique_logins.len(), environments.len());

    // All graph endpoints should be unique
    let unique_graphs: std::collections::HashSet<_> = graph_endpoints.iter().collect();
    assert_eq!(unique_graphs.len(), environments.len());
}

/// Tests default environment is Commercial.
#[test]
fn test_default_environment_is_commercial() {
    let default_env = EntraCloudEnvironment::default();
    assert_eq!(default_env.login_endpoint(), EntraCloudEnvironment::Commercial.login_endpoint());
    assert_eq!(default_env.graph_endpoint(), EntraCloudEnvironment::Commercial.graph_endpoint());
}
