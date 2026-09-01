//! Response types for SAML API

use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

/// SSO redirect query parameters
#[derive(Debug, Deserialize, IntoParams)]
pub struct SsoRedirectQuery {
    #[serde(rename = "SAMLRequest")]
    pub saml_request: String,
    #[serde(rename = "RelayState")]
    pub relay_state: Option<String>,
    #[serde(rename = "SigAlg")]
    pub sig_alg: Option<String>,
    #[serde(rename = "Signature")]
    pub signature: Option<String>,
    /// Tenant ID (required for SP-initiated SSO via browser redirect)
    pub tenant: Option<String>,
}

/// SSO POST form data
#[derive(Debug, Deserialize, ToSchema)]
pub struct SsoPostForm {
    #[serde(rename = "SAMLRequest")]
    pub saml_request: String,
    #[serde(rename = "RelayState")]
    pub relay_state: Option<String>,
}

/// IdP-initiated SSO request
#[derive(Debug, Deserialize, ToSchema)]
pub struct InitiateSsoRequest {
    pub relay_state: Option<String>,
}

/// Service Provider list response
#[derive(Debug, Serialize, ToSchema)]
pub struct ServiceProviderListResponse {
    pub items: Vec<ServiceProviderResponse>,
    pub total: i64,
    pub limit: i32,
    pub offset: i32,
}

/// Single Service Provider response
#[derive(Debug, Serialize, ToSchema)]
pub struct ServiceProviderResponse {
    pub id: Uuid,
    pub entity_id: String,
    pub name: String,
    pub acs_urls: Vec<String>,
    pub certificate: Option<String>,
    pub attribute_mapping: serde_json::Value,
    pub name_id_format: String,
    pub sign_assertions: bool,
    pub validate_signatures: bool,
    pub assertion_validity_seconds: i32,
    pub enabled: bool,
    pub metadata_url: Option<String>,
    pub slo_url: Option<String>,
    pub slo_binding: String,
    /// Custom SAML attribute name for groups (default: "groups").
    pub group_attribute_name: Option<String>,
    /// How to format group values: "name", "id", or "dn".
    pub group_value_format: String,
    /// JSON filter config for which groups to include.
    pub group_filter: Option<serde_json::Value>,
    /// Whether to include groups in assertions.
    pub include_groups: bool,
    /// Whether to omit the groups attribute when the user has no groups.
    pub omit_empty_groups: bool,
    /// Base DN for DN format.
    pub group_dn_base: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<xavyo_db::models::SamlServiceProvider> for ServiceProviderResponse {
    fn from(sp: xavyo_db::models::SamlServiceProvider) -> Self {
        Self {
            id: sp.id,
            entity_id: sp.entity_id,
            name: sp.name,
            acs_urls: sp.acs_urls,
            certificate: sp.certificate,
            attribute_mapping: sp.attribute_mapping,
            name_id_format: sp.name_id_format,
            sign_assertions: sp.sign_assertions,
            validate_signatures: sp.validate_signatures,
            assertion_validity_seconds: sp.assertion_validity_seconds,
            enabled: sp.enabled,
            metadata_url: sp.metadata_url,
            slo_url: sp.slo_url,
            slo_binding: sp.slo_binding,
            group_attribute_name: sp.group_attribute_name,
            group_value_format: sp.group_value_format,
            group_filter: sp.group_filter,
            include_groups: sp.include_groups,
            omit_empty_groups: sp.omit_empty_groups,
            group_dn_base: sp.group_dn_base,
            created_at: sp.created_at,
            updated_at: sp.updated_at,
        }
    }
}

/// Certificate list response
#[derive(Debug, Serialize, ToSchema)]
pub struct CertificateListResponse {
    #[schema(value_type = Vec<CertificateInfo>)]
    pub items: Vec<xavyo_db::models::CertificateInfo>,
}

/// Re-export `CertificateInfo` for schema reference
pub use xavyo_db::models::CertificateInfo;

/// Pagination query parameters
#[derive(Debug, Deserialize, IntoParams)]
pub struct PaginationQuery {
    #[serde(default = "default_limit")]
    pub limit: i32,
    #[serde(default)]
    pub offset: i32,
    pub enabled: Option<bool>,
}

fn default_limit() -> i32 {
    20
}

/// SAML Response auto-submit form HTML
#[must_use]
pub fn generate_auto_submit_form(
    acs_url: &str,
    saml_response: &str,
    relay_state: Option<&str>,
) -> String {
    let relay_input = relay_state
        .map(|rs| {
            format!(
                r#"<input type="hidden" name="RelayState" value="{}"/>"#,
                html_escape(rs)
            )
        })
        .unwrap_or_default();

    format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>SAML SSO</title>
</head>
<body onload="document.forms[0].submit()">
    <noscript>
        <p>JavaScript is disabled. Click the button below to continue.</p>
    </noscript>
    <form method="POST" action="{}">
        <input type="hidden" name="SAMLResponse" value="{}"/>
        {}
        <noscript>
            <input type="submit" value="Continue"/>
        </noscript>
    </form>
</body>
</html>"#,
        html_escape(acs_url),
        html_escape(saml_response),
        relay_input
    )
}

/// HTML escape for XSS prevention
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use serde_json::json;
    use uuid::Uuid;

    fn sample_sp() -> xavyo_db::models::SamlServiceProvider {
        xavyo_db::models::SamlServiceProvider {
            id: Uuid::nil(),
            tenant_id: Uuid::nil(),
            entity_id: "https://sp.example".to_string(),
            name: "app".to_string(),
            acs_urls: vec!["https://sp.example/acs".to_string()],
            certificate: None,
            attribute_mapping: json!({}),
            name_id_format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress".to_string(),
            sign_assertions: true,
            validate_signatures: false,
            assertion_validity_seconds: 300,
            enabled: true,
            metadata_url: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            group_attribute_name: Some("Roles".to_string()),
            group_value_format: "id".to_string(),
            group_filter: Some(json!({"filter_type":"allowlist","allowlist":["admins"]})),
            include_groups: false,
            omit_empty_groups: false,
            group_dn_base: Some("ou=Groups,dc=example,dc=com".to_string()),
            slo_url: None,
            slo_binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST".to_string(),
        }
    }

    #[test]
    fn get_and_list_responses_include_group_config() {
        let item = ServiceProviderResponse::from(sample_sp());
        assert_eq!(item.group_attribute_name.as_deref(), Some("Roles"));
        assert_eq!(item.group_value_format, "id");
        assert!(!item.include_groups);
        assert!(!item.omit_empty_groups);
        assert_eq!(
            item.group_dn_base.as_deref(),
            Some("ou=Groups,dc=example,dc=com")
        );

        let list = ServiceProviderListResponse {
            items: vec![item],
            total: 1,
            limit: 20,
            offset: 0,
        };
        let value = serde_json::to_value(&list).unwrap();
        assert_eq!(value["items"][0]["group_attribute_name"], "Roles");
        assert_eq!(value["items"][0]["group_value_format"], "id");
        assert_eq!(value["items"][0]["include_groups"], false);
        assert_eq!(
            value["items"][0]["group_filter"]["filter_type"],
            "allowlist"
        );
    }
}
