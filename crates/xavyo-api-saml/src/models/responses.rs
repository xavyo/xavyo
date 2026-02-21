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
