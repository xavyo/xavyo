//! `IdP` Metadata generator

use crate::error::SamlResult;
use crate::saml::{
    SigningCredentials, NAMEID_FORMAT_EMAIL, NAMEID_FORMAT_PERSISTENT, NAMEID_FORMAT_TRANSIENT,
};

/// Service for generating `IdP` SAML 2.0 metadata
pub struct MetadataGenerator {
    entity_id: String,
    sso_url: String,
    credentials: Option<SigningCredentials>,
}

impl MetadataGenerator {
    /// Create a new metadata generator
    #[must_use] 
    pub fn new(
        entity_id: String,
        sso_url: String,
        credentials: Option<SigningCredentials>,
    ) -> Self {
        Self {
            entity_id,
            sso_url,
            credentials,
        }
    }

    /// Generate `IdP` metadata XML
    pub fn generate(&self) -> SamlResult<String> {
        let certificate_element = if let Some(ref creds) = self.credentials {
            let cert_base64 = creds.certificate_base64_der()?;
            format!(
                r#"
        <md:KeyDescriptor use="signing">
            <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                <ds:X509Data>
                    <ds:X509Certificate>{cert_base64}</ds:X509Certificate>
                </ds:X509Data>
            </ds:KeyInfo>
        </md:KeyDescriptor>"#
            )
        } else {
            String::new()
        };

        let xml = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="{entity_id}">
    <md:IDPSSODescriptor WantAuthnRequestsSigned="false"
        protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">{certificate_element}
        <md:NameIDFormat>{email_format}</md:NameIDFormat>
        <md:NameIDFormat>{persistent_format}</md:NameIDFormat>
        <md:NameIDFormat>{transient_format}</md:NameIDFormat>
        <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            Location="{sso_url}"/>
        <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            Location="{sso_url}"/>
    </md:IDPSSODescriptor>
</md:EntityDescriptor>"#,
            entity_id = xml_escape(&self.entity_id),
            certificate_element = certificate_element,
            email_format = NAMEID_FORMAT_EMAIL,
            persistent_format = NAMEID_FORMAT_PERSISTENT,
            transient_format = NAMEID_FORMAT_TRANSIENT,
            sso_url = xml_escape(&self.sso_url),
        );

        Ok(xml)
    }
}

/// XML escape special characters
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_metadata_without_cert() {
        let generator = MetadataGenerator::new(
            "https://idp.example.com".to_string(),
            "https://idp.example.com/saml/sso".to_string(),
            None,
        );

        let xml = generator.generate().unwrap();
        assert!(xml.contains("EntityDescriptor"));
        assert!(xml.contains("entityID=\"https://idp.example.com\""));
        assert!(xml.contains("IDPSSODescriptor"));
        assert!(xml.contains("SingleSignOnService"));
        assert!(xml.contains("HTTP-Redirect"));
        assert!(xml.contains("HTTP-POST"));
    }
}
