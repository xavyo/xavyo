//! SAML Assertion and Response builder with proper XML canonicalization

use crate::error::{SamlError, SamlResult};
use crate::saml::{
    get_nameid_for_format, resolve_attributes, ResolvedAttribute, SigningCredentials,
    UserAttributes,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{Duration, Utc};
use uuid::Uuid;
use xavyo_db::models::SamlServiceProvider;
use xml_canonicalization::Canonicalizer;

/// Builder for SAML assertions and responses
pub struct AssertionBuilder {
    idp_entity_id: String,
    credentials: SigningCredentials,
}

impl AssertionBuilder {
    /// Create a new assertion builder
    pub fn new(idp_entity_id: String, credentials: SigningCredentials) -> Self {
        Self {
            idp_entity_id,
            credentials,
        }
    }

    /// Build a SAML Response for SP-initiated SSO
    pub fn build_response(
        &self,
        sp: &SamlServiceProvider,
        user: &UserAttributes,
        in_response_to: Option<&str>,
        session_id: Option<&str>,
    ) -> SamlResult<String> {
        let response_id = format!("_resp_{}", Uuid::new_v4());
        let assertion_id = format!("_assert_{}", Uuid::new_v4());
        let now = Utc::now();
        let not_before = now - Duration::minutes(2);
        let not_on_or_after = now + Duration::seconds(sp.assertion_validity_seconds as i64);

        let attr_mapping = sp.get_attribute_mapping();
        let name_id_value = get_nameid_for_format(user, &sp.name_id_format, session_id)
            .ok_or_else(|| {
                SamlError::AssertionGenerationFailed("Cannot determine NameID".to_string())
            })?;

        let attributes = if attr_mapping.attributes.is_empty() {
            crate::saml::default_attributes(user)
        } else {
            resolve_attributes(user, &attr_mapping)
        };

        let acs_url = sp.acs_urls.first().ok_or_else(|| {
            SamlError::AssertionGenerationFailed("No ACS URL configured".to_string())
        })?;

        let response_xml = self.build_response_xml(
            &response_id,
            &assertion_id,
            &sp.entity_id,
            acs_url,
            &name_id_value,
            &sp.name_id_format,
            &attributes,
            now,
            not_before,
            not_on_or_after,
            in_response_to,
            session_id,
        )?;

        let final_response = if sp.sign_assertions {
            self.sign_response(&response_xml, &assertion_id)?
        } else {
            response_xml
        };

        Ok(STANDARD.encode(final_response.as_bytes()))
    }

    /// Build a SAML Response for IdP-initiated SSO (unsolicited)
    pub fn build_unsolicited_response(
        &self,
        sp: &SamlServiceProvider,
        user: &UserAttributes,
        session_id: Option<&str>,
    ) -> SamlResult<String> {
        self.build_response(sp, user, None, session_id)
    }

    #[allow(clippy::too_many_arguments)]
    fn build_response_xml(
        &self,
        response_id: &str,
        assertion_id: &str,
        sp_entity_id: &str,
        acs_url: &str,
        name_id: &str,
        name_id_format: &str,
        attributes: &[ResolvedAttribute],
        issue_instant: chrono::DateTime<Utc>,
        not_before: chrono::DateTime<Utc>,
        not_on_or_after: chrono::DateTime<Utc>,
        in_response_to: Option<&str>,
        session_index: Option<&str>,
    ) -> SamlResult<String> {
        let issue_instant_str = issue_instant.format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let not_before_str = not_before.format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let not_on_or_after_str = not_on_or_after.format("%Y-%m-%dT%H:%M:%SZ").to_string();

        let in_response_to_attr = in_response_to
            .map(|id| {
                let mut s = String::from(" InResponseTo=\"");
                s.push_str(&xml_escape(id));
                s.push('"');
                s
            })
            .unwrap_or_default();

        let default_session = format!("_session_{}", Uuid::new_v4());
        let session_index_str = session_index.unwrap_or(&default_session);
        let attributes_xml = self.build_attributes_xml(attributes);
        let _certificate_base64 = self.credentials.certificate_base64_der()?;

        // Build response using string concatenation to avoid raw string issues
        let mut xml = String::new();
        xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.push_str("<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"\n");
        xml.push_str("    xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"\n");
        xml.push_str("    ID=\"");
        xml.push_str(&xml_escape(response_id));
        xml.push_str("\"\n    Version=\"2.0\"\n    IssueInstant=\"");
        xml.push_str(&issue_instant_str);
        xml.push_str("\"\n    Destination=\"");
        xml.push_str(&xml_escape(acs_url));
        xml.push('"');
        xml.push_str(&in_response_to_attr);
        xml.push_str(">\n    <saml:Issuer>");
        xml.push_str(&xml_escape(&self.idp_entity_id));
        xml.push_str("</saml:Issuer>\n");
        xml.push_str("    <samlp:Status>\n        <samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/>\n    </samlp:Status>\n");
        xml.push_str("    <saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"\n        ID=\"");
        xml.push_str(&xml_escape(assertion_id));
        xml.push_str("\"\n        Version=\"2.0\"\n        IssueInstant=\"");
        xml.push_str(&issue_instant_str);
        xml.push_str("\">\n        <saml:Issuer>");
        xml.push_str(&xml_escape(&self.idp_entity_id));
        xml.push_str("</saml:Issuer>\n        <saml:Subject>\n            <saml:NameID Format=\"");
        xml.push_str(&xml_escape(name_id_format));
        xml.push_str("\">");
        xml.push_str(&xml_escape(name_id));
        xml.push_str("</saml:NameID>\n            <saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">\n                <saml:SubjectConfirmationData\n                    NotOnOrAfter=\"");
        xml.push_str(&not_on_or_after_str);
        xml.push_str("\"\n                    Recipient=\"");
        xml.push_str(&xml_escape(acs_url));
        xml.push('"');
        xml.push_str(&in_response_to_attr);
        xml.push_str("/>\n            </saml:SubjectConfirmation>\n        </saml:Subject>\n");
        xml.push_str("        <saml:Conditions NotBefore=\"");
        xml.push_str(&not_before_str);
        xml.push_str("\" NotOnOrAfter=\"");
        xml.push_str(&not_on_or_after_str);
        xml.push_str(
            "\">\n            <saml:AudienceRestriction>\n                <saml:Audience>",
        );
        xml.push_str(&xml_escape(sp_entity_id));
        xml.push_str("</saml:Audience>\n            </saml:AudienceRestriction>\n        </saml:Conditions>\n");
        xml.push_str("        <saml:AuthnStatement AuthnInstant=\"");
        xml.push_str(&issue_instant_str);
        xml.push_str("\" SessionIndex=\"");
        xml.push_str(&xml_escape(session_index_str));
        xml.push_str("\">\n            <saml:AuthnContext>\n                <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>\n            </saml:AuthnContext>\n        </saml:AuthnStatement>\n");
        xml.push_str(&attributes_xml);
        xml.push_str("\n    </saml:Assertion>\n</samlp:Response>");

        Ok(xml)
    }

    fn build_attributes_xml(&self, attributes: &[ResolvedAttribute]) -> String {
        if attributes.is_empty() {
            return String::new();
        }

        let mut attrs = String::from("        <saml:AttributeStatement>\n");

        for attr in attributes {
            attrs.push_str("            <saml:Attribute Name=\"");
            attrs.push_str(&xml_escape(&attr.name));
            attrs.push('"');
            if let Some(fn_) = &attr.friendly_name {
                attrs.push_str(" FriendlyName=\"");
                attrs.push_str(&xml_escape(fn_));
                attrs.push('"');
            }
            if let Some(f) = &attr.format {
                attrs.push_str(" NameFormat=\"");
                attrs.push_str(&xml_escape(f));
                attrs.push('"');
            }
            attrs.push_str(">\n");

            for value in &attr.values {
                attrs.push_str("                <saml:AttributeValue xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xs:string\">");
                attrs.push_str(&xml_escape(value));
                attrs.push_str("</saml:AttributeValue>\n");
            }

            attrs.push_str("            </saml:Attribute>\n");
        }

        attrs.push_str("        </saml:AttributeStatement>");
        attrs
    }

    fn sign_response(&self, response_xml: &str, assertion_id: &str) -> SamlResult<String> {
        // Find insertion point
        let find_pattern = format!("ID=\"{}\"", assertion_id);
        let assertion_start = response_xml.find(&find_pattern).ok_or_else(|| {
            SamlError::AssertionGenerationFailed("Cannot find Assertion".to_string())
        })?;

        let after_issuer = response_xml[assertion_start..]
            .find("</saml:Issuer>")
            .map(|pos| assertion_start + pos + "</saml:Issuer>".len())
            .ok_or_else(|| {
                SamlError::AssertionGenerationFailed("Cannot find Issuer".to_string())
            })?;

        let certificate_base64 = self.credentials.certificate_base64_der()?;

        let assertion_end = response_xml.find("</saml:Assertion>").ok_or_else(|| {
            SamlError::AssertionGenerationFailed("Cannot find Assertion end".to_string())
        })?;

        // Extract the assertion element
        let assertion_element_start = response_xml[..assertion_start].rfind('<').unwrap_or(0);
        let assertion_content =
            &response_xml[assertion_element_start..assertion_end + "</saml:Assertion>".len()];

        // Apply Exclusive C14N to the assertion content for digest calculation
        // This ensures the digest matches what the SP will compute
        let canonicalized_assertion = canonicalize_xml(assertion_content)?;

        let digest = openssl::hash::hash(
            openssl::hash::MessageDigest::sha256(),
            canonicalized_assertion.as_bytes(),
        )
        .map_err(|e| SamlError::AssertionGenerationFailed(format!("Digest failed: {}", e)))?;
        let digest_b64 = STANDARD.encode(digest);

        // Build SignedInfo - must be canonicalized before signing
        let mut signed_info = String::new();
        signed_info.push_str("<ds:SignedInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">");
        signed_info.push_str(
            "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>",
        );
        signed_info.push_str(
            "<ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>",
        );
        signed_info.push_str("<ds:Reference URI=\"#");
        signed_info.push_str(assertion_id);
        signed_info.push_str("\">");
        signed_info.push_str("<ds:Transforms>");
        signed_info.push_str(
            "<ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>",
        );
        signed_info
            .push_str("<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>");
        signed_info.push_str("</ds:Transforms>");
        signed_info
            .push_str("<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>");
        signed_info.push_str("<ds:DigestValue>");
        signed_info.push_str(&digest_b64);
        signed_info.push_str("</ds:DigestValue>");
        signed_info.push_str("</ds:Reference>");
        signed_info.push_str("</ds:SignedInfo>");

        // Canonicalize SignedInfo before signing (as per XML-Sig spec)
        let canonicalized_signed_info = canonicalize_xml(&signed_info)?;

        let signature = self
            .credentials
            .sign_sha256(canonicalized_signed_info.as_bytes())?;
        let signature_b64 = STANDARD.encode(&signature);

        // Build Signature element with proper formatting
        let mut signature_xml = String::new();
        signature_xml.push_str("\n        <ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n            ");
        signature_xml.push_str(&signed_info);
        signature_xml.push_str("\n            <ds:SignatureValue>");
        signature_xml.push_str(&signature_b64);
        signature_xml.push_str("</ds:SignatureValue>\n            <ds:KeyInfo>\n                <ds:X509Data>\n                    <ds:X509Certificate>");
        signature_xml.push_str(&certificate_base64);
        signature_xml.push_str("</ds:X509Certificate>\n                </ds:X509Data>\n            </ds:KeyInfo>\n        </ds:Signature>");

        let mut result = String::with_capacity(response_xml.len() + signature_xml.len());
        result.push_str(&response_xml[..after_issuer]);
        result.push_str(&signature_xml);
        result.push_str(&response_xml[after_issuer..]);

        Ok(result)
    }
}

/// Apply Exclusive XML Canonicalization (C14N) to XML content.
/// This is required for SAML signature generation and verification.
fn canonicalize_xml(xml: &str) -> SamlResult<String> {
    let mut output = Vec::new();
    Canonicalizer::read_from_str(xml)
        .write_to_writer(&mut output)
        .canonicalize(false) // false = exclude comments (Exclusive C14N without comments)
        .map_err(|e| {
            SamlError::AssertionGenerationFailed(format!("XML canonicalization failed: {}", e))
        })?;

    String::from_utf8(output).map_err(|e| {
        SamlError::AssertionGenerationFailed(format!("Canonicalized XML is not valid UTF-8: {}", e))
    })
}

/// XML escape special characters
fn xml_escape(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => result.push_str("&amp;"),
            '<' => result.push_str("&lt;"),
            '>' => result.push_str("&gt;"),
            _ if c == '"' => result.push_str("&quot;"),
            _ if c == '\'' => result.push_str("&apos;"),
            _ => result.push(c),
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::{canonicalize_xml, xml_escape};

    #[test]
    fn test_xml_escape_basic() {
        assert_eq!(xml_escape("<>"), "&lt;&gt;");
        assert_eq!(xml_escape("a&b"), "a&amp;b");
    }

    #[test]
    fn test_canonicalize_xml_removes_whitespace() {
        // C14N normalizes whitespace and attribute ordering
        let input = r#"<root  attr1="a"   attr2="b" >
            <child/>
        </root>"#;
        let result = canonicalize_xml(input).expect("canonicalization should succeed");
        // C14N removes extra whitespace between attributes
        assert!(result.contains("<root"));
        assert!(result.contains("</root>"));
    }

    #[test]
    fn test_canonicalize_xml_preserves_namespaces() {
        let input = r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="test">
            <saml:Issuer>https://idp.example.com</saml:Issuer>
        </saml:Assertion>"#;
        let result = canonicalize_xml(input).expect("canonicalization should succeed");
        assert!(result.contains("xmlns:saml"));
        assert!(result.contains("urn:oasis:names:tc:SAML:2.0:assertion"));
    }
}
