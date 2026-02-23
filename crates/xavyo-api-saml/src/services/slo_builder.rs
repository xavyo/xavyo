//! SAML LogoutRequest and LogoutResponse builder

use crate::error::{SamlError, SamlResult};
use crate::saml::SigningCredentials;
use base64::{engine::general_purpose::STANDARD, Engine};
use uuid::Uuid;
use super::assertion_builder::canonicalize_xml;

/// Builder for SAML LogoutRequest and LogoutResponse messages
pub struct SloBuilder {
    idp_entity_id: String,
    credentials: SigningCredentials,
}

impl SloBuilder {
    /// Create a new SLO builder
    #[must_use]
    pub fn new(idp_entity_id: String, credentials: SigningCredentials) -> Self {
        Self {
            idp_entity_id,
            credentials,
        }
    }

    /// Build a signed LogoutRequest XML (base64 encoded) to send to an SP.
    pub fn build_logout_request(
        &self,
        destination: &str,
        name_id: &str,
        name_id_format: &str,
        session_index: &str,
    ) -> SamlResult<String> {
        let request_id = format!("_lr_{}", Uuid::new_v4());
        let issue_instant = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

        let mut xml = String::new();
        xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.push_str("<samlp:LogoutRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"\n");
        xml.push_str("    xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"\n");
        xml.push_str("    ID=\"");
        xml.push_str(&xml_escape(&request_id));
        xml.push_str("\"\n    Version=\"2.0\"\n    IssueInstant=\"");
        xml.push_str(&issue_instant);
        xml.push_str("\"\n    Destination=\"");
        xml.push_str(&xml_escape(destination));
        xml.push_str("\">\n    <saml:Issuer>");
        xml.push_str(&xml_escape(&self.idp_entity_id));
        xml.push_str("</saml:Issuer>\n    <saml:NameID Format=\"");
        xml.push_str(&xml_escape(name_id_format));
        xml.push_str("\">");
        xml.push_str(&xml_escape(name_id));
        xml.push_str("</saml:NameID>\n    <samlp:SessionIndex>");
        xml.push_str(&xml_escape(session_index));
        xml.push_str("</samlp:SessionIndex>\n</samlp:LogoutRequest>");

        let signed_xml = self.sign_xml(&xml, "LogoutRequest", &request_id)?;
        Ok(STANDARD.encode(signed_xml.as_bytes()))
    }

    /// Build a signed LogoutResponse XML (base64 encoded) to send back to an SP.
    pub fn build_logout_response(
        &self,
        in_response_to: &str,
        destination: &str,
        success: bool,
    ) -> SamlResult<String> {
        let response_id = format!("_lresp_{}", Uuid::new_v4());
        let issue_instant = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

        let status_value = if success {
            "urn:oasis:names:tc:SAML:2.0:status:Success"
        } else {
            "urn:oasis:names:tc:SAML:2.0:status:Responder"
        };

        let mut xml = String::new();
        xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.push_str(
            "<samlp:LogoutResponse xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"\n",
        );
        xml.push_str("    xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"\n");
        xml.push_str("    ID=\"");
        xml.push_str(&xml_escape(&response_id));
        xml.push_str("\"\n    Version=\"2.0\"\n    IssueInstant=\"");
        xml.push_str(&issue_instant);
        xml.push_str("\"\n    Destination=\"");
        xml.push_str(&xml_escape(destination));
        xml.push_str("\"\n    InResponseTo=\"");
        xml.push_str(&xml_escape(in_response_to));
        xml.push_str("\">\n    <saml:Issuer>");
        xml.push_str(&xml_escape(&self.idp_entity_id));
        xml.push_str("</saml:Issuer>\n    <samlp:Status>\n        <samlp:StatusCode Value=\"");
        xml.push_str(status_value);
        xml.push_str("\"/>\n    </samlp:Status>\n</samlp:LogoutResponse>");

        // Sign the LogoutResponse for integrity
        let signed_xml = self.sign_xml(&xml, "LogoutResponse", &response_id)?;
        Ok(STANDARD.encode(signed_xml.as_bytes()))
    }

    /// Sign a SAML XML message by injecting an enveloped signature after the Issuer element.
    fn sign_xml(&self, xml: &str, element_name: &str, element_id: &str) -> SamlResult<String> {
        let issuer_end = xml.find("</saml:Issuer>").ok_or_else(|| {
            SamlError::InternalError(format!("Cannot find Issuer in {element_name}"))
        })?;
        let after_issuer = issuer_end + "</saml:Issuer>".len();

        // Find the root element for digest
        let element_tag = format!("<samlp:{element_name}");
        let request_start = xml.find(&element_tag).ok_or_else(|| {
            SamlError::InternalError(format!("Cannot find {element_name} element"))
        })?;
        let request_content = &xml[request_start..xml.len()];

        let canonicalized = canonicalize_xml(request_content)?;

        let digest = openssl::hash::hash(
            openssl::hash::MessageDigest::sha256(),
            canonicalized.as_bytes(),
        )
        .map_err(|e| SamlError::InternalError(format!("Digest failed: {e}")))?;
        let digest_b64 = STANDARD.encode(digest);

        let mut signed_info = String::new();
        signed_info.push_str("<ds:SignedInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">");
        signed_info.push_str(
            "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>",
        );
        signed_info.push_str(
            "<ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>",
        );
        signed_info.push_str("<ds:Reference URI=\"#");
        signed_info.push_str(element_id);
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

        let canonicalized_signed_info = canonicalize_xml(&signed_info)?;
        let signature = self
            .credentials
            .sign_sha256(canonicalized_signed_info.as_bytes())?;
        let signature_b64 = STANDARD.encode(&signature);

        let certificate_base64 = self.credentials.certificate_base64_der()?;

        // No leading whitespace — see assertion_builder.rs sign_response() for explanation
        let mut sig_xml = String::new();
        sig_xml.push_str("<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">");
        sig_xml.push_str(&signed_info);
        sig_xml.push_str("<ds:SignatureValue>");
        sig_xml.push_str(&signature_b64);
        sig_xml.push_str("</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>");
        sig_xml.push_str(&certificate_base64);
        sig_xml.push_str("</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>");

        let mut result = String::with_capacity(xml.len() + sig_xml.len());
        result.push_str(&xml[..after_issuer]);
        result.push_str(&sig_xml);
        result.push_str(&xml[after_issuer..]);

        Ok(result)
    }
}


fn xml_escape(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => result.push_str("&amp;"),
            '<' => result.push_str("&lt;"),
            '>' => result.push_str("&gt;"),
            '"' => result.push_str("&quot;"),
            '\'' => result.push_str("&apos;"),
            _ => result.push(c),
        }
    }
    result
}
