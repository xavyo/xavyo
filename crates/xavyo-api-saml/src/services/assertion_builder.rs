//! SAML Assertion and Response builder with Exclusive XML Canonicalization

use crate::error::{SamlError, SamlResult};
use crate::saml::{
    get_nameid_for_format, resolve_attributes, ResolvedAttribute, SigningCredentials,
    UserAttributes,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{Duration, Utc};
use quick_xml::events::Event;
use quick_xml::reader::Reader;
use uuid::Uuid;
use xavyo_db::models::SamlServiceProvider;

/// Output from building a SAML Response, containing the encoded response
/// and session metadata needed for SP session tracking.
pub struct SamlResponseOutput {
    /// Base64-encoded SAML Response
    pub encoded_response: String,
    /// SessionIndex from the AuthnStatement
    pub session_index: String,
    /// NameID sent in the assertion
    pub name_id: String,
    /// NameID format
    pub name_id_format: String,
}

/// Builder for SAML assertions and responses
pub struct AssertionBuilder {
    idp_entity_id: String,
    credentials: SigningCredentials,
}

impl AssertionBuilder {
    /// Create a new assertion builder
    #[must_use]
    pub fn new(idp_entity_id: String, credentials: SigningCredentials) -> Self {
        Self {
            idp_entity_id,
            credentials,
        }
    }

    /// Build a SAML Response for SP-initiated SSO.
    ///
    /// `target_acs_url` should be the resolved ACS URL to use as the Destination/Recipient.
    /// If `None`, falls back to the first configured ACS URL for the SP.
    pub fn build_response(
        &self,
        sp: &SamlServiceProvider,
        user: &UserAttributes,
        in_response_to: Option<&str>,
        session_id: Option<&str>,
        target_acs_url: Option<&str>,
    ) -> SamlResult<SamlResponseOutput> {
        let response_id = format!("_resp_{}", Uuid::new_v4());
        let assertion_id = format!("_assert_{}", Uuid::new_v4());
        let now = Utc::now();
        let not_before = now - Duration::minutes(2);
        let not_on_or_after = now + Duration::seconds(i64::from(sp.assertion_validity_seconds));

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

        // Use explicitly provided ACS URL, falling back to first configured URL.
        let fallback_acs = sp.acs_urls.first().ok_or_else(|| {
            SamlError::AssertionGenerationFailed("No ACS URL configured".to_string())
        })?;
        let acs_url = target_acs_url.unwrap_or(fallback_acs);

        // Generate session index for SP session tracking
        let session_index = format!("_session_{}", Uuid::new_v4());

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
            Some(&session_index),
        )?;

        let final_response = if sp.sign_assertions {
            self.sign_response(&response_xml, &assertion_id)?
        } else {
            response_xml
        };

        Ok(SamlResponseOutput {
            encoded_response: STANDARD.encode(final_response.as_bytes()),
            session_index,
            name_id: name_id_value,
            name_id_format: sp.name_id_format.clone(),
        })
    }

    /// Build a SAML Response for IdP-initiated SSO (unsolicited)
    pub fn build_unsolicited_response(
        &self,
        sp: &SamlServiceProvider,
        user: &UserAttributes,
        session_id: Option<&str>,
    ) -> SamlResult<SamlResponseOutput> {
        self.build_response(sp, user, None, session_id, None)
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

        let fallback_session = format!("_session_{}", Uuid::new_v4());
        let session_index_str = session_index.unwrap_or(&fallback_session);
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
        // SECURITY NOTE: This method operates on XML that we generated ourselves
        // (via build_response_xml above), so the structure is fully controlled.
        // String-based boundary detection is acceptable here because:
        // 1. assertion_id is a UUID we generated (no injection risk)
        // 2. The XML structure is deterministic from our builder
        // 3. There is exactly one <saml:Assertion> element in our output

        // Find the assertion tag by its ID attribute
        let assertion_tag = format!("<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"\n        ID=\"{}\"", xml_escape(assertion_id));
        let assertion_element_start = response_xml.find(&assertion_tag).ok_or_else(|| {
            SamlError::AssertionGenerationFailed("Cannot find Assertion element".to_string())
        })?;

        // Find the Issuer closing tag after the assertion start
        let after_issuer = response_xml[assertion_element_start..]
            .find("</saml:Issuer>")
            .map(|pos| assertion_element_start + pos + "</saml:Issuer>".len())
            .ok_or_else(|| {
                SamlError::AssertionGenerationFailed("Cannot find Issuer in Assertion".to_string())
            })?;

        let certificate_base64 = self.credentials.certificate_base64_der()?;

        // Find the assertion end tag AFTER the assertion start (not from the beginning)
        let assertion_end = response_xml[assertion_element_start..]
            .find("</saml:Assertion>")
            .map(|pos| assertion_element_start + pos)
            .ok_or_else(|| {
                SamlError::AssertionGenerationFailed("Cannot find Assertion end".to_string())
            })?;

        // Extract the full assertion element
        let assertion_content =
            &response_xml[assertion_element_start..assertion_end + "</saml:Assertion>".len()];

        // Apply Exclusive C14N to the assertion content for digest calculation
        // This ensures the digest matches what the SP will compute
        let canonicalized_assertion = canonicalize_xml(assertion_content)?;

        let digest = openssl::hash::hash(
            openssl::hash::MessageDigest::sha256(),
            canonicalized_assertion.as_bytes(),
        )
        .map_err(|e| SamlError::AssertionGenerationFailed(format!("Digest failed: {e}")))?;
        let digest_b64 = STANDARD.encode(digest);

        // Build SignedInfo — already in canonical form (no self-closing tags,
        // no extra whitespace, namespace declared on root element)
        let signed_info = build_canonical_signed_info(assertion_id, &digest_b64);

        // Sign the canonical SignedInfo directly (no further canonicalization needed)
        let signature = self
            .credentials
            .sign_sha256(signed_info.as_bytes())?;
        let signature_b64 = STANDARD.encode(&signature);

        // Build Signature element.
        // IMPORTANT: No leading whitespace before <ds:Signature> — when the SP
        // validates the signature, it removes the Signature element from the DOM
        // (enveloped-signature transform). Leading whitespace would leave extra
        // text nodes that change the canonical form and break the digest.
        let mut signature_xml = String::new();
        signature_xml.push_str("<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">");
        signature_xml.push_str(&signed_info);
        signature_xml.push_str("<ds:SignatureValue>");
        signature_xml.push_str(&signature_b64);
        signature_xml.push_str("</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>");
        signature_xml.push_str(&certificate_base64);
        signature_xml.push_str("</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>");

        let mut result = String::with_capacity(response_xml.len() + signature_xml.len());
        result.push_str(&response_xml[..after_issuer]);
        result.push_str(&signature_xml);
        result.push_str(&response_xml[after_issuer..]);

        Ok(result)
    }
}

/// Build SignedInfo in Exclusive C14N canonical form.
///
/// The output is already canonical: no self-closing tags, no extra whitespace,
/// namespace declared on the root element, attributes in document order.
/// This avoids the need for a separate canonicalization pass.
fn build_canonical_signed_info(assertion_id: &str, digest_b64: &str) -> String {
    let mut s = String::new();
    s.push_str("<ds:SignedInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">");
    s.push_str("<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></ds:CanonicalizationMethod>");
    s.push_str("<ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"></ds:SignatureMethod>");
    s.push_str("<ds:Reference URI=\"#");
    s.push_str(assertion_id);
    s.push_str("\">");
    s.push_str("<ds:Transforms>");
    s.push_str("<ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"></ds:Transform>");
    s.push_str("<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></ds:Transform>");
    s.push_str("</ds:Transforms>");
    s.push_str("<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"></ds:DigestMethod>");
    s.push_str("<ds:DigestValue>");
    s.push_str(digest_b64);
    s.push_str("</ds:DigestValue>");
    s.push_str("</ds:Reference>");
    s.push_str("</ds:SignedInfo>");
    s
}

/// Extract element name as an owned String
fn element_name_str(e: &quick_xml::events::BytesStart<'_>) -> SamlResult<String> {
    String::from_utf8(e.name().as_ref().to_vec()).map_err(|err| {
        SamlError::AssertionGenerationFailed(format!("Invalid UTF-8 in element name: {err}"))
    })
}

/// Apply Exclusive XML Canonicalization (exc-c14n) without comments.
///
/// Uses `quick-xml` to parse and re-emit XML in canonical form:
/// - No XML declaration
/// - Empty elements expanded to start+end tags
/// - Attributes sorted: namespace declarations (by prefix), then regular attributes (by name)
/// - Proper C14N character escaping
pub(crate) fn canonicalize_xml(xml: &str) -> SamlResult<String> {
    let mut reader = Reader::from_str(xml);
    // Preserve whitespace in text nodes — C14N keeps inter-element whitespace
    reader.config_mut().trim_text(false);

    let mut output = String::with_capacity(xml.len());
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) => {
                write_c14n_start_tag(&mut output, e)?;
            }
            Ok(Event::Empty(ref e)) => {
                // C14N: empty elements become explicit open+close tags
                let name = element_name_str(e)?;
                write_c14n_start_tag(&mut output, e)?;
                output.push_str("</");
                output.push_str(&name);
                output.push('>');
            }
            Ok(Event::End(ref e)) => {
                let name = String::from_utf8(e.name().as_ref().to_vec()).map_err(|err| {
                    SamlError::AssertionGenerationFailed(format!(
                        "Invalid UTF-8 in element name: {err}"
                    ))
                })?;
                output.push_str("</");
                output.push_str(&name);
                output.push('>');
            }
            Ok(Event::Text(ref e)) => {
                let text = e.unescape().map_err(|err| {
                    SamlError::AssertionGenerationFailed(format!("XML unescape error: {err}"))
                })?;
                c14n_escape_text(&mut output, &text);
            }
            Ok(Event::Decl(_) | Event::Comment(_) | Event::PI(_)) => {
                // Strip XML declaration, comments, and processing instructions
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(e) => {
                return Err(SamlError::AssertionGenerationFailed(format!(
                    "XML parse error during canonicalization: {e}"
                )));
            }
        }
        buf.clear();
    }

    Ok(output)
}

/// Write an element's start tag in C14N canonical form.
///
/// Attributes are sorted: namespace declarations first (sorted by prefix),
/// then regular attributes (sorted by local name).
fn write_c14n_start_tag(
    output: &mut String,
    e: &quick_xml::events::BytesStart<'_>,
) -> SamlResult<()> {
    let name = element_name_str(e)?;

    output.push('<');
    output.push_str(&name);

    // Separate namespace declarations from regular attributes
    let mut ns_attrs: Vec<(String, String)> = Vec::new();
    let mut regular_attrs: Vec<(String, String)> = Vec::new();

    for attr_result in e.attributes() {
        let attr = attr_result.map_err(|err| {
            SamlError::AssertionGenerationFailed(format!("XML attribute parse error: {err}"))
        })?;
        let key = std::str::from_utf8(attr.key.as_ref()).map_err(|err| {
            SamlError::AssertionGenerationFailed(format!(
                "Invalid UTF-8 in attribute name: {err}"
            ))
        })?;
        let value = attr.unescape_value().map_err(|err| {
            SamlError::AssertionGenerationFailed(format!(
                "XML attribute unescape error: {err}"
            ))
        })?;

        if key == "xmlns" || key.starts_with("xmlns:") {
            ns_attrs.push((key.to_string(), value.to_string()));
        } else {
            regular_attrs.push((key.to_string(), value.to_string()));
        }
    }

    // Sort namespace declarations: default namespace first, then by prefix
    ns_attrs.sort_by(|a, b| {
        if a.0 == "xmlns" {
            return std::cmp::Ordering::Less;
        }
        if b.0 == "xmlns" {
            return std::cmp::Ordering::Greater;
        }
        a.0.cmp(&b.0)
    });

    // Sort regular attributes by name
    regular_attrs.sort_by(|a, b| a.0.cmp(&b.0));

    // Write namespace declarations first, then regular attributes
    for (key, value) in ns_attrs.iter().chain(regular_attrs.iter()) {
        output.push(' ');
        output.push_str(key);
        output.push_str("=\"");
        c14n_escape_attr(output, value);
        output.push('"');
    }

    output.push('>');
    Ok(())
}

/// C14N text node escaping: & < > and CR
fn c14n_escape_text(output: &mut String, text: &str) {
    for c in text.chars() {
        match c {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '\r' => output.push_str("&#xD;"),
            _ => output.push(c),
        }
    }
}

/// C14N attribute value escaping: & < " TAB LF CR
fn c14n_escape_attr(output: &mut String, text: &str) {
    for c in text.chars() {
        match c {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '"' => output.push_str("&quot;"),
            '\t' => output.push_str("&#x9;"),
            '\n' => output.push_str("&#xA;"),
            '\r' => output.push_str("&#xD;"),
            _ => output.push(c),
        }
    }
}

/// XML escape special characters for building XML strings
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

#[cfg(test)]
mod tests {
    use super::{build_canonical_signed_info, canonicalize_xml, xml_escape};

    #[test]
    fn test_xml_escape_basic() {
        assert_eq!(xml_escape("<>"), "&lt;&gt;");
        assert_eq!(xml_escape("a&b"), "a&amp;b");
    }

    #[test]
    fn test_canonicalize_xml_removes_declaration() {
        let input = "<?xml version=\"1.0\"?><root><child>text</child></root>";
        let result = canonicalize_xml(input).unwrap();
        assert_eq!(result, "<root><child>text</child></root>");
    }

    #[test]
    fn test_canonicalize_xml_expands_empty_elements() {
        let input = "<root><empty/></root>";
        let result = canonicalize_xml(input).unwrap();
        assert_eq!(result, "<root><empty></empty></root>");
    }

    #[test]
    fn test_canonicalize_xml_sorts_attributes() {
        let input = r#"<root z="3" a="1" m="2"></root>"#;
        let result = canonicalize_xml(input).unwrap();
        assert_eq!(result, r#"<root a="1" m="2" z="3"></root>"#);
    }

    #[test]
    fn test_canonicalize_xml_ns_decls_first() {
        let input = r#"<saml:Assertion ID="test" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0"></saml:Assertion>"#;
        let result = canonicalize_xml(input).unwrap();
        // xmlns:saml should come before ID and Version
        assert_eq!(
            result,
            r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="test" Version="2.0"></saml:Assertion>"#
        );
    }

    #[test]
    fn test_canonicalize_full_assertion() {
        let xml = "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"\n        ID=\"_assert_test123\"\n        Version=\"2.0\"\n        IssueInstant=\"2026-02-23T07:00:00Z\">\n        <saml:Issuer>https://api.xavyo.net/saml/metadata?tenant=test</saml:Issuer>\n        <saml:Subject>\n            <saml:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\">user@example.com</saml:NameID>\n            <saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">\n                <saml:SubjectConfirmationData\n                    NotOnOrAfter=\"2026-02-23T07:05:00Z\"\n                    Recipient=\"https://sp.example.com/acs\"/>\n            </saml:SubjectConfirmation>\n        </saml:Subject>\n        <saml:Conditions NotBefore=\"2026-02-23T06:58:00Z\" NotOnOrAfter=\"2026-02-23T07:05:00Z\">\n            <saml:AudienceRestriction>\n                <saml:Audience>https://sp.example.com</saml:Audience>\n            </saml:AudienceRestriction>\n        </saml:Conditions>\n        <saml:AuthnStatement AuthnInstant=\"2026-02-23T07:00:00Z\" SessionIndex=\"_session_test456\">\n            <saml:AuthnContext>\n                <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>\n            </saml:AuthnContext>\n        </saml:AuthnStatement>\n    </saml:Assertion>";
        let result = canonicalize_xml(xml);
        assert!(
            result.is_ok(),
            "Canonicalization of full assertion should succeed: {:?}",
            result.err()
        );
        let canonical = result.unwrap();
        // Self-closing SubjectConfirmationData should be expanded
        assert!(canonical.contains("</saml:SubjectConfirmationData>"));
        // Namespace should be present
        assert!(canonical.contains("xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\""));
        // Attributes on SubjectConfirmationData should be sorted
        assert!(canonical.contains("NotOnOrAfter=\"2026-02-23T07:05:00Z\" Recipient=\"https://sp.example.com/acs\""));
    }

    #[test]
    fn test_canonicalize_signed_info() {
        let xml = "<ds:SignedInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/><ds:Reference URI=\"#_assert_test123\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><ds:DigestValue>dGVzdA==</ds:DigestValue></ds:Reference></ds:SignedInfo>";
        let result = canonicalize_xml(xml);
        assert!(
            result.is_ok(),
            "Canonicalization of SignedInfo should succeed: {:?}",
            result.err()
        );
        let canonical = result.unwrap();
        // All self-closing tags should be expanded
        assert!(canonical.contains("</ds:CanonicalizationMethod>"));
        assert!(canonical.contains("</ds:SignatureMethod>"));
        assert!(canonical.contains("</ds:DigestMethod>"));
    }

    #[test]
    fn test_canonical_signed_info_builder() {
        let result = build_canonical_signed_info("_assert_abc", "dGVzdA==");
        // Should already be in canonical form (no self-closing tags)
        assert!(result.contains("</ds:CanonicalizationMethod>"));
        assert!(result.contains("</ds:SignatureMethod>"));
        assert!(result.contains("</ds:DigestMethod>"));
        assert!(result.contains("</ds:Transform>"));
        assert!(result.contains("URI=\"#_assert_abc\""));
        assert!(result.contains("<ds:DigestValue>dGVzdA==</ds:DigestValue>"));
    }

    #[test]
    fn test_canonicalize_xml_preserves_namespaces() {
        let input = "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"test\">\n            <saml:Issuer>https://idp.example.com</saml:Issuer>\n        </saml:Assertion>";
        let result = canonicalize_xml(input).expect("canonicalization should succeed");
        assert!(result.contains("xmlns:saml"));
        assert!(result.contains("urn:oasis:names:tc:SAML:2.0:assertion"));
    }
}
