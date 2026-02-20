//! SAML `AuthnRequest` parsing service

use crate::error::{SamlError, SamlResult};
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{DateTime, Utc};
use flate2::read::DeflateDecoder;
use std::io::Read;

/// Maximum allowed clock skew for `IssueInstant` validation (5 minutes)
const MAX_CLOCK_SKEW_SECS: i64 = 300;

/// Maximum age for an `AuthnRequest` (5 minutes)
const MAX_REQUEST_AGE_SECS: i64 = 300;

/// Maximum decompressed size for deflate decoding (64 KB) to prevent deflate bomb DoS
const MAX_DECOMPRESSED_SIZE: u64 = 64 * 1024;

/// Maximum encoded size for SAMLRequest in HTTP-Redirect binding (128 KB)
/// Prevents memory exhaustion from oversized base64 input before decoding.
const MAX_ENCODED_SIZE_REDIRECT: usize = 128 * 1024;

/// Maximum encoded size for SAMLRequest in HTTP-POST binding (512 KB)
const MAX_ENCODED_SIZE_POST: usize = 512 * 1024;

/// Maximum length for the AuthnRequest ID attribute
const MAX_REQUEST_ID_LENGTH: usize = 256;

/// Maximum length for the Issuer element value
const MAX_ISSUER_LENGTH: usize = 1024;

/// Parsed SAML `AuthnRequest`
#[derive(Debug, Clone)]
pub struct ParsedAuthnRequest {
    pub id: String,
    pub issuer: String,
    pub assertion_consumer_service_url: Option<String>,
    pub name_id_policy_format: Option<String>,
    pub is_passive: bool,
    pub force_authn: bool,
    pub issue_instant: DateTime<Utc>,
}

/// Service for parsing SAML `AuthnRequest` messages
pub struct RequestParser;

impl RequestParser {
    /// Parse an `AuthnRequest` from HTTP-Redirect binding (deflate + base64)
    pub fn parse_redirect(encoded_request: &str) -> SamlResult<ParsedAuthnRequest> {
        // SECURITY (H9): Reject oversized input before base64 decode to prevent OOM.
        if encoded_request.len() > MAX_ENCODED_SIZE_REDIRECT {
            return Err(SamlError::InvalidAuthnRequest(format!(
                "Encoded SAMLRequest exceeds maximum size ({} > {} bytes)",
                encoded_request.len(),
                MAX_ENCODED_SIZE_REDIRECT
            )));
        }
        // Decode base64
        let decoded = STANDARD
            .decode(encoded_request)
            .map_err(|e| SamlError::InvalidAuthnRequest(format!("Base64 decode failed: {e}")))?;

        // Inflate (decompress) with size limit to prevent deflate bomb DoS
        let decoder = DeflateDecoder::new(&decoded[..]);
        let mut xml = String::new();
        decoder
            .take(MAX_DECOMPRESSED_SIZE)
            .read_to_string(&mut xml)
            .map_err(|e| SamlError::InvalidAuthnRequest(format!("Deflate decode failed: {e}")))?;

        // Check if we hit the size limit
        if xml.len() as u64 >= MAX_DECOMPRESSED_SIZE {
            return Err(SamlError::InvalidAuthnRequest(
                "Decompressed AuthnRequest exceeds maximum size limit (64 KB)".to_string(),
            ));
        }

        Self::parse_xml(&xml)
    }

    /// Parse an `AuthnRequest` from HTTP-POST binding (base64 only)
    pub fn parse_post(encoded_request: &str) -> SamlResult<ParsedAuthnRequest> {
        // SECURITY (H9): Reject oversized input before base64 decode.
        if encoded_request.len() > MAX_ENCODED_SIZE_POST {
            return Err(SamlError::InvalidAuthnRequest(format!(
                "Encoded SAMLRequest exceeds maximum size ({} > {} bytes)",
                encoded_request.len(),
                MAX_ENCODED_SIZE_POST
            )));
        }
        // Decode base64
        let decoded = STANDARD
            .decode(encoded_request)
            .map_err(|e| SamlError::InvalidAuthnRequest(format!("Base64 decode failed: {e}")))?;

        let xml = String::from_utf8(decoded)
            .map_err(|e| SamlError::InvalidAuthnRequest(format!("Invalid UTF-8: {e}")))?;

        Self::parse_xml(&xml)
    }

    /// Parse `AuthnRequest` XML.
    ///
    /// Public entry point for callers that have already decoded the XML
    /// (e.g. HTTP-POST binding where the handler decodes base64 once).
    pub fn parse_xml_public(xml: &str) -> SamlResult<ParsedAuthnRequest> {
        Self::parse_xml(xml)
    }

    /// Parse `AuthnRequest` XML (internal)
    fn parse_xml(xml: &str) -> SamlResult<ParsedAuthnRequest> {
        use quick_xml::events::Event;
        use quick_xml::Reader;

        let mut reader = Reader::from_str(xml);
        reader.config_mut().trim_text(true);

        let mut id = None;
        let mut issuer = None;
        let mut acs_url = None;
        let mut name_id_format = None;
        let mut is_passive = false;
        let mut force_authn = false;
        let mut in_issuer = false;
        let mut issue_instant_raw = None;

        loop {
            match reader.read_event() {
                Ok(Event::Start(e) | Event::Empty(e)) => {
                    let name = e.local_name();
                    let name_str = std::str::from_utf8(name.as_ref()).unwrap_or("");

                    match name_str {
                        "AuthnRequest" => {
                            for attr in e.attributes().flatten() {
                                let key = std::str::from_utf8(attr.key.as_ref()).unwrap_or("");
                                let value = attr.unescape_value().unwrap_or_default();

                                match key {
                                    "ID" => id = Some(value.to_string()),
                                    "IssueInstant" => {
                                        issue_instant_raw = Some(value.to_string());
                                    }
                                    "AssertionConsumerServiceURL" => {
                                        acs_url = Some(value.to_string());
                                    }
                                    "IsPassive" => is_passive = value == "true",
                                    "ForceAuthn" => force_authn = value == "true",
                                    _ => {}
                                }
                            }
                        }
                        "Issuer" => {
                            in_issuer = true;
                        }
                        "NameIDPolicy" => {
                            for attr in e.attributes().flatten() {
                                let key = std::str::from_utf8(attr.key.as_ref()).unwrap_or("");
                                if key == "Format" {
                                    name_id_format =
                                        Some(attr.unescape_value().unwrap_or_default().to_string());
                                }
                            }
                        }
                        _ => {}
                    }
                }
                Ok(Event::Text(e)) => {
                    if in_issuer {
                        issuer = Some(e.unescape().unwrap_or_default().to_string());
                    }
                }
                Ok(Event::End(e)) => {
                    let local_name = e.local_name();
                    let name = std::str::from_utf8(local_name.as_ref()).unwrap_or("");
                    if name == "Issuer" {
                        in_issuer = false;
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => {
                    return Err(SamlError::InvalidAuthnRequest(format!(
                        "XML parse error: {e}"
                    )));
                }
                _ => {}
            }
        }

        let id =
            id.ok_or_else(|| SamlError::InvalidAuthnRequest("Missing ID attribute".to_string()))?;

        // SECURITY (M4): Validate request_id length to prevent abuse
        if id.len() > MAX_REQUEST_ID_LENGTH {
            return Err(SamlError::InvalidAuthnRequest(format!(
                "ID attribute exceeds maximum length of {MAX_REQUEST_ID_LENGTH} characters"
            )));
        }

        let issuer = issuer
            .ok_or_else(|| SamlError::InvalidAuthnRequest("Missing Issuer element".to_string()))?;

        // SECURITY (M4): Validate issuer length to prevent abuse
        if issuer.len() > MAX_ISSUER_LENGTH {
            return Err(SamlError::InvalidAuthnRequest(format!(
                "Issuer exceeds maximum length of {MAX_ISSUER_LENGTH} characters"
            )));
        }

        // Validate IssueInstant
        let issue_instant_str = issue_instant_raw.ok_or_else(|| {
            SamlError::InvalidAuthnRequest("Missing IssueInstant attribute".to_string())
        })?;

        let issue_instant = DateTime::parse_from_rfc3339(&issue_instant_str)
            .map(|dt| dt.with_timezone(&Utc))
            .map_err(|e| {
                SamlError::InvalidAuthnRequest(format!("Invalid IssueInstant format: {e}"))
            })?;

        let now = Utc::now();
        let age_secs = (now - issue_instant).num_seconds();

        // Reject if IssueInstant is too far in the future (clock skew tolerance)
        if age_secs < -MAX_CLOCK_SKEW_SECS {
            return Err(SamlError::InvalidAuthnRequest(format!(
                "IssueInstant is in the future (skew: {}s exceeds {}s tolerance)",
                -age_secs, MAX_CLOCK_SKEW_SECS
            )));
        }

        // Reject if IssueInstant is too old
        if age_secs > MAX_REQUEST_AGE_SECS {
            return Err(SamlError::InvalidAuthnRequest(format!(
                "IssueInstant is too old (age: {age_secs}s exceeds {MAX_REQUEST_AGE_SECS}s maximum)"
            )));
        }

        Ok(ParsedAuthnRequest {
            id,
            issuer,
            assertion_consumer_service_url: acs_url,
            name_id_policy_format: name_id_format,
            is_passive,
            force_authn,
            issue_instant,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a sample `AuthnRequest` XML with the given `IssueInstant` value.
    fn sample_authn_request(issue_instant: &str) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="_abc123"
    Version="2.0"
    IssueInstant="{issue_instant}"
    AssertionConsumerServiceURL="https://sp.example.com/saml/acs"
    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
    <saml:Issuer>https://sp.example.com/saml/metadata</saml:Issuer>
    <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"/>
</samlp:AuthnRequest>"#
        )
    }

    #[test]
    fn test_parse_xml() {
        let now = Utc::now().to_rfc3339();
        let xml = sample_authn_request(&now);
        let parsed = RequestParser::parse_xml(&xml).unwrap();
        assert_eq!(parsed.id, "_abc123");
        assert_eq!(parsed.issuer, "https://sp.example.com/saml/metadata");
        assert_eq!(
            parsed.assertion_consumer_service_url,
            Some("https://sp.example.com/saml/acs".to_string())
        );
        assert_eq!(
            parsed.name_id_policy_format,
            Some("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress".to_string())
        );
    }

    #[test]
    fn test_issue_instant_missing() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="_abc123" Version="2.0">
    <saml:Issuer>https://sp.example.com</saml:Issuer>
</samlp:AuthnRequest>"#;
        let err = RequestParser::parse_xml(xml).unwrap_err();
        assert!(err.to_string().contains("Missing IssueInstant"));
    }

    #[test]
    fn test_issue_instant_too_old() {
        let old = Utc::now() - chrono::Duration::seconds(600);
        let xml = sample_authn_request(&old.to_rfc3339());
        let err = RequestParser::parse_xml(&xml).unwrap_err();
        assert!(err.to_string().contains("too old"));
    }

    #[test]
    fn test_issue_instant_future() {
        let future = Utc::now() + chrono::Duration::seconds(600);
        let xml = sample_authn_request(&future.to_rfc3339());
        let err = RequestParser::parse_xml(&xml).unwrap_err();
        assert!(err.to_string().contains("future"));
    }

    #[test]
    fn test_issue_instant_within_skew() {
        // Slightly in the future but within tolerance
        let slight_future = Utc::now() + chrono::Duration::seconds(120);
        let xml = sample_authn_request(&slight_future.to_rfc3339());
        let parsed = RequestParser::parse_xml(&xml);
        assert!(
            parsed.is_ok(),
            "Should accept IssueInstant within clock skew tolerance"
        );
    }
}
