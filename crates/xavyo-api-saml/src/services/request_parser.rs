//! SAML AuthnRequest parsing service

use crate::error::{SamlError, SamlResult};
use base64::{engine::general_purpose::STANDARD, Engine};
use flate2::read::DeflateDecoder;
use std::io::Read;

/// Parsed SAML AuthnRequest
#[derive(Debug, Clone)]
pub struct ParsedAuthnRequest {
    pub id: String,
    pub issuer: String,
    pub assertion_consumer_service_url: Option<String>,
    pub name_id_policy_format: Option<String>,
    pub is_passive: bool,
    pub force_authn: bool,
}

/// Service for parsing SAML AuthnRequest messages
pub struct RequestParser;

impl RequestParser {
    /// Parse an AuthnRequest from HTTP-Redirect binding (deflate + base64)
    pub fn parse_redirect(encoded_request: &str) -> SamlResult<ParsedAuthnRequest> {
        // Decode base64
        let decoded = STANDARD
            .decode(encoded_request)
            .map_err(|e| SamlError::InvalidAuthnRequest(format!("Base64 decode failed: {}", e)))?;

        // Inflate (decompress)
        let mut decoder = DeflateDecoder::new(&decoded[..]);
        let mut xml = String::new();
        decoder
            .read_to_string(&mut xml)
            .map_err(|e| SamlError::InvalidAuthnRequest(format!("Deflate decode failed: {}", e)))?;

        Self::parse_xml(&xml)
    }

    /// Parse an AuthnRequest from HTTP-POST binding (base64 only)
    pub fn parse_post(encoded_request: &str) -> SamlResult<ParsedAuthnRequest> {
        // Decode base64
        let decoded = STANDARD
            .decode(encoded_request)
            .map_err(|e| SamlError::InvalidAuthnRequest(format!("Base64 decode failed: {}", e)))?;

        let xml = String::from_utf8(decoded)
            .map_err(|e| SamlError::InvalidAuthnRequest(format!("Invalid UTF-8: {}", e)))?;

        Self::parse_xml(&xml)
    }

    /// Parse AuthnRequest XML
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

        loop {
            match reader.read_event() {
                Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                    let name = e.local_name();
                    let name_str = std::str::from_utf8(name.as_ref()).unwrap_or("");

                    match name_str {
                        "AuthnRequest" => {
                            for attr in e.attributes().flatten() {
                                let key = std::str::from_utf8(attr.key.as_ref()).unwrap_or("");
                                let value = attr.unescape_value().unwrap_or_default();

                                match key {
                                    "ID" => id = Some(value.to_string()),
                                    "AssertionConsumerServiceURL" => {
                                        acs_url = Some(value.to_string())
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
                        "XML parse error: {}",
                        e
                    )));
                }
                _ => {}
            }
        }

        let id =
            id.ok_or_else(|| SamlError::InvalidAuthnRequest("Missing ID attribute".to_string()))?;

        let issuer = issuer
            .ok_or_else(|| SamlError::InvalidAuthnRequest("Missing Issuer element".to_string()))?;

        Ok(ParsedAuthnRequest {
            id,
            issuer,
            assertion_consumer_service_url: acs_url,
            name_id_policy_format: name_id_format,
            is_passive,
            force_authn,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_AUTHN_REQUEST: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="_abc123"
    Version="2.0"
    IssueInstant="2024-01-01T00:00:00Z"
    AssertionConsumerServiceURL="https://sp.example.com/saml/acs"
    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
    <saml:Issuer>https://sp.example.com/saml/metadata</saml:Issuer>
    <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"/>
</samlp:AuthnRequest>"#;

    #[test]
    fn test_parse_xml() {
        let parsed = RequestParser::parse_xml(SAMPLE_AUTHN_REQUEST).unwrap();
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
}
