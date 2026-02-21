//! Parse incoming SAML LogoutRequest XML

use crate::error::{SamlError, SamlResult};
use base64::{engine::general_purpose::STANDARD, Engine};
use quick_xml::events::Event;
use quick_xml::reader::Reader;

/// Parsed LogoutRequest data
#[derive(Debug, Clone)]
pub struct ParsedLogoutRequest {
    pub id: String,
    pub issuer: String,
    pub name_id: String,
    pub name_id_format: String,
    pub session_index: Option<String>,
}

/// Parse a base64-encoded SAML LogoutRequest
pub fn parse_logout_request(encoded: &str) -> SamlResult<ParsedLogoutRequest> {
    // Size check before decode
    if encoded.len() > 512 * 1024 {
        return Err(SamlError::InvalidLogoutRequest(
            "LogoutRequest too large".to_string(),
        ));
    }

    let decoded = STANDARD
        .decode(encoded)
        .map_err(|e| SamlError::InvalidLogoutRequest(format!("Base64 decode failed: {e}")))?;
    let xml = String::from_utf8(decoded)
        .map_err(|e| SamlError::InvalidLogoutRequest(format!("Invalid UTF-8: {e}")))?;

    parse_logout_request_xml(&xml)
}

/// Parse LogoutRequest from raw XML
pub fn parse_logout_request_xml(xml: &str) -> SamlResult<ParsedLogoutRequest> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut id = None;
    let mut issuer = None;
    let mut name_id = None;
    let mut name_id_format = String::new();
    let mut session_index = None;
    let mut current_element = String::new();

    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e)) => {
                let local = String::from_utf8_lossy(e.local_name().into_inner()).to_string();
                current_element = local.clone();

                if local == "LogoutRequest" {
                    for attr in e.attributes().flatten() {
                        let key =
                            String::from_utf8_lossy(attr.key.local_name().into_inner()).to_string();
                        if key == "ID" {
                            id = Some(String::from_utf8_lossy(&attr.value).to_string());
                        }
                    }
                } else if local == "NameID" {
                    for attr in e.attributes().flatten() {
                        let key =
                            String::from_utf8_lossy(attr.key.local_name().into_inner()).to_string();
                        if key == "Format" {
                            name_id_format = String::from_utf8_lossy(&attr.value).to_string();
                        }
                    }
                }
            }
            Ok(Event::Text(ref e)) => {
                let text = e.unescape().unwrap_or_default().to_string();
                match current_element.as_str() {
                    "Issuer" => issuer = Some(text),
                    "NameID" => name_id = Some(text),
                    "SessionIndex" => session_index = Some(text),
                    _ => {}
                }
            }
            Ok(Event::End(_)) => {
                current_element.clear();
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(SamlError::InvalidLogoutRequest(format!(
                    "XML parse error: {e}"
                )));
            }
            _ => {}
        }
        buf.clear();
    }

    let id =
        id.ok_or_else(|| SamlError::InvalidLogoutRequest("Missing LogoutRequest ID".to_string()))?;
    let issuer =
        issuer.ok_or_else(|| SamlError::InvalidLogoutRequest("Missing Issuer".to_string()))?;
    let name_id =
        name_id.ok_or_else(|| SamlError::InvalidLogoutRequest("Missing NameID".to_string()))?;

    // Validate lengths
    if id.len() > 256 {
        return Err(SamlError::InvalidLogoutRequest(
            "ID too long (max 256)".to_string(),
        ));
    }
    if issuer.len() > 1024 {
        return Err(SamlError::InvalidLogoutRequest(
            "Issuer too long (max 1024)".to_string(),
        ));
    }
    if name_id.len() > 4096 {
        return Err(SamlError::InvalidLogoutRequest(
            "NameID too long (max 4096)".to_string(),
        ));
    }
    if let Some(ref si) = session_index {
        if si.len() > 256 {
            return Err(SamlError::InvalidLogoutRequest(
                "SessionIndex too long (max 256)".to_string(),
            ));
        }
    }

    Ok(ParsedLogoutRequest {
        id,
        issuer,
        name_id,
        name_id_format,
        session_index,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_logout_request() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="_lr_test123" Version="2.0" IssueInstant="2026-02-21T10:00:00Z"
    Destination="https://idp.example.com/saml/slo">
    <saml:Issuer>https://sp.example.com</saml:Issuer>
    <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">user@example.com</saml:NameID>
    <samlp:SessionIndex>_session_abc123</samlp:SessionIndex>
</samlp:LogoutRequest>"#;

        let result = parse_logout_request_xml(xml).unwrap();
        assert_eq!(result.id, "_lr_test123");
        assert_eq!(result.issuer, "https://sp.example.com");
        assert_eq!(result.name_id, "user@example.com");
        assert_eq!(
            result.name_id_format,
            "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
        );
        assert_eq!(result.session_index, Some("_session_abc123".to_string()));
    }

    #[test]
    fn test_parse_logout_request_without_session_index() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="_lr_test456" Version="2.0" IssueInstant="2026-02-21T10:00:00Z">
    <saml:Issuer>https://sp.example.com</saml:Issuer>
    <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">user@example.com</saml:NameID>
</samlp:LogoutRequest>"#;

        let result = parse_logout_request_xml(xml).unwrap();
        assert_eq!(result.id, "_lr_test456");
        assert!(result.session_index.is_none());
    }

    #[test]
    fn test_parse_logout_request_missing_issuer() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="_lr_test789" Version="2.0">
    <saml:NameID>user@example.com</saml:NameID>
</samlp:LogoutRequest>"#;

        let result = parse_logout_request_xml(xml);
        assert!(result.is_err());
    }
}
