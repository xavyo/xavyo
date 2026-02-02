//! AuthnRequest signature validation service
//!
//! Validates SAML AuthnRequest signatures for both HTTP-Redirect and HTTP-POST bindings.

use crate::error::{SamlError, SamlResult};
use base64::{engine::general_purpose::STANDARD, Engine};
use openssl::hash::MessageDigest;
use openssl::sign::Verifier;
use openssl::x509::X509;
use xml_canonicalization::Canonicalizer;

/// Service for validating SAML message signatures
pub struct SignatureValidator;

impl SignatureValidator {
    /// Validate signature for HTTP-Redirect binding.
    ///
    /// Per SAML 2.0 Bindings spec, the signature covers:
    /// `SAMLRequest=value&RelayState=value&SigAlg=value` (URL-encoded)
    ///
    /// # Arguments
    /// * `saml_request` - URL-encoded SAMLRequest parameter value
    /// * `relay_state` - Optional URL-encoded RelayState parameter value
    /// * `sig_alg` - URL-encoded SigAlg parameter value
    /// * `signature` - Base64-encoded signature value
    /// * `sp_certificate_pem` - SP's X.509 certificate in PEM format
    pub fn validate_redirect_signature(
        saml_request: &str,
        relay_state: Option<&str>,
        sig_alg: &str,
        signature: &str,
        sp_certificate_pem: &str,
    ) -> SamlResult<()> {
        // Parse certificate
        let cert = parse_certificate(sp_certificate_pem)?;
        let public_key = cert.public_key().map_err(|e| {
            SamlError::SignatureValidationFailed(format!("Invalid certificate: {}", e))
        })?;

        // Reconstruct the signed data (URL query string order matters!)
        let mut signed_data = format!("SAMLRequest={}", saml_request);
        if let Some(rs) = relay_state {
            if !rs.is_empty() {
                signed_data.push_str("&RelayState=");
                signed_data.push_str(rs);
            }
        }
        signed_data.push_str("&SigAlg=");
        signed_data.push_str(sig_alg);

        // Decode signature
        let signature_bytes = STANDARD.decode(signature).map_err(|e| {
            SamlError::SignatureValidationFailed(format!("Invalid signature encoding: {}", e))
        })?;

        // Determine digest algorithm from SigAlg
        let (digest, _alg_name) = match urlencoding::decode(sig_alg)
            .map_err(|e| {
                SamlError::SignatureValidationFailed(format!("Invalid SigAlg encoding: {}", e))
            })?
            .as_ref()
        {
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" => {
                (MessageDigest::sha256(), "RSA-SHA256")
            }
            "http://www.w3.org/2000/09/xmldsig#rsa-sha1" => (MessageDigest::sha1(), "RSA-SHA1"),
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384" => {
                (MessageDigest::sha384(), "RSA-SHA384")
            }
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512" => {
                (MessageDigest::sha512(), "RSA-SHA512")
            }
            alg => {
                return Err(SamlError::SignatureValidationFailed(format!(
                    "Unsupported signature algorithm: {}",
                    alg
                )));
            }
        };

        // Verify signature
        let mut verifier = Verifier::new(digest, &public_key).map_err(|e| {
            SamlError::SignatureValidationFailed(format!("Verifier creation failed: {}", e))
        })?;

        verifier.update(signed_data.as_bytes()).map_err(|e| {
            SamlError::SignatureValidationFailed(format!("Signature update failed: {}", e))
        })?;

        let valid = verifier.verify(&signature_bytes).map_err(|e| {
            SamlError::SignatureValidationFailed(format!("Signature verification failed: {}", e))
        })?;

        if valid {
            Ok(())
        } else {
            Err(SamlError::SignatureValidationFailed(
                "Signature verification failed: invalid signature".to_string(),
            ))
        }
    }

    /// Validate embedded signature for HTTP-POST binding.
    ///
    /// Extracts the ds:Signature element from the XML and validates it.
    ///
    /// # Arguments
    /// * `xml` - The decoded AuthnRequest XML
    /// * `sp_certificate_pem` - SP's X.509 certificate in PEM format
    pub fn validate_post_signature(xml: &str, sp_certificate_pem: &str) -> SamlResult<()> {
        // Parse certificate
        let cert = parse_certificate(sp_certificate_pem)?;
        let public_key = cert.public_key().map_err(|e| {
            SamlError::SignatureValidationFailed(format!("Invalid certificate: {}", e))
        })?;

        // Extract signature components from XML
        let sig_info = extract_signature_info(xml)?;

        // Verify the digest first
        verify_reference_digest(xml, &sig_info)?;

        // Canonicalize SignedInfo and verify signature
        let canonicalized_signed_info = canonicalize_xml(&sig_info.signed_info)?;

        // Decode signature value
        let signature_bytes = STANDARD
            .decode(sig_info.signature_value.replace(['\n', '\r', ' '], ""))
            .map_err(|e| {
                SamlError::SignatureValidationFailed(format!("Invalid signature encoding: {}", e))
            })?;

        // Verify signature (assume SHA256 for now, can extend based on SignatureMethod)
        let mut verifier = Verifier::new(MessageDigest::sha256(), &public_key).map_err(|e| {
            SamlError::SignatureValidationFailed(format!("Verifier creation failed: {}", e))
        })?;

        verifier
            .update(canonicalized_signed_info.as_bytes())
            .map_err(|e| {
                SamlError::SignatureValidationFailed(format!("Signature update failed: {}", e))
            })?;

        let valid = verifier.verify(&signature_bytes).map_err(|e| {
            SamlError::SignatureValidationFailed(format!("Signature verification failed: {}", e))
        })?;

        if valid {
            Ok(())
        } else {
            Err(SamlError::SignatureValidationFailed(
                "Signature verification failed: invalid signature".to_string(),
            ))
        }
    }
}

/// Signature information extracted from XML
struct SignatureInfo {
    signed_info: String,
    signature_value: String,
    reference_uri: String,
    digest_value: String,
}

/// Parse X.509 certificate from PEM format
fn parse_certificate(pem: &str) -> SamlResult<X509> {
    // Handle both with and without PEM headers
    let pem_data = if pem.contains("-----BEGIN CERTIFICATE-----") {
        pem.to_string()
    } else {
        format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
            pem.trim()
        )
    };

    X509::from_pem(pem_data.as_bytes())
        .map_err(|e| SamlError::SignatureValidationFailed(format!("Invalid certificate: {}", e)))
}

/// Apply Exclusive XML Canonicalization (C14N)
fn canonicalize_xml(xml: &str) -> SamlResult<String> {
    let mut output = Vec::new();
    Canonicalizer::read_from_str(xml)
        .write_to_writer(&mut output)
        .canonicalize(false) // Exclusive C14N without comments
        .map_err(|e| {
            SamlError::SignatureValidationFailed(format!("Canonicalization failed: {}", e))
        })?;

    String::from_utf8(output)
        .map_err(|e| SamlError::SignatureValidationFailed(format!("Invalid UTF-8: {}", e)))
}

/// Extract signature information from XML using quick-xml
fn extract_signature_info(xml: &str) -> SamlResult<SignatureInfo> {
    use quick_xml::events::Event;
    use quick_xml::Reader;

    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false); // Preserve whitespace for signature verification

    let mut in_signed_info = false;
    let mut in_signature_value = false;
    let mut in_digest_value = false;
    let mut signed_info_content = String::new();
    let mut signature_value = String::new();
    let mut digest_value = String::new();
    let mut reference_uri = String::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let local_name = e.local_name();
                let name = std::str::from_utf8(local_name.as_ref()).unwrap_or("");

                if name == "SignedInfo" {
                    in_signed_info = true;
                    // Capture the start tag with all attributes and namespaces
                    let full_tag = std::str::from_utf8(&e).unwrap_or("");
                    signed_info_content.push('<');
                    signed_info_content.push_str(full_tag);
                    signed_info_content.push('>');
                } else if in_signed_info {
                    let full_tag = std::str::from_utf8(&e).unwrap_or("");
                    signed_info_content.push('<');
                    signed_info_content.push_str(full_tag);
                    signed_info_content.push('>');
                } else if name == "SignatureValue" {
                    in_signature_value = true;
                } else if name == "DigestValue" {
                    in_digest_value = true;
                } else if name == "Reference" {
                    for attr in e.attributes().flatten() {
                        let key = std::str::from_utf8(attr.key.as_ref()).unwrap_or("");
                        if key == "URI" {
                            reference_uri = attr.unescape_value().unwrap_or_default().to_string();
                        }
                    }
                }
            }
            Ok(Event::Empty(e)) => {
                if in_signed_info {
                    let full_tag = std::str::from_utf8(&e).unwrap_or("");
                    signed_info_content.push('<');
                    signed_info_content.push_str(full_tag);
                    signed_info_content.push_str("/>");
                }
            }
            Ok(Event::End(e)) => {
                let local_name = e.local_name();
                let name = std::str::from_utf8(local_name.as_ref()).unwrap_or("");

                if name == "SignedInfo" && in_signed_info {
                    signed_info_content.push_str("</");
                    signed_info_content.push_str(name);
                    signed_info_content.push('>');
                    in_signed_info = false;
                } else if in_signed_info {
                    signed_info_content.push_str("</");
                    signed_info_content.push_str(name);
                    signed_info_content.push('>');
                } else if name == "SignatureValue" {
                    in_signature_value = false;
                } else if name == "DigestValue" {
                    in_digest_value = false;
                }
            }
            Ok(Event::Text(e)) => {
                let text = e.unescape().unwrap_or_default();
                if in_signed_info {
                    signed_info_content.push_str(&text);
                } else if in_signature_value {
                    signature_value.push_str(&text);
                } else if in_digest_value {
                    digest_value.push_str(&text);
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(SamlError::SignatureValidationFailed(format!(
                    "XML parse error: {}",
                    e
                )));
            }
            _ => {}
        }
    }

    if signed_info_content.is_empty() {
        return Err(SamlError::SignatureValidationFailed(
            "No SignedInfo element found".to_string(),
        ));
    }

    if signature_value.is_empty() {
        return Err(SamlError::SignatureValidationFailed(
            "No SignatureValue element found".to_string(),
        ));
    }

    Ok(SignatureInfo {
        signed_info: signed_info_content,
        signature_value,
        reference_uri,
        digest_value,
    })
}

/// Verify the reference digest matches the actual content
fn verify_reference_digest(xml: &str, sig_info: &SignatureInfo) -> SamlResult<()> {
    // Find the referenced element (remove # prefix from URI)
    let element_id = sig_info.reference_uri.trim_start_matches('#');
    if element_id.is_empty() {
        // Empty URI means the whole document
        return verify_document_digest(xml, sig_info);
    }

    // Find element with this ID
    let id_pattern = format!("ID=\"{}\"", element_id);
    let element_start = xml.find(&id_pattern).ok_or_else(|| {
        SamlError::SignatureValidationFailed(format!(
            "Referenced element not found: {}",
            element_id
        ))
    })?;

    // Find the element boundaries (this is a simplified approach)
    // In production, you'd want to properly parse the XML
    let open_tag_start = xml[..element_start].rfind('<').unwrap_or(0);

    // Find the corresponding end tag - for AuthnRequest this is usually the root element
    let tag_name = extract_tag_name(&xml[open_tag_start..]);
    let close_tag = format!("</{}", tag_name);
    let element_end = xml
        .find(&close_tag)
        .map(|pos| pos + close_tag.len() + 1) // +1 for the >
        .ok_or_else(|| {
            SamlError::SignatureValidationFailed("Cannot find element end".to_string())
        })?;

    let element_content = &xml[open_tag_start..element_end];

    // Remove the Signature element from the content (enveloped signature transform)
    let content_without_sig = remove_signature_element(element_content);

    // Canonicalize and compute digest
    let canonicalized = canonicalize_xml(&content_without_sig)?;
    let digest = openssl::hash::hash(MessageDigest::sha256(), canonicalized.as_bytes())
        .map_err(|e| SamlError::SignatureValidationFailed(format!("Hash failed: {}", e)))?;
    let computed_digest = STANDARD.encode(digest);

    // Compare with expected digest
    let expected_digest = sig_info.digest_value.replace(['\n', '\r', ' '], "");
    if computed_digest != expected_digest {
        return Err(SamlError::SignatureValidationFailed(
            "Digest mismatch".to_string(),
        ));
    }

    Ok(())
}

/// Verify digest when URI is empty (whole document)
fn verify_document_digest(xml: &str, sig_info: &SignatureInfo) -> SamlResult<()> {
    // Remove the Signature element
    let content_without_sig = remove_signature_element(xml);

    // Canonicalize and compute digest
    let canonicalized = canonicalize_xml(&content_without_sig)?;
    let digest = openssl::hash::hash(MessageDigest::sha256(), canonicalized.as_bytes())
        .map_err(|e| SamlError::SignatureValidationFailed(format!("Hash failed: {}", e)))?;
    let computed_digest = STANDARD.encode(digest);

    let expected_digest = sig_info.digest_value.replace(['\n', '\r', ' '], "");
    if computed_digest != expected_digest {
        return Err(SamlError::SignatureValidationFailed(
            "Digest mismatch".to_string(),
        ));
    }

    Ok(())
}

/// Extract tag name from XML opening tag
fn extract_tag_name(tag_start: &str) -> String {
    let tag = tag_start
        .trim_start_matches('<')
        .split_whitespace()
        .next()
        .unwrap_or("")
        .trim_end_matches('>');
    tag.to_string()
}

/// Remove the ds:Signature element from XML (for enveloped signature transform)
fn remove_signature_element(xml: &str) -> String {
    // Find and remove the Signature element
    if let Some(sig_start) = xml.find("<ds:Signature") {
        if let Some(sig_end) = xml.find("</ds:Signature>") {
            let mut result = String::with_capacity(xml.len());
            result.push_str(&xml[..sig_start]);
            result.push_str(&xml[sig_end + "</ds:Signature>".len()..]);
            return result;
        }
    }
    // Also try without namespace prefix
    if let Some(sig_start) = xml.find("<Signature") {
        if let Some(sig_end) = xml.find("</Signature>") {
            let mut result = String::with_capacity(xml.len());
            result.push_str(&xml[..sig_start]);
            result.push_str(&xml[sig_end + "</Signature>".len()..]);
            return result;
        }
    }
    xml.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Valid self-signed test certificate
    const TEST_CERT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIC/zCCAeegAwIBAgIUeBumeIsMNakKlofC3AioissDusswDQYJKoZIhvcNAQEL
BQAwDzENMAsGA1UEAwwEdGVzdDAeFw0yNjAxMjMwMzQzMDRaFw0yNzAxMjMwMzQz
MDRaMA8xDTALBgNVBAMMBHRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQCk+cG6tSoKRZ0LxMcY3E0oMirafnj7qeSVhDv8LQLuocklq8tIzOvVN1HE
b/ZZyuD7E0Xy03SOw9ZeTy0FWCqXcDWpGD2+RbdMZku8q6G35joLq+dW/95kK+ds
vWu427ySPVT0AsxzH6VuhdiNQY8ncNc0jV82aMgLt74FGG61xWfwt3Su2NEJ4ZUj
9M+0q/o1tmDCBIYF7hUsI5F3qLV9Ivm8UU2C/Uuqxnb3ZtsG5wvnCgi720cU2j+1
C0hmt1wf1zUgr18Q1UZ92iQeXHW0FEg3XmULMh3/5GehrP6RyGhegRs4stOdaEZF
ojW93wQ/YGYQjQmIXW32dq4nyNQ9AgMBAAGjUzBRMB0GA1UdDgQWBBS/LUDCdZWG
Fd4Ra/rLdqUT2WKkWzAfBgNVHSMEGDAWgBS/LUDCdZWGFd4Ra/rLdqUT2WKkWzAP
BgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBUAol6uvWDwrX1XZk7
Fzi0zLo4vPslAPxzestYgla+wbmL/Aeo+H3zw5IDmVxq4EOACKHZmAJ7QzVY4XpH
tq60zj4HpqGqCJELCh53rrIfJNweIGUxYzMPYueq8aeyFgnGzxIUtLDdJUrrc6ku
VDv3g0vVY7loS28Zjps+E4/W7s2dPhsco73dc0VZJra77xGh2F7pYdIVw84Jf1/Q
EP7G+qT00T3iLtw8TueXFhkYskhQx24/F1+Giwq9Lki2Dgf8TLpXtkcy/aqfRguE
FHZhsLOKh09hTj+7qXLoUp5iCz7fA5hrUKjvYxyeYGatyLExkqIG4E3nH5UrOWH+
t6Rp
-----END CERTIFICATE-----"#;

    // Same certificate without PEM headers (base64 only)
    const TEST_CERT_BASE64: &str = "MIIC/zCCAeegAwIBAgIUeBumeIsMNakKlofC3AioissDusswDQYJKoZIhvcNAQELBQAwDzENMAsGA1UEAwwEdGVzdDAeFw0yNjAxMjMwMzQzMDRaFw0yNzAxMjMwMzQzMDRaMA8xDTALBgNVBAMMBHRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCk+cG6tSoKRZ0LxMcY3E0oMirafnj7qeSVhDv8LQLuocklq8tIzOvVN1HEb/ZZyuD7E0Xy03SOw9ZeTy0FWCqXcDWpGD2+RbdMZku8q6G35joLq+dW/95kK+dsvWu427ySPVT0AsxzH6VuhdiNQY8ncNc0jV82aMgLt74FGG61xWfwt3Su2NEJ4ZUj9M+0q/o1tmDCBIYF7hUsI5F3qLV9Ivm8UU2C/Uuqxnb3ZtsG5wvnCgi720cU2j+1C0hmt1wf1zUgr18Q1UZ92iQeXHW0FEg3XmULMh3/5GehrP6RyGhegRs4stOdaEZFojW93wQ/YGYQjQmIXW32dq4nyNQ9AgMBAAGjUzBRMB0GA1UdDgQWBBS/LUDCdZWGFd4Ra/rLdqUT2WKkWzAfBgNVHSMEGDAWgBS/LUDCdZWGFd4Ra/rLdqUT2WKkWzAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBUAol6uvWDwrX1XZk7Fzi0zLo4vPslAPxzestYgla+wbmL/Aeo+H3zw5IDmVxq4EOACKHZmAJ7QzVY4XpHtq60zj4HpqGqCJELCh53rrIfJNweIGUxYzMPYueq8aeyFgnGzxIUtLDdJUrrc6kuVDv3g0vVY7loS28Zjps+E4/W7s2dPhsco73dc0VZJra77xGh2F7pYdIVw84Jf1/QEP7G+qT00T3iLtw8TueXFhkYskhQx24/F1+Giwq9Lki2Dgf8TLpXtkcy/aqfRguEFHZhsLOKh09hTj+7qXLoUp5iCz7fA5hrUKjvYxyeYGatyLExkqIG4E3nH5UrOWH+t6Rp";

    #[test]
    fn test_parse_certificate_with_headers() {
        let cert = parse_certificate(TEST_CERT_PEM);
        assert!(
            cert.is_ok(),
            "Failed to parse certificate: {:?}",
            cert.err()
        );
    }

    #[test]
    fn test_parse_certificate_without_headers() {
        let cert = parse_certificate(TEST_CERT_BASE64);
        assert!(
            cert.is_ok(),
            "Failed to parse certificate: {:?}",
            cert.err()
        );
    }

    #[test]
    fn test_remove_signature_element() {
        let xml = r#"<AuthnRequest ID="test"><ds:Signature>...</ds:Signature><Issuer>test</Issuer></AuthnRequest>"#;
        let result = remove_signature_element(xml);
        assert!(!result.contains("Signature"));
        assert!(result.contains("Issuer"));
    }

    #[test]
    fn test_extract_tag_name() {
        assert_eq!(
            extract_tag_name("<samlp:AuthnRequest xmlns:samlp=\"...\""),
            "samlp:AuthnRequest"
        );
        assert_eq!(
            extract_tag_name("<AuthnRequest ID=\"test\">"),
            "AuthnRequest"
        );
    }
}
