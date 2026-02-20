//! `AuthnRequest` signature validation service
//!
//! Validates SAML `AuthnRequest` signatures for both HTTP-Redirect and HTTP-POST bindings.

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
    /// * `saml_request` - URL-encoded `SAMLRequest` parameter value
    /// * `relay_state` - Optional URL-encoded `RelayState` parameter value
    /// * `sig_alg` - URL-encoded `SigAlg` parameter value
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
            SamlError::SignatureValidationFailed(format!("Invalid certificate: {e}"))
        })?;

        // Reconstruct the signed data (URL query string order matters!)
        let mut signed_data = format!("SAMLRequest={saml_request}");
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
            SamlError::SignatureValidationFailed(format!("Invalid signature encoding: {e}"))
        })?;

        // Determine digest algorithm from SigAlg
        let (digest, _alg_name) = match urlencoding::decode(sig_alg)
            .map_err(|e| {
                SamlError::SignatureValidationFailed(format!("Invalid SigAlg encoding: {e}"))
            })?
            .as_ref()
        {
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" => {
                (MessageDigest::sha256(), "RSA-SHA256")
            }
            "http://www.w3.org/2000/09/xmldsig#rsa-sha1" => {
                return Err(SamlError::SignatureValidationFailed(
                    "SHA-1 signature algorithm is rejected: cryptographically broken".to_string(),
                ));
            }
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384" => {
                (MessageDigest::sha384(), "RSA-SHA384")
            }
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512" => {
                (MessageDigest::sha512(), "RSA-SHA512")
            }
            alg => {
                return Err(SamlError::SignatureValidationFailed(format!(
                    "Unsupported signature algorithm: {alg}"
                )));
            }
        };

        // Verify signature
        let mut verifier = Verifier::new(digest, &public_key).map_err(|e| {
            SamlError::SignatureValidationFailed(format!("Verifier creation failed: {e}"))
        })?;

        verifier.update(signed_data.as_bytes()).map_err(|e| {
            SamlError::SignatureValidationFailed(format!("Signature update failed: {e}"))
        })?;

        let valid = verifier.verify(&signature_bytes).map_err(|e| {
            SamlError::SignatureValidationFailed(format!("Signature verification failed: {e}"))
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
    /// * `xml` - The decoded `AuthnRequest` XML
    /// * `sp_certificate_pem` - SP's X.509 certificate in PEM format
    /// * `authn_request_id` - Optional ID of the AuthnRequest to verify reference URI
    pub fn validate_post_signature(
        xml: &str,
        sp_certificate_pem: &str,
        authn_request_id: Option<&str>,
    ) -> SamlResult<()> {
        // Parse certificate
        let cert = parse_certificate(sp_certificate_pem)?;
        let public_key = cert.public_key().map_err(|e| {
            SamlError::SignatureValidationFailed(format!("Invalid certificate: {e}"))
        })?;

        // Extract signature components from XML
        let sig_info = extract_signature_info(xml)?;

        // SECURITY: Verify that the signature Reference URI points to the AuthnRequest
        // root element (or the entire document). This prevents XSW attacks where an attacker
        // signs an arbitrary sub-element while leaving the AuthnRequest fields unsigned.
        if let Some(req_id) = authn_request_id {
            let ref_uri = &sig_info.reference_uri;
            if !ref_uri.is_empty() {
                let expected_ref = format!("#{req_id}");
                if ref_uri != &expected_ref {
                    return Err(SamlError::SignatureValidationFailed(
                        "Signature reference URI does not match AuthnRequest ID".to_string(),
                    ));
                }
            }
            // Empty URI = entire document, which is acceptable
        }

        // Verify the digest first
        verify_reference_digest(xml, &sig_info)?;

        // Canonicalize SignedInfo and verify signature
        let canonicalized_signed_info = canonicalize_xml(&sig_info.signed_info)?;

        // Decode signature value
        let signature_bytes = STANDARD
            .decode(sig_info.signature_value.replace(['\n', '\r', ' '], ""))
            .map_err(|e| {
                SamlError::SignatureValidationFailed(format!("Invalid signature encoding: {e}"))
            })?;

        // Determine signature algorithm from SignedInfo's SignatureMethod
        let sig_digest = resolve_signature_digest(sig_info.signature_algorithm.as_deref())?;

        let mut verifier = Verifier::new(sig_digest, &public_key).map_err(|e| {
            SamlError::SignatureValidationFailed(format!("Verifier creation failed: {e}"))
        })?;

        verifier
            .update(canonicalized_signed_info.as_bytes())
            .map_err(|e| {
                SamlError::SignatureValidationFailed(format!("Signature update failed: {e}"))
            })?;

        let valid = verifier.verify(&signature_bytes).map_err(|e| {
            SamlError::SignatureValidationFailed(format!("Signature verification failed: {e}"))
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
    /// SignatureMethod Algorithm URI from SignedInfo
    signature_algorithm: Option<String>,
    /// DigestMethod Algorithm URI from SignedInfo
    digest_algorithm: Option<String>,
}

/// Parse X.509 certificate from PEM format and validate it is not expired.
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

    let cert = X509::from_pem(pem_data.as_bytes())
        .map_err(|e| SamlError::SignatureValidationFailed(format!("Invalid certificate: {e}")))?;

    // SECURITY: Reject expired certificates. Accepting expired certs could allow
    // using compromised keys after the CA has rotated them.
    let now = openssl::asn1::Asn1Time::days_from_now(0)
        .map_err(|e| SamlError::SignatureValidationFailed(format!("Time error: {e}")))?;

    if cert.not_after() < now {
        return Err(SamlError::SignatureValidationFailed(
            "SP certificate has expired".to_string(),
        ));
    }

    // Also check not-yet-valid certificates
    if cert.not_before() > now {
        return Err(SamlError::SignatureValidationFailed(
            "SP certificate is not yet valid".to_string(),
        ));
    }

    Ok(cert)
}

/// Resolve the MessageDigest from a SignatureMethod Algorithm URI.
/// Rejects SHA-1 as cryptographically broken.
fn resolve_signature_digest(algorithm_uri: Option<&str>) -> SamlResult<MessageDigest> {
    match algorithm_uri {
        Some("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
        | Some("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256-mgf1")
        | None => Ok(MessageDigest::sha256()), // default to SHA-256 when unspecified
        Some("http://www.w3.org/2001/04/xmldsig-more#rsa-sha384") => Ok(MessageDigest::sha384()),
        Some("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512") => Ok(MessageDigest::sha512()),
        Some("http://www.w3.org/2000/09/xmldsig#rsa-sha1") => {
            Err(SamlError::SignatureValidationFailed(
                "SHA-1 signature algorithm is rejected: cryptographically broken".to_string(),
            ))
        }
        Some(other) => Err(SamlError::SignatureValidationFailed(format!(
            "Unsupported signature algorithm: {other}"
        ))),
    }
}

/// Resolve the MessageDigest from a DigestMethod Algorithm URI.
fn resolve_digest_method(algorithm_uri: Option<&str>) -> SamlResult<MessageDigest> {
    match algorithm_uri {
        Some("http://www.w3.org/2001/04/xmlenc#sha256") | None => Ok(MessageDigest::sha256()),
        Some("http://www.w3.org/2001/04/xmldsig-more#sha384") => Ok(MessageDigest::sha384()),
        Some("http://www.w3.org/2001/04/xmlenc#sha512") => Ok(MessageDigest::sha512()),
        Some("http://www.w3.org/2000/09/xmldsig#sha1") => {
            Err(SamlError::SignatureValidationFailed(
                "SHA-1 digest algorithm is rejected: cryptographically broken".to_string(),
            ))
        }
        Some(other) => Err(SamlError::SignatureValidationFailed(format!(
            "Unsupported digest algorithm: {other}"
        ))),
    }
}

/// Apply Exclusive XML Canonicalization (C14N)
fn canonicalize_xml(xml: &str) -> SamlResult<String> {
    let mut output = Vec::new();
    Canonicalizer::read_from_str(xml)
        .write_to_writer(&mut output)
        .canonicalize(false) // Exclusive C14N without comments
        .map_err(|e| {
            SamlError::SignatureValidationFailed(format!("Canonicalization failed: {e}"))
        })?;

    String::from_utf8(output)
        .map_err(|e| SamlError::SignatureValidationFailed(format!("Invalid UTF-8: {e}")))
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
    let mut signature_algorithm: Option<String> = None;
    let mut digest_algorithm: Option<String> = None;

    // Track namespace declarations from ancestor elements so they can be injected
    // into the extracted SignedInfo fragment. Without this, SignedInfo elements that
    // use prefixes declared on ancestors (e.g., `ds:` declared on `<Signature>`)
    // produce different C14N output than the signer computed.
    let mut ancestor_namespaces: Vec<(String, String)> = Vec::new(); // (prefix, uri)

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let local_name = e.local_name();
                let name = std::str::from_utf8(local_name.as_ref()).unwrap_or("");

                if name == "SignedInfo" {
                    in_signed_info = true;
                    // Capture the start tag, injecting any missing ancestor xmlns decls
                    let full_tag = std::str::from_utf8(&e).unwrap_or("");
                    signed_info_content.push('<');
                    signed_info_content.push_str(full_tag);
                    // Inject ancestor namespace declarations not already on SignedInfo
                    for (prefix, uri) in &ancestor_namespaces {
                        let decl = format!("xmlns:{prefix}");
                        if !full_tag.contains(&decl) {
                            signed_info_content.push_str(&format!(" xmlns:{prefix}=\"{uri}\""));
                        }
                    }
                    signed_info_content.push('>');
                } else if in_signed_info {
                    let full_tag = std::str::from_utf8(&e).unwrap_or("");
                    signed_info_content.push('<');
                    signed_info_content.push_str(full_tag);
                    signed_info_content.push('>');
                } else {
                    // Collect xmlns:* declarations from ancestor elements
                    for attr in e.attributes().flatten() {
                        let key = std::str::from_utf8(attr.key.as_ref()).unwrap_or("");
                        if let Some(prefix) = key.strip_prefix("xmlns:") {
                            let value = attr.unescape_value().unwrap_or_default().to_string();
                            // Keep only the latest declaration per prefix
                            ancestor_namespaces.retain(|(p, _)| p != prefix);
                            ancestor_namespaces.push((prefix.to_string(), value));
                        }
                    }
                }

                if name == "SignatureValue" {
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

                    // Capture SignatureMethod and DigestMethod Algorithm attributes
                    let local_name_owned = e.local_name();
                    let local = std::str::from_utf8(local_name_owned.as_ref()).unwrap_or("");
                    if local == "SignatureMethod" {
                        for attr in e.attributes().flatten() {
                            let key = std::str::from_utf8(attr.key.as_ref()).unwrap_or("");
                            if key == "Algorithm" {
                                signature_algorithm =
                                    Some(attr.unescape_value().unwrap_or_default().to_string());
                            }
                        }
                    } else if local == "DigestMethod" {
                        for attr in e.attributes().flatten() {
                            let key = std::str::from_utf8(attr.key.as_ref()).unwrap_or("");
                            if key == "Algorithm" {
                                digest_algorithm =
                                    Some(attr.unescape_value().unwrap_or_default().to_string());
                            }
                        }
                    }
                }
            }
            Ok(Event::End(e)) => {
                let local_name = e.local_name();
                let local = std::str::from_utf8(local_name.as_ref()).unwrap_or("");
                // Use the full qualified name (preserving namespace prefix) for correct C14N
                let name_ref = e.name();
                let full_name = std::str::from_utf8(name_ref.as_ref()).unwrap_or(local);

                if local == "SignedInfo" && in_signed_info {
                    signed_info_content.push_str("</");
                    signed_info_content.push_str(full_name);
                    signed_info_content.push('>');
                    in_signed_info = false;
                } else if in_signed_info {
                    signed_info_content.push_str("</");
                    signed_info_content.push_str(full_name);
                    signed_info_content.push('>');
                } else if local == "SignatureValue" {
                    in_signature_value = false;
                } else if local == "DigestValue" {
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
                    "XML parse error: {e}"
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
        signature_algorithm,
        digest_algorithm,
    })
}

/// Verify the reference digest matches the actual content.
///
/// Uses proper XML parsing to find the referenced element by ID attribute,
/// preventing XML Signature Wrapping (XSW) attacks that exploit string-based
/// element boundary detection.
fn verify_reference_digest(xml: &str, sig_info: &SignatureInfo) -> SamlResult<()> {
    // Find the referenced element (remove # prefix from URI)
    let element_id = sig_info.reference_uri.trim_start_matches('#');
    if element_id.is_empty() {
        // Empty URI means the whole document
        return verify_document_digest(xml, sig_info);
    }

    // Use XML parser to find the referenced element by ID and extract it safely.
    // This prevents XSW attacks where duplicate IDs or injected closing tags
    // could trick string-based boundary detection.
    let element_content = extract_element_by_id(xml, element_id)?;

    // Remove the Signature element from the content (enveloped signature transform)
    let content_without_sig = remove_signature_element_parsed(&element_content)?;

    // Canonicalize and compute digest using the specified algorithm
    let digest_md = resolve_digest_method(sig_info.digest_algorithm.as_deref())?;
    let canonicalized = canonicalize_xml(&content_without_sig)?;
    let digest = openssl::hash::hash(digest_md, canonicalized.as_bytes())
        .map_err(|e| SamlError::SignatureValidationFailed(format!("Hash failed: {e}")))?;
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
    // Remove the Signature element using parser-based approach
    let content_without_sig = remove_signature_element_parsed(xml)?;

    // Canonicalize and compute digest using the specified algorithm
    let digest_md = resolve_digest_method(sig_info.digest_algorithm.as_deref())?;
    let canonicalized = canonicalize_xml(&content_without_sig)?;
    let digest = openssl::hash::hash(digest_md, canonicalized.as_bytes())
        .map_err(|e| SamlError::SignatureValidationFailed(format!("Hash failed: {e}")))?;
    let computed_digest = STANDARD.encode(digest);

    let expected_digest = sig_info.digest_value.replace(['\n', '\r', ' '], "");
    if computed_digest != expected_digest {
        return Err(SamlError::SignatureValidationFailed(
            "Digest mismatch".to_string(),
        ));
    }

    Ok(())
}

/// Extract an element and all its children by ID attribute using XML parsing.
///
/// This uses quick-xml to properly track nesting depth, preventing XSW attacks
/// where injected duplicate closing tags could truncate the element early.
fn extract_element_by_id(xml: &str, element_id: &str) -> SamlResult<String> {
    use quick_xml::events::Event;
    use quick_xml::Reader;

    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);

    let mut depth: u32 = 0;
    let mut capturing = false;
    let mut result = String::new();
    let mut capture_start_offset: Option<usize> = None;

    loop {
        let event_offset = reader.buffer_position() as usize;
        match reader.read_event() {
            Ok(Event::Start(ref e)) => {
                if !capturing {
                    for attr in e.attributes().flatten() {
                        let key = std::str::from_utf8(attr.key.as_ref()).unwrap_or("");
                        // SECURITY: Use case-sensitive "ID" match per SAML 2.0 spec (XML ID type).
                        // Case-insensitive matching would find non-SAML elements with lowercase
                        // "id" attributes, enabling an XSW variant attack.
                        if key == "ID" {
                            let val = attr.unescape_value().unwrap_or_default();
                            if val.as_ref() == element_id {
                                capturing = true;
                                depth = 1;
                                capture_start_offset = Some(event_offset);
                                break;
                            }
                        }
                    }
                } else {
                    depth += 1;
                }
            }
            Ok(Event::End(_)) => {
                if capturing {
                    depth -= 1;
                    if depth == 0 {
                        let end_offset = reader.buffer_position() as usize;
                        if let Some(start) = capture_start_offset {
                            // SECURITY: Use .get() to prevent panic on non-ASCII UTF-8 boundary misalignment.
                            result = xml
                                .get(start..end_offset)
                                .ok_or_else(|| {
                                    SamlError::SignatureValidationFailed(
                                        "XML byte offset misaligned with UTF-8 character boundary"
                                            .to_string(),
                                    )
                                })?
                                .to_string();
                        }
                        return Ok(result);
                    }
                }
            }
            Ok(Event::Empty(ref e)) => {
                if !capturing {
                    for attr in e.attributes().flatten() {
                        let key = std::str::from_utf8(attr.key.as_ref()).unwrap_or("");
                        if key == "ID" {
                            let val = attr.unescape_value().unwrap_or_default();
                            if val.as_ref() == element_id {
                                let end_offset = reader.buffer_position() as usize;
                                return Ok(xml.get(event_offset..end_offset)
                                    .ok_or_else(|| SamlError::SignatureValidationFailed(
                                        "XML byte offset misaligned with UTF-8 character boundary".to_string(),
                                    ))?
                                    .to_string());
                            }
                        }
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(SamlError::SignatureValidationFailed(format!(
                    "XML parse error: {e}"
                )));
            }
            _ => {}
        }
    }

    Err(SamlError::SignatureValidationFailed(format!(
        "Referenced element not found: {element_id}"
    )))
}

/// Remove ALL Signature elements from XML using proper XML parsing.
///
/// This prevents XSW attacks by:
/// 1. Correctly tracking nesting depth to find the true end of each Signature element
/// 2. Removing ALL Signature elements (not just the first one found)
/// 3. Handling both `ds:Signature` and unprefixed `Signature` elements
fn remove_signature_element_parsed(xml: &str) -> SamlResult<String> {
    use quick_xml::events::Event;
    use quick_xml::Reader;

    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);

    let mut sig_ranges: Vec<(usize, usize)> = Vec::new();
    let mut sig_depth: u32 = 0;
    let mut sig_start_offset: Option<usize> = None;

    loop {
        let event_offset = reader.buffer_position() as usize;
        match reader.read_event() {
            Ok(Event::Start(ref e)) => {
                let local_name = e.local_name();
                let name = std::str::from_utf8(local_name.as_ref()).unwrap_or("");
                if name == "Signature" && sig_depth == 0 {
                    sig_depth = 1;
                    sig_start_offset = Some(event_offset);
                } else if sig_depth > 0 {
                    sig_depth += 1;
                }
            }
            Ok(Event::End(_)) => {
                if sig_depth > 0 {
                    sig_depth -= 1;
                    if sig_depth == 0 {
                        let end_offset = reader.buffer_position() as usize;
                        if let Some(start) = sig_start_offset.take() {
                            sig_ranges.push((start, end_offset));
                        }
                    }
                }
            }
            Ok(Event::Empty(ref e)) => {
                let local_name = e.local_name();
                let name = std::str::from_utf8(local_name.as_ref()).unwrap_or("");
                if name == "Signature" && sig_depth == 0 {
                    let end_offset = reader.buffer_position() as usize;
                    sig_ranges.push((event_offset, end_offset));
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(SamlError::SignatureValidationFailed(format!(
                    "XML parse error during signature removal: {e}"
                )));
            }
            _ => {}
        }
    }

    // Reconstruct XML without any Signature elements
    let mut result = String::with_capacity(xml.len());
    let mut last_end = 0;
    for (start, end) in &sig_ranges {
        result.push_str(&xml[last_end..*start]);
        last_end = *end;
    }
    result.push_str(&xml[last_end..]);

    Ok(result)
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
    fn test_remove_signature_element_parsed() {
        let xml = r#"<AuthnRequest ID="test"><ds:Signature>...</ds:Signature><Issuer>test</Issuer></AuthnRequest>"#;
        let result = remove_signature_element_parsed(xml).unwrap();
        assert!(!result.contains("Signature"));
        assert!(result.contains("Issuer"));
    }

    #[test]
    fn test_remove_signature_element_no_prefix() {
        let xml = r#"<AuthnRequest ID="test"><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo/></Signature><Issuer>test</Issuer></AuthnRequest>"#;
        let result = remove_signature_element_parsed(xml).unwrap();
        assert!(!result.contains("Signature"));
        assert!(result.contains("Issuer"));
    }

    #[test]
    fn test_remove_multiple_signature_elements_xsw() {
        // XSW attack: multiple Signature elements — all must be removed
        let xml = r#"<AuthnRequest ID="test"><ds:Signature>legit</ds:Signature><ds:Signature>injected</ds:Signature><Issuer>test</Issuer></AuthnRequest>"#;
        let result = remove_signature_element_parsed(xml).unwrap();
        assert!(
            !result.contains("Signature"),
            "All Signature elements must be removed"
        );
        assert!(result.contains("Issuer"));
    }

    #[test]
    fn test_extract_element_by_id() {
        let xml = r#"<Root><AuthnRequest ID="req123" xmlns="urn:oasis:names:tc:SAML:2.0:protocol"><Issuer>test</Issuer></AuthnRequest></Root>"#;
        let result = extract_element_by_id(xml, "req123").unwrap();
        assert!(result.contains("AuthnRequest"));
        assert!(result.contains("Issuer"));
        assert!(result.contains("req123"));
    }

    #[test]
    fn test_extract_element_by_id_not_found() {
        let xml = r#"<AuthnRequest ID="req123"><Issuer>test</Issuer></AuthnRequest>"#;
        let result = extract_element_by_id(xml, "nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn test_xsw_nested_closing_tags() {
        // Ensure nested elements with same tag name don't confuse depth tracking
        let xml = r##"<AuthnRequest ID="req1"><ds:Signature><ds:SignedInfo><ds:Reference URI="#req1"><ds:Transforms/></ds:Reference></ds:SignedInfo></ds:Signature></AuthnRequest>"##;
        let result = remove_signature_element_parsed(xml).unwrap();
        assert!(!result.contains("Signature"));
        assert!(result.contains("AuthnRequest"));
    }

    #[test]
    fn test_reject_sha1_redirect_signature() {
        // SHA-1 should be rejected as cryptographically broken.
        // Use a valid base64 value since signature decoding happens before algorithm check.
        let dummy_sig = STANDARD.encode(b"dummy signature bytes for testing");
        let result = SignatureValidator::validate_redirect_signature(
            "dummyRequest",
            None,
            "http%3A%2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23rsa-sha1",
            &dummy_sig,
            TEST_CERT_PEM,
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("SHA-1"),
            "Error should mention SHA-1: {err}"
        );
    }
}
