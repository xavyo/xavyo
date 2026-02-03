//! Common test utilities for SP interoperability tests
//!
//! Provides SP profile builders, test user fixtures, XML validation helpers,
//! and mock signing credentials.

use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{DateTime, Duration, Utc};
use quick_xml::events::Event;
use quick_xml::Reader;
use std::collections::HashMap;
use uuid::Uuid;

// ============================================================================
// SP Profile Builders
// ============================================================================

/// Standard test user for most SP tests
#[derive(Debug, Clone)]
pub struct StandardTestUser {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub email: String,
    pub username: String,
    pub first_name: String,
    pub last_name: String,
    pub display_name: String,
    pub federation_id: String,
    pub employee_id: String,
    pub groups: Vec<String>,
}

impl Default for StandardTestUser {
    fn default() -> Self {
        Self {
            id: Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            tenant_id: Uuid::parse_str("660e8400-e29b-41d4-a716-446655440001").unwrap(),
            email: "john.doe@example.com".to_string(),
            username: "john.doe".to_string(),
            first_name: "John".to_string(),
            last_name: "Doe".to_string(),
            display_name: "John Doe".to_string(),
            federation_id: "jdoe-12345".to_string(),
            employee_id: "EMP001".to_string(),
            groups: vec![
                "Engineering".to_string(),
                "VPN-Users".to_string(),
                "SSO-Admins".to_string(),
            ],
        }
    }
}

/// AWS-specific test user with role assignments
#[derive(Debug, Clone)]
pub struct AwsRoleTestUser {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub email: String,
    pub username: String,
    pub aws_roles: Vec<String>,
    pub session_duration: i32,
}

impl Default for AwsRoleTestUser {
    fn default() -> Self {
        Self {
            id: Uuid::parse_str("770e8400-e29b-41d4-a716-446655440002").unwrap(),
            tenant_id: Uuid::parse_str("660e8400-e29b-41d4-a716-446655440001").unwrap(),
            email: "cloud.admin@example.com".to_string(),
            username: "cloud.admin".to_string(),
            aws_roles: vec![
                "arn:aws:iam::123456789012:role/AdminRole,arn:aws:iam::123456789012:saml-provider/ExampleIdP".to_string(),
                "arn:aws:iam::123456789012:role/ReadOnlyRole,arn:aws:iam::123456789012:saml-provider/ExampleIdP".to_string(),
            ],
            session_duration: 3600,
        }
    }
}

/// SP Profile configuration for testing
#[derive(Debug, Clone)]
pub struct SpProfile {
    pub name: String,
    pub entity_id: String,
    pub acs_url: String,
    pub name_id_format: String,
    pub attributes: Vec<AttributeMapping>,
    pub sign_assertions: bool,
    pub assertion_validity_seconds: i32,
    pub group_attribute_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AttributeMapping {
    pub source: String,
    pub target_name: String,
    pub format: Option<String>,
    pub multi_value: bool,
}

impl SpProfile {
    /// Create a Salesforce SP profile
    pub fn salesforce() -> Self {
        Self {
            name: "Salesforce".to_string(),
            entity_id: "https://company.my.salesforce.com".to_string(),
            acs_url: "https://company.my.salesforce.com/saml/acs".to_string(),
            name_id_format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress".to_string(),
            attributes: vec![
                AttributeMapping {
                    source: "federation_id".to_string(),
                    target_name: "User.FederationIdentifier".to_string(),
                    format: Some("urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified".to_string()),
                    multi_value: false,
                },
                AttributeMapping {
                    source: "email".to_string(),
                    target_name: "User.Email".to_string(),
                    format: Some("urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified".to_string()),
                    multi_value: false,
                },
            ],
            sign_assertions: true,
            assertion_validity_seconds: 300,
            group_attribute_name: None,
        }
    }

    /// Create a ServiceNow SP profile
    pub fn servicenow() -> Self {
        Self {
            name: "ServiceNow".to_string(),
            entity_id: "https://company.service-now.com".to_string(),
            acs_url: "https://company.service-now.com/navpage.do".to_string(),
            name_id_format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress".to_string(),
            attributes: vec![
                AttributeMapping {
                    source: "username".to_string(),
                    target_name: "user_name".to_string(),
                    format: None,
                    multi_value: false,
                },
                AttributeMapping {
                    source: "email".to_string(),
                    target_name: "user_email".to_string(),
                    format: None,
                    multi_value: false,
                },
                AttributeMapping {
                    source: "first_name".to_string(),
                    target_name: "user_first_name".to_string(),
                    format: None,
                    multi_value: false,
                },
                AttributeMapping {
                    source: "last_name".to_string(),
                    target_name: "user_last_name".to_string(),
                    format: None,
                    multi_value: false,
                },
            ],
            sign_assertions: true,
            assertion_validity_seconds: 300,
            group_attribute_name: Some("Roles".to_string()),
        }
    }

    /// Create a Workday SP profile
    pub fn workday() -> Self {
        Self {
            name: "Workday".to_string(),
            entity_id: "https://wd3-impl-services1.workday.com/tenant-name".to_string(),
            acs_url: "https://wd3-impl-services1.workday.com/saml/Receiver".to_string(),
            name_id_format: "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified".to_string(),
            attributes: vec![AttributeMapping {
                source: "employee_id".to_string(),
                target_name: "WorkdayID".to_string(),
                format: None,
                multi_value: false,
            }],
            sign_assertions: true, // Required for Workday
            assertion_validity_seconds: 300,
            group_attribute_name: None,
        }
    }

    /// Create an AWS SSO SP profile
    pub fn aws_sso() -> Self {
        Self {
            name: "AWS SSO".to_string(),
            entity_id: "urn:amazon:webservices".to_string(),
            acs_url: "https://signin.aws.amazon.com/saml".to_string(),
            name_id_format: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent".to_string(),
            attributes: vec![
                AttributeMapping {
                    source: "aws_roles".to_string(),
                    target_name: "https://aws.amazon.com/SAML/Attributes/Role".to_string(),
                    format: Some("urn:oasis:names:tc:SAML:2.0:attrname-format:uri".to_string()),
                    multi_value: true,
                },
                AttributeMapping {
                    source: "username".to_string(),
                    target_name: "https://aws.amazon.com/SAML/Attributes/RoleSessionName".to_string(),
                    format: Some("urn:oasis:names:tc:SAML:2.0:attrname-format:uri".to_string()),
                    multi_value: false,
                },
                AttributeMapping {
                    source: "session_duration".to_string(),
                    target_name: "https://aws.amazon.com/SAML/Attributes/SessionDuration".to_string(),
                    format: Some("urn:oasis:names:tc:SAML:2.0:attrname-format:uri".to_string()),
                    multi_value: false,
                },
            ],
            sign_assertions: true,
            assertion_validity_seconds: 900,
            group_attribute_name: None,
        }
    }
}

// ============================================================================
// Mock Signing Credentials
// ============================================================================

/// Generate mock signing credentials for testing
/// Returns a tuple of (certificate_pem, private_key_pem)
pub fn mock_signing_credentials() -> (String, String) {
    // Use pre-generated test certificates (self-signed, for testing only)
    // These are NOT real certificates and should never be used in production
    let cert = r#"-----BEGIN CERTIFICATE-----
MIICpDCCAYwCCQDU+pQ4P5aDgTANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls
b2NhbGhvc3QwHhcNMjQwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjAUMRIwEAYD
VQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7
o5e7gReJwANHxPQgFdYGPhSTlK8cA4BzVmFQr6KwdJ5bJqR0TxCY7VYpJoqJyFy1
yMYrFU4hXzLZJFgWJCmzaLSQ7OYEJl2Lx5mCXQ3jU5z0cCRkfJL8KxDAU8oC8xBx
YPZLrJ4J8CrB0lRIqSEr1jWlKJoLqjJKNYwT5zJZJrJ5xLJvJHJOJrJ9JqJFJjJ3
JlJCJiJ7JpJGJgJ1JoJEJdJzJnJBJcJyJmJAJbJxJkJ9JaJwJjJ8J0J6J2J4JqJF
JjJ3JlJCJiJ7JpJGJgJ1JoJEJdJzJnJBJcJyJmJAJbJxJkJ9JaJwJjJ8J0J6J2J4
JqJFAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAKxC9m5k7lLLW5+M7TKlZbBhJ5ye
QaLqJM7n6zK7HqL7GkJ6xE4vN6lJ8x0n7hQd8cCuVkp7lL9o8F7t2YsD5e0yqT4Q
-----END CERTIFICATE-----"#;

    let key = r#"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7o5e7gReJwANH
xPQgFdYGPhSTlK8cA4BzVmFQr6KwdJ5bJqR0TxCY7VYpJoqJyFy1yMYrFU4hXzLZ
JFgWJCmzaLSQ7OYEJl2Lx5mCXQ3jU5z0cCRkfJL8KxDAU8oC8xBxYPZLrJ4J8CrB
0lRIqSEr1jWlKJoLqjJKNYwT5zJZJrJ5xLJvJHJOJrJ9JqJFJjJ3JlJCJiJ7JpJG
JgJ1JoJEJdJzJnJBJcJyJmJAJbJxJkJ9JaJwJjJ8J0J6J2J4JqJFJjJ3JlJCJiJ7
JpJGJgJ1JoJEJdJzJnJBJcJyJmJAJbJxJkJ9JaJwJjJ8J0J6J2J4JqJFAgMBAAEC
ggEAYZ1wD8dKJ8nLK7J9xL5J7J6J5J4J3J2J1J0JzJyJxJwJvJuJtJsJrJqJpJoJn
-----END PRIVATE KEY-----"#;

    (cert.to_string(), key.to_string())
}

// ============================================================================
// XML Assertion Validation Helpers
// ============================================================================

/// Parsed SAML assertion for validation
#[derive(Debug, Default)]
pub struct ParsedAssertion {
    pub response_id: Option<String>,
    pub assertion_id: Option<String>,
    pub issuer: Option<String>,
    pub destination: Option<String>,
    pub issue_instant: Option<String>,
    pub in_response_to: Option<String>,
    pub name_id: Option<String>,
    pub name_id_format: Option<String>,
    pub not_before: Option<String>,
    pub not_on_or_after: Option<String>,
    pub audience: Option<String>,
    pub session_index: Option<String>,
    pub authn_context_class_ref: Option<String>,
    pub attributes: HashMap<String, Vec<String>>,
    pub has_signature: bool,
    pub signature_algorithm: Option<String>,
    pub digest_algorithm: Option<String>,
    pub canonicalization_method: Option<String>,
}

/// Decode and parse a base64-encoded SAML response
pub fn parse_saml_response(base64_response: &str) -> Result<ParsedAssertion, String> {
    let decoded = STANDARD
        .decode(base64_response)
        .map_err(|e| format!("Base64 decode error: {}", e))?;

    let xml = String::from_utf8(decoded).map_err(|e| format!("UTF-8 decode error: {}", e))?;

    parse_saml_xml(&xml)
}

/// Parse SAML XML directly
pub fn parse_saml_xml(xml: &str) -> Result<ParsedAssertion, String> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut parsed = ParsedAssertion::default();
    let mut current_element = String::new();
    let mut current_attribute_name: Option<String> = None;
    let mut in_attribute_value = false;

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                let name = String::from_utf8_lossy(e.local_name().as_ref()).to_string();
                current_element = name.clone();

                match name.as_str() {
                    "Response" => {
                        for attr in e.attributes().flatten() {
                            let local_name = attr.key.local_name();
                            let key = String::from_utf8_lossy(local_name.as_ref()).to_string();
                            let value = String::from_utf8_lossy(&attr.value).to_string();
                            match key.as_str() {
                                "ID" => parsed.response_id = Some(value),
                                "Destination" => parsed.destination = Some(value),
                                "IssueInstant" => parsed.issue_instant = Some(value),
                                "InResponseTo" => parsed.in_response_to = Some(value),
                                _ => {}
                            }
                        }
                    }
                    "Assertion" => {
                        for attr in e.attributes().flatten() {
                            let local_name = attr.key.local_name();
                            let key = String::from_utf8_lossy(local_name.as_ref()).to_string();
                            let value = String::from_utf8_lossy(&attr.value).to_string();
                            if key == "ID" {
                                parsed.assertion_id = Some(value);
                            }
                        }
                    }
                    "NameID" => {
                        for attr in e.attributes().flatten() {
                            let local_name = attr.key.local_name();
                            let key = String::from_utf8_lossy(local_name.as_ref()).to_string();
                            let value = String::from_utf8_lossy(&attr.value).to_string();
                            if key == "Format" {
                                parsed.name_id_format = Some(value);
                            }
                        }
                    }
                    "Conditions" => {
                        for attr in e.attributes().flatten() {
                            let local_name = attr.key.local_name();
                            let key = String::from_utf8_lossy(local_name.as_ref()).to_string();
                            let value = String::from_utf8_lossy(&attr.value).to_string();
                            match key.as_str() {
                                "NotBefore" => parsed.not_before = Some(value),
                                "NotOnOrAfter" => parsed.not_on_or_after = Some(value),
                                _ => {}
                            }
                        }
                    }
                    "AuthnStatement" => {
                        for attr in e.attributes().flatten() {
                            let local_name = attr.key.local_name();
                            let key = String::from_utf8_lossy(local_name.as_ref()).to_string();
                            let value = String::from_utf8_lossy(&attr.value).to_string();
                            if key == "SessionIndex" {
                                parsed.session_index = Some(value);
                            }
                        }
                    }
                    "Attribute" => {
                        for attr in e.attributes().flatten() {
                            let local_name = attr.key.local_name();
                            let key = String::from_utf8_lossy(local_name.as_ref()).to_string();
                            let value = String::from_utf8_lossy(&attr.value).to_string();
                            if key == "Name" {
                                current_attribute_name = Some(value);
                            }
                        }
                    }
                    "AttributeValue" => {
                        in_attribute_value = true;
                    }
                    "Signature" => {
                        parsed.has_signature = true;
                    }
                    "SignatureMethod" => {
                        for attr in e.attributes().flatten() {
                            let local_name = attr.key.local_name();
                            let key = String::from_utf8_lossy(local_name.as_ref()).to_string();
                            let value = String::from_utf8_lossy(&attr.value).to_string();
                            if key == "Algorithm" {
                                parsed.signature_algorithm = Some(value);
                            }
                        }
                    }
                    "DigestMethod" => {
                        for attr in e.attributes().flatten() {
                            let local_name = attr.key.local_name();
                            let key = String::from_utf8_lossy(local_name.as_ref()).to_string();
                            let value = String::from_utf8_lossy(&attr.value).to_string();
                            if key == "Algorithm" {
                                parsed.digest_algorithm = Some(value);
                            }
                        }
                    }
                    "CanonicalizationMethod" => {
                        for attr in e.attributes().flatten() {
                            let local_name = attr.key.local_name();
                            let key = String::from_utf8_lossy(local_name.as_ref()).to_string();
                            let value = String::from_utf8_lossy(&attr.value).to_string();
                            if key == "Algorithm" {
                                parsed.canonicalization_method = Some(value);
                            }
                        }
                    }
                    _ => {}
                }
            }
            Ok(Event::Text(e)) => {
                let text = e.unescape().unwrap_or_default().to_string();
                match current_element.as_str() {
                    "Issuer" => {
                        if parsed.issuer.is_none() {
                            parsed.issuer = Some(text);
                        }
                    }
                    "NameID" => {
                        parsed.name_id = Some(text);
                    }
                    "Audience" => {
                        parsed.audience = Some(text);
                    }
                    "AuthnContextClassRef" => {
                        parsed.authn_context_class_ref = Some(text);
                    }
                    "AttributeValue" => {
                        if in_attribute_value {
                            if let Some(ref attr_name) = current_attribute_name {
                                parsed
                                    .attributes
                                    .entry(attr_name.clone())
                                    .or_default()
                                    .push(text);
                            }
                        }
                    }
                    _ => {}
                }
            }
            Ok(Event::End(e)) => {
                let name = String::from_utf8_lossy(e.local_name().as_ref()).to_string();
                if name == "AttributeValue" {
                    in_attribute_value = false;
                }
                if name == "Attribute" {
                    current_attribute_name = None;
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(format!("XML parse error: {}", e)),
            _ => {}
        }
    }

    Ok(parsed)
}

/// Validate that an assertion has all required elements for a given SP
pub fn validate_assertion_structure(
    assertion: &ParsedAssertion,
    sp: &SpProfile,
) -> Vec<String> {
    let mut errors = Vec::new();

    // Required elements
    if assertion.response_id.is_none() {
        errors.push("Missing Response ID".to_string());
    }
    if assertion.assertion_id.is_none() {
        errors.push("Missing Assertion ID".to_string());
    }
    if assertion.issuer.is_none() {
        errors.push("Missing Issuer".to_string());
    }
    if assertion.name_id.is_none() {
        errors.push("Missing NameID".to_string());
    }
    if assertion.not_before.is_none() {
        errors.push("Missing NotBefore".to_string());
    }
    if assertion.not_on_or_after.is_none() {
        errors.push("Missing NotOnOrAfter".to_string());
    }
    if assertion.audience.is_none() {
        errors.push("Missing Audience".to_string());
    }

    // SP-specific validation
    if sp.sign_assertions && !assertion.has_signature {
        errors.push(format!("{} requires signed assertions", sp.name));
    }

    // Validate Audience matches SP entity_id
    if let Some(ref audience) = assertion.audience {
        if audience != &sp.entity_id {
            errors.push(format!(
                "Audience '{}' does not match SP entity ID '{}'",
                audience, sp.entity_id
            ));
        }
    }

    errors
}

/// Extract attribute values by name
pub fn get_attribute_values(assertion: &ParsedAssertion, name: &str) -> Option<Vec<String>> {
    assertion.attributes.get(name).cloned()
}

/// Validate NameID format matches expected format
pub fn validate_nameid_format(assertion: &ParsedAssertion, expected_format: &str) -> bool {
    assertion
        .name_id_format
        .as_ref()
        .map(|f| f == expected_format)
        .unwrap_or(false)
}

/// Validate assertion timing is within acceptable window
pub fn validate_assertion_timing(
    assertion: &ParsedAssertion,
    max_validity_seconds: i64,
) -> Result<(), String> {
    let not_before = assertion
        .not_before
        .as_ref()
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc))
        .ok_or("Invalid NotBefore timestamp")?;

    let not_on_or_after = assertion
        .not_on_or_after
        .as_ref()
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc))
        .ok_or("Invalid NotOnOrAfter timestamp")?;

    let validity_duration = not_on_or_after - not_before;
    if validity_duration > Duration::seconds(max_validity_seconds) {
        return Err(format!(
            "Assertion validity window ({} seconds) exceeds maximum ({} seconds)",
            validity_duration.num_seconds(),
            max_validity_seconds
        ));
    }

    Ok(())
}

/// Validate signature algorithm is RSA-SHA256
pub fn validate_signature_algorithm(assertion: &ParsedAssertion) -> bool {
    assertion
        .signature_algorithm
        .as_ref()
        .map(|a| a == "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
        .unwrap_or(false)
}

/// Validate canonicalization method is Exclusive C14N
pub fn validate_canonicalization_method(assertion: &ParsedAssertion) -> bool {
    assertion
        .canonicalization_method
        .as_ref()
        .map(|m| m == "http://www.w3.org/2001/10/xml-exc-c14n#")
        .unwrap_or(false)
}

// ============================================================================
// Test Assertion Builder (for generating test assertions)
// ============================================================================

/// Build a test SAML response XML for validation testing
pub fn build_test_response(
    sp: &SpProfile,
    user: &StandardTestUser,
    in_response_to: Option<&str>,
) -> String {
    let response_id = format!("_resp_{}", Uuid::new_v4());
    let assertion_id = format!("_assert_{}", Uuid::new_v4());
    let now = Utc::now();
    let issue_instant = now.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let not_before = (now - Duration::minutes(2))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
    let not_on_or_after = (now + Duration::seconds(sp.assertion_validity_seconds as i64))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();

    let in_response_to_attr = in_response_to
        .map(|id| format!(" InResponseTo=\"{}\"", id))
        .unwrap_or_default();

    let name_id_value = if sp.name_id_format.contains("emailAddress") {
        &user.email
    } else if sp.name_id_format.contains("persistent") {
        &user.id.to_string()
    } else {
        &user.employee_id
    };

    // Build attributes
    let mut attrs_xml = String::new();
    for mapping in &sp.attributes {
        let values = match mapping.source.as_str() {
            "email" => vec![user.email.clone()],
            "username" => vec![user.username.clone()],
            "first_name" => vec![user.first_name.clone()],
            "last_name" => vec![user.last_name.clone()],
            "federation_id" => vec![user.federation_id.clone()],
            "employee_id" => vec![user.employee_id.clone()],
            _ => vec![],
        };

        if !values.is_empty() {
            attrs_xml.push_str(&format!(
                r#"            <saml:Attribute Name="{}"{}>"#,
                mapping.target_name,
                mapping
                    .format
                    .as_ref()
                    .map(|f| format!(r#" NameFormat="{}""#, f))
                    .unwrap_or_default()
            ));
            attrs_xml.push('\n');
            for value in values {
                attrs_xml.push_str(&format!(
                    r#"                <saml:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">{}</saml:AttributeValue>"#,
                    value
                ));
                attrs_xml.push('\n');
            }
            attrs_xml.push_str("            </saml:Attribute>\n");
        }
    }

    // Add groups if configured
    if let Some(ref group_attr) = sp.group_attribute_name {
        if !user.groups.is_empty() {
            attrs_xml.push_str(&format!(
                r#"            <saml:Attribute Name="{}">"#,
                group_attr
            ));
            attrs_xml.push('\n');
            for group in &user.groups {
                attrs_xml.push_str(&format!(
                    r#"                <saml:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">{}</saml:AttributeValue>"#,
                    group
                ));
                attrs_xml.push('\n');
            }
            attrs_xml.push_str("            </saml:Attribute>\n");
        }
    }

    let attribute_statement = if !attrs_xml.is_empty() {
        format!(
            r#"        <saml:AttributeStatement>
{}        </saml:AttributeStatement>"#,
            attrs_xml
        )
    } else {
        String::new()
    };

    let signature_xml = if sp.sign_assertions {
        r#"
        <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                <ds:Reference URI="">
                    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                    <ds:DigestValue>TEST_DIGEST</ds:DigestValue>
                </ds:Reference>
            </ds:SignedInfo>
            <ds:SignatureValue>TEST_SIGNATURE</ds:SignatureValue>
        </ds:Signature>"#
    } else {
        ""
    };

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{response_id}"
    Version="2.0"
    IssueInstant="{issue_instant}"
    Destination="{acs_url}"{in_response_to_attr}>
    <saml:Issuer>https://auth.xavyo.com/saml</saml:Issuer>
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </samlp:Status>
    <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
        ID="{assertion_id}"
        Version="2.0"
        IssueInstant="{issue_instant}">
        <saml:Issuer>https://auth.xavyo.com/saml</saml:Issuer>{signature_xml}
        <saml:Subject>
            <saml:NameID Format="{name_id_format}">{name_id_value}</saml:NameID>
            <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                <saml:SubjectConfirmationData
                    NotOnOrAfter="{not_on_or_after}"
                    Recipient="{acs_url}"{in_response_to_attr}/>
            </saml:SubjectConfirmation>
        </saml:Subject>
        <saml:Conditions NotBefore="{not_before}" NotOnOrAfter="{not_on_or_after}">
            <saml:AudienceRestriction>
                <saml:Audience>{entity_id}</saml:Audience>
            </saml:AudienceRestriction>
        </saml:Conditions>
        <saml:AuthnStatement AuthnInstant="{issue_instant}" SessionIndex="_session_{session_id}">
            <saml:AuthnContext>
                <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
            </saml:AuthnContext>
        </saml:AuthnStatement>
{attribute_statement}
    </saml:Assertion>
</samlp:Response>"#,
        response_id = response_id,
        assertion_id = assertion_id,
        issue_instant = issue_instant,
        acs_url = sp.acs_url,
        in_response_to_attr = in_response_to_attr,
        signature_xml = signature_xml,
        name_id_format = sp.name_id_format,
        name_id_value = name_id_value,
        not_before = not_before,
        not_on_or_after = not_on_or_after,
        entity_id = sp.entity_id,
        session_id = Uuid::new_v4(),
        attribute_statement = attribute_statement,
    )
}

/// Build a test SAML response for AWS SSO with role attributes
pub fn build_aws_test_response(sp: &SpProfile, user: &AwsRoleTestUser) -> String {
    let response_id = format!("_resp_{}", Uuid::new_v4());
    let assertion_id = format!("_assert_{}", Uuid::new_v4());
    let now = Utc::now();
    let issue_instant = now.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let not_before = (now - Duration::minutes(2))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
    let not_on_or_after = (now + Duration::seconds(sp.assertion_validity_seconds as i64))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();

    // Build role attributes
    let mut role_values = String::new();
    for role in &user.aws_roles {
        role_values.push_str(&format!(
            r#"                <saml:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">{}</saml:AttributeValue>
"#,
            role
        ));
    }

    let signature_xml = r#"
        <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                <ds:Reference URI="">
                    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                    <ds:DigestValue>TEST_DIGEST</ds:DigestValue>
                </ds:Reference>
            </ds:SignedInfo>
            <ds:SignatureValue>TEST_SIGNATURE</ds:SignatureValue>
        </ds:Signature>"#;

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{response_id}"
    Version="2.0"
    IssueInstant="{issue_instant}"
    Destination="{acs_url}">
    <saml:Issuer>https://auth.xavyo.com/saml</saml:Issuer>
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </samlp:Status>
    <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
        ID="{assertion_id}"
        Version="2.0"
        IssueInstant="{issue_instant}">
        <saml:Issuer>https://auth.xavyo.com/saml</saml:Issuer>{signature_xml}
        <saml:Subject>
            <saml:NameID Format="{name_id_format}">{user_id}</saml:NameID>
            <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                <saml:SubjectConfirmationData
                    NotOnOrAfter="{not_on_or_after}"
                    Recipient="{acs_url}"/>
            </saml:SubjectConfirmation>
        </saml:Subject>
        <saml:Conditions NotBefore="{not_before}" NotOnOrAfter="{not_on_or_after}">
            <saml:AudienceRestriction>
                <saml:Audience>{entity_id}</saml:Audience>
            </saml:AudienceRestriction>
        </saml:Conditions>
        <saml:AuthnStatement AuthnInstant="{issue_instant}" SessionIndex="_session_{session_id}">
            <saml:AuthnContext>
                <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
            </saml:AuthnContext>
        </saml:AuthnStatement>
        <saml:AttributeStatement>
            <saml:Attribute Name="https://aws.amazon.com/SAML/Attributes/Role" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
{role_values}            </saml:Attribute>
            <saml:Attribute Name="https://aws.amazon.com/SAML/Attributes/RoleSessionName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
                <saml:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">{username}</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="https://aws.amazon.com/SAML/Attributes/SessionDuration" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
                <saml:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">{session_duration}</saml:AttributeValue>
            </saml:Attribute>
        </saml:AttributeStatement>
    </saml:Assertion>
</samlp:Response>"#,
        response_id = response_id,
        assertion_id = assertion_id,
        issue_instant = issue_instant,
        acs_url = sp.acs_url,
        signature_xml = signature_xml,
        name_id_format = sp.name_id_format,
        user_id = user.id,
        not_before = not_before,
        not_on_or_after = not_on_or_after,
        entity_id = sp.entity_id,
        session_id = Uuid::new_v4(),
        role_values = role_values,
        username = user.username,
        session_duration = user.session_duration,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_saml_xml_basic() {
        let sp = SpProfile::salesforce();
        let user = StandardTestUser::default();
        let xml = build_test_response(&sp, &user, None);

        let parsed = parse_saml_xml(&xml).expect("Should parse XML");

        assert!(parsed.response_id.is_some());
        assert!(parsed.assertion_id.is_some());
        assert!(parsed.issuer.is_some());
        assert!(parsed.name_id.is_some());
        assert!(parsed.has_signature);
    }

    #[test]
    fn test_sp_profile_salesforce() {
        let sp = SpProfile::salesforce();
        assert_eq!(sp.name, "Salesforce");
        assert!(sp.name_id_format.contains("emailAddress"));
        assert!(sp.sign_assertions);
    }

    #[test]
    fn test_sp_profile_servicenow() {
        let sp = SpProfile::servicenow();
        assert_eq!(sp.name, "ServiceNow");
        assert!(sp.group_attribute_name.is_some());
    }

    #[test]
    fn test_sp_profile_workday() {
        let sp = SpProfile::workday();
        assert_eq!(sp.name, "Workday");
        assert!(sp.name_id_format.contains("unspecified"));
    }

    #[test]
    fn test_sp_profile_aws_sso() {
        let sp = SpProfile::aws_sso();
        assert_eq!(sp.entity_id, "urn:amazon:webservices");
        assert!(sp.name_id_format.contains("persistent"));
    }
}
