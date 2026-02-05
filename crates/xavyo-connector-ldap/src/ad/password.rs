//! AD password operations using unicodePwd attribute encoding.
//!
//! Active Directory requires passwords to be set via the `unicodePwd` attribute
//! using a specific encoding:
//! 1. Surround the password with double quotes: `"password"`
//! 2. Encode the quoted string as UTF-16LE bytes
//!
//! This encoding is required for both LDAP add and modify operations on the
//! unicodePwd attribute. LDAPS (port 636) is required for password operations.

use tracing::{debug, instrument};
use xavyo_connector::error::{ConnectorError, ConnectorResult};

/// Encode a plaintext password for AD's unicodePwd attribute.
///
/// The password is surrounded with double quotes and then encoded as UTF-16LE.
/// This is the format required by Active Directory for setting passwords
/// via LDAP modify operations.
///
/// # Arguments
/// * `password` — the plaintext password to encode
///
/// # Returns
/// UTF-16LE encoded bytes suitable for the unicodePwd LDAP attribute.
///
/// # Errors
/// Returns an error if the password is empty.
#[instrument(skip(password))]
pub fn encode_ad_password(password: &str) -> ConnectorResult<Vec<u8>> {
    if password.is_empty() {
        return Err(ConnectorError::InvalidConfiguration {
            message: "Password cannot be empty".to_string(),
        });
    }

    // Surround with double quotes as required by AD
    let quoted = format!("\"{password}\"");

    // Encode as UTF-16LE
    let encoded: Vec<u8> = quoted.encode_utf16().flat_map(u16::to_le_bytes).collect();

    Ok(encoded)
}

/// Validate that the connection is suitable for password operations.
///
/// AD requires LDAPS (SSL/TLS) for any password modification. This function
/// checks the configuration and returns an error if SSL is not enabled.
#[instrument]
pub fn validate_password_connection(use_ssl: bool) -> ConnectorResult<()> {
    if !use_ssl {
        return Err(ConnectorError::InvalidConfiguration {
            message: "LDAPS (SSL) connection required for password operations. \
                      AD rejects unicodePwd modifications over non-encrypted connections."
                .to_string(),
        });
    }
    Ok(())
}

/// Build LDAP modify operations for setting a new password.
///
/// Returns the attribute name and encoded value for an LDAP replace operation
/// on the unicodePwd attribute.
///
/// # Arguments
/// * `password` — the new plaintext password
/// * `use_ssl` — whether the connection uses SSL/TLS
#[instrument(skip(password))]
pub fn build_password_modify(password: &str, use_ssl: bool) -> ConnectorResult<(String, Vec<u8>)> {
    validate_password_connection(use_ssl)?;
    let encoded = encode_ad_password(password)?;
    Ok(("unicodePwd".to_string(), encoded))
}

/// Build LDAP modify operations for changing a password (old + new).
///
/// Returns two tuples: one for deleting the old password and one for adding the new.
/// This is the standard AD password change flow where the user provides their
/// current password.
///
/// # Arguments
/// * `old_password` — the current password
/// * `new_password` — the new password
/// * `use_ssl` — whether the connection uses SSL/TLS
#[instrument(skip(old_password, new_password))]
pub fn build_password_change(
    old_password: &str,
    new_password: &str,
    use_ssl: bool,
) -> ConnectorResult<(Vec<u8>, Vec<u8>)> {
    validate_password_connection(use_ssl)?;
    let old_encoded = encode_ad_password(old_password)?;
    let new_encoded = encode_ad_password(new_password)?;
    Ok((old_encoded, new_encoded))
}

/// Compute the userAccountControl value for a newly created AD user.
///
/// New accounts are created with `NORMAL_ACCOUNT` (0x200) flag.
/// Optionally, the account can be created in disabled state (ACCOUNTDISABLE 0x2).
#[must_use]
pub fn new_account_uac(disabled: bool) -> u32 {
    let mut uac: u32 = 0x200; // NORMAL_ACCOUNT
    if disabled {
        uac |= 0x2; // ACCOUNTDISABLE
    }
    uac
}

/// Build the Distinguished Name for a new user in the target OU.
///
/// Constructs: `CN=<display_name>,<target_ou>`
///
/// # Arguments
/// * `display_name` — the user's display name (used as CN)
/// * `target_ou` — the target OU DN (e.g., "OU=Users,DC=example,DC=com")
#[instrument]
pub fn build_user_dn(display_name: &str, target_ou: &str) -> ConnectorResult<String> {
    if display_name.is_empty() {
        return Err(ConnectorError::InvalidConfiguration {
            message: "Display name cannot be empty for DN construction".to_string(),
        });
    }
    if target_ou.is_empty() {
        return Err(ConnectorError::InvalidConfiguration {
            message: "Target OU cannot be empty for DN construction".to_string(),
        });
    }

    // Escape special DN characters in the CN
    let escaped_cn = escape_dn_value(display_name);
    let dn = format!("CN={escaped_cn},{target_ou}");
    debug!(dn = %dn, "Built user DN for outbound provisioning");

    Ok(dn)
}

/// Escape special characters in a DN attribute value per RFC 4514.
fn escape_dn_value(value: &str) -> String {
    let mut result = String::with_capacity(value.len());
    for (i, c) in value.chars().enumerate() {
        match c {
            '"' | '+' | ',' | ';' | '<' | '>' | '\\' => {
                result.push('\\');
                result.push(c);
            }
            '#' if i == 0 => {
                result.push('\\');
                result.push(c);
            }
            ' ' if i == 0 || i == value.len() - 1 => {
                result.push('\\');
                result.push(c);
            }
            _ => result.push(c),
        }
    }
    result
}

/// Map platform user attributes to AD LDAP attributes for outbound provisioning.
///
/// This is the reverse of the inbound mapping defined in sync.rs.
/// Returns a list of (`attribute_name`, value) pairs for an LDAP add operation.
#[instrument(skip(attrs))]
pub fn map_platform_to_ad_attributes(
    attrs: &std::collections::HashMap<String, serde_json::Value>,
) -> Vec<(String, String)> {
    let mut ad_attrs = Vec::new();

    // Reverse mapping: platform → AD
    if let Some(v) = attrs.get("username").and_then(|v| v.as_str()) {
        ad_attrs.push(("sAMAccountName".to_string(), v.to_string()));
    }
    if let Some(v) = attrs.get("upn").and_then(|v| v.as_str()) {
        ad_attrs.push(("userPrincipalName".to_string(), v.to_string()));
    }
    if let Some(v) = attrs.get("email").and_then(|v| v.as_str()) {
        ad_attrs.push(("mail".to_string(), v.to_string()));
    }
    if let Some(v) = attrs.get("display_name").and_then(|v| v.as_str()) {
        ad_attrs.push(("displayName".to_string(), v.to_string()));
        ad_attrs.push(("cn".to_string(), v.to_string()));
    }
    if let Some(v) = attrs.get("first_name").and_then(|v| v.as_str()) {
        ad_attrs.push(("givenName".to_string(), v.to_string()));
    }
    if let Some(v) = attrs.get("last_name").and_then(|v| v.as_str()) {
        ad_attrs.push(("sn".to_string(), v.to_string()));
    }
    if let Some(v) = attrs.get("department").and_then(|v| v.as_str()) {
        ad_attrs.push(("department".to_string(), v.to_string()));
    }
    if let Some(v) = attrs.get("job_title").and_then(|v| v.as_str()) {
        ad_attrs.push(("title".to_string(), v.to_string()));
    }
    if let Some(v) = attrs.get("company").and_then(|v| v.as_str()) {
        ad_attrs.push(("company".to_string(), v.to_string()));
    }
    if let Some(v) = attrs.get("employee_id").and_then(|v| v.as_str()) {
        ad_attrs.push(("employeeID".to_string(), v.to_string()));
    }
    if let Some(v) = attrs.get("phone").and_then(|v| v.as_str()) {
        ad_attrs.push(("telephoneNumber".to_string(), v.to_string()));
    }

    ad_attrs
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- T028: unicodePwd encoding tests ---

    #[test]
    fn test_encode_ad_password_basic() {
        let encoded = encode_ad_password("Test123!").unwrap();

        // Expected: "\"Test123!\"" encoded as UTF-16LE
        let expected_str = "\"Test123!\"";
        let expected: Vec<u8> = expected_str
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();

        assert_eq!(encoded, expected);
    }

    #[test]
    fn test_encode_ad_password_starts_with_quote() {
        let encoded = encode_ad_password("P@ssw0rd").unwrap();

        // First two bytes should be UTF-16LE for '"' = 0x22 0x00
        assert_eq!(encoded[0], 0x22);
        assert_eq!(encoded[1], 0x00);

        // Last two bytes should be UTF-16LE for '"' = 0x22 0x00
        let len = encoded.len();
        assert_eq!(encoded[len - 2], 0x22);
        assert_eq!(encoded[len - 1], 0x00);
    }

    #[test]
    fn test_encode_ad_password_empty_rejected() {
        let result = encode_ad_password("");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty"));
    }

    #[test]
    fn test_encode_ad_password_unicode_chars() {
        // Test with unicode characters (e.g., accented chars)
        let encoded = encode_ad_password("Pässwörd!").unwrap();
        assert!(!encoded.is_empty());

        // Should be properly UTF-16LE encoded
        // ä = U+00E4, ö = U+00F6
        // Verify we have even number of bytes (UTF-16LE pairs)
        assert_eq!(encoded.len() % 2, 0);
    }

    #[test]
    fn test_encode_ad_password_special_symbols() {
        let encoded = encode_ad_password("P@$$w0rd!#%^&*").unwrap();
        assert!(!encoded.is_empty());
        assert_eq!(encoded.len() % 2, 0);
    }

    #[test]
    fn test_encode_ad_password_length() {
        let encoded = encode_ad_password("abc").unwrap();
        // "abc" -> 5 chars including quotes -> 10 bytes in UTF-16LE
        assert_eq!(encoded.len(), 10);
    }

    // --- SSL validation tests ---

    #[test]
    fn test_validate_password_connection_ssl_ok() {
        assert!(validate_password_connection(true).is_ok());
    }

    #[test]
    fn test_validate_password_connection_no_ssl_error() {
        let result = validate_password_connection(false);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("SSL"));
    }

    #[test]
    fn test_build_password_modify_ssl() {
        let (attr, value) = build_password_modify("Test123!", true).unwrap();
        assert_eq!(attr, "unicodePwd");
        assert!(!value.is_empty());
    }

    #[test]
    fn test_build_password_modify_no_ssl() {
        let result = build_password_modify("Test123!", false);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_password_change() {
        let (old, new) = build_password_change("OldPass!", "NewPass!", true).unwrap();
        assert_ne!(old, new);
        assert!(!old.is_empty());
        assert!(!new.is_empty());
    }

    // --- T029: outbound provisioning attribute mapping tests ---

    #[test]
    fn test_new_account_uac_enabled() {
        let uac = new_account_uac(false);
        assert_eq!(uac, 0x200); // NORMAL_ACCOUNT
        assert_eq!(uac & 0x2, 0); // Not disabled
    }

    #[test]
    fn test_new_account_uac_disabled() {
        let uac = new_account_uac(true);
        assert_eq!(uac & 0x200, 0x200); // NORMAL_ACCOUNT set
        assert_eq!(uac & 0x2, 0x2); // ACCOUNTDISABLE set
        assert_eq!(uac, 0x202);
    }

    #[test]
    fn test_build_user_dn() {
        let dn = build_user_dn("John Doe", "OU=Users,DC=example,DC=com").unwrap();
        assert_eq!(dn, "CN=John Doe,OU=Users,DC=example,DC=com");
    }

    #[test]
    fn test_build_user_dn_special_chars() {
        let dn = build_user_dn("Doe, John (Jr.)", "OU=Users,DC=example,DC=com").unwrap();
        // Comma should be escaped
        assert_eq!(dn, "CN=Doe\\, John (Jr.),OU=Users,DC=example,DC=com");
    }

    #[test]
    fn test_build_user_dn_empty_name() {
        let result = build_user_dn("", "OU=Users,DC=example,DC=com");
        assert!(result.is_err());
    }

    #[test]
    fn test_build_user_dn_empty_ou() {
        let result = build_user_dn("John Doe", "");
        assert!(result.is_err());
    }

    #[test]
    fn test_escape_dn_value_no_escaping() {
        assert_eq!(escape_dn_value("John Doe"), "John Doe");
    }

    #[test]
    fn test_escape_dn_value_comma() {
        assert_eq!(escape_dn_value("Doe, John"), "Doe\\, John");
    }

    #[test]
    fn test_escape_dn_value_plus_sign() {
        assert_eq!(escape_dn_value("A+B"), "A\\+B");
    }

    #[test]
    fn test_escape_dn_value_leading_hash() {
        assert_eq!(escape_dn_value("#admin"), "\\#admin");
    }

    #[test]
    fn test_escape_dn_value_leading_space() {
        assert_eq!(escape_dn_value(" admin"), "\\ admin");
    }

    #[test]
    fn test_escape_dn_value_trailing_space() {
        assert_eq!(escape_dn_value("admin "), "admin\\ ");
    }

    #[test]
    fn test_escape_dn_value_quotes() {
        assert_eq!(escape_dn_value("O\"Brien"), "O\\\"Brien");
    }

    #[test]
    fn test_map_platform_to_ad_basic() {
        let mut attrs = std::collections::HashMap::new();
        attrs.insert(
            "username".to_string(),
            serde_json::Value::String("john.doe".to_string()),
        );
        attrs.insert(
            "email".to_string(),
            serde_json::Value::String("john@example.com".to_string()),
        );
        attrs.insert(
            "display_name".to_string(),
            serde_json::Value::String("John Doe".to_string()),
        );
        attrs.insert(
            "first_name".to_string(),
            serde_json::Value::String("John".to_string()),
        );
        attrs.insert(
            "last_name".to_string(),
            serde_json::Value::String("Doe".to_string()),
        );

        let ad_attrs = map_platform_to_ad_attributes(&attrs);

        let map: std::collections::HashMap<&str, &str> = ad_attrs
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();

        assert_eq!(map.get("sAMAccountName"), Some(&"john.doe"));
        assert_eq!(map.get("mail"), Some(&"john@example.com"));
        assert_eq!(map.get("displayName"), Some(&"John Doe"));
        assert_eq!(map.get("cn"), Some(&"John Doe"));
        assert_eq!(map.get("givenName"), Some(&"John"));
        assert_eq!(map.get("sn"), Some(&"Doe"));
    }

    #[test]
    fn test_map_platform_to_ad_organizational() {
        let mut attrs = std::collections::HashMap::new();
        attrs.insert(
            "department".to_string(),
            serde_json::Value::String("Engineering".to_string()),
        );
        attrs.insert(
            "job_title".to_string(),
            serde_json::Value::String("Senior Dev".to_string()),
        );
        attrs.insert(
            "company".to_string(),
            serde_json::Value::String("Example Corp".to_string()),
        );
        attrs.insert(
            "employee_id".to_string(),
            serde_json::Value::String("EMP001".to_string()),
        );
        attrs.insert(
            "phone".to_string(),
            serde_json::Value::String("+1-555-0100".to_string()),
        );

        let ad_attrs = map_platform_to_ad_attributes(&attrs);

        let map: std::collections::HashMap<&str, &str> = ad_attrs
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();

        assert_eq!(map.get("department"), Some(&"Engineering"));
        assert_eq!(map.get("title"), Some(&"Senior Dev"));
        assert_eq!(map.get("company"), Some(&"Example Corp"));
        assert_eq!(map.get("employeeID"), Some(&"EMP001"));
        assert_eq!(map.get("telephoneNumber"), Some(&"+1-555-0100"));
    }

    #[test]
    fn test_map_platform_to_ad_empty() {
        let attrs = std::collections::HashMap::new();
        let ad_attrs = map_platform_to_ad_attributes(&attrs);
        assert!(ad_attrs.is_empty());
    }

    #[test]
    fn test_map_platform_to_ad_upn() {
        let mut attrs = std::collections::HashMap::new();
        attrs.insert(
            "upn".to_string(),
            serde_json::Value::String("john@example.com".to_string()),
        );

        let ad_attrs = map_platform_to_ad_attributes(&attrs);
        let has_upn = ad_attrs
            .iter()
            .any(|(k, v)| k == "userPrincipalName" && v == "john@example.com");
        assert!(has_upn);
    }
}
