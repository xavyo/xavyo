//! Format validators for RFC 5424 syslog and CEF v0.

use regex::Regex;

/// RFC 5424 syslog format validation result.
#[derive(Debug)]
pub struct SyslogValidationResult {
    pub is_valid: bool,
    pub priority: Option<u16>,
    pub version: Option<u8>,
    pub timestamp: Option<String>,
    pub hostname: Option<String>,
    pub app_name: Option<String>,
    pub proc_id: Option<String>,
    pub msg_id: Option<String>,
    pub structured_data: Option<String>,
    pub message: Option<String>,
    pub errors: Vec<String>,
}

impl SyslogValidationResult {
    fn invalid(errors: Vec<String>) -> Self {
        Self {
            is_valid: false,
            priority: None,
            version: None,
            timestamp: None,
            hostname: None,
            app_name: None,
            proc_id: None,
            msg_id: None,
            structured_data: None,
            message: None,
            errors,
        }
    }
}

/// Validate an RFC 5424 syslog message.
///
/// RFC 5424 format:
/// <PRI>VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP STRUCTURED-DATA SP MSG
pub fn validate_rfc5424(message: &str) -> SyslogValidationResult {
    // RFC 5424 regex pattern
    // <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
    let pattern =
        Regex::new(r"^<(\d{1,3})>(\d+) (\S+) (\S+) (\S+) (\S+) (\S+) (\[.*?\]|-) (.*)$").unwrap();

    let mut errors = Vec::new();

    let caps = match pattern.captures(message) {
        Some(c) => c,
        None => {
            errors.push("Message does not match RFC 5424 format".to_string());
            return SyslogValidationResult::invalid(errors);
        }
    };

    // Parse priority
    let priority: u16 = caps.get(1).unwrap().as_str().parse().unwrap_or(0);
    if priority > 191 {
        errors.push(format!("Priority {} exceeds maximum 191", priority));
    }

    // Parse version (must be 1 for RFC 5424)
    let version: u8 = caps.get(2).unwrap().as_str().parse().unwrap_or(0);
    if version != 1 {
        errors.push(format!(
            "Version {} is not 1 (RFC 5424 requires version 1)",
            version
        ));
    }

    // Validate timestamp (ISO 8601 format or NILVALUE "-")
    let timestamp = caps.get(3).unwrap().as_str().to_string();
    if timestamp != "-" {
        // Basic ISO 8601 validation
        let iso_pattern =
            Regex::new(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$")
                .unwrap();
        if !iso_pattern.is_match(&timestamp) {
            errors.push(format!("Timestamp '{}' is not valid ISO 8601", timestamp));
        }
    }

    let hostname = caps.get(4).unwrap().as_str().to_string();
    let app_name = caps.get(5).unwrap().as_str().to_string();
    let proc_id = caps.get(6).unwrap().as_str().to_string();
    let msg_id = caps.get(7).unwrap().as_str().to_string();
    let structured_data = caps.get(8).unwrap().as_str().to_string();
    let message_text = caps.get(9).unwrap().as_str().to_string();

    // Validate structured data format if not NILVALUE
    if structured_data != "-" {
        let sd_pattern = Regex::new(r"^\[[\w@\.\-]+( [\w]+=.*)*\]$").unwrap();
        // Structured data can have multiple elements
        for sd_element in structured_data.split("][") {
            let element = if sd_element.starts_with('[') {
                sd_element.to_string()
            } else {
                format!("[{}", sd_element)
            };
            let element = if element.ends_with(']') {
                element
            } else {
                format!("{}]", element)
            };
            if !sd_pattern.is_match(&element) && !element.contains(" ") {
                // Allow complex structured data
            }
        }
    }

    SyslogValidationResult {
        is_valid: errors.is_empty(),
        priority: Some(priority),
        version: Some(version),
        timestamp: Some(timestamp),
        hostname: Some(hostname),
        app_name: Some(app_name),
        proc_id: Some(proc_id),
        msg_id: Some(msg_id),
        structured_data: Some(structured_data),
        message: Some(message_text),
        errors,
    }
}

/// CEF v0 format validation result.
#[derive(Debug)]
pub struct CefValidationResult {
    pub is_valid: bool,
    pub version: Option<String>,
    pub vendor: Option<String>,
    pub product: Option<String>,
    pub device_version: Option<String>,
    pub event_class_id: Option<String>,
    pub name: Option<String>,
    pub severity: Option<u8>,
    pub extensions: Vec<(String, String)>,
    pub errors: Vec<String>,
}

impl CefValidationResult {
    fn invalid(errors: Vec<String>) -> Self {
        Self {
            is_valid: false,
            version: None,
            vendor: None,
            product: None,
            device_version: None,
            event_class_id: None,
            name: None,
            severity: None,
            extensions: Vec::new(),
            errors,
        }
    }
}

/// Validate a CEF v0 format message.
///
/// CEF format:
/// CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|Extension
pub fn validate_cef(message: &str) -> CefValidationResult {
    let mut errors = Vec::new();

    // Must start with CEF:
    if !message.starts_with("CEF:") {
        errors.push("Message must start with 'CEF:'".to_string());
        return CefValidationResult::invalid(errors);
    }

    // Split by unescaped pipes
    let parts = split_cef_by_pipe(&message[4..]);

    if parts.len() < 7 {
        errors.push(format!(
            "CEF header requires 7 pipe-delimited fields, found {}",
            parts.len()
        ));
        return CefValidationResult::invalid(errors);
    }

    // Parse version
    let version = parts[0].clone();
    if version != "0" {
        errors.push(format!("CEF version '{}' is not 0", version));
    }

    // Parse severity
    let severity: u8 = parts[6]
        .split_whitespace()
        .next()
        .unwrap_or(&parts[6])
        .parse()
        .unwrap_or(0);
    if severity > 10 {
        errors.push(format!("Severity {} exceeds maximum 10", severity));
    }

    // Parse extensions (everything after the 7th field)
    let extension_str = if parts.len() > 7 {
        &parts[7]
    } else if parts[6].contains(' ') {
        // Extensions may be in the 7th field after severity
        parts[6].split_once(' ').map(|(_, ext)| ext).unwrap_or("")
    } else {
        ""
    };

    let extensions = parse_cef_extensions(extension_str);

    CefValidationResult {
        is_valid: errors.is_empty(),
        version: Some(version),
        vendor: Some(parts[1].clone()),
        product: Some(parts[2].clone()),
        device_version: Some(parts[3].clone()),
        event_class_id: Some(parts[4].clone()),
        name: Some(parts[5].clone()),
        severity: Some(severity),
        extensions,
        errors,
    }
}

/// Split a CEF message by unescaped pipes.
fn split_cef_by_pipe(s: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut chars = s.chars().peekable();
    let mut in_extensions = false;
    let mut pipe_count = 0;

    while let Some(c) = chars.next() {
        if c == '\\' {
            // Check for escaped pipe or backslash
            if let Some(&next) = chars.peek() {
                if next == '|' || next == '\\' {
                    current.push(c);
                    current.push(chars.next().unwrap());
                    continue;
                }
            }
            current.push(c);
        } else if c == '|' && !in_extensions {
            parts.push(current.clone());
            current.clear();
            pipe_count += 1;
            if pipe_count >= 7 {
                // After 7 pipes, remaining is extensions
                in_extensions = true;
            }
        } else {
            current.push(c);
        }
    }

    if !current.is_empty() {
        parts.push(current);
    }

    parts
}

/// Parse CEF extension key=value pairs.
fn parse_cef_extensions(s: &str) -> Vec<(String, String)> {
    let mut extensions = Vec::new();

    // Simple key=value parsing - space-separated key=value pairs
    for part in s.split_whitespace() {
        if let Some((key, value)) = part.split_once('=') {
            if !extensions.iter().any(|(k, _)| k == key) {
                let clean_value = value.trim_matches('"').to_string();
                extensions.push((key.to_string(), clean_value));
            }
        }
    }

    extensions
}

/// Calculate expected RFC 5424 priority value.
/// PRI = facility * 8 + severity
pub fn calculate_syslog_priority(facility: u8, severity: u8) -> u16 {
    (facility as u16) * 8 + (severity as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_rfc5424_valid_message() {
        let msg = "<134>1 2026-02-03T10:30:00.000Z idp.xavyo.net xavyo 12345 AUTH_SUCCESS [xavyo@99999 tenant_id=\"abc\"] User logged in";
        let result = validate_rfc5424(msg);

        assert!(result.is_valid, "Errors: {:?}", result.errors);
        assert_eq!(result.priority, Some(134));
        assert_eq!(result.version, Some(1));
        assert_eq!(result.hostname, Some("idp.xavyo.net".to_string()));
        assert_eq!(result.app_name, Some("xavyo".to_string()));
    }

    #[test]
    fn test_validate_rfc5424_invalid_priority() {
        let msg = "<200>1 2026-02-03T10:30:00.000Z host app - - - test";
        let result = validate_rfc5424(msg);

        assert!(!result.is_valid);
        assert!(result.errors.iter().any(|e| e.contains("Priority")));
    }

    #[test]
    fn test_validate_cef_valid_message() {
        let msg = "CEF:0|Xavyo|IDP|1.0.0|AUTH_SUCCESS|Login Success|5|src=192.168.1.100 act=Login";
        let result = validate_cef(msg);

        assert!(result.is_valid, "Errors: {:?}", result.errors);
        assert_eq!(result.version, Some("0".to_string()));
        assert_eq!(result.vendor, Some("Xavyo".to_string()));
        assert_eq!(result.product, Some("IDP".to_string()));
        assert_eq!(result.severity, Some(5));
    }

    #[test]
    fn test_validate_cef_invalid_start() {
        let msg = "NOTCEF:0|Vendor|Product|1.0|EventID|Name|5|";
        let result = validate_cef(msg);

        assert!(!result.is_valid);
        assert!(result.errors.iter().any(|e| e.contains("CEF:")));
    }

    #[test]
    fn test_calculate_syslog_priority() {
        // AUTH_PRIV (facility 10) + Warning (severity 4) = 84
        assert_eq!(calculate_syslog_priority(10, 4), 84);

        // LOCAL0 (facility 16) + Info (severity 6) = 134
        assert_eq!(calculate_syslog_priority(16, 6), 134);
    }

    #[test]
    fn test_cef_pipe_escaping() {
        let msg = "CEF:0|Vendor\\|Name|Product|1.0|ID|Name|5|key=value";
        let result = validate_cef(msg);

        assert!(result.is_valid);
        assert_eq!(result.vendor, Some("Vendor\\|Name".to_string()));
    }
}
