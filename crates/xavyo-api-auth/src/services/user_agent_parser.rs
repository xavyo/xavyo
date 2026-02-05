//! Simple user-agent parser for extracting device information.
//!
//! This parser extracts browser, OS, and device type from user-agent strings
//! without external dependencies.

use serde::Serialize;

/// Parsed device information from a user-agent string.
#[derive(Debug, Clone, Default, Serialize)]
pub struct DeviceInfo {
    /// Generated device name (e.g., "Chrome on Windows").
    pub device_name: String,
    /// Device type: "desktop", "mobile", "tablet", "unknown".
    pub device_type: String,
    /// Browser name.
    pub browser: Option<String>,
    /// Browser version.
    pub browser_version: Option<String>,
    /// Operating system name.
    pub os: Option<String>,
    /// Operating system version.
    pub os_version: Option<String>,
}

/// Parse a user-agent string to extract device information.
#[must_use]
pub fn parse_user_agent(user_agent: &str) -> DeviceInfo {
    let ua = user_agent.to_lowercase();

    let device_type = detect_device_type(&ua);
    let (browser, browser_version) = detect_browser(user_agent);
    let (os, os_version) = detect_os(user_agent);

    let device_name = generate_device_name(&browser, &os);

    DeviceInfo {
        device_name,
        device_type,
        browser,
        browser_version,
        os,
        os_version,
    }
}

/// Detect device type from user-agent.
fn detect_device_type(ua: &str) -> String {
    // Check for tablets first (iPad, Android tablet)
    if ua.contains("ipad") || (ua.contains("android") && !ua.contains("mobile")) {
        return "tablet".to_string();
    }

    // Check for mobile devices
    if ua.contains("mobile")
        || ua.contains("iphone")
        || ua.contains("ipod")
        || ua.contains("android")
        || ua.contains("blackberry")
        || ua.contains("windows phone")
    {
        return "mobile".to_string();
    }

    // Default to desktop
    "desktop".to_string()
}

/// Detect browser and version from user-agent.
fn detect_browser(ua: &str) -> (Option<String>, Option<String>) {
    // Order matters - check more specific browsers first

    // Edge (new Chromium-based)
    if ua.contains("Edg/") {
        let version = extract_version(ua, "Edg/");
        return (Some("Edge".to_string()), version);
    }

    // Edge (old)
    if ua.contains("Edge/") {
        let version = extract_version(ua, "Edge/");
        return (Some("Edge".to_string()), version);
    }

    // Chrome (but not Chromium-based browsers)
    if ua.contains("Chrome/") && !ua.contains("Chromium") {
        let version = extract_version(ua, "Chrome/");
        return (Some("Chrome".to_string()), version);
    }

    // Firefox
    if ua.contains("Firefox/") {
        let version = extract_version(ua, "Firefox/");
        return (Some("Firefox".to_string()), version);
    }

    // Safari (must check after Chrome since Chrome also contains Safari)
    if ua.contains("Safari/") && !ua.contains("Chrome") && !ua.contains("Chromium") {
        let version = extract_version(ua, "Version/");
        return (Some("Safari".to_string()), version);
    }

    // Opera
    if ua.contains("OPR/") || ua.contains("Opera/") {
        let version = extract_version(ua, "OPR/").or_else(|| extract_version(ua, "Opera/"));
        return (Some("Opera".to_string()), version);
    }

    // Internet Explorer
    if ua.contains("MSIE") || ua.contains("Trident/") {
        let version = extract_ie_version(ua);
        return (Some("Internet Explorer".to_string()), version);
    }

    (None, None)
}

/// Detect operating system and version from user-agent.
fn detect_os(ua: &str) -> (Option<String>, Option<String>) {
    // iOS - check BEFORE macOS because iOS user agents contain "like Mac OS X"
    if ua.contains("iPhone") || ua.contains("iPad") || ua.contains("iPod") {
        let version = extract_ios_version(ua);
        return (Some("iOS".to_string()), version);
    }

    // Windows
    if ua.contains("Windows") {
        let version = extract_windows_version(ua);
        return (Some("Windows".to_string()), version);
    }

    // macOS / Mac OS X (must check after iOS)
    if ua.contains("Macintosh") || ua.contains("Mac OS X") {
        let version = extract_macos_version(ua);
        return (Some("macOS".to_string()), version);
    }

    // Android
    if ua.contains("Android") {
        let version = extract_version(ua, "Android ");
        return (Some("Android".to_string()), version);
    }

    // Linux
    if ua.contains("Linux") {
        return (Some("Linux".to_string()), None);
    }

    // Chrome OS
    if ua.contains("CrOS") {
        return (Some("Chrome OS".to_string()), None);
    }

    (None, None)
}

/// Extract version number after a prefix.
fn extract_version(ua: &str, prefix: &str) -> Option<String> {
    let start = ua.find(prefix)? + prefix.len();
    let rest = &ua[start..];
    let end = rest
        .find(|c: char| !c.is_numeric() && c != '.')
        .unwrap_or(rest.len());
    let version = &rest[..end];
    if version.is_empty() {
        None
    } else {
        Some(version.to_string())
    }
}

/// Extract IE version from user-agent.
fn extract_ie_version(ua: &str) -> Option<String> {
    // MSIE 10.0 format
    if let Some(start) = ua.find("MSIE ") {
        let rest = &ua[start + 5..];
        let end = rest
            .find(|c: char| !c.is_numeric() && c != '.')
            .unwrap_or(rest.len());
        return Some(rest[..end].to_string());
    }

    // IE 11 uses Trident/7.0
    if ua.contains("Trident/7.0") {
        return Some("11".to_string());
    }

    None
}

/// Extract Windows version from user-agent.
fn extract_windows_version(ua: &str) -> Option<String> {
    if ua.contains("Windows NT 10.0") {
        Some("10".to_string())
    } else if ua.contains("Windows NT 6.3") {
        Some("8.1".to_string())
    } else if ua.contains("Windows NT 6.2") {
        Some("8".to_string())
    } else if ua.contains("Windows NT 6.1") {
        Some("7".to_string())
    } else if ua.contains("Windows NT 6.0") {
        Some("Vista".to_string())
    } else if ua.contains("Windows NT 5.1") {
        Some("XP".to_string())
    } else {
        None
    }
}

/// Extract macOS version from user-agent.
fn extract_macos_version(ua: &str) -> Option<String> {
    // Mac OS X 10_15_7 or Mac OS X 10.15.7
    let prefix = "Mac OS X ";
    if let Some(start) = ua.find(prefix) {
        let rest = &ua[start + prefix.len()..];
        let end = rest
            .find(|c: char| !c.is_numeric() && c != '_' && c != '.')
            .unwrap_or(rest.len());
        let version = &rest[..end];
        if !version.is_empty() {
            return Some(version.replace('_', "."));
        }
    }
    None
}

/// Extract iOS version from user-agent.
fn extract_ios_version(ua: &str) -> Option<String> {
    // iPhone OS 15_0 like Mac OS X or CPU iPhone OS 15_0
    for prefix in &["iPhone OS ", "CPU iPhone OS ", "CPU OS "] {
        if let Some(start) = ua.find(prefix) {
            let rest = &ua[start + prefix.len()..];
            let end = rest
                .find(|c: char| !c.is_numeric() && c != '_')
                .unwrap_or(rest.len());
            let version = &rest[..end];
            if !version.is_empty() {
                return Some(version.replace('_', "."));
            }
        }
    }
    None
}

/// Generate a human-readable device name.
fn generate_device_name(browser: &Option<String>, os: &Option<String>) -> String {
    match (browser, os) {
        (Some(b), Some(o)) => format!("{b} on {o}"),
        (Some(b), None) => b.clone(),
        (None, Some(o)) => format!("Unknown browser on {o}"),
        (None, None) => "Unknown device".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chrome_windows() {
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
        let info = parse_user_agent(ua);

        assert_eq!(info.browser, Some("Chrome".to_string()));
        assert_eq!(info.browser_version, Some("120.0.0.0".to_string()));
        assert_eq!(info.os, Some("Windows".to_string()));
        assert_eq!(info.os_version, Some("10".to_string()));
        assert_eq!(info.device_type, "desktop");
        assert_eq!(info.device_name, "Chrome on Windows");
    }

    #[test]
    fn test_firefox_macos() {
        let ua =
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0";
        let info = parse_user_agent(ua);

        assert_eq!(info.browser, Some("Firefox".to_string()));
        assert_eq!(info.browser_version, Some("121.0".to_string()));
        assert_eq!(info.os, Some("macOS".to_string()));
        assert_eq!(info.os_version, Some("10.15".to_string()));
        assert_eq!(info.device_type, "desktop");
    }

    #[test]
    fn test_safari_ios_iphone() {
        let ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1";
        let info = parse_user_agent(ua);

        assert_eq!(info.browser, Some("Safari".to_string()));
        assert_eq!(info.browser_version, Some("17.0".to_string()));
        assert_eq!(info.os, Some("iOS".to_string()));
        assert_eq!(info.os_version, Some("17.0".to_string()));
        assert_eq!(info.device_type, "mobile");
    }

    #[test]
    fn test_safari_ios_ipad() {
        let ua = "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1";
        let info = parse_user_agent(ua);

        assert_eq!(info.browser, Some("Safari".to_string()));
        assert_eq!(info.os, Some("iOS".to_string()));
        assert_eq!(info.device_type, "tablet");
    }

    #[test]
    fn test_chrome_android() {
        let ua = "Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36";
        let info = parse_user_agent(ua);

        assert_eq!(info.browser, Some("Chrome".to_string()));
        assert_eq!(info.os, Some("Android".to_string()));
        assert_eq!(info.os_version, Some("13".to_string()));
        assert_eq!(info.device_type, "mobile");
    }

    #[test]
    fn test_edge_windows() {
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0";
        let info = parse_user_agent(ua);

        assert_eq!(info.browser, Some("Edge".to_string()));
        assert_eq!(info.browser_version, Some("120.0.0.0".to_string()));
        assert_eq!(info.os, Some("Windows".to_string()));
    }

    #[test]
    fn test_unknown_user_agent() {
        let ua = "Some random string";
        let info = parse_user_agent(ua);

        assert_eq!(info.browser, None);
        assert_eq!(info.os, None);
        assert_eq!(info.device_type, "desktop");
        assert_eq!(info.device_name, "Unknown device");
    }

    #[test]
    fn test_empty_user_agent() {
        let ua = "";
        let info = parse_user_agent(ua);

        assert_eq!(info.device_name, "Unknown device");
        assert_eq!(info.device_type, "desktop");
    }
}
