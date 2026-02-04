//! Country code extraction utilities for Storm-2372 remediation.
//!
//! Extracts the country code from HTTP headers set by CDNs/proxies.
//! Currently supports `CloudFlare` and custom X-Country-Code headers.

use axum::http::HeaderMap;

/// Unknown country code constant.
pub const UNKNOWN_COUNTRY: &str = "XX";

/// Extract the country code from request headers.
///
/// Priority order:
/// 1. CF-IPCountry (`CloudFlare`)
/// 2. X-Country-Code (custom header)
/// 3. Returns "XX" if no country information available
///
/// # Arguments
/// * `headers` - HTTP headers from the request
///
/// # Returns
/// A 2-letter ISO 3166-1 alpha-2 country code, or "XX" if unknown.
#[must_use] 
pub fn extract_country_code(headers: &HeaderMap) -> String {
    // 1. CloudFlare: CF-IPCountry
    if let Some(cf_country) = headers.get("CF-IPCountry") {
        if let Ok(country) = cf_country.to_str() {
            let country = country.trim().to_uppercase();
            if is_valid_country_code(&country) {
                return country;
            }
        }
    }

    // 2. Custom: X-Country-Code
    if let Some(country_header) = headers.get("X-Country-Code") {
        if let Ok(country) = country_header.to_str() {
            let country = country.trim().to_uppercase();
            if is_valid_country_code(&country) {
                return country;
            }
        }
    }

    // 3. Fallback: Unknown
    UNKNOWN_COUNTRY.to_string()
}

/// Validate that a string is a valid 2-letter country code.
///
/// Accepts standard ISO 3166-1 alpha-2 codes (2 alphabetic characters)
/// as well as `CloudFlare` special codes:
/// - T1: Tor exit node
/// - A1: Anonymous proxy
/// - A2: Satellite provider
fn is_valid_country_code(code: &str) -> bool {
    if code.len() != 2 {
        return false;
    }

    // CloudFlare special codes
    const SPECIAL_CODES: [&str; 3] = ["T1", "A1", "A2"];
    if SPECIAL_CODES.contains(&code) {
        return true;
    }

    // Standard ISO 3166-1 alpha-2 codes
    code.chars().all(|c| c.is_ascii_alphabetic())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn create_headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.insert(
                axum::http::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        headers
    }

    #[test]
    fn test_cloudflare_country() {
        let headers = create_headers(&[("CF-IPCountry", "US")]);
        let result = extract_country_code(&headers);
        assert_eq!(result, "US");
    }

    #[test]
    fn test_custom_country_header() {
        let headers = create_headers(&[("X-Country-Code", "FR")]);
        let result = extract_country_code(&headers);
        assert_eq!(result, "FR");
    }

    #[test]
    fn test_cloudflare_priority() {
        let headers = create_headers(&[("CF-IPCountry", "US"), ("X-Country-Code", "GB")]);
        let result = extract_country_code(&headers);
        assert_eq!(result, "US"); // CloudFlare wins
    }

    #[test]
    fn test_unknown_fallback() {
        let headers = HeaderMap::new();
        let result = extract_country_code(&headers);
        assert_eq!(result, "XX");
    }

    #[test]
    fn test_lowercase_normalized() {
        let headers = create_headers(&[("CF-IPCountry", "de")]);
        let result = extract_country_code(&headers);
        assert_eq!(result, "DE"); // Uppercase normalized
    }

    #[test]
    fn test_whitespace_trimmed() {
        let headers = create_headers(&[("CF-IPCountry", "  JP  ")]);
        let result = extract_country_code(&headers);
        assert_eq!(result, "JP");
    }

    #[test]
    fn test_invalid_code_too_long() {
        let headers = create_headers(&[("CF-IPCountry", "USA")]);
        let result = extract_country_code(&headers);
        assert_eq!(result, "XX"); // Invalid, too long
    }

    #[test]
    fn test_invalid_code_too_short() {
        let headers = create_headers(&[("CF-IPCountry", "U")]);
        let result = extract_country_code(&headers);
        assert_eq!(result, "XX"); // Invalid, too short
    }

    #[test]
    fn test_invalid_code_numeric() {
        let headers = create_headers(&[("CF-IPCountry", "12")]);
        let result = extract_country_code(&headers);
        assert_eq!(result, "XX"); // Invalid, not alphabetic
    }

    #[test]
    fn test_empty_header() {
        let headers = create_headers(&[("CF-IPCountry", "")]);
        let result = extract_country_code(&headers);
        assert_eq!(result, "XX");
    }

    #[test]
    fn test_t1_special_code() {
        // CloudFlare uses T1 for Tor
        let headers = create_headers(&[("CF-IPCountry", "T1")]);
        let result = extract_country_code(&headers);
        assert_eq!(result, "T1"); // Valid 2-letter code
    }
}
