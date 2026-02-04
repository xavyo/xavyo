//! IP address extraction utilities for Storm-2372 remediation.
//!
//! Extracts the client's real IP address from HTTP headers, supporting
//! various proxy configurations (`CloudFlare`, nginx, standard).

use axum::http::HeaderMap;
use std::net::SocketAddr;

/// Extract the origin IP address from request headers.
///
/// Priority order:
/// 1. CF-Connecting-IP (`CloudFlare`)
/// 2. X-Real-IP (nginx)
/// 3. X-Forwarded-For (first IP in chain)
/// 4. Socket peer address (fallback)
///
/// # Arguments
/// * `headers` - HTTP headers from the request
/// * `socket_addr` - Direct socket peer address (fallback)
///
/// # Returns
/// The extracted IP address as a string, or `None` if unavailable.
#[must_use] 
pub fn extract_origin_ip(headers: &HeaderMap, socket_addr: Option<&SocketAddr>) -> Option<String> {
    // 1. CloudFlare: CF-Connecting-IP
    if let Some(cf_ip) = headers.get("CF-Connecting-IP") {
        if let Ok(ip) = cf_ip.to_str() {
            let ip = ip.trim();
            if !ip.is_empty() && is_valid_ip(ip) {
                return Some(ip.to_string());
            }
        }
    }

    // 2. nginx: X-Real-IP
    if let Some(real_ip) = headers.get("X-Real-IP") {
        if let Ok(ip) = real_ip.to_str() {
            let ip = ip.trim();
            if !ip.is_empty() && is_valid_ip(ip) {
                return Some(ip.to_string());
            }
        }
    }

    // 3. Standard: X-Forwarded-For (first IP)
    if let Some(forwarded) = headers.get("X-Forwarded-For") {
        if let Ok(ips) = forwarded.to_str() {
            if let Some(first_ip) = ips.split(',').next() {
                let ip = first_ip.trim();
                if !ip.is_empty() && is_valid_ip(ip) {
                    return Some(ip.to_string());
                }
            }
        }
    }

    // 4. Fallback: Socket peer address
    socket_addr.map(|addr| addr.ip().to_string())
}

/// Basic validation that a string looks like an IP address.
fn is_valid_ip(ip: &str) -> bool {
    // IPv4: contains dots, no spaces
    // IPv6: contains colons
    (ip.contains('.') || ip.contains(':')) && !ip.contains(' ')
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use std::net::{IpAddr, Ipv4Addr};

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
    fn test_cloudflare_ip() {
        let headers = create_headers(&[("CF-Connecting-IP", "203.0.113.195")]);
        let result = extract_origin_ip(&headers, None);
        assert_eq!(result, Some("203.0.113.195".to_string()));
    }

    #[test]
    fn test_real_ip() {
        let headers = create_headers(&[("X-Real-IP", "192.168.1.100")]);
        let result = extract_origin_ip(&headers, None);
        assert_eq!(result, Some("192.168.1.100".to_string()));
    }

    #[test]
    fn test_forwarded_for_single() {
        let headers = create_headers(&[("X-Forwarded-For", "10.0.0.1")]);
        let result = extract_origin_ip(&headers, None);
        assert_eq!(result, Some("10.0.0.1".to_string()));
    }

    #[test]
    fn test_forwarded_for_chain() {
        let headers = create_headers(&[(
            "X-Forwarded-For",
            "203.0.113.195, 70.41.3.18, 150.172.238.178",
        )]);
        let result = extract_origin_ip(&headers, None);
        assert_eq!(result, Some("203.0.113.195".to_string())); // First IP only
    }

    #[test]
    fn test_cloudflare_priority() {
        let headers = create_headers(&[
            ("CF-Connecting-IP", "1.2.3.4"),
            ("X-Real-IP", "5.6.7.8"),
            ("X-Forwarded-For", "9.10.11.12"),
        ]);
        let result = extract_origin_ip(&headers, None);
        assert_eq!(result, Some("1.2.3.4".to_string())); // CloudFlare wins
    }

    #[test]
    fn test_socket_fallback() {
        let headers = HeaderMap::new();
        let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080);
        let result = extract_origin_ip(&headers, Some(&socket));
        assert_eq!(result, Some("127.0.0.1".to_string()));
    }

    #[test]
    fn test_ipv6() {
        let headers = create_headers(&[("X-Real-IP", "2001:db8::1")]);
        let result = extract_origin_ip(&headers, None);
        assert_eq!(result, Some("2001:db8::1".to_string()));
    }

    #[test]
    fn test_empty_headers_no_socket() {
        let headers = HeaderMap::new();
        let result = extract_origin_ip(&headers, None);
        assert_eq!(result, None);
    }

    #[test]
    fn test_empty_header_value() {
        let headers = create_headers(&[("X-Real-IP", "")]);
        let result = extract_origin_ip(&headers, None);
        assert_eq!(result, None);
    }

    #[test]
    fn test_whitespace_trimmed() {
        let headers = create_headers(&[("X-Real-IP", "  192.168.1.1  ")]);
        let result = extract_origin_ip(&headers, None);
        assert_eq!(result, Some("192.168.1.1".to_string()));
    }
}
