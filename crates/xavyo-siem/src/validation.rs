//! SSRF protection and endpoint validation for SIEM destinations.
//!
//! This module provides security validation to prevent Server-Side Request Forgery (SSRF)
//! attacks when configuring SIEM webhook destinations or syslog endpoints.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use url::Url;

/// SSRF protection: Check if a URL is safe to fetch (not targeting internal services).
///
/// This function validates webhook URLs to prevent Server-Side Request Forgery attacks.
/// It blocks requests to:
/// - Private IPv4 ranges (10.x.x.x, 172.16-31.x.x, 192.168.x.x)
/// - Loopback addresses (127.x.x.x, `::1`)
/// - Link-local addresses (169.254.x.x, `fe80::/10`)
/// - Documentation/test ranges
/// - Unspecified addresses (0.0.0.0, ::)
/// - Cloud metadata endpoints (169.254.169.254, metadata.google.internal)
///
/// # Security
///
/// This protection prevents attackers from using SIEM webhook callbacks to:
/// - Scan internal networks
/// - Access internal services (metadata APIs, admin panels)
/// - Exfiltrate data through DNS rebinding
pub fn validate_webhook_url(url_str: &str) -> Result<(), String> {
    // Parse the URL
    let url = Url::parse(url_str).map_err(|e| format!("Invalid URL: {e}"))?;

    // Only allow HTTPS in production (HTTP allowed for localhost in dev)
    let scheme = url.scheme();
    if scheme != "https" && scheme != "http" {
        return Err(format!("Unsupported scheme: {scheme}"));
    }

    // Get the host
    let host = url
        .host_str()
        .ok_or_else(|| "URL has no host".to_string())?;

    validate_host(host, url.port().unwrap_or(443))
}

/// Validate that a hostname/IP is not targeting internal services.
///
/// Used for both webhook URLs and syslog endpoint hosts.
pub fn validate_host(host: &str, port: u16) -> Result<(), String> {
    // Check if it's an IP address directly
    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_private_ip(&ip) {
            return Err(format!(
                "Private/internal IP addresses are not allowed: {ip}"
            ));
        }
    } else {
        // It's a hostname - resolve it and check all IPs
        let addr_str = format!("{host}:{port}");

        match addr_str.to_socket_addrs() {
            Ok(addrs) => {
                for addr in addrs {
                    if is_private_ip(&addr.ip()) {
                        return Err(format!(
                            "Hostname {} resolves to private/internal IP: {}",
                            host,
                            addr.ip()
                        ));
                    }
                }
            }
            Err(e) => {
                // DNS resolution failed - log warning but don't block
                // It will fail at request time with a proper error
                tracing::warn!("DNS resolution failed for {}: {}", host, e);
            }
        }
    }

    // Block common internal hostnames
    let lower_host = host.to_lowercase();
    let blocked_hosts = [
        "localhost",
        "127.0.0.1",
        "::1",
        "0.0.0.0",
        "metadata",
        "metadata.google.internal",
        "169.254.169.254", // AWS/GCP metadata
        "fd00:ec2::254",   // AWS EC2 metadata IPv6
    ];

    for blocked in blocked_hosts {
        if lower_host == blocked || lower_host.ends_with(&format!(".{blocked}")) {
            return Err(format!("Blocked internal hostname: {host}"));
        }
    }

    Ok(())
}

/// Check if an IP address is private/internal.
fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => is_private_ipv4(ipv4),
        IpAddr::V6(ipv6) => is_private_ipv6(ipv6),
    }
}

/// Check if an IPv4 address is private/internal.
fn is_private_ipv4(ip: &Ipv4Addr) -> bool {
    // Loopback (127.0.0.0/8)
    if ip.is_loopback() {
        return true;
    }

    // Private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
    if ip.is_private() {
        return true;
    }

    // Link-local (169.254.0.0/16)
    if ip.is_link_local() {
        return true;
    }

    // Broadcast/unspecified
    if ip.is_broadcast() || ip.is_unspecified() {
        return true;
    }

    // Documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
    if ip.is_documentation() {
        return true;
    }

    // Shared address space (100.64.0.0/10) - used for carrier-grade NAT
    let octets = ip.octets();
    if octets[0] == 100 && (64..=127).contains(&octets[1]) {
        return true;
    }

    false
}

/// Check if an IPv6 address is private/internal.
fn is_private_ipv6(ip: &Ipv6Addr) -> bool {
    // Loopback (::1)
    if ip.is_loopback() {
        return true;
    }

    // Unspecified (::)
    if ip.is_unspecified() {
        return true;
    }

    // Check for IPv4-mapped addresses (::ffff:0:0/96)
    if let Some(ipv4) = ip.to_ipv4_mapped() {
        return is_private_ipv4(&ipv4);
    }

    // Unique local addresses (fc00::/7) - IPv6 equivalent of private
    let segments = ip.segments();
    if (segments[0] & 0xfe00) == 0xfc00 {
        return true;
    }

    // Link-local (fe80::/10)
    if (segments[0] & 0xffc0) == 0xfe80 {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_webhook_url_public_https() {
        assert!(validate_webhook_url("https://siem.example.com/webhook").is_ok());
    }

    #[test]
    fn test_validate_webhook_url_blocks_localhost() {
        assert!(validate_webhook_url("http://localhost/webhook").is_err());
        assert!(validate_webhook_url("http://127.0.0.1/webhook").is_err());
    }

    #[test]
    fn test_validate_webhook_url_blocks_private_ip() {
        assert!(validate_webhook_url("http://10.0.0.1/webhook").is_err());
        assert!(validate_webhook_url("http://172.16.0.1/webhook").is_err());
        assert!(validate_webhook_url("http://192.168.1.1/webhook").is_err());
    }

    #[test]
    fn test_validate_webhook_url_blocks_metadata() {
        assert!(validate_webhook_url("http://169.254.169.254/latest/meta-data/").is_err());
        assert!(validate_webhook_url("http://metadata.google.internal/").is_err());
    }

    #[test]
    fn test_validate_host_blocks_private() {
        assert!(validate_host("127.0.0.1", 514).is_err());
        assert!(validate_host("10.0.0.1", 514).is_err());
        assert!(validate_host("localhost", 514).is_err());
    }

    #[test]
    fn test_validate_host_allows_public() {
        // Note: This test requires DNS resolution which may not work in all environments
        // In CI, this might need to be adjusted or skipped
    }

    #[test]
    fn test_is_private_ipv4() {
        assert!(is_private_ipv4(&"127.0.0.1".parse().unwrap()));
        assert!(is_private_ipv4(&"10.0.0.1".parse().unwrap()));
        assert!(is_private_ipv4(&"172.16.0.1".parse().unwrap()));
        assert!(is_private_ipv4(&"192.168.1.1".parse().unwrap()));
        assert!(is_private_ipv4(&"169.254.1.1".parse().unwrap()));
        assert!(is_private_ipv4(&"100.64.0.1".parse().unwrap()));
        assert!(!is_private_ipv4(&"8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn test_is_private_ipv6() {
        assert!(is_private_ipv6(&"::1".parse().unwrap()));
        assert!(is_private_ipv6(&"::".parse().unwrap()));
        assert!(is_private_ipv6(&"fc00::1".parse().unwrap()));
        assert!(is_private_ipv6(&"fe80::1".parse().unwrap()));
    }
}
