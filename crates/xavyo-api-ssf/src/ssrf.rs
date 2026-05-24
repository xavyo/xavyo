//! SSRF guard for SSF receiver endpoints.
//!
//! The push transmitter POSTs Security Event Tokens to a receiver-supplied
//! `endpoint_url`. Left unchecked, that turns the IdP into an SSRF primitive
//! (an attacker registers a stream pointing at `http://169.254.169.254/…` or an
//! internal service). This module enforces, at registration time: `https` only,
//! and — when the host is an IP literal — that the address is public (no
//! loopback / private / link-local / ULA / CGNAT / unspecified / multicast).
//!
//! NOTE (documented limitation): a *hostname* that resolves to a private
//! address at delivery time is not caught here. Closing that requires a
//! resolving HTTP connector that re-checks the resolved IP at connect time
//! (DNS-rebinding-safe) — tracked for the transmitter (increment D2).

use crate::error::SsfApiError;
use std::net::{Ipv4Addr, Ipv6Addr};
use url::{Host, Url};

/// Validate that a receiver endpoint URL is safe for the transmitter to call.
///
/// # Errors
/// [`SsfApiError::InvalidRequest`] if the URL is malformed, not `https`, has no
/// host, names an internal host, or is an IP literal in a non-public range.
pub fn validate_receiver_url(raw: &str) -> Result<(), SsfApiError> {
    let url = Url::parse(raw)
        .map_err(|_| SsfApiError::InvalidRequest("endpoint_url is not a valid URL".to_string()))?;

    if url.scheme() != "https" {
        return Err(SsfApiError::InvalidRequest(
            "endpoint_url must use https".to_string(),
        ));
    }

    match url.host() {
        Some(Host::Domain(domain)) => {
            let d = domain.to_ascii_lowercase();
            if d == "localhost"
                || d.ends_with(".localhost")
                || d.ends_with(".local")
                || d.ends_with(".internal")
            {
                return Err(SsfApiError::InvalidRequest(
                    "endpoint_url host is not allowed".to_string(),
                ));
            }
            Ok(())
        }
        Some(Host::Ipv4(ip)) => {
            if ipv4_is_public(ip) {
                Ok(())
            } else {
                Err(SsfApiError::InvalidRequest(
                    "endpoint_url must not target a non-public IP".to_string(),
                ))
            }
        }
        Some(Host::Ipv6(ip)) => {
            if ipv6_is_public(ip) {
                Ok(())
            } else {
                Err(SsfApiError::InvalidRequest(
                    "endpoint_url must not target a non-public IP".to_string(),
                ))
            }
        }
        None => Err(SsfApiError::InvalidRequest(
            "endpoint_url has no host".to_string(),
        )),
    }
}

/// Whether an IPv4 address is a public/global address safe to call.
fn ipv4_is_public(ip: Ipv4Addr) -> bool {
    let [a, b, _, _] = ip.octets();
    !(ip.is_private()         // 10/8, 172.16/12, 192.168/16
        || ip.is_loopback()      // 127/8
        || ip.is_link_local()    // 169.254/16
        || ip.is_unspecified()   // 0.0.0.0
        || ip.is_broadcast()     // 255.255.255.255
        || ip.is_documentation() // 192.0.2/24, 198.51.100/24, 203.0.113/24
        || ip.is_multicast()     // 224/4
        || a == 0                // 0/8
        || (a == 100 && (64..=127).contains(&b))) // 100.64/10 CGNAT
}

/// Whether an IPv6 address is a public/global address safe to call.
fn ipv6_is_public(ip: Ipv6Addr) -> bool {
    // IPv4-mapped (::ffff:0:0/96) — classify the embedded IPv4.
    if let Some(v4) = ip.to_ipv4_mapped() {
        return ipv4_is_public(v4);
    }
    let seg0 = ip.segments()[0];
    !(ip.is_loopback()                  // ::1
        || ip.is_unspecified()             // ::
        || ip.is_multicast()               // ff00::/8
        || (seg0 & 0xfe00) == 0xfc00       // ULA fc00::/7
        || (seg0 & 0xffc0) == 0xfe80) // link-local fe80::/10
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(u: &str) -> bool {
        validate_receiver_url(u).is_ok()
    }

    #[test]
    fn accepts_public_https() {
        assert!(ok("https://rp.example.com/ssf"));
        assert!(ok("https://93.184.216.34/ssf")); // public IP literal
        assert!(ok("https://[2606:2800:220:1:248:1893:25c8:1946]/ssf")); // public v6
    }

    #[test]
    fn rejects_non_https() {
        assert!(!ok("http://rp.example.com/ssf"));
        assert!(!ok("ftp://rp.example.com"));
    }

    #[test]
    fn rejects_internal_hostnames() {
        assert!(!ok("https://localhost/ssf"));
        assert!(!ok("https://foo.localhost/ssf"));
        assert!(!ok("https://svc.internal/ssf"));
        assert!(!ok("https://printer.local/ssf"));
    }

    #[test]
    fn rejects_private_and_special_ipv4() {
        for h in [
            "https://127.0.0.1/x",
            "https://10.0.0.5/x",
            "https://172.16.0.1/x",
            "https://192.168.1.1/x",
            "https://169.254.169.254/x", // cloud metadata
            "https://0.0.0.0/x",
            "https://100.64.0.1/x", // CGNAT
        ] {
            assert!(!ok(h), "should reject {h}");
        }
    }

    #[test]
    fn rejects_private_and_special_ipv6() {
        for h in [
            "https://[::1]/x",             // loopback
            "https://[::]/x",              // unspecified
            "https://[fc00::1]/x",         // ULA
            "https://[fe80::1]/x",         // link-local
            "https://[::ffff:10.0.0.1]/x", // v4-mapped private
        ] {
            assert!(!ok(h), "should reject {h}");
        }
    }

    #[test]
    fn rejects_malformed() {
        assert!(!ok("not a url"));
        assert!(!ok("https://"));
    }
}
