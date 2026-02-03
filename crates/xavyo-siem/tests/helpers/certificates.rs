//! Test certificate generation for TLS testing.
//!
//! Uses rcgen to generate self-signed certificates at test runtime.

use rcgen::{CertificateParams, DnType, KeyPair, SanType};

/// Generate a self-signed test certificate for localhost.
///
/// Returns (certificate PEM, private key PEM) as byte vectors.
pub fn generate_test_cert() -> (Vec<u8>, Vec<u8>) {
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    params
        .distinguished_name
        .push(DnType::OrganizationName, "Xavyo Test");
    params.subject_alt_names = vec![
        SanType::DnsName("localhost".try_into().unwrap()),
        SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))),
    ];

    // Generate a key pair using default algorithm (ECDSA P-256)
    let key_pair = KeyPair::generate().expect("Failed to generate key pair");

    // Self-sign the certificate
    let cert = params
        .self_signed(&key_pair)
        .expect("Failed to generate certificate");

    (
        cert.pem().into_bytes(),
        key_pair.serialize_pem().into_bytes(),
    )
}

/// Generate a test certificate with a specific hostname.
pub fn generate_test_cert_for_host(hostname: &str) -> (Vec<u8>, Vec<u8>) {
    let mut params = CertificateParams::default();
    params.distinguished_name.push(DnType::CommonName, hostname);
    params
        .distinguished_name
        .push(DnType::OrganizationName, "Xavyo Test");
    params.subject_alt_names = vec![SanType::DnsName(hostname.try_into().unwrap())];

    let key_pair = KeyPair::generate().expect("Failed to generate key pair");
    let cert = params
        .self_signed(&key_pair)
        .expect("Failed to generate certificate");

    (
        cert.pem().into_bytes(),
        key_pair.serialize_pem().into_bytes(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_test_cert() {
        let (cert_pem, key_pem) = generate_test_cert();

        // Check that we got valid PEM data
        let cert_str = String::from_utf8(cert_pem).unwrap();
        let key_str = String::from_utf8(key_pem).unwrap();

        assert!(cert_str.contains("-----BEGIN CERTIFICATE-----"));
        assert!(cert_str.contains("-----END CERTIFICATE-----"));
        assert!(key_str.contains("-----BEGIN PRIVATE KEY-----"));
        assert!(key_str.contains("-----END PRIVATE KEY-----"));
    }

    #[test]
    fn test_generate_test_cert_for_host() {
        let (cert_pem, key_pem) = generate_test_cert_for_host("siem.example.com");

        let cert_str = String::from_utf8(cert_pem).unwrap();
        let key_str = String::from_utf8(key_pem).unwrap();

        assert!(cert_str.contains("-----BEGIN CERTIFICATE-----"));
        assert!(key_str.contains("-----BEGIN PRIVATE KEY-----"));
    }
}
