//! Mutual-TLS certificate thumbprints (RFC 8705) for certificate-bound tokens.
//!
//! Pure (no I/O) helpers to compute the RFC 8705 §3.1 `x5t#S256` confirmation
//! value — the base64url-no-pad SHA-256 of a client certificate's DER encoding.
//! Used to bind an access token to a client's mTLS certificate (the `cnf`
//! member `x5t#S256`) and, at resource endpoints, to verify the presented
//! certificate matches.
//!
//! The certificate itself reaches the application from the TLS-terminating
//! gateway (e.g. a trusted header carrying the client cert / its thumbprint);
//! this module only does the cryptographic thumbprinting.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use sha2::{Digest, Sha256};

/// Compute the RFC 8705 `x5t#S256` value: base64url-no-pad SHA-256 of the
/// certificate's DER bytes.
#[must_use]
pub fn compute_x5t_s256(cert_der: &[u8]) -> String {
    let digest = Sha256::digest(cert_der);
    URL_SAFE_NO_PAD.encode(digest)
}

/// Extract the DER bytes from the first PEM `CERTIFICATE` block, if present.
#[must_use]
pub fn pem_to_der(pem: &str) -> Option<Vec<u8>> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let start = pem.find(BEGIN)? + BEGIN.len();
    let stop = pem.find(END)?;
    if stop <= start {
        return None;
    }
    let b64: String = pem[start..stop].split_whitespace().collect();
    STANDARD.decode(b64).ok()
}

/// Compute `x5t#S256` directly from a PEM-encoded certificate.
#[must_use]
pub fn x5t_s256_from_pem(pem: &str) -> Option<String> {
    pem_to_der(pem).map(|der| compute_x5t_s256(&der))
}

/// Whether a certificate-bound token's confirmation is satisfied by the
/// presented client certificate (RFC 8705 §3): the presented cert's `x5t#S256`
/// MUST be present and equal to the token's `cnf["x5t#S256"]`. Fail-closed —
/// a missing presented thumbprint never satisfies a cert-bound token.
#[must_use]
pub fn cert_binding_satisfied(token_x5t_s256: &str, presented_x5t_s256: Option<&str>) -> bool {
    presented_x5t_s256 == Some(token_x5t_s256)
}

/// Accept a forwarded client-cert thumbprint only when the TLS terminator
/// also asserted verification (`X-SSL-Client-Verify: SUCCESS`). A lone
/// `X-Client-Cert-Thumbprint` from an untrusted client is ignored.
#[must_use]
pub fn forwarded_cert_thumbprint<'a>(
    ssl_client_verify: Option<&'a str>,
    thumbprint: Option<&'a str>,
) -> Option<&'a str> {
    match ssl_client_verify {
        Some(v) if v.eq_ignore_ascii_case("SUCCESS") => thumbprint,
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Throwaway self-signed cert (CN=mtls-test-client) — TEST ONLY.
    // Its `x5t#S256` (computed independently via openssl) is the EXPECTED value.
    const TEST_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIDFzCCAf+gAwIBAgIUbwjmdXjP5dXtLYd30NOmOeYT2AYwDQYJKoZIhvcNAQEL
BQAwGzEZMBcGA1UEAwwQbXRscy10ZXN0LWNsaWVudDAeFw0yNjA1MjQyMDE1NDha
Fw0yNjA1MjYyMDE1NDhaMBsxGTAXBgNVBAMMEG10bHMtdGVzdC1jbGllbnQwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCmhTZHq2fPWBSX9zwXEJOzfF11
nX12rGGkDZqVkBGWvSGIZWeIlgVuAQFdYwjUhIXos1NsKheuLhQieoI4EPNObZYU
B45b1EThc3PSPI6DvryTIwV4NSOKoMYRauIo9Wnld/Q3yohJmRGGYn0nhCBr8Xpp
6TQ79B+6uy9hcFSuCIkPDZPHVGbKQDsACK9iFCqJvdKRe5JHwOkDoCDuQ9BNTtRY
wqu9drSAZVwEyL3zgsStklACOsINd11iVDxlA64jJ74ET2kESZLRp62ZixXiqt/L
0f4bg5Z7/10TjKFz7eIWS2YzaxkJYFEo9AWmC6xOCqIniie7gB5ZBYpvvJW5AgMB
AAGjUzBRMB0GA1UdDgQWBBRQm6FDbVoe8Oz3MrQFQcbK4dB8HTAfBgNVHSMEGDAW
gBRQm6FDbVoe8Oz3MrQFQcbK4dB8HTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3
DQEBCwUAA4IBAQBsYMKY2E1zh5LcPJsnfgAJRCvDBc6z3jCYuqjlDEaTsrwey0tC
8AgKWo6NL1FRYzh+7V2QnjF9unE0xbXpaJFditDSch1sPriDBrjosB41wu+I5Zt5
UBlFYPhjftMl5W8VPFaed3G+h6C4+M1QSqB9mejwerJ2dKWgjihQ0tekPIpLy8St
sqqhxRytC11avpcTZjG6OYinKTilM5P41twG7HlfrbLc8xyz2PKGJkyKHxSvo9yq
sgecHrmM1KGM7LSFDlvz3ivG8nJrbRVaxvoba3AOMSXOrgvPYFgOMDxmlqu8rgnL
NGdmso7Y1SHNIjM37dHlwgVBOboONKzg7liB
-----END CERTIFICATE-----";

    const EXPECTED_X5T: &str = "ZKcRjPtxMyQxhrPLIM-aPlVhmBmhWjk1dNkmq0lBf18";

    #[test]
    fn x5t_s256_from_pem_matches_openssl() {
        assert_eq!(x5t_s256_from_pem(TEST_CERT_PEM).unwrap(), EXPECTED_X5T);
    }

    #[test]
    fn x5t_is_base64url_no_pad_length() {
        // SHA-256 = 32 bytes → 43 base64url chars, no padding.
        let t = x5t_s256_from_pem(TEST_CERT_PEM).unwrap();
        assert_eq!(t.len(), 43);
        assert!(!t.contains('=') && !t.contains('+') && !t.contains('/'));
    }

    #[test]
    fn compute_is_deterministic() {
        let der = pem_to_der(TEST_CERT_PEM).unwrap();
        assert_eq!(compute_x5t_s256(&der), compute_x5t_s256(&der));
    }

    #[test]
    fn pem_to_der_rejects_garbage() {
        assert!(pem_to_der("not a pem").is_none());
        assert!(
            pem_to_der("-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----").is_none()
        );
    }

    #[test]
    fn cert_binding_is_fail_closed() {
        assert!(cert_binding_satisfied(EXPECTED_X5T, Some(EXPECTED_X5T)));
        // Missing presented cert never satisfies a cert-bound token.
        assert!(!cert_binding_satisfied(EXPECTED_X5T, None));
        // Mismatched thumbprint is rejected.
        assert!(!cert_binding_satisfied(EXPECTED_X5T, Some("different")));
    }

    #[test]
    fn lone_client_thumbprint_header_is_ignored() {
        assert_eq!(forwarded_cert_thumbprint(None, Some(EXPECTED_X5T)), None);
        assert_eq!(
            forwarded_cert_thumbprint(Some("SUCCESS"), Some(EXPECTED_X5T)),
            Some(EXPECTED_X5T)
        );
        assert_eq!(
            forwarded_cert_thumbprint(Some("NONE"), Some(EXPECTED_X5T)),
            None
        );
    }
}
