//! SAML signing utilities using X.509 certificates

use crate::error::{SamlError, SamlResult};
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Signer;
use openssl::x509::X509;

/// X.509 certificate and key pair for SAML signing
#[derive(Clone)]
pub struct SigningCredentials {
    certificate: X509,
    private_key: PKey<openssl::pkey::Private>,
    key_id: String,
}

impl SigningCredentials {
    /// Create credentials from PEM-encoded certificate and private key
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> SamlResult<Self> {
        let certificate = X509::from_pem(cert_pem.as_bytes()).map_err(|e| {
            SamlError::CertificateParseError(format!("Failed to parse certificate: {}", e))
        })?;

        let private_key = PKey::private_key_from_pem(key_pem.as_bytes()).map_err(|e| {
            SamlError::PrivateKeyError(format!("Failed to parse private key: {}", e))
        })?;

        // Compute key_id as SHA-256 thumbprint of certificate
        let key_id = compute_certificate_thumbprint(&certificate)?;

        Ok(Self {
            certificate,
            private_key,
            key_id,
        })
    }

    /// Get the certificate in PEM format
    pub fn certificate_pem(&self) -> SamlResult<String> {
        let pem = self.certificate.to_pem().map_err(|e| {
            SamlError::CertificateParseError(format!("Failed to encode certificate: {}", e))
        })?;
        String::from_utf8(pem)
            .map_err(|e| SamlError::CertificateParseError(format!("Invalid UTF-8 in PEM: {}", e)))
    }

    /// Get the certificate in base64 DER format (for KeyInfo)
    pub fn certificate_base64_der(&self) -> SamlResult<String> {
        let der = self.certificate.to_der().map_err(|e| {
            SamlError::CertificateParseError(format!("Failed to encode certificate DER: {}", e))
        })?;
        Ok(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &der,
        ))
    }

    /// Get the key ID (certificate thumbprint)
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Get the subject DN
    pub fn subject_dn(&self) -> String {
        self.certificate
            .subject_name()
            .entries()
            .map(|e| {
                format!(
                    "{}={}",
                    e.object().nid().short_name().unwrap_or("?"),
                    e.data()
                        .as_utf8()
                        .map(|s| s.to_string())
                        .unwrap_or_default()
                )
            })
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Get the issuer DN
    pub fn issuer_dn(&self) -> String {
        self.certificate
            .issuer_name()
            .entries()
            .map(|e| {
                format!(
                    "{}={}",
                    e.object().nid().short_name().unwrap_or("?"),
                    e.data()
                        .as_utf8()
                        .map(|s| s.to_string())
                        .unwrap_or_default()
                )
            })
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Get certificate validity start
    pub fn not_before(&self) -> chrono::DateTime<chrono::Utc> {
        asn1_time_to_datetime(self.certificate.not_before())
    }

    /// Get certificate validity end
    pub fn not_after(&self) -> chrono::DateTime<chrono::Utc> {
        asn1_time_to_datetime(self.certificate.not_after())
    }

    /// Sign data using RSA-SHA256
    pub fn sign_sha256(&self, data: &[u8]) -> SamlResult<Vec<u8>> {
        let mut signer = Signer::new(MessageDigest::sha256(), &self.private_key).map_err(|e| {
            SamlError::AssertionGenerationFailed(format!("Failed to create signer: {}", e))
        })?;

        signer.update(data).map_err(|e| {
            SamlError::AssertionGenerationFailed(format!("Failed to update signer: {}", e))
        })?;

        signer
            .sign_to_vec()
            .map_err(|e| SamlError::AssertionGenerationFailed(format!("Failed to sign: {}", e)))
    }
}

/// Compute SHA-256 thumbprint of certificate
fn compute_certificate_thumbprint(cert: &X509) -> SamlResult<String> {
    let der = cert.to_der().map_err(|e| {
        SamlError::CertificateParseError(format!("Failed to encode certificate DER: {}", e))
    })?;

    let digest = openssl::hash::hash(MessageDigest::sha256(), &der).map_err(|e| {
        SamlError::CertificateParseError(format!("Failed to compute thumbprint: {}", e))
    })?;

    Ok(hex::encode(digest))
}

/// Convert OpenSSL ASN1 time to chrono DateTime
fn asn1_time_to_datetime(time: &openssl::asn1::Asn1TimeRef) -> chrono::DateTime<chrono::Utc> {
    // ASN1 time format is YYYYMMDDHHMMSSZ or YYMMDDHHMMSSZ
    let time_str = time.to_string();

    // Try to parse as RFC2822 or fall back to now
    chrono::DateTime::parse_from_rfc2822(&time_str)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .unwrap_or_else(|_| {
            // Try common ASN1 format: "Mon DD HH:MM:SS YYYY GMT"
            chrono::NaiveDateTime::parse_from_str(&time_str, "%b %d %H:%M:%S %Y GMT")
                .map(|ndt| chrono::DateTime::from_naive_utc_and_offset(ndt, chrono::Utc))
                .unwrap_or_else(|_| chrono::Utc::now())
        })
}

/// Parse an SP certificate for signature validation
pub fn parse_sp_certificate(cert_pem: &str) -> SamlResult<X509> {
    X509::from_pem(cert_pem.as_bytes()).map_err(|e| {
        SamlError::InvalidSpCertificate(format!("Failed to parse SP certificate: {}", e))
    })
}

/// Verify a signature using an SP's certificate
pub fn verify_signature(cert: &X509, signature: &[u8], data: &[u8]) -> SamlResult<bool> {
    let public_key = cert
        .public_key()
        .map_err(|e| SamlError::InvalidSpCertificate(format!("Failed to get public key: {}", e)))?;

    let mut verifier =
        openssl::sign::Verifier::new(MessageDigest::sha256(), &public_key).map_err(|e| {
            SamlError::SignatureValidationFailed(format!("Failed to create verifier: {}", e))
        })?;

    verifier.update(data).map_err(|e| {
        SamlError::SignatureValidationFailed(format!("Failed to update verifier: {}", e))
    })?;

    verifier
        .verify(signature)
        .map_err(|e| SamlError::SignatureValidationFailed(format!("Verification failed: {}", e)))
}

// Add hex encoding dependency
mod hex {
    pub fn encode(data: impl AsRef<[u8]>) -> String {
        data.as_ref().iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test certificate (self-signed for testing)
    const TEST_CERT: &str = r#"-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHBfNPqGLvIMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl
c3RDQTAPIBY2NTAxMDEwMDAwMDBaFw0zNTAxMDEwMDAwMDBaMBExDzANBgNVBAMM
BnRlc3RDQTBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC6xoLYdPl0bZR0VTQBa3l0
lVn+HbNdALhEpLVnNaEQ+L5HRpQG3YS9lhP1EY7Qcp+0hqPCAVJ+0TH9KV3XRVNH
AgMBAAGjUzBRMB0GA1UdDgQWBBRDt0lYy4N5NXUV0kCEwL8P9cjhNjAfBgNVHSME
GDAWgBRDt0lYy4N5NXUV0kCEwL8P9cjhNjAPBgNVHRMBAf8EBTADAQH/MA0GCSqG
SIb3DQEBCwUAA0EA
-----END CERTIFICATE-----"#;

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex::encode([0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }
}
