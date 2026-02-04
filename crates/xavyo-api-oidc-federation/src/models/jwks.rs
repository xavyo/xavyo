//! JWKS (JSON Web Key Set) models for token verification.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};

/// JSON Web Key Set - a collection of JWKs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwkSet {
    /// The array of JWKs.
    pub keys: Vec<Jwk>,
}

impl JwkSet {
    /// Find a key by its key ID (kid).
    #[must_use] 
    pub fn find_key(&self, kid: &str) -> Option<&Jwk> {
        self.keys.iter().find(|k| k.kid.as_deref() == Some(kid))
    }

    /// Find a key suitable for signature verification.
    /// If kid is provided, match by kid. Otherwise, return first RSA signing key.
    #[must_use] 
    pub fn find_signing_key(&self, kid: Option<&str>) -> Option<&Jwk> {
        if let Some(kid) = kid {
            self.find_key(kid)
        } else {
            // Find first RSA key with use=sig or no use specified
            self.keys
                .iter()
                .find(|k| k.kty == "RSA" && (k.use_.is_none() || k.use_.as_deref() == Some("sig")))
        }
    }
}

/// JSON Web Key - represents a single cryptographic key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    /// Key type (e.g., "RSA", "EC").
    pub kty: String,

    /// Public key use (e.g., "sig" for signature, "enc" for encryption).
    #[serde(rename = "use")]
    pub use_: Option<String>,

    /// Key ID - unique identifier for the key.
    pub kid: Option<String>,

    /// Algorithm (e.g., "RS256").
    pub alg: Option<String>,

    /// RSA modulus (base64url encoded).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,

    /// RSA exponent (base64url encoded).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,

    /// X.509 certificate chain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5c: Option<Vec<String>>,

    /// X.509 certificate thumbprint (SHA-1).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5t: Option<String>,
}

impl Jwk {
    /// Check if this key is an RSA key.
    #[must_use] 
    pub fn is_rsa(&self) -> bool {
        self.kty == "RSA"
    }

    /// Check if this key is suitable for signature verification.
    #[must_use] 
    pub fn is_signing_key(&self) -> bool {
        self.use_.is_none() || self.use_.as_deref() == Some("sig")
    }

    /// Convert RSA JWK to PEM-encoded public key.
    ///
    /// Returns None if the key is not an RSA key or required components are missing.
    #[must_use] 
    pub fn to_pem(&self) -> Option<Vec<u8>> {
        if !self.is_rsa() {
            return None;
        }

        let n = self.n.as_ref()?;
        let e = self.e.as_ref()?;

        // Decode base64url components
        let n_bytes = URL_SAFE_NO_PAD.decode(n).ok()?;
        let e_bytes = URL_SAFE_NO_PAD.decode(e).ok()?;

        // Build DER-encoded RSA public key
        let der = build_rsa_public_key_der(&n_bytes, &e_bytes);

        // Convert to PEM format
        let pem = build_pem("PUBLIC KEY", &der);

        Some(pem)
    }
}

/// Build DER-encoded RSA public key from modulus and exponent.
fn build_rsa_public_key_der(n: &[u8], e: &[u8]) -> Vec<u8> {
    // RSAPublicKey ::= SEQUENCE {
    //     modulus           INTEGER,  -- n
    //     publicExponent    INTEGER   -- e
    // }
    //
    // SubjectPublicKeyInfo ::= SEQUENCE {
    //     algorithm         AlgorithmIdentifier,
    //     subjectPublicKey  BIT STRING
    // }

    // Build the inner RSAPublicKey SEQUENCE
    let n_int = build_der_integer(n);
    let e_int = build_der_integer(e);

    let rsa_pub_key = build_der_sequence(&[&n_int, &e_int]);

    // AlgorithmIdentifier for RSA: OID 1.2.840.113549.1.1.1 with NULL params
    let rsa_oid = [
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
    ];
    let null_param = [0x05, 0x00];
    let algorithm = build_der_sequence(&[&rsa_oid, &null_param]);

    // BIT STRING wrapping the RSAPublicKey
    let mut bit_string = vec![0x03];
    let bs_content_len = rsa_pub_key.len() + 1; // +1 for unused bits byte
    encode_der_length(&mut bit_string, bs_content_len);
    bit_string.push(0x00); // unused bits = 0
    bit_string.extend_from_slice(&rsa_pub_key);

    // Final SubjectPublicKeyInfo SEQUENCE
    build_der_sequence(&[&algorithm, &bit_string])
}

/// Build a DER-encoded INTEGER.
fn build_der_integer(data: &[u8]) -> Vec<u8> {
    let mut result = vec![0x02]; // INTEGER tag

    // Skip leading zeros but keep at least one byte
    let mut start = 0;
    while start < data.len() - 1 && data[start] == 0 {
        start += 1;
    }
    let trimmed = &data[start..];

    // Add leading zero if high bit is set (to ensure positive integer)
    let needs_zero = !trimmed.is_empty() && (trimmed[0] & 0x80) != 0;

    let len = trimmed.len() + usize::from(needs_zero);
    encode_der_length(&mut result, len);

    if needs_zero {
        result.push(0x00);
    }
    result.extend_from_slice(trimmed);

    result
}

/// Build a DER-encoded SEQUENCE.
fn build_der_sequence(items: &[&[u8]]) -> Vec<u8> {
    let mut result = vec![0x30]; // SEQUENCE tag

    let total_len: usize = items.iter().map(|i| i.len()).sum();
    encode_der_length(&mut result, total_len);

    for item in items {
        result.extend_from_slice(item);
    }

    result
}

/// Encode DER length.
fn encode_der_length(buf: &mut Vec<u8>, len: usize) {
    if len < 128 {
        buf.push(len as u8);
    } else if len < 256 {
        buf.push(0x81);
        buf.push(len as u8);
    } else {
        buf.push(0x82);
        buf.push((len >> 8) as u8);
        buf.push((len & 0xFF) as u8);
    }
}

/// Build PEM-encoded key from label and DER data.
fn build_pem(label: &str, der: &[u8]) -> Vec<u8> {
    use base64::engine::general_purpose::STANDARD;

    let mut pem = format!("-----BEGIN {label}-----\n").into_bytes();

    let b64 = STANDARD.encode(der);
    for chunk in b64.as_bytes().chunks(64) {
        pem.extend_from_slice(chunk);
        pem.push(b'\n');
    }

    pem.extend_from_slice(format!("-----END {label}-----\n").as_bytes());
    pem
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwk_set_find_key() {
        let jwks = JwkSet {
            keys: vec![
                Jwk {
                    kty: "RSA".to_string(),
                    use_: Some("sig".to_string()),
                    kid: Some("key-1".to_string()),
                    alg: Some("RS256".to_string()),
                    n: Some("test".to_string()),
                    e: Some("AQAB".to_string()),
                    x5c: None,
                    x5t: None,
                },
                Jwk {
                    kty: "RSA".to_string(),
                    use_: Some("sig".to_string()),
                    kid: Some("key-2".to_string()),
                    alg: Some("RS256".to_string()),
                    n: Some("test2".to_string()),
                    e: Some("AQAB".to_string()),
                    x5c: None,
                    x5t: None,
                },
            ],
        };

        let key = jwks.find_key("key-1");
        assert!(key.is_some());
        assert_eq!(key.unwrap().kid, Some("key-1".to_string()));

        let key = jwks.find_key("key-3");
        assert!(key.is_none());
    }

    #[test]
    fn test_jwk_is_rsa() {
        let rsa_key = Jwk {
            kty: "RSA".to_string(),
            use_: Some("sig".to_string()),
            kid: Some("key-1".to_string()),
            alg: None,
            n: Some("test".to_string()),
            e: Some("AQAB".to_string()),
            x5c: None,
            x5t: None,
        };
        assert!(rsa_key.is_rsa());

        let ec_key = Jwk {
            kty: "EC".to_string(),
            use_: Some("sig".to_string()),
            kid: Some("key-2".to_string()),
            alg: None,
            n: None,
            e: None,
            x5c: None,
            x5t: None,
        };
        assert!(!ec_key.is_rsa());
    }

    #[test]
    fn test_jwk_is_signing_key() {
        let sig_key = Jwk {
            kty: "RSA".to_string(),
            use_: Some("sig".to_string()),
            kid: None,
            alg: None,
            n: None,
            e: None,
            x5c: None,
            x5t: None,
        };
        assert!(sig_key.is_signing_key());

        let enc_key = Jwk {
            kty: "RSA".to_string(),
            use_: Some("enc".to_string()),
            kid: None,
            alg: None,
            n: None,
            e: None,
            x5c: None,
            x5t: None,
        };
        assert!(!enc_key.is_signing_key());

        let no_use_key = Jwk {
            kty: "RSA".to_string(),
            use_: None,
            kid: None,
            alg: None,
            n: None,
            e: None,
            x5c: None,
            x5t: None,
        };
        assert!(no_use_key.is_signing_key());
    }
}
