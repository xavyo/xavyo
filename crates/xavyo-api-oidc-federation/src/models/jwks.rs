//! JWKS (JSON Web Key Set) models for token verification.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use xavyo_auth::Algorithm;

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
    /// If kid is provided, match by kid. Otherwise, return first RSA or EC signing key.
    #[must_use]
    pub fn find_signing_key(&self, kid: Option<&str>) -> Option<&Jwk> {
        if let Some(kid) = kid {
            self.find_key(kid)
        } else {
            // Find first RSA or EC key with use=sig or no use specified
            self.keys.iter().find(|k| {
                (k.kty == "RSA" || k.kty == "EC")
                    && (k.use_.is_none() || k.use_.as_deref() == Some("sig"))
            })
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

    /// EC curve name (e.g., "P-256", "P-384").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,

    /// EC X coordinate (base64url encoded).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,

    /// EC Y coordinate (base64url encoded).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
}

/// Decoded JWK information for token verification.
pub struct JwkDecodingInfo {
    /// PEM-encoded public key bytes.
    pub pem: Vec<u8>,
    /// Detected algorithm for this key.
    pub algorithm: Algorithm,
}

impl Jwk {
    /// Check if this key is an RSA key.
    #[must_use]
    pub fn is_rsa(&self) -> bool {
        self.kty == "RSA"
    }

    /// Check if this key is an EC key.
    #[must_use]
    pub fn is_ec(&self) -> bool {
        self.kty == "EC"
    }

    /// Check if this key is suitable for signature verification.
    #[must_use]
    pub fn is_signing_key(&self) -> bool {
        self.use_.is_none() || self.use_.as_deref() == Some("sig")
    }

    /// Detect the algorithm for this JWK.
    ///
    /// Uses the `alg` field if present, otherwise falls back to `kty`+`crv`.
    /// Algorithm is determined from the JWK itself (never from untrusted JWT headers).
    #[must_use]
    pub fn algorithm(&self) -> Option<Algorithm> {
        // Prefer explicit alg field
        if let Some(ref alg) = self.alg {
            return match alg.as_str() {
                "RS256" => Some(Algorithm::RS256),
                "RS384" => Some(Algorithm::RS384),
                "RS512" => Some(Algorithm::RS512),
                "ES256" => Some(Algorithm::ES256),
                "ES384" => Some(Algorithm::ES384),
                _ => None,
            };
        }

        // Fallback: kty + crv
        match self.kty.as_str() {
            "RSA" => Some(Algorithm::RS256), // Default RSA algorithm
            "EC" => match self.crv.as_deref() {
                Some("P-256") => Some(Algorithm::ES256),
                Some("P-384") => Some(Algorithm::ES384),
                _ => None,
            },
            _ => None,
        }
    }

    /// Get PEM and algorithm together for token verification.
    ///
    /// Returns `None` if the key type is unsupported or required fields are missing.
    #[must_use]
    pub fn decoding_info(&self) -> Option<JwkDecodingInfo> {
        Some(JwkDecodingInfo {
            pem: self.to_pem()?,
            algorithm: self.algorithm()?,
        })
    }

    /// Convert JWK to PEM-encoded public key.
    ///
    /// Supports RSA and EC (P-256, P-384) keys.
    /// Returns None if the key type is unsupported or required components are missing.
    #[must_use]
    pub fn to_pem(&self) -> Option<Vec<u8>> {
        if self.is_rsa() {
            let n = self.n.as_ref()?;
            let e = self.e.as_ref()?;

            let n_bytes = URL_SAFE_NO_PAD.decode(n).ok()?;
            let e_bytes = URL_SAFE_NO_PAD.decode(e).ok()?;

            let der = build_rsa_public_key_der(&n_bytes, &e_bytes);
            Some(build_pem("PUBLIC KEY", &der))
        } else if self.is_ec() {
            let crv = self.crv.as_deref()?;
            let x = self.x.as_ref()?;
            let y = self.y.as_ref()?;

            let x_bytes = URL_SAFE_NO_PAD.decode(x).ok()?;
            let y_bytes = URL_SAFE_NO_PAD.decode(y).ok()?;

            let der = build_ec_public_key_der(crv, &x_bytes, &y_bytes)?;
            Some(build_pem("PUBLIC KEY", &der))
        } else {
            None
        }
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

    // R9: Guard against empty input to prevent underflow in `data.len() - 1`
    if data.is_empty() {
        result.push(1); // length
        result.push(0); // INTEGER 0
        return result;
    }

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

/// Build DER-encoded EC SubjectPublicKeyInfo from curve name and coordinates.
///
/// Returns `None` for unsupported curves.
fn build_ec_public_key_der(crv: &str, x: &[u8], y: &[u8]) -> Option<Vec<u8>> {
    // Curve OIDs and expected coordinate sizes
    let (curve_oid, coord_size): (&[u8], usize) = match crv {
        "P-256" => (
            // OID 1.2.840.10045.3.1.7 (prime256v1)
            &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07],
            32,
        ),
        "P-384" => (
            // OID 1.3.132.0.34 (secp384r1)
            &[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22],
            48,
        ),
        _ => return None,
    };

    // Left-pad coordinates to expected size
    let x_padded = left_pad_bytes(x, coord_size);
    let y_padded = left_pad_bytes(y, coord_size);

    // Uncompressed EC point: 0x04 || x || y
    let mut point = Vec::with_capacity(1 + 2 * coord_size);
    point.push(0x04);
    point.extend_from_slice(&x_padded);
    point.extend_from_slice(&y_padded);

    // EC algorithm OID: 1.2.840.10045.2.1 (id-ecPublicKey)
    let ec_oid: &[u8] = &[0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];

    // AlgorithmIdentifier SEQUENCE: ecPublicKey OID + curve OID
    let algorithm = build_der_sequence(&[ec_oid, curve_oid]);

    // BIT STRING wrapping the EC point
    let mut bit_string = vec![0x03];
    let bs_content_len = point.len() + 1; // +1 for unused bits byte
    encode_der_length(&mut bit_string, bs_content_len);
    bit_string.push(0x00); // unused bits = 0
    bit_string.extend_from_slice(&point);

    // SubjectPublicKeyInfo SEQUENCE
    Some(build_der_sequence(&[&algorithm, &bit_string]))
}

/// Left-pad bytes to a target length with leading zeros.
fn left_pad_bytes(data: &[u8], target_len: usize) -> Vec<u8> {
    if data.len() >= target_len {
        // If longer (leading zeros in base64url encoding), take the last target_len bytes
        return data[data.len() - target_len..].to_vec();
    }
    let mut padded = vec![0u8; target_len - data.len()];
    padded.extend_from_slice(data);
    padded
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
                    crv: None,
                    x: None,
                    y: None,
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
                    crv: None,
                    x: None,
                    y: None,
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
            crv: None,
            x: None,
            y: None,
        };
        assert!(rsa_key.is_rsa());
        assert!(!rsa_key.is_ec());

        let ec_key = Jwk {
            kty: "EC".to_string(),
            use_: Some("sig".to_string()),
            kid: Some("key-2".to_string()),
            alg: None,
            n: None,
            e: None,
            x5c: None,
            x5t: None,
            crv: Some("P-256".to_string()),
            x: Some("test".to_string()),
            y: Some("test".to_string()),
        };
        assert!(!ec_key.is_rsa());
        assert!(ec_key.is_ec());
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
            crv: None,
            x: None,
            y: None,
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
            crv: None,
            x: None,
            y: None,
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
            crv: None,
            x: None,
            y: None,
        };
        assert!(no_use_key.is_signing_key());
    }

    #[test]
    fn test_ec_algorithm_detection() {
        // Explicit alg field
        let jwk = Jwk {
            kty: "EC".to_string(),
            use_: Some("sig".to_string()),
            kid: None,
            alg: Some("ES256".to_string()),
            n: None,
            e: None,
            x5c: None,
            x5t: None,
            crv: Some("P-256".to_string()),
            x: Some("test".to_string()),
            y: Some("test".to_string()),
        };
        assert_eq!(jwk.algorithm(), Some(Algorithm::ES256));

        // Fallback: kty + crv (no alg)
        let jwk_no_alg = Jwk {
            kty: "EC".to_string(),
            use_: Some("sig".to_string()),
            kid: None,
            alg: None,
            n: None,
            e: None,
            x5c: None,
            x5t: None,
            crv: Some("P-384".to_string()),
            x: Some("test".to_string()),
            y: Some("test".to_string()),
        };
        assert_eq!(jwk_no_alg.algorithm(), Some(Algorithm::ES384));

        // RSA default
        let rsa_jwk = Jwk {
            kty: "RSA".to_string(),
            use_: Some("sig".to_string()),
            kid: None,
            alg: None,
            n: Some("test".to_string()),
            e: Some("AQAB".to_string()),
            x5c: None,
            x5t: None,
            crv: None,
            x: None,
            y: None,
        };
        assert_eq!(rsa_jwk.algorithm(), Some(Algorithm::RS256));
    }

    #[test]
    fn test_ec_jwk_to_pem_p256() {
        // Known P-256 test key coordinates (from RFC 7517 appendix examples)
        let jwk = Jwk {
            kty: "EC".to_string(),
            use_: Some("sig".to_string()),
            kid: Some("ec-test".to_string()),
            alg: Some("ES256".to_string()),
            n: None,
            e: None,
            x5c: None,
            x5t: None,
            crv: Some("P-256".to_string()),
            x: Some("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU".to_string()),
            y: Some("x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0".to_string()),
        };

        let pem = jwk.to_pem();
        assert!(pem.is_some());

        let pem_str = String::from_utf8(pem.unwrap()).unwrap();
        assert!(pem_str.starts_with("-----BEGIN PUBLIC KEY-----"));
        assert!(pem_str.ends_with("-----END PUBLIC KEY-----\n"));
    }

    #[test]
    fn test_find_signing_key_ec_fallback() {
        // JWKS with only an EC key (no kid match needed)
        let jwks = JwkSet {
            keys: vec![Jwk {
                kty: "EC".to_string(),
                use_: Some("sig".to_string()),
                kid: Some("ec-key-1".to_string()),
                alg: Some("ES256".to_string()),
                n: None,
                e: None,
                x5c: None,
                x5t: None,
                crv: Some("P-256".to_string()),
                x: Some("test".to_string()),
                y: Some("test".to_string()),
            }],
        };

        // Should find EC key when no kid specified
        let key = jwks.find_signing_key(None);
        assert!(key.is_some());
        assert_eq!(key.unwrap().kty, "EC");

        // Should find by kid
        let key = jwks.find_signing_key(Some("ec-key-1"));
        assert!(key.is_some());
    }

    #[test]
    fn test_ec_jwk_unsupported_curve() {
        let jwk = Jwk {
            kty: "EC".to_string(),
            use_: Some("sig".to_string()),
            kid: None,
            alg: None,
            n: None,
            e: None,
            x5c: None,
            x5t: None,
            crv: Some("P-521".to_string()),
            x: Some("test".to_string()),
            y: Some("test".to_string()),
        };

        // P-521 not supported by jsonwebtoken crate
        assert_eq!(jwk.algorithm(), None);
        assert!(jwk.to_pem().is_none());
        assert!(jwk.decoding_info().is_none());
    }
}
