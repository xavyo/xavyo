//! Security Event Token (SET) builder/signer (RFC 8417 + SSF §4).
//!
//! Builds and signs the SET that carries a single CAEP event to a stream's
//! receiver. Per SSF §4: explicit typing (`typ: "secevent+jwt"`), a top-level
//! `sub_id` Subject Identifier, an `events` claim, and **no `sub` and no `exp`**
//! claims. Signed RS256 with the OAuth signing key + `kid` (verifiable via the
//! existing JWKS).

use crate::events::CaepEvent;
use crate::subject::SubjectId;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::Serialize;
use thiserror::Error;

/// Explicit SET media type for the JOSE `typ` header (SSF §4).
pub const SET_TYP: &str = "secevent+jwt";

/// Errors from SET construction/signing.
#[derive(Debug, Error)]
pub enum SsfError {
    /// The RSA signing key (PEM) could not be loaded.
    #[error("invalid signing key: {0}")]
    InvalidKey(String),
    /// JWS encoding failed.
    #[error("failed to sign SET: {0}")]
    Signing(String),
}

/// A Security Event Token to emit to one stream's receiver.
#[derive(Debug, Clone)]
pub struct SecurityEventToken {
    /// The transmitter's issuer identifier (xavyo issuer).
    pub issuer: String,
    /// The intended receiver (the stream's `aud`).
    pub audience: String,
    /// The subject the event is about.
    pub subject: SubjectId,
    /// The single CAEP event conveyed.
    pub event: CaepEvent,
}

#[derive(Serialize)]
struct SetClaims {
    iss: String,
    iat: i64,
    jti: String,
    aud: String,
    sub_id: serde_json::Value,
    events: serde_json::Value,
}

impl SecurityEventToken {
    /// Construct a SET for `event` about `subject`, from `issuer` to `audience`.
    pub fn new(
        issuer: impl Into<String>,
        audience: impl Into<String>,
        subject: SubjectId,
        event: CaepEvent,
    ) -> Self {
        Self {
            issuer: issuer.into(),
            audience: audience.into(),
            subject,
            event,
        }
    }

    /// Build the (unsigned) SET claims. `now` is the `iat`; `jti` is the unique
    /// token id. The `events` claim is the single-entry map
    /// `{ "<type-uri>": { <payload> } }`. No `sub`/`exp` (SSF §4.1.2/§4.1.7).
    fn claims(&self, now: i64, jti: &str) -> SetClaims {
        let mut events = serde_json::Map::new();
        events.insert(self.event.type_uri().to_string(), self.event.payload());
        SetClaims {
            iss: self.issuer.clone(),
            iat: now,
            jti: jti.to_string(),
            aud: self.audience.clone(),
            sub_id: serde_json::to_value(&self.subject).unwrap_or(serde_json::Value::Null),
            events: serde_json::Value::Object(events),
        }
    }

    /// Sign the SET into a compact JWS (RS256, `typ: secevent+jwt`, `kid`).
    ///
    /// # Errors
    /// [`SsfError::InvalidKey`] if the PEM is not a usable RSA private key;
    /// [`SsfError::Signing`] if JWS encoding fails.
    pub fn sign(
        &self,
        private_key_pem: &[u8],
        kid: &str,
        now: i64,
        jti: &str,
    ) -> Result<String, SsfError> {
        let key = EncodingKey::from_rsa_pem(private_key_pem)
            .map_err(|e| SsfError::InvalidKey(e.to_string()))?;
        let mut header = Header::new(Algorithm::RS256);
        header.typ = Some(SET_TYP.to_string());
        header.kid = Some(kid.to_string());
        encode(&header, &self.claims(now, jti), &key).map_err(|e| SsfError::Signing(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{CredentialChangeType, CREDENTIAL_CHANGE_URI, SESSION_REVOKED_URI};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use jsonwebtoken::{decode, DecodingKey, Validation};
    use std::collections::HashSet;

    // Throwaway RSA-2048 test keypair — TEST ONLY, never used in production.
    const TEST_PRIV: &str = "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7WUnwVG6nYOUZ
5rZdcLHie0TFPUPXlWb2oP1KnVPTzXkUm/0SdeBUVr767OIIe1VVNTJss56MAzRc
cv8mbxBDOUbowvQQ4tvxtLONNKQTk1a0m4QxiJlpoX/EXXnqC1OTuV8w6gWxjqzz
gDMWJs13Jtu1FQHac2mL0bYLNNhGov3tWdrXd620asjUUx0aP/b0MozI69tsQfvM
WsJZNII6IE7ZqKGSkyGU8RKrH1wlqVb20is3EQn5FzS4MlC/nXFc6YazjAdVEV12
prZe/ztFCy37omPlAx4GMqqXukpDzCbg3BxlLjFKU8duz6pFaxbr2SqGw5z6xuT8
Z9CI/jifAgMBAAECggEAEERMxDOV4ViWFoKkEPGTsGuC6XFMA7BINAp/E6HHa9t/
s4dmbi+SnnVjDbHQX8DTBEajLdxcBszRw2PaEuyPx+vK5Ajmsin7GOiCB9+rOLvm
n7XlFiabKMMfWd3Ck8y59q32Eu7ZjF+BVX8rGwrxdMgInuzHsBUB9A7ttIQOcfYs
98TLh/YOknXWwmf9J0XYcC2R31hCtEh5Ycd1w57m3AnUnAXhzv50lyYDjLK8E9v/
hXdcvC+iZ6X8bbQbn5UUkFg1sSbcIUACoxo0NBC6PCTqEbiTLppI2ZfJgHp1Z7wz
6oh3ORNfaNAixw3h1OCDS+USmeUNoltG/qT/ftmQ0QKBgQDdL6M79dYjx+OqQjwL
i1ADpUN7K2v1rF5jhMf7zWv1dmA3aaHUaT8XuRWG8/GtIbcRB/YCojqK7wvpTvZP
F46EpLGw9pAYeIuJVXf8KF7Ud1Mo+NfapBZPIUTXHy8SKgK1o/lhPKaz6eyC/b4p
YL7hNHwKVqX+qOzqdLvypZx7WQKBgQDY1jpRlkOA7tVvROaqavJNhj1NOpvVSg5R
rl1GUzATs/0BxlKR22lDBvHIoMa+sJBrv19OYItmEqY7VYkG9s04RCw56VkXey0Z
6rVhI431LucF5aeRw3ImIfMpEntEuAOsWYa13svSERQ4y8uvtQtWfp3XjEC7EGHQ
NteatkzstwKBgQCvkQSMr5IOTLfViUWIFEiq3B84QTssgmlZrSfgIyoyaIfu9BXU
OMYv2mXP/Qo0VrKs/hiz9nlpll1qD5dLKHOjreathMjT47s+g2z95j1/gEeuGfec
QOrEXK/74XDHhjkoXMOx/yaDYIavYyHyTiy1LafXvPd9sDB92bLl47bV4QKBgQCn
7qIT9dAp1s6t8irC6TjnGYP4f9+YfFZCpEvQ3zRozgiwiyv/knIfWw1+WCYUISJ4
kCn7xYGwd9kOMtyA7DtbzFCEOViqetcfL0tyA9s5fC2nv4jbtwZ8yeZMdOfK/Mi7
fkp6KCaqdle29P63AfvZ7Q3JlfG77qASZabtRyqkWQKBgFElkUelvS62aVhs7cxW
zkV7vbaQtTk/VuN5rsWT5/MUlMUOiG6FX27AcKodNdNN9bTLS6j2DgUzHvExDRDC
Fxg7L/k9nTqSFsgyZW4tvTBWadHYgR9XXu2X5uIeofEJ7CUpnBbkb6Nxl3WgbJkp
AYkBAj0hJt/G0IfvVpvETQOy
-----END PRIVATE KEY-----";

    const TEST_PUB: &str = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1lJ8FRup2DlGea2XXCx
4ntExT1D15Vm9qD9Sp1T0815FJv9EnXgVFa++uziCHtVVTUybLOejAM0XHL/Jm8Q
QzlG6ML0EOLb8bSzjTSkE5NWtJuEMYiZaaF/xF156gtTk7lfMOoFsY6s84AzFibN
dybbtRUB2nNpi9G2CzTYRqL97Vna13ettGrI1FMdGj/29DKMyOvbbEH7zFrCWTSC
OiBO2aihkpMhlPESqx9cJalW9tIrNxEJ+Rc0uDJQv51xXOmGs4wHVRFddqa2Xv87
RQst+6Jj5QMeBjKql7pKQ8wm4NwcZS4xSlPHbs+qRWsW69kqhsOc+sbk/GfQiP44
nwIDAQAB
-----END PUBLIC KEY-----";

    fn sample() -> SecurityEventToken {
        SecurityEventToken::new(
            "https://idp.example.com",
            "https://rp.example.com/ssf",
            SubjectId::iss_sub("https://idp.example.com", "user-42"),
            CaepEvent::SessionRevoked {
                event_timestamp: 1_700_000_000,
                reason: Some("admin revoked".into()),
            },
        )
    }

    #[test]
    fn claims_have_no_sub_or_exp_and_carry_sub_id_and_events() {
        let claims = sample().claims(1_700_000_001, "jti-1");
        let v = serde_json::to_value(&claims).unwrap();
        assert!(v.get("sub").is_none(), "SET must not carry `sub`");
        assert!(v.get("exp").is_none(), "SET must not carry `exp`");
        assert_eq!(v["iss"], "https://idp.example.com");
        assert_eq!(v["aud"], "https://rp.example.com/ssf");
        assert_eq!(v["sub_id"]["format"], "iss_sub");
        assert_eq!(v["sub_id"]["sub"], "user-42");
        // events is keyed by the CAEP type URI.
        assert!(v["events"].get(SESSION_REVOKED_URI).is_some());
        assert_eq!(
            v["events"][SESSION_REVOKED_URI]["event_timestamp"],
            1_700_000_000
        );
    }

    #[test]
    fn signed_set_has_secevent_typ_header() {
        let jwt = sample()
            .sign(TEST_PRIV.as_bytes(), "kid-1", 1, "jti")
            .unwrap();
        let header_b64 = jwt.split('.').next().unwrap();
        let header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header_b64).unwrap()).unwrap();
        assert_eq!(header["typ"], SET_TYP);
        assert_eq!(header["alg"], "RS256");
        assert_eq!(header["kid"], "kid-1");
    }

    #[test]
    fn signed_set_verifies_with_public_key() {
        let jwt = sample()
            .sign(TEST_PRIV.as_bytes(), "kid-1", 1_700_000_001, "jti-xyz")
            .unwrap();
        let key = DecodingKey::from_rsa_pem(TEST_PUB.as_bytes()).unwrap();
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = false; // SETs have no exp
        validation.validate_aud = false;
        validation.required_spec_claims = HashSet::new();
        let data = decode::<serde_json::Value>(&jwt, &key, &validation).expect("SET must verify");
        assert_eq!(data.claims["jti"], "jti-xyz");
        assert_eq!(
            data.claims["events"][SESSION_REVOKED_URI]["event_timestamp"],
            1_700_000_000
        );
    }

    #[test]
    fn credential_change_set_verifies() {
        let set = SecurityEventToken::new(
            "https://idp.example.com",
            "https://rp.example.com/ssf",
            SubjectId::email("u@example.com"),
            CaepEvent::CredentialChange {
                event_timestamp: 99,
                credential_type: "password".into(),
                change_type: CredentialChangeType::Update,
            },
        );
        let jwt = set.sign(TEST_PRIV.as_bytes(), "k", 1, "j").unwrap();
        let key = DecodingKey::from_rsa_pem(TEST_PUB.as_bytes()).unwrap();
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = false;
        validation.validate_aud = false;
        validation.required_spec_claims = HashSet::new();
        let data = decode::<serde_json::Value>(&jwt, &key, &validation).unwrap();
        assert_eq!(data.claims["sub_id"]["format"], "email");
        assert_eq!(
            data.claims["events"][CREDENTIAL_CHANGE_URI]["change_type"],
            "update"
        );
    }

    #[test]
    fn invalid_key_errors() {
        let err = sample()
            .sign(b"not a pem", "k", 1, "j")
            .expect_err("must reject bad key");
        assert!(matches!(err, SsfError::InvalidKey(_)));
    }
}
