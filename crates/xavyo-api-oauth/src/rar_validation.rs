//! RFC 9396 `authorization_details` request-side validation.
//!
//! Bridges the wire format (an optional JSON-array string on the PAR / authorize
//! request) to the typed, validated form in `xavyo-auth`, returning a canonical
//! JSON value suitable for storage (`par_requests` / `authorization_codes`).
//! Parsing rejects malformed input and unknown `type`s with the RFC 9396 §5
//! `invalid_authorization_details` error.

use crate::error::OAuthError;

/// Parse, validate, and canonicalize an optional `authorization_details` string.
///
/// - `None` / empty / whitespace ⇒ `Ok(None)` (the request is scope-only).
/// - A valid array ⇒ `Ok(Some(value))`, where `value` is the re-serialized
///   *typed* form (unknown object fields dropped — canonical storage).
/// - Malformed / unknown `type` / limit exceeded ⇒
///   [`OAuthError::InvalidAuthorizationDetails`].
///
/// # Errors
/// See above.
pub(crate) fn validate_authorization_details(
    raw: Option<&str>,
) -> Result<Option<serde_json::Value>, OAuthError> {
    let Some(raw) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let details = xavyo_auth::parse_authorization_details(raw)
        .map_err(|e| OAuthError::InvalidAuthorizationDetails(e.to_string()))?;
    let value = serde_json::to_value(&details).map_err(|e| {
        OAuthError::Internal(format!("failed to serialize authorization_details: {e}"))
    })?;
    Ok(Some(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn none_and_empty_are_scope_only() {
        assert!(validate_authorization_details(None).unwrap().is_none());
        assert!(validate_authorization_details(Some("")).unwrap().is_none());
        assert!(validate_authorization_details(Some("   "))
            .unwrap()
            .is_none());
    }

    #[test]
    fn valid_tool_access_canonicalizes() {
        let raw =
            r#"[{"type":"tool_access","tool":"send_email","actions":["send"],"extra":"dropped"}]"#;
        let value = validate_authorization_details(Some(raw)).unwrap().unwrap();
        let arr = value.as_array().expect("array");
        assert_eq!(arr.len(), 1);
        // Unknown "extra" field dropped by the typed round-trip.
        assert!(arr[0].get("extra").is_none());
        assert_eq!(arr[0]["type"], "tool_access");
        assert_eq!(arr[0]["tool"], "send_email");
    }

    #[test]
    fn unknown_type_is_invalid_authorization_details() {
        let raw = r#"[{"type":"payment_initiation","amount":"100"}]"#;
        let err = validate_authorization_details(Some(raw)).unwrap_err();
        assert!(matches!(err, OAuthError::InvalidAuthorizationDetails(_)));
    }

    #[test]
    fn malformed_is_invalid_authorization_details() {
        let err = validate_authorization_details(Some("not json")).unwrap_err();
        assert!(matches!(err, OAuthError::InvalidAuthorizationDetails(_)));
    }
}
