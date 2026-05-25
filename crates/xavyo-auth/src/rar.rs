//! Rich Authorization Requests (RFC 9396) — `authorization_details`.
//!
//! Pure types + parsing/validation (no DB, no I/O). An `authorization_details`
//! value is a JSON array of typed objects expressing fine-grained authorization
//! beyond coarse scopes. v1 ships one first-class type, `tool_access`, for the
//! AI-agent tool-scoping use case; per RFC 9396 §6 the AS MUST reject unknown
//! `type` values — modelled structurally via a `#[serde(tag = "type")]` enum
//! that fails to deserialize unknown discriminators.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Maximum number of authorization-detail elements accepted in one request
/// (DoS guard).
pub const MAX_AUTHORIZATION_DETAILS: usize = 32;

/// Errors from `authorization_details` handling.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RarError {
    /// The value was not a valid `authorization_details` array, contained an
    /// unknown `type`, or violated a limit. Maps to the RFC 9396 §5
    /// `invalid_authorization_details` error.
    #[error("invalid authorization_details: {0}")]
    Invalid(String),
}

/// A single RFC 9396 authorization detail. Tagged on `type`; unknown types fail
/// to deserialize (the §6 reject requirement).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type")]
pub enum AuthorizationDetail {
    /// Fine-grained access to a named tool (AI-agent use case).
    #[serde(rename = "tool_access")]
    ToolAccess {
        /// The tool identifier the agent may invoke.
        tool: String,
        /// Permitted actions on the tool (e.g. `["send"]`).
        actions: Vec<String>,
        /// Optional resource locators the actions are scoped to.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        resources: Vec<String>,
    },
}

impl AuthorizationDetail {
    /// The `type` discriminator string.
    #[must_use]
    pub fn detail_type(&self) -> &'static str {
        match self {
            AuthorizationDetail::ToolAccess { .. } => "tool_access",
        }
    }

    /// Per-type semantic validation (beyond structural deserialization).
    ///
    /// # Errors
    /// [`RarError::Invalid`] if a required field is empty.
    pub fn validate(&self) -> Result<(), RarError> {
        match self {
            AuthorizationDetail::ToolAccess { tool, actions, .. } => {
                if tool.trim().is_empty() {
                    return Err(RarError::Invalid(
                        "tool_access.tool must not be empty".into(),
                    ));
                }
                if actions.is_empty() {
                    return Err(RarError::Invalid(
                        "tool_access.actions must not be empty".into(),
                    ));
                }
                Ok(())
            }
        }
    }
}

/// Parse and validate an `authorization_details` JSON array string (RFC 9396).
///
/// Rejects: non-array / malformed JSON, unknown `type` (structurally), more
/// than [`MAX_AUTHORIZATION_DETAILS`] elements, and any element failing
/// [`AuthorizationDetail::validate`].
///
/// # Errors
/// [`RarError::Invalid`] on any of the above.
pub fn parse_authorization_details(json: &str) -> Result<Vec<AuthorizationDetail>, RarError> {
    let details: Vec<AuthorizationDetail> =
        serde_json::from_str(json).map_err(|e| RarError::Invalid(e.to_string()))?;
    if details.len() > MAX_AUTHORIZATION_DETAILS {
        return Err(RarError::Invalid(format!(
            "too many authorization_details (max {MAX_AUTHORIZATION_DETAILS})"
        )));
    }
    for d in &details {
        d.validate()?;
    }
    Ok(details)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_tool_access() {
        let json = r#"[{"type":"tool_access","tool":"send_email","actions":["send"]}]"#;
        let details = parse_authorization_details(json).expect("valid");
        assert_eq!(details.len(), 1);
        assert_eq!(details[0].detail_type(), "tool_access");
        match &details[0] {
            AuthorizationDetail::ToolAccess { tool, actions, .. } => {
                assert_eq!(tool, "send_email");
                assert_eq!(actions, &vec!["send".to_string()]);
            }
        }
    }

    #[test]
    fn test_parse_with_resources_roundtrips() {
        let json =
            r#"[{"type":"tool_access","tool":"db","actions":["read","write"],"resources":["t1"]}]"#;
        let details = parse_authorization_details(json).expect("valid");
        // Round-trip serialize (as it would appear in the token claim).
        let out = serde_json::to_string(&details).unwrap();
        let reparsed = parse_authorization_details(&out).unwrap();
        assert_eq!(details, reparsed);
    }

    #[test]
    fn test_reject_unknown_type() {
        // RFC 9396 §6: unknown type MUST be rejected.
        let json = r#"[{"type":"payment_initiation","amount":"100"}]"#;
        assert!(matches!(
            parse_authorization_details(json),
            Err(RarError::Invalid(_))
        ));
    }

    #[test]
    fn test_reject_malformed() {
        assert!(parse_authorization_details("not json").is_err());
        // Not an array.
        assert!(parse_authorization_details(r#"{"type":"tool_access"}"#).is_err());
    }

    #[test]
    fn test_reject_empty_required_fields() {
        let no_tool = r#"[{"type":"tool_access","tool":"","actions":["send"]}]"#;
        assert!(parse_authorization_details(no_tool).is_err());
        let no_actions = r#"[{"type":"tool_access","tool":"x","actions":[]}]"#;
        assert!(parse_authorization_details(no_actions).is_err());
    }

    #[test]
    fn test_reject_too_many() {
        let one = r#"{"type":"tool_access","tool":"t","actions":["a"]}"#;
        let arr = format!("[{}]", vec![one; MAX_AUTHORIZATION_DETAILS + 1].join(","));
        assert!(parse_authorization_details(&arr).is_err());
    }
}
