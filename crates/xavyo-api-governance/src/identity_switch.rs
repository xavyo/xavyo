//! Fail-closed identity-switch JWT issuance (persona context and PoA assume).
//!
//! Persona switch and Power of Attorney assume/drop must mint a signed JWT
//! with the new identity claims. Until that issuer is wired, these endpoints
//! return HTTP 501 instead of a placeholder `access_token` that a BFF would
//! store as the session cookie.

use xavyo_governance::error::GovernanceError;

use crate::error::ApiGovernanceError;

/// Signed JWT re-issuance for persona/PoA identity switch is not wired.
///
/// Callers must not receive a placeholder `access_token`.
pub fn unimplemented_identity_switch_jwt() -> ApiGovernanceError {
    ApiGovernanceError::Governance(GovernanceError::NotImplemented(
        "Identity-switch JWT re-issuance is not implemented".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    #[tokio::test]
    async fn identity_switch_jwt_is_501_without_placeholder_token() {
        let response = unimplemented_identity_switch_jwt().into_response();
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
        assert!(
            !response.status().is_success(),
            "placeholder identity tokens must not be HTTP success"
        );

        let body = to_bytes(response.into_body(), 1024)
            .await
            .expect("response body");
        let text = String::from_utf8(body.to_vec()).expect("utf8");
        assert!(
            text.contains("not_implemented"),
            "501 body must advertise not_implemented: {text}"
        );
        for needle in [
            "persona_token_",
            "physical_token_",
            "assumed_token_",
            "original_token_",
            "access_token",
        ] {
            assert!(
                !text.contains(needle),
                "501 body must not look like a session token ({needle}): {text}"
            );
        }
    }

    #[test]
    fn persona_and_poa_handlers_do_not_mint_placeholder_tokens() {
        let personas = include_str!("handlers/personas.rs");
        let poa = include_str!("handlers/power_of_attorney.rs");
        for src in [personas, poa] {
            for needle in [
                "persona_token_",
                "physical_token_",
                "assumed_token_",
                "original_token_",
            ] {
                assert!(
                    !src.contains(needle),
                    "identity-switch handlers must not mint placeholder tokens ({needle})"
                );
            }
        }
    }
}
