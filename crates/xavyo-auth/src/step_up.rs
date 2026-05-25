//! Step-up authentication (RFC 9470).
//!
//! A resource that needs higher assurance for a sensitive operation calls
//! [`check_step_up`] with the access token's claims and its requirement. If the
//! token's `acr` (assurance) or `auth_time` (freshness) is insufficient, the
//! resource answers `401` with the [`step_up_challenge_header`]
//! `WWW-Authenticate: Bearer error="insufficient_user_authentication", …`; an
//! OIDC client re-authenticates at the requested `acr_values` / `max_age` and
//! retries.
//!
//! These are pure primitives — no DB, no HTTP. The acr/amr/auth_time they read
//! are stamped on login tokens by the auth flow and carried across refresh.

use crate::claims::JwtClaims;

/// What a sensitive operation requires of the caller's authentication (RFC 9470).
#[derive(Debug, Clone)]
pub struct StepUpRequirement {
    /// Minimum acr (xavyo scheme: `"1"` single-factor, `"2"` multi-factor).
    pub acr: String,
    /// Maximum age of the authentication in seconds (`auth_time` freshness). A
    /// `None` means freshness is not required.
    pub max_age: Option<i64>,
}

impl StepUpRequirement {
    /// Require multi-factor authentication (`acr` ≥ `"2"`), no freshness bound.
    #[must_use]
    pub fn mfa() -> Self {
        Self {
            acr: "2".to_string(),
            max_age: None,
        }
    }

    /// Require multi-factor authentication completed within `max_age` seconds.
    #[must_use]
    pub fn mfa_within(max_age_secs: i64) -> Self {
        Self {
            acr: "2".to_string(),
            max_age: Some(max_age_secs),
        }
    }
}

/// The result of a step-up check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepUpOutcome {
    /// The token meets the requirement — proceed.
    Satisfied,
    /// Insufficient — answer `401` and challenge with these parameters.
    Challenge {
        /// The `acr_values` to request (the requirement's acr).
        acr_values: String,
        /// The `max_age` to request, if any.
        max_age: Option<i64>,
    },
}

/// Whether `claims` satisfy `req` at time `now` (Unix seconds).
///
/// `acr` is compared numerically when both are integer strings (xavyo's `"1"` /
/// `"2"`), falling back to exact match otherwise. A missing `acr` never
/// satisfies a requirement. When `max_age` is set, a missing or too-old
/// `auth_time` fails (freshness cannot be confirmed).
#[must_use]
pub fn check_step_up(claims: &JwtClaims, req: &StepUpRequirement, now: i64) -> StepUpOutcome {
    let acr_ok = match (
        claims.acr.as_deref().and_then(|a| a.parse::<u32>().ok()),
        req.acr.parse::<u32>().ok(),
    ) {
        (Some(have), Some(need)) => have >= need,
        // Non-numeric scheme: require an exact match.
        _ => claims.acr.as_deref() == Some(req.acr.as_str()),
    };

    let age_ok = match req.max_age {
        None => true,
        Some(max) => claims.auth_time.is_some_and(|t| now - t <= max),
    };

    if acr_ok && age_ok {
        StepUpOutcome::Satisfied
    } else {
        StepUpOutcome::Challenge {
            acr_values: req.acr.clone(),
            max_age: req.max_age,
        }
    }
}

/// Build the RFC 9470 §3 `WWW-Authenticate` challenge value for a `401`.
///
/// e.g. `Bearer error="insufficient_user_authentication",
/// error_description="…", acr_values="2", max_age="300"`.
#[must_use]
pub fn step_up_challenge_header(acr_values: &str, max_age: Option<i64>) -> String {
    let mut h = format!(
        "Bearer error=\"insufficient_user_authentication\", \
         error_description=\"A higher authentication assurance is required\", \
         acr_values=\"{acr_values}\""
    );
    if let Some(age) = max_age {
        h.push_str(&format!(", max_age=\"{age}\""));
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims_with(acr: Option<&str>, auth_time: Option<i64>) -> JwtClaims {
        let mut b = JwtClaims::builder().subject("u1");
        if let Some(a) = acr {
            b = b.acr(a);
        }
        if let Some(t) = auth_time {
            b = b.auth_time(t);
        }
        b.build()
    }

    #[test]
    fn mfa_requirement_satisfied_by_acr_2() {
        let c = claims_with(Some("2"), None);
        assert_eq!(
            check_step_up(&c, &StepUpRequirement::mfa(), 1000),
            StepUpOutcome::Satisfied
        );
    }

    #[test]
    fn mfa_requirement_challenges_acr_1_and_missing() {
        let req = StepUpRequirement::mfa();
        assert!(matches!(
            check_step_up(&claims_with(Some("1"), None), &req, 1000),
            StepUpOutcome::Challenge { .. }
        ));
        assert!(matches!(
            check_step_up(&claims_with(None, None), &req, 1000),
            StepUpOutcome::Challenge { .. }
        ));
    }

    #[test]
    fn max_age_freshness_enforced() {
        let req = StepUpRequirement::mfa_within(300);
        // Fresh enough.
        assert_eq!(
            check_step_up(&claims_with(Some("2"), Some(900)), &req, 1000),
            StepUpOutcome::Satisfied
        );
        // Too old.
        assert!(matches!(
            check_step_up(&claims_with(Some("2"), Some(600)), &req, 1000),
            StepUpOutcome::Challenge { .. }
        ));
        // acr ok but no auth_time → cannot confirm freshness → challenge.
        assert!(matches!(
            check_step_up(&claims_with(Some("2"), None), &req, 1000),
            StepUpOutcome::Challenge { .. }
        ));
    }

    #[test]
    fn challenge_header_format() {
        assert_eq!(
            step_up_challenge_header("2", Some(300)),
            "Bearer error=\"insufficient_user_authentication\", \
             error_description=\"A higher authentication assurance is required\", \
             acr_values=\"2\", max_age=\"300\""
        );
        assert!(!step_up_challenge_header("2", None).contains("max_age"));
    }
}
