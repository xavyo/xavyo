//! Fuzz target for JWT claims builder.
//!
//! This fuzzer tests the JwtClaims builder to ensure it handles
//! arbitrary input safely and produces valid claims.
//!
//! Run with:
//! cargo +nightly fuzz run fuzz_claims_builder -- -max_total_time=600

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use xavyo_auth::JwtClaims;
use xavyo_core::TenantId;

/// Arbitrary input for claims builder
#[derive(Arbitrary, Debug)]
struct ClaimsInput {
    subject: String,
    issuer: Option<String>,
    audience: Option<Vec<String>>,
    roles: Option<Vec<String>>,
    expiration_secs: Option<i64>,
    use_tenant_id: bool,
}

fuzz_target!(|input: ClaimsInput| {
    // Skip very long strings to avoid memory issues
    if input.subject.len() > 1000 {
        return;
    }

    if let Some(ref iss) = input.issuer {
        if iss.len() > 1000 {
            return;
        }
    }

    // Build claims with fuzzed input
    let mut builder = JwtClaims::builder().subject(&input.subject);

    if let Some(ref iss) = input.issuer {
        builder = builder.issuer(iss);
    }

    if let Some(ref aud) = input.audience {
        if aud.iter().all(|a| a.len() < 500) {
            builder = builder.audience(aud.iter().map(|s| s.as_str()).collect());
        }
    }

    if let Some(ref roles) = input.roles {
        if roles.iter().all(|r| r.len() < 100) {
            builder = builder.roles(roles.iter().map(|s| s.as_str()).collect());
        }
    }

    if let Some(exp) = input.expiration_secs {
        // Only use reasonable expiration values
        if exp > 0 && exp < 86400 * 365 {
            builder = builder.expires_in_secs(exp);
        }
    }

    if input.use_tenant_id {
        builder = builder.tenant_id(TenantId::new());
    }

    let claims = builder.build();

    // Verify the claims are valid
    assert_eq!(claims.sub, input.subject);

    if let Some(ref iss) = input.issuer {
        assert_eq!(claims.iss, *iss);
    }

    if input.use_tenant_id {
        assert!(claims.tid.is_some());
    }

    // Claims should be serializable
    let _ = serde_json::to_string(&claims);
});
