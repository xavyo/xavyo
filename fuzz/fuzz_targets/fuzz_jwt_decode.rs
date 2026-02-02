//! Fuzz target for JWT decoding.
//!
//! This fuzzer tests the JWT token parsing and validation logic
//! to find potential parser bugs, signature bypass, or DoS vectors.
//!
//! Run with:
//! cargo +nightly fuzz run fuzz_jwt_decode -- -max_total_time=600

#![no_main]

use libfuzzer_sys::fuzz_target;
use xavyo_auth::{decode_token, ValidationConfig};

// Test RSA public key (for fuzzing only - we're testing the parser, not real validation)
const TEST_PUBLIC_KEY: &[u8] = br#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuOs2bjkrVK1Vi6uSrZAG
jy/YTQlC0eMz4YLJHVDgdXPm8UYjonBBykwbKm+C0p4syG93yBDeV7lC+U8zgSk9
4QHP4CilO9VShORDHG37iy1cU6o9PCto+z8wgoc88nWRowFn4rJ3QEnkDyCdRzNy
4d1YV2q97sMW6U9iqsefQu0g6Qkx7GcLy1TLqchIi/tfKxSO7w75Zx8bqBuXZBmY
cmay3ysdQN3l+PVIm4ic/CpuFLW0XmeTvlUp3R2JoSxVySh3faTq+18cspk7nBiW
5mTpko2924GiIWMh/graaMU7agn1ItpBwmXQtXBhfd1J6i5jSKu53NGG4SSXPvu9
jQIDAQAB
-----END PUBLIC KEY-----"#;

fuzz_target!(|data: &[u8]| {
    // Convert bytes to string for token input
    if let Ok(token) = std::str::from_utf8(data) {
        // Try to decode the token - we expect this to fail gracefully
        // for invalid input, not panic or crash
        let _ = decode_token(token, TEST_PUBLIC_KEY);

        // Also test with custom validation config
        let config = ValidationConfig::default().skip_exp_validation();
        let _ = xavyo_auth::decode_token_with_config(token, TEST_PUBLIC_KEY, &config);
    }
});
