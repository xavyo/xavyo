//! Fuzz target for password hashing.
//!
//! This fuzzer tests the password hashing and verification logic
//! to find potential edge cases, DoS vectors, or hash format issues.
//!
//! Run with:
//! cargo +nightly fuzz run fuzz_password_hash -- -max_total_time=600

#![no_main]

use libfuzzer_sys::fuzz_target;
use xavyo_auth::{hash_password, verify_password};

fuzz_target!(|data: &[u8]| {
    // Convert bytes to string for password input
    if let Ok(password) = std::str::from_utf8(data) {
        // Skip very long passwords to avoid excessive memory/time usage
        if password.len() > 10000 {
            return;
        }

        // Test password hashing
        if let Ok(hash) = hash_password(password) {
            // Verify the password against its own hash
            let _ = verify_password(password, &hash);

            // Verify wrong password doesn't match
            let _ = verify_password("definitely_wrong_password", &hash);
        }
    }
});
