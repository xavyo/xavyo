//! Fuzz target for token hashing.
//!
//! This fuzzer tests the SHA-256 token hashing logic
//! to ensure it handles arbitrary input safely.
//!
//! Run with:
//! cargo +nightly fuzz run fuzz_token_hash -- -max_total_time=600

#![no_main]

use libfuzzer_sys::fuzz_target;
use sha2::{Digest, Sha256};

fuzz_target!(|data: &[u8]| {
    // Test token hashing with arbitrary data
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();

    // Hash should always be 32 bytes (256 bits)
    assert_eq!(hash.len(), 32);

    // Hex encoding should always produce 64 characters
    let hex_hash = hex::encode(hash);
    assert_eq!(hex_hash.len(), 64);

    // Hash should be deterministic
    let mut hasher2 = Sha256::new();
    hasher2.update(data);
    let hash2 = hasher2.finalize();
    assert_eq!(hash, hash2);
});
