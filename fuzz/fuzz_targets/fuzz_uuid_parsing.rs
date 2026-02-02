//! Fuzz target for UUID parsing.
//!
//! This fuzzer tests UUID parsing to ensure it handles
//! malformed input gracefully without panicking.
//!
//! Run with:
//! cargo +nightly fuzz run fuzz_uuid_parsing -- -max_total_time=600

#![no_main]

use libfuzzer_sys::fuzz_target;
use uuid::Uuid;
use xavyo_core::TenantId;

fuzz_target!(|data: &[u8]| {
    // Try parsing as UUID string
    if let Ok(s) = std::str::from_utf8(data) {
        // Test standard UUID parsing
        if let Ok(uuid) = Uuid::parse_str(s) {
            // Verify round-trip
            let formatted = uuid.to_string();
            let parsed = Uuid::parse_str(&formatted).unwrap();
            assert_eq!(uuid, parsed);

            // Test TenantId construction
            let tenant_id = TenantId::from_uuid(uuid);
            assert_eq!(tenant_id.as_uuid(), &uuid);
        }

        // Test hyphenated format
        if let Ok(uuid) = Uuid::try_parse(s) {
            let _ = TenantId::from_uuid(uuid);
        }
    }

    // Test from raw bytes (if exactly 16 bytes)
    if data.len() == 16 {
        let uuid = Uuid::from_slice(data).unwrap();
        let tenant_id = TenantId::from_uuid(uuid);
        assert_eq!(tenant_id.as_uuid(), &uuid);
    }
});
