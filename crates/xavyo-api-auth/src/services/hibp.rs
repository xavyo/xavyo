//! HIBP (Have I Been Pwned) breached password check.
//!
//! Uses the k-anonymity range API to check if a password has appeared in known data breaches.
//! This is a NIST 800-63B requirement for credential screening.
//!
//! Results are cached in-process by SHA-1 prefix with a 24h TTL. The cache:
//! - cuts API round-trips for hot passwords / dictionary fragments;
//! - provides a grace window if `api.pwnedpasswords.com` is briefly unreachable;
//! - is bounded (`MAX_ENTRIES`) with random eviction to keep memory predictable.
//!
//! Fail-mode is decided by `password_policy_service::hibp_on_unavailable`
//! (fail-closed by default). The cache only reduces how often that path runs.

use sha1::{Digest, Sha1};
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};
use tracing::warn;

/// TTL for cached k-anonymity ranges. HIBP updates are infrequent; 24h is the
/// upstream's own recommended cache lifetime.
const CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// Hard cap on cached entries. Each entry is ~30 KB (≈ 800 lines × 40 chars),
/// so 1000 entries ≈ 30 MB — bounded and predictable.
const MAX_ENTRIES: usize = 1000;

struct CacheEntry {
    inserted_at: Instant,
    body: String,
}

static PREFIX_CACHE: LazyLock<Mutex<HashMap<String, CacheEntry>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Try to read a fresh body for `prefix` from cache.
///
/// Returns `Some(body)` only if the entry exists and is not past `CACHE_TTL`.
/// Stale entries are removed lazily by `store_in_cache` (we don't bother
/// purging on every read — a stale read is just a miss).
fn fetch_from_cache(prefix: &str) -> Option<String> {
    let guard = PREFIX_CACHE.lock().ok()?;
    let entry = guard.get(prefix)?;
    if entry.inserted_at.elapsed() < CACHE_TTL {
        Some(entry.body.clone())
    } else {
        None
    }
}

/// Insert (or replace) a cache entry. Evicts a random entry if the cache is
/// full — random eviction is fine here because every entry has roughly equal
/// re-use probability across passwords, and avoiding LRU bookkeeping keeps
/// the lock critical section tiny.
fn store_in_cache(prefix: &str, body: String) {
    let Ok(mut guard) = PREFIX_CACHE.lock() else {
        return;
    };
    if guard.len() >= MAX_ENTRIES {
        if let Some(victim) = guard.keys().next().cloned() {
            guard.remove(&victim);
        }
    }
    guard.insert(
        prefix.to_string(),
        CacheEntry {
            inserted_at: Instant::now(),
            body,
        },
    );
}

/// Check if a password has appeared in a known data breach via the HIBP API.
///
/// Uses k-anonymity: only the first 5 characters of the SHA-1 hash are sent to the API.
/// Returns `Ok(true)` if breached, `Ok(false)` if clean, `Err(())` if the API is unreachable
/// AND nothing fresh is in cache.
///
/// Fail-mode (open vs. closed) is decided by the caller — see
/// `password_policy_service::check_breached`.
pub async fn check_password_breached(password: &str) -> Result<bool, ()> {
    let hash = hex::encode(Sha1::digest(password.as_bytes())).to_uppercase();
    let (prefix, suffix) = hash.split_at(5);

    // Cache hit — no network call needed.
    if let Some(body) = fetch_from_cache(prefix) {
        return Ok(matches_suffix(&body, suffix));
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| {
            warn!(error = %e, "Failed to build HIBP HTTP client");
        })?;

    let url = format!("https://api.pwnedpasswords.com/range/{prefix}");

    let response = client
        .get(&url)
        .header("User-Agent", "Xavyo-IDP/1.0")
        .send()
        .await
        .map_err(|e| {
            warn!(error = %e, "HIBP API request failed");
        })?;

    let body = response.text().await.map_err(|e| {
        warn!(error = %e, "Failed to read HIBP API response body");
    })?;

    let found = matches_suffix(&body, suffix);
    store_in_cache(prefix, body);
    Ok(found)
}

/// Scan a k-anonymity range response for an exact suffix match.
fn matches_suffix(body: &str, suffix: &str) -> bool {
    for line in body.lines() {
        if let Some((line_suffix, _count)) = line.split_once(':') {
            if line_suffix == suffix {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha1_hash_format() {
        // "password" SHA-1 = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        let hash = hex::encode(Sha1::digest(b"password")).to_uppercase();
        assert_eq!(hash, "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8");
        assert_eq!(&hash[..5], "5BAA6");
    }

    #[test]
    fn test_matches_suffix() {
        let body =
            "1E4C9B93F3F0682250B6CF8331B7EE68FD8:10\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:0\n";
        assert!(matches_suffix(body, "1E4C9B93F3F0682250B6CF8331B7EE68FD8"));
        assert!(!matches_suffix(
            body,
            "0000000000000000000000000000000000000"
        ));
    }

    #[test]
    fn test_cache_roundtrip() {
        // Use a synthetic prefix that won't collide with real HIBP usage.
        let prefix = "ZZZZZ";
        let body = "AAA:1\nBBB:2\n".to_string();
        store_in_cache(prefix, body.clone());
        assert_eq!(fetch_from_cache(prefix), Some(body));
    }
}
