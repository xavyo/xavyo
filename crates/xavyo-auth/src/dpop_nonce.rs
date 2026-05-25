//! Stateless DPoP-Nonce (RFC 9449 §8).
//!
//! A server-provided `nonce` lets the AS/RS force DPoP-proof freshness: the
//! server returns a `DPoP-Nonce` value (and a `use_dpop_nonce` challenge), and
//! the client must echo it in the proof's `nonce` claim. Rather than store
//! issued nonces, this derives them statelessly as `HMAC-SHA256(secret, window)`
//! over a coarse time window — so any node can issue + verify with only the
//! shared secret, and a nonce is implicitly time-bounded.
//!
//! Verification uses the HMAC's constant-time `verify_slice`, and accepts the
//! current window plus a bounded number of recent past windows (clock skew +
//! the time between issuing the challenge and receiving the retried request).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Default DPoP-Nonce time window, in seconds.
pub const DPOP_NONCE_WINDOW_SECS: i64 = 300;

/// Default number of recent past windows a presented nonce may belong to.
pub const DPOP_NONCE_ALLOWED_AGE_WINDOWS: i64 = 1;

/// The domain-separation prefix for the nonce MAC.
const NONCE_DOMAIN: &[u8] = b"dpop-nonce:v1:";

fn mac_for_window(secret: &[u8], window: i64) -> HmacSha256 {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(NONCE_DOMAIN);
    mac.update(&window.to_le_bytes());
    mac
}

/// Issue a stateless DPoP nonce for the time window containing `now`.
#[must_use]
pub fn issue_dpop_nonce(secret: &[u8], now: i64, window_secs: i64) -> String {
    let window = now.div_euclid(window_secs.max(1));
    URL_SAFE_NO_PAD.encode(mac_for_window(secret, window).finalize().into_bytes())
}

/// Verify a presented DPoP nonce: it must match the MAC for the current window
/// or one of the previous `allowed_age_windows` windows. Future windows are
/// never accepted. Comparison is constant-time (HMAC `verify_slice`).
#[must_use]
pub fn verify_dpop_nonce(
    secret: &[u8],
    candidate: &str,
    now: i64,
    window_secs: i64,
    allowed_age_windows: i64,
) -> bool {
    let Ok(candidate_bytes) = URL_SAFE_NO_PAD.decode(candidate) else {
        return false;
    };
    let current = now.div_euclid(window_secs.max(1));
    let oldest = current - allowed_age_windows.max(0);
    (oldest..=current).any(|window| {
        mac_for_window(secret, window)
            .verify_slice(&candidate_bytes)
            .is_ok()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"test-dpop-nonce-secret-key-material";
    const W: i64 = DPOP_NONCE_WINDOW_SECS;

    #[test]
    fn issued_nonce_verifies_in_same_window() {
        let now = 1_000_000;
        let nonce = issue_dpop_nonce(SECRET, now, W);
        assert!(verify_dpop_nonce(SECRET, &nonce, now, W, 1));
        // Still the same window a few seconds later.
        assert!(verify_dpop_nonce(SECRET, &nonce, now + 5, W, 1));
    }

    #[test]
    fn nonce_verifies_into_next_window_within_allowance() {
        let now = 1_000_000;
        let nonce = issue_dpop_nonce(SECRET, now, W);
        // One window later, with allowance 1, the previous window is accepted.
        assert!(verify_dpop_nonce(SECRET, &nonce, now + W, W, 1));
    }

    #[test]
    fn stale_nonce_beyond_allowance_is_rejected() {
        let now = 1_000_000;
        let nonce = issue_dpop_nonce(SECRET, now, W);
        // Two windows later with allowance 1 → too old.
        assert!(!verify_dpop_nonce(SECRET, &nonce, now + 2 * W, W, 1));
    }

    #[test]
    fn wrong_secret_rejected() {
        let now = 1_000_000;
        let nonce = issue_dpop_nonce(SECRET, now, W);
        assert!(!verify_dpop_nonce(b"different-secret", &nonce, now, W, 1));
    }

    #[test]
    fn tampered_and_garbage_rejected() {
        let now = 1_000_000;
        let mut nonce = issue_dpop_nonce(SECRET, now, W);
        nonce.push('x');
        assert!(!verify_dpop_nonce(SECRET, &nonce, now, W, 1));
        assert!(!verify_dpop_nonce(SECRET, "!!!not-base64!!!", now, W, 1));
        assert!(!verify_dpop_nonce(SECRET, "", now, W, 1));
    }

    #[test]
    fn future_window_not_accepted() {
        // A nonce minted for a future window must not verify now.
        let now = 1_000_000;
        let future = issue_dpop_nonce(SECRET, now + 10 * W, W);
        assert!(!verify_dpop_nonce(SECRET, &future, now, W, 1));
    }
}
