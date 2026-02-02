//! Key rotation management with configurable transition periods.
//!
//! When a signing key is rotated, the old key is kept for verification
//! during the transition period (default: 7 days). After the transition
//! expires, the old key is removed.

use chrono::{DateTime, Duration, Utc};

/// A signing key tracked by the rotation manager.
#[derive(Debug, Clone)]
pub struct TrackedKey {
    /// Key ID (kid).
    pub kid: String,
    /// PEM-encoded private key (only for active key).
    pub private_key_pem: Option<String>,
    /// PEM-encoded public key.
    pub public_key_pem: String,
    /// Whether this is the current active signing key.
    pub is_active: bool,
    /// When this key was activated (or added).
    pub activated_at: DateTime<Utc>,
    /// When this key was retired (replaced by a newer key).
    pub retired_at: Option<DateTime<Utc>>,
}

/// Manages key rotation with transition period support.
#[derive(Debug)]
pub struct KeyRotationManager {
    /// All tracked keys (active + transitioning).
    keys: Vec<TrackedKey>,
    /// Transition period for retired keys.
    transition_period: Duration,
}

impl KeyRotationManager {
    /// Create a new rotation manager with the given transition period in days.
    pub fn new(transition_period_days: i64) -> Self {
        Self {
            keys: Vec::new(),
            transition_period: Duration::days(transition_period_days),
        }
    }

    /// Initialize with a set of keys. The key with `is_active=true` becomes
    /// the current signing key.
    pub fn initialize(&mut self, keys: Vec<TrackedKey>) {
        self.keys = keys;
    }

    /// Get the current active signing key.
    pub fn current_signing_key(&self) -> Option<&TrackedKey> {
        self.keys.iter().find(|k| k.is_active)
    }

    /// Get all keys valid for verification (active + within transition period).
    pub fn all_verification_keys(&self) -> Vec<&TrackedKey> {
        let now = Utc::now();
        self.keys
            .iter()
            .filter(|k| {
                if k.is_active {
                    return true;
                }
                // Retired keys within transition period
                if let Some(retired_at) = k.retired_at {
                    return now < retired_at + self.transition_period;
                }
                // Keys without retired_at but not active — still include
                true
            })
            .collect()
    }

    /// Rotate to a new key. The previous active key enters the transition period.
    pub fn rotate_key(&mut self, new_key: TrackedKey) {
        let now = Utc::now();

        // Retire the current active key
        for key in &mut self.keys {
            if key.is_active {
                key.is_active = false;
                key.retired_at = Some(now);
                key.private_key_pem = None; // Clear private key from retired keys
                tracing::info!(
                    kid = %key.kid,
                    "Key retired, entering transition period"
                );
            }
        }

        tracing::info!(
            kid = %new_key.kid,
            "New signing key activated"
        );

        self.keys.push(new_key);
    }

    /// Remove keys whose transition period has expired.
    pub fn cleanup_expired(&mut self) -> Vec<String> {
        let now = Utc::now();
        let mut removed = Vec::new();

        self.keys.retain(|k| {
            if k.is_active {
                return true;
            }
            if let Some(retired_at) = k.retired_at {
                if now >= retired_at + self.transition_period {
                    tracing::info!(
                        kid = %k.kid,
                        retired_at = %retired_at,
                        "Removing expired transition key"
                    );
                    removed.push(k.kid.clone());
                    return false;
                }
            }
            true
        });

        removed
    }

    /// Get the number of tracked keys.
    pub fn key_count(&self) -> usize {
        self.keys.len()
    }

    /// Get the transition period in days.
    pub fn transition_period_days(&self) -> i64 {
        self.transition_period.num_days()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_key(kid: &str, active: bool) -> TrackedKey {
        TrackedKey {
            kid: kid.to_string(),
            private_key_pem: if active {
                Some("-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----".to_string())
            } else {
                None
            },
            public_key_pem: "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----"
                .to_string(),
            is_active: active,
            activated_at: Utc::now(),
            retired_at: None,
        }
    }

    #[test]
    fn test_current_signing_key() {
        let mut mgr = KeyRotationManager::new(7);
        mgr.initialize(vec![make_key("key-1", true)]);

        let active = mgr.current_signing_key().unwrap();
        assert_eq!(active.kid, "key-1");
        assert!(active.is_active);
    }

    #[test]
    fn test_rotate_key() {
        let mut mgr = KeyRotationManager::new(7);
        mgr.initialize(vec![make_key("key-1", true)]);

        let new_key = make_key("key-2", true);
        mgr.rotate_key(new_key);

        // New key should be active
        let active = mgr.current_signing_key().unwrap();
        assert_eq!(active.kid, "key-2");

        // Old key should still be in verification set (transition period)
        let verification_keys = mgr.all_verification_keys();
        assert_eq!(verification_keys.len(), 2);
        assert!(verification_keys.iter().any(|k| k.kid == "key-1"));
        assert!(verification_keys.iter().any(|k| k.kid == "key-2"));
    }

    #[test]
    fn test_cleanup_expired() {
        let mut mgr = KeyRotationManager::new(0); // 0-day transition = immediate expiry
        mgr.initialize(vec![make_key("key-1", true)]);

        // Rotate to key-2
        let new_key = make_key("key-2", true);
        mgr.rotate_key(new_key);

        // Before cleanup: 2 keys
        assert_eq!(mgr.key_count(), 2);

        // After cleanup: expired key-1 should be removed
        let removed = mgr.cleanup_expired();
        assert_eq!(removed, vec!["key-1"]);
        assert_eq!(mgr.key_count(), 1);
    }

    #[test]
    fn test_all_verification_keys_active_only() {
        let mut mgr = KeyRotationManager::new(7);
        mgr.initialize(vec![make_key("key-1", true)]);

        let keys = mgr.all_verification_keys();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].kid, "key-1");
    }

    #[test]
    fn test_transition_period_days() {
        let mgr = KeyRotationManager::new(14);
        assert_eq!(mgr.transition_period_days(), 14);
    }

    #[test]
    fn test_rotate_clears_private_key() {
        let mut mgr = KeyRotationManager::new(7);
        mgr.initialize(vec![make_key("key-1", true)]);
        mgr.rotate_key(make_key("key-2", true));

        // Old key should have private_key_pem cleared
        let old_key = mgr
            .all_verification_keys()
            .into_iter()
            .find(|k| k.kid == "key-1")
            .unwrap();
        assert!(old_key.private_key_pem.is_none());
    }
}
