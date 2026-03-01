//! HIBP (Have I Been Pwned) breached password check.
//!
//! Uses the k-anonymity range API to check if a password has appeared in known data breaches.
//! This is a NIST 800-63B requirement for credential screening.

use sha1::{Digest, Sha1};
use tracing::warn;

/// Check if a password has appeared in a known data breach via the HIBP API.
///
/// Uses k-anonymity: only the first 5 characters of the SHA-1 hash are sent to the API.
/// Returns `Ok(true)` if breached, `Ok(false)` if clean, `Err(())` if the API is unreachable.
/// Fails open -- a network error will not block the user from setting their password.
pub async fn check_password_breached(password: &str) -> Result<bool, ()> {
    let hash = hex::encode(Sha1::digest(password.as_bytes())).to_uppercase();
    let (prefix, suffix) = hash.split_at(5);

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
            warn!(error = %e, "HIBP API request failed, failing open");
        })?;

    let body = response.text().await.map_err(|e| {
        warn!(error = %e, "Failed to read HIBP API response body");
    })?;

    for line in body.lines() {
        if let Some((line_suffix, _count)) = line.split_once(':') {
            if line_suffix == suffix {
                return Ok(true);
            }
        }
    }

    Ok(false)
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
}
