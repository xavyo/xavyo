//! Device code response model

use serde::{Deserialize, Serialize};

/// Response from the device code request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceCodeResponse {
    /// Device code for polling
    pub device_code: String,

    /// User code to display
    pub user_code: String,

    /// URL for user to visit
    pub verification_uri: String,

    /// URL with user code pre-filled (optional)
    pub verification_uri_complete: Option<String>,

    /// Seconds until device code expires
    pub expires_in: u64,

    /// Minimum seconds between polling attempts
    pub interval: u64,
}

impl DeviceCodeResponse {
    /// Get the URL to display to the user
    ///
    /// Prefers verification_uri_complete if available
    pub fn display_url(&self) -> &str {
        self.verification_uri_complete
            .as_deref()
            .unwrap_or(&self.verification_uri)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_code_response_deserialization() {
        let json = r#"{
            "device_code": "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
            "user_code": "WDJB-MJHT",
            "verification_uri": "https://auth.xavyo.net/device",
            "verification_uri_complete": "https://auth.xavyo.net/device?user_code=WDJB-MJHT",
            "expires_in": 600,
            "interval": 5
        }"#;

        let response: DeviceCodeResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.user_code, "WDJB-MJHT");
        assert_eq!(response.expires_in, 600);
        assert_eq!(response.interval, 5);
    }

    #[test]
    fn test_display_url_prefers_complete() {
        let response = DeviceCodeResponse {
            device_code: "test".to_string(),
            user_code: "TEST-CODE".to_string(),
            verification_uri: "https://auth.xavyo.net/device".to_string(),
            verification_uri_complete: Some(
                "https://auth.xavyo.net/device?user_code=TEST-CODE".to_string(),
            ),
            expires_in: 600,
            interval: 5,
        };

        assert_eq!(
            response.display_url(),
            "https://auth.xavyo.net/device?user_code=TEST-CODE"
        );
    }

    #[test]
    fn test_display_url_fallback() {
        let response = DeviceCodeResponse {
            device_code: "test".to_string(),
            user_code: "TEST-CODE".to_string(),
            verification_uri: "https://auth.xavyo.net/device".to_string(),
            verification_uri_complete: None,
            expires_in: 600,
            interval: 5,
        };

        assert_eq!(response.display_url(), "https://auth.xavyo.net/device");
    }
}
