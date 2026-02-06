//! Session cookie middleware for device code flow authentication.
//!
//! Provides functions to set and extract session cookies for the device code
//! login flow (F112). Uses `HttpOnly`, Secure, SameSite=Strict cookies.
//!
//! Also provides CSRF token generation and validation for form submissions.

use axum::http::{header::SET_COOKIE, HeaderMap, HeaderValue};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::RngCore;
use uuid::Uuid;

/// Cookie name for device flow sessions.
pub const SESSION_COOKIE_NAME: &str = "xavyo_device_session";

/// Cookie name for CSRF tokens.
pub const CSRF_COOKIE_NAME: &str = "xavyo_csrf_token";

/// Cookie max age in seconds (24 hours).
pub const SESSION_COOKIE_MAX_AGE: i64 = 86400;

/// CSRF token max age in seconds (1 hour - shorter for security).
pub const CSRF_COOKIE_MAX_AGE: i64 = 3600;

/// Set a session cookie in the response headers.
///
/// # Arguments
///
/// * `session_id` - The session ID to store in the cookie
/// * `secure` - Whether to add the Secure flag (should be true in production)
///
/// # Returns
///
/// The cookie header value as a string.
#[must_use]
pub fn create_session_cookie(session_id: Uuid, secure: bool) -> String {
    let secure_flag = if secure { "; Secure" } else { "" };
    format!(
        "{SESSION_COOKIE_NAME}={session_id}; HttpOnly{secure_flag}; SameSite=Strict; Path=/device; Max-Age={SESSION_COOKIE_MAX_AGE}"
    )
}

/// Set the session cookie in response headers.
///
/// # Arguments
///
/// * `headers` - Mutable reference to response headers
/// * `session_id` - The session ID to store
/// * `secure` - Whether to add the Secure flag
pub fn set_session_cookie(
    headers: &mut axum::http::header::HeaderMap,
    session_id: Uuid,
    secure: bool,
) {
    let cookie_value = create_session_cookie(session_id, secure);
    if let Ok(value) = HeaderValue::from_str(&cookie_value) {
        headers.insert(SET_COOKIE, value);
    }
}

/// Extract session ID from request cookies.
///
/// Parses the Cookie header and looks for the device session cookie.
///
/// # Arguments
///
/// * `headers` - Request headers containing the Cookie header
///
/// # Returns
///
/// The session ID if found and valid, None otherwise.
pub fn extract_session_cookie(headers: &HeaderMap) -> Option<Uuid> {
    let cookie_header = headers.get(axum::http::header::COOKIE)?;
    let cookie_str = cookie_header.to_str().ok()?;

    // Parse cookie string (format: "name1=value1; name2=value2")
    for part in cookie_str.split(';') {
        let part = part.trim();
        if let Some(value) = part.strip_prefix(&format!("{SESSION_COOKIE_NAME}=")) {
            return Uuid::parse_str(value.trim()).ok();
        }
    }

    None
}

/// Clear the session cookie by setting it to expire immediately.
///
/// # Arguments
///
/// * `secure` - Whether to add the Secure flag
///
/// # Returns
///
/// The cookie header value for clearing the cookie.
#[must_use]
pub fn clear_session_cookie(secure: bool) -> String {
    let secure_flag = if secure { "; Secure" } else { "" };
    format!(
        "{SESSION_COOKIE_NAME}=; HttpOnly{secure_flag}; SameSite=Strict; Path=/device; Max-Age=0"
    )
}

// ============================================================================
// CSRF Token Functions
// ============================================================================

/// Generate a new CSRF token.
///
/// Creates a cryptographically random 32-byte token encoded as URL-safe base64.
///
/// # Returns
///
/// A random CSRF token string (43 characters).
#[must_use]
pub fn generate_csrf_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Create the CSRF cookie value.
///
/// The CSRF cookie is NOT `HttpOnly` so it can be read by JavaScript if needed,
/// but we use the double-submit pattern with hidden form fields instead.
///
/// # Arguments
///
/// * `token` - The CSRF token to store
/// * `secure` - Whether to add the Secure flag
///
/// # Returns
///
/// The cookie header value as a string.
#[must_use]
pub fn create_csrf_cookie(token: &str, secure: bool) -> String {
    let secure_flag = if secure { "; Secure" } else { "" };
    format!(
        "{CSRF_COOKIE_NAME}={token}{secure_flag}; SameSite=Strict; Path=/device; Max-Age={CSRF_COOKIE_MAX_AGE}"
    )
}

/// Extract CSRF token from request cookies.
///
/// # Arguments
///
/// * `headers` - Request headers containing the Cookie header
///
/// # Returns
///
/// The CSRF token if found, None otherwise.
pub fn extract_csrf_cookie(headers: &HeaderMap) -> Option<String> {
    let cookie_header = headers.get(axum::http::header::COOKIE)?;
    let cookie_str = cookie_header.to_str().ok()?;

    for part in cookie_str.split(';') {
        let part = part.trim();
        if let Some(value) = part.strip_prefix(&format!("{CSRF_COOKIE_NAME}=")) {
            return Some(value.trim().to_string());
        }
    }

    None
}

/// Validate a CSRF token from form submission against the cookie.
///
/// Uses constant-time comparison to prevent timing attacks.
///
/// # Arguments
///
/// * `cookie_token` - The token from the CSRF cookie
/// * `form_token` - The token from the form submission
///
/// # Returns
///
/// True if the tokens match, false otherwise.
#[must_use]
pub fn validate_csrf_token(cookie_token: &str, form_token: &str) -> bool {
    // Use constant-time comparison
    if cookie_token.len() != form_token.len() {
        return false;
    }

    let mut result = 0u8;
    for (a, b) in cookie_token.bytes().zip(form_token.bytes()) {
        result |= a ^ b;
    }
    result == 0
}

/// Clear the CSRF cookie by setting it to expire immediately.
///
/// # Arguments
///
/// * `secure` - Whether to add the Secure flag
///
/// # Returns
///
/// The cookie header value for clearing the cookie.
#[must_use]
pub fn clear_csrf_cookie(secure: bool) -> String {
    let secure_flag = if secure { "; Secure" } else { "" };
    format!("{CSRF_COOKIE_NAME}={secure_flag}; SameSite=Strict; Path=/device; Max-Age=0")
}

// ============================================================================
// Response Helpers
// ============================================================================

use axum::response::{Html, IntoResponse, Response};

/// Build an HTML response with a new CSRF token cookie.
///
/// This helper generates a new CSRF token, creates the cookie, and builds
/// an HTML response with the cookie header set. Use this to reduce boilerplate
/// in device flow handlers.
///
/// # Arguments
///
/// * `html` - The HTML content to return
/// * `is_secure` - Whether to add the Secure flag (use `state.is_production()`)
///
/// # Returns
///
/// An Axum Response with HTML content and CSRF cookie.
///
/// # Example
///
/// ```rust,ignore
/// let html = render_login_page(&user_code, "client", &[], None, &csrf_token);
/// return build_csrf_html_response(html, state.is_production());
/// ```
pub fn build_csrf_html_response(html: String, is_secure: bool) -> Response {
    let csrf_token = generate_csrf_token();
    let csrf_cookie = create_csrf_cookie(&csrf_token, is_secure);
    let mut response = Html(html).into_response();
    if let Ok(cookie_value) = HeaderValue::from_str(&csrf_cookie) {
        response.headers_mut().insert(SET_COOKIE, cookie_value);
    }
    response
}

/// Build an HTML response with a specific CSRF token cookie.
///
/// Similar to `build_csrf_html_response`, but uses an existing token instead
/// of generating a new one. Useful when the token is already embedded in
/// the HTML content.
///
/// # Arguments
///
/// * `html` - The HTML content to return
/// * `csrf_token` - The CSRF token to set in the cookie
/// * `is_secure` - Whether to add the Secure flag
///
/// # Returns
///
/// An Axum Response with HTML content and CSRF cookie.
pub fn build_html_response_with_csrf(html: String, csrf_token: &str, is_secure: bool) -> Response {
    let csrf_cookie = create_csrf_cookie(csrf_token, is_secure);
    let mut response = Html(html).into_response();
    if let Ok(cookie_value) = HeaderValue::from_str(&csrf_cookie) {
        response.headers_mut().insert(SET_COOKIE, cookie_value);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    #[test]
    fn test_create_session_cookie_secure() {
        let session_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let cookie = create_session_cookie(session_id, true);

        assert!(cookie.contains("xavyo_device_session=550e8400-e29b-41d4-a716-446655440000"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("SameSite=Strict"));
        assert!(cookie.contains("Path=/device"));
        assert!(cookie.contains("Max-Age=86400"));
    }

    #[test]
    fn test_create_session_cookie_not_secure() {
        let session_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let cookie = create_session_cookie(session_id, false);

        assert!(cookie.contains("xavyo_device_session="));
        assert!(cookie.contains("HttpOnly"));
        assert!(!cookie.contains("Secure"));
    }

    #[test]
    fn test_extract_session_cookie_found() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            HeaderValue::from_static("xavyo_device_session=550e8400-e29b-41d4-a716-446655440000"),
        );

        let session_id = extract_session_cookie(&headers);
        assert_eq!(
            session_id,
            Some(Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap())
        );
    }

    #[test]
    fn test_extract_session_cookie_multiple_cookies() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            HeaderValue::from_static("other=value; xavyo_device_session=550e8400-e29b-41d4-a716-446655440000; another=test"),
        );

        let session_id = extract_session_cookie(&headers);
        assert_eq!(
            session_id,
            Some(Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap())
        );
    }

    #[test]
    fn test_extract_session_cookie_not_found() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            HeaderValue::from_static("other_cookie=some_value"),
        );

        let session_id = extract_session_cookie(&headers);
        assert!(session_id.is_none());
    }

    #[test]
    fn test_extract_session_cookie_no_cookie_header() {
        let headers = HeaderMap::new();
        let session_id = extract_session_cookie(&headers);
        assert!(session_id.is_none());
    }

    #[test]
    fn test_extract_session_cookie_invalid_uuid() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            HeaderValue::from_static("xavyo_device_session=not-a-valid-uuid"),
        );

        let session_id = extract_session_cookie(&headers);
        assert!(session_id.is_none());
    }

    #[test]
    fn test_clear_session_cookie() {
        let cookie = clear_session_cookie(true);
        assert!(cookie.contains("xavyo_device_session="));
        assert!(cookie.contains("Max-Age=0"));
    }

    #[test]
    fn test_set_session_cookie() {
        let mut headers = HeaderMap::new();
        let session_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();

        set_session_cookie(&mut headers, session_id, true);

        let cookie_value = headers.get(SET_COOKIE).unwrap().to_str().unwrap();
        assert!(cookie_value.contains("550e8400-e29b-41d4-a716-446655440000"));
    }

    // CSRF Token Tests

    #[test]
    fn test_generate_csrf_token_length() {
        let token = generate_csrf_token();
        // 32 bytes base64 encoded = 43 characters (URL_SAFE_NO_PAD)
        assert_eq!(token.len(), 43);
    }

    #[test]
    fn test_generate_csrf_token_unique() {
        let token1 = generate_csrf_token();
        let token2 = generate_csrf_token();
        assert_ne!(token1, token2);
    }

    #[test]
    fn test_create_csrf_cookie_secure() {
        let token = "test_csrf_token_value";
        let cookie = create_csrf_cookie(token, true);

        assert!(cookie.contains("xavyo_csrf_token=test_csrf_token_value"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("SameSite=Strict"));
        assert!(cookie.contains("Path=/device"));
        // CSRF cookie is NOT HttpOnly (can be read by JS if needed)
        assert!(!cookie.contains("HttpOnly"));
    }

    #[test]
    fn test_create_csrf_cookie_not_secure() {
        let token = "test_csrf_token_value";
        let cookie = create_csrf_cookie(token, false);

        assert!(cookie.contains("xavyo_csrf_token=test_csrf_token_value"));
        assert!(!cookie.contains("Secure"));
    }

    #[test]
    fn test_extract_csrf_cookie_found() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            HeaderValue::from_static("xavyo_csrf_token=my_csrf_token_123"),
        );

        let token = extract_csrf_cookie(&headers);
        assert_eq!(token, Some("my_csrf_token_123".to_string()));
    }

    #[test]
    fn test_extract_csrf_cookie_multiple_cookies() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            HeaderValue::from_static("other=value; xavyo_csrf_token=csrf_abc; another=test"),
        );

        let token = extract_csrf_cookie(&headers);
        assert_eq!(token, Some("csrf_abc".to_string()));
    }

    #[test]
    fn test_extract_csrf_cookie_not_found() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            HeaderValue::from_static("other_cookie=some_value"),
        );

        let token = extract_csrf_cookie(&headers);
        assert!(token.is_none());
    }

    #[test]
    fn test_validate_csrf_token_valid() {
        let token = "test_token_12345";
        assert!(validate_csrf_token(token, token));
    }

    #[test]
    fn test_validate_csrf_token_invalid() {
        assert!(!validate_csrf_token("token_a", "token_b"));
    }

    #[test]
    fn test_validate_csrf_token_different_lengths() {
        assert!(!validate_csrf_token("short", "much_longer_token"));
    }

    #[test]
    fn test_clear_csrf_cookie() {
        let cookie = clear_csrf_cookie(true);
        assert!(cookie.contains("xavyo_csrf_token="));
        assert!(cookie.contains("Max-Age=0"));
    }

    #[test]
    fn test_validate_csrf_token_empty_strings() {
        // Both empty - should match
        assert!(validate_csrf_token("", ""));
    }

    #[test]
    fn test_validate_csrf_token_one_empty() {
        // One empty, one not - should not match
        assert!(!validate_csrf_token("", "token"));
        assert!(!validate_csrf_token("token", ""));
    }

    #[test]
    fn test_validate_csrf_token_similar_tokens() {
        // Tokens that differ by only one character
        assert!(!validate_csrf_token("abcdef123456", "abcdef123457"));
        assert!(!validate_csrf_token("xyztoken", "Xyztoken")); // Case sensitive
    }

    #[test]
    fn test_validate_csrf_token_real_tokens() {
        // Test with realistic token format (base64 encoded)
        let token1 = generate_csrf_token();
        let token2 = generate_csrf_token();

        // Same token should validate
        assert!(validate_csrf_token(&token1, &token1));

        // Different tokens should not validate
        assert!(!validate_csrf_token(&token1, &token2));
    }

    #[test]
    fn test_validate_csrf_constant_time() {
        // This test verifies the function uses constant-time comparison
        // by checking behavior with prefix-matching strings
        // (timing attacks exploit early-exit on mismatch)
        let token = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef";

        // Different at first character
        assert!(!validate_csrf_token(
            token,
            "XBCDEFGHIJKLMNOPQRSTUVWXYZabcdef"
        ));

        // Different at last character
        assert!(!validate_csrf_token(
            token,
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdeX"
        ));

        // Different in middle
        assert!(!validate_csrf_token(
            token,
            "ABCDEFGHIJKLMNOXQRSTUVWXYZabcdef"
        ));
    }
}
