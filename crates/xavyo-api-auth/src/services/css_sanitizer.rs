//! CSS sanitization for custom branding.
//!
//! Uses an allowlist approach to prevent XSS attacks in custom CSS.

use crate::error::ApiAuthError;
use std::collections::HashSet;

/// Allowed CSS properties (safe for branding customization).
const ALLOWED_PROPERTIES: &[&str] = &[
    // Colors
    "color",
    "background-color",
    "background",
    "border-color",
    // Typography
    "font-family",
    "font-size",
    "font-weight",
    "font-style",
    "line-height",
    "letter-spacing",
    "text-align",
    "text-decoration",
    "text-transform",
    // Box model
    "margin",
    "margin-top",
    "margin-right",
    "margin-bottom",
    "margin-left",
    "padding",
    "padding-top",
    "padding-right",
    "padding-bottom",
    "padding-left",
    // Border
    "border",
    "border-width",
    "border-style",
    "border-radius",
    // Layout
    "width",
    "max-width",
    "min-width",
    "height",
    "max-height",
    "min-height",
    // Display
    "display",
    "opacity",
    // Effects
    "box-shadow",
    "transition",
];

/// Disallowed patterns in CSS values (security risks).
const DISALLOWED_PATTERNS: &[&str] = &[
    "javascript:",
    "expression(",
    "url(",
    "-moz-binding",
    "behavior:",
    "@import",
    "@charset",
    "data:",
    "vbscript:",
    "<script",
    "</script",
    "onclick",
    "onerror",
    "onload",
];

/// Sanitize custom CSS by validating against allowlist.
///
/// Returns the sanitized CSS or an error if invalid content is found.
pub fn sanitize_css(css: &str) -> Result<String, ApiAuthError> {
    if css.is_empty() {
        return Ok(String::new());
    }

    // Check for maximum length (16KB)
    if css.len() > 16 * 1024 {
        return Err(ApiAuthError::InvalidCss(
            "CSS exceeds maximum length of 16KB".to_string(),
        ));
    }

    let css_lower = css.to_lowercase();

    // Check for disallowed patterns
    for pattern in DISALLOWED_PATTERNS {
        if css_lower.contains(pattern) {
            return Err(ApiAuthError::InvalidCss(format!(
                "CSS contains disallowed pattern: {pattern}"
            )));
        }
    }

    // Basic validation: ensure it looks like CSS (has property: value pairs)
    // This is a simple check - a full CSS parser would be more robust
    if !css.contains(':') && !css.contains('{') {
        return Err(ApiAuthError::InvalidCss("Invalid CSS format".to_string()));
    }

    // Validate properties against allowlist (basic check)
    let allowed: HashSet<&str> = ALLOWED_PROPERTIES.iter().copied().collect();

    // Extract property names (simple regex-free approach)
    for line in css.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("/*") || line.starts_with("//") {
            continue;
        }

        // Skip selectors (lines ending with { or starting with . # etc)
        if line.ends_with('{') || line.ends_with('}') {
            continue;
        }

        // Look for property: value; patterns
        if let Some(colon_pos) = line.find(':') {
            let property = line[..colon_pos].trim().to_lowercase();

            // Skip if it looks like a selector (contains . or # or [)
            if property.contains('.') || property.contains('#') || property.contains('[') {
                continue;
            }

            // Validate property is allowed
            if !property.is_empty() && !allowed.contains(property.as_str()) {
                // Allow vendor prefixes of allowed properties
                let without_prefix = property
                    .trim_start_matches("-webkit-")
                    .trim_start_matches("-moz-")
                    .trim_start_matches("-ms-")
                    .trim_start_matches("-o-");

                if !allowed.contains(without_prefix) {
                    return Err(ApiAuthError::InvalidCss(format!(
                        "CSS property '{property}' is not allowed"
                    )));
                }
            }
        }
    }

    Ok(css.to_string())
}

/// Sanitize CSS using ammonia for HTML content within CSS (belt and suspenders).
pub fn sanitize_css_strict(css: &str) -> Result<String, ApiAuthError> {
    // First pass: our custom validation
    let validated = sanitize_css(css)?;

    // Second pass: use ammonia to strip any remaining HTML-like content
    // (This is mainly for values that might contain HTML)
    let cleaned = ammonia::clean(&validated);

    // If ammonia changed the content significantly, there was HTML in it
    if cleaned.len() < validated.len() * 8 / 10 {
        return Err(ApiAuthError::InvalidCss(
            "CSS contains HTML-like content".to_string(),
        ));
    }

    Ok(validated)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_css() {
        let css = r#"
            .login-button {
                background-color: #1a73e8;
                color: white;
                border-radius: 4px;
            }
        "#;
        assert!(sanitize_css(css).is_ok());
    }

    #[test]
    fn test_css_with_javascript() {
        let css = "background: url(javascript:alert(1))";
        assert!(matches!(
            sanitize_css(css),
            Err(ApiAuthError::InvalidCss(_))
        ));
    }

    #[test]
    fn test_css_with_expression() {
        let css = "width: expression(alert(1))";
        assert!(matches!(
            sanitize_css(css),
            Err(ApiAuthError::InvalidCss(_))
        ));
    }

    #[test]
    fn test_css_with_import() {
        let css = "@import url('evil.css');";
        assert!(matches!(
            sanitize_css(css),
            Err(ApiAuthError::InvalidCss(_))
        ));
    }

    #[test]
    fn test_css_with_data_uri() {
        let css = "background: data:text/html,<script>alert(1)</script>";
        assert!(matches!(
            sanitize_css(css),
            Err(ApiAuthError::InvalidCss(_))
        ));
    }

    #[test]
    fn test_empty_css() {
        assert_eq!(sanitize_css("").unwrap(), "");
    }

    #[test]
    fn test_css_too_long() {
        let long_css = "a".repeat(20 * 1024);
        assert!(matches!(
            sanitize_css(&long_css),
            Err(ApiAuthError::InvalidCss(_))
        ));
    }

    #[test]
    fn test_allowed_properties() {
        let css = "color: red; background-color: blue; font-size: 14px;";
        assert!(sanitize_css(css).is_ok());
    }

    #[test]
    fn test_vendor_prefixes() {
        let css = "-webkit-border-radius: 4px; -moz-border-radius: 4px;";
        assert!(sanitize_css(css).is_ok());
    }
}
