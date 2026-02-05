//! Validation utilities for branding.

use regex::Regex;

/// Regex for validating hex color format (#RRGGBB or #RGB).
static HEX_COLOR_REGEX: std::sync::LazyLock<Regex> =
    std::sync::LazyLock::new(|| Regex::new(r"^#([0-9A-Fa-f]{3}|[0-9A-Fa-f]{6})$").unwrap());

/// Validate hex color format.
///
/// Returns true if the color is a valid hex color (#RGB or #RRGGBB).
pub fn validate_hex_color(color: &str) -> bool {
    HEX_COLOR_REGEX.is_match(color)
}

/// Normalize hex color to #RRGGBB format.
///
/// Converts #RGB to #RRGGBB (e.g., #ABC -> #AABBCC).
/// Returns None if invalid format.
pub fn normalize_hex_color(color: &str) -> Option<String> {
    if !HEX_COLOR_REGEX.is_match(color) {
        return None;
    }

    if color.len() == 4 {
        // Convert #RGB to #RRGGBB (uppercase)
        let chars: Vec<char> = color.to_uppercase().chars().collect();
        Some(format!(
            "#{}{}{}{}{}{}",
            chars[1], chars[1], chars[2], chars[2], chars[3], chars[3]
        ))
    } else {
        Some(color.to_uppercase())
    }
}

/// Validate URL format (basic validation).
///
/// Allows absolute URLs (http/https) or relative paths starting with /.
#[must_use]
pub fn validate_url(url: &str) -> bool {
    if url.is_empty() {
        return false;
    }

    // Allow relative paths
    if url.starts_with('/') {
        return true;
    }

    // Allow http/https URLs
    url.starts_with("http://") || url.starts_with("https://")
}

/// Validate font family name.
///
/// Allows common safe font names and Google Fonts style names.
#[must_use]
pub fn validate_font_family(font: &str) -> bool {
    if font.is_empty() || font.len() > 200 {
        return false;
    }

    // Only allow alphanumeric, spaces, hyphens, commas, and quotes
    font.chars().all(|c| {
        c.is_alphanumeric() || c.is_whitespace() || c == '-' || c == ',' || c == '\'' || c == '"'
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_hex_colors() {
        assert!(validate_hex_color("#1a73e8"));
        assert!(validate_hex_color("#1A73E8"));
        assert!(validate_hex_color("#abc"));
        assert!(validate_hex_color("#ABC"));
        assert!(validate_hex_color("#000000"));
        assert!(validate_hex_color("#fff"));
    }

    #[test]
    fn test_invalid_hex_colors() {
        assert!(!validate_hex_color("1a73e8")); // Missing #
        assert!(!validate_hex_color("#1a73e")); // 5 chars
        assert!(!validate_hex_color("#1a73e8f")); // 7 chars
        assert!(!validate_hex_color("#gggggg")); // Invalid chars
        assert!(!validate_hex_color("")); // Empty
        assert!(!validate_hex_color("red")); // Named color
    }

    #[test]
    fn test_normalize_hex_color() {
        // Short form #RGB expands to #RRGGBB in lowercase
        let result = normalize_hex_color("#abc");
        assert!(result.is_some());
        assert!(result.as_ref().unwrap().len() == 7);

        // Already 6 chars - normalizes to uppercase
        let result = normalize_hex_color("#1a73e8");
        assert!(result.is_some());

        // Invalid format returns None
        assert_eq!(normalize_hex_color("invalid"), None);
    }

    #[test]
    fn test_validate_url() {
        assert!(validate_url("/assets/logo.png"));
        assert!(validate_url("https://example.com/logo.png"));
        assert!(validate_url("http://example.com/logo.png"));
        assert!(!validate_url(""));
        assert!(!validate_url("ftp://example.com"));
        assert!(!validate_url("example.com/logo.png"));
    }

    #[test]
    fn test_validate_font_family() {
        assert!(validate_font_family("Inter"));
        assert!(validate_font_family("Inter, sans-serif"));
        assert!(validate_font_family("'Roboto', Arial, sans-serif"));
        assert!(!validate_font_family("")); // Empty
        assert!(!validate_font_family(&"a".repeat(201))); // Too long
    }
}
