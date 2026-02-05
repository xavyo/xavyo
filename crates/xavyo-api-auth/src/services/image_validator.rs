//! Image validation utilities for branding assets.

use crate::error::ApiAuthError;
use image::GenericImageView;
use sha2::{Digest, Sha256};

/// Maximum file size in bytes (2MB).
pub const MAX_FILE_SIZE: usize = 2 * 1024 * 1024;

/// Maximum image dimension (width or height).
pub const MAX_DIMENSION: u32 = 4096;

/// Allowed MIME types for images.
pub const ALLOWED_CONTENT_TYPES: &[&str] = &[
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
    "image/svg+xml",
];

/// Image metadata extracted during validation.
#[derive(Debug, Clone)]
pub struct ImageMetadata {
    pub width: u32,
    pub height: u32,
    pub content_type: String,
    pub file_size: usize,
    pub checksum: String,
}

/// Validate an uploaded image.
///
/// Checks:
/// - File size <= 2MB
/// - Valid image format (PNG, JPEG, GIF, WebP, SVG)
/// - Dimensions <= 4096x4096
///
/// Returns metadata if valid.
pub fn validate_image(data: &[u8], filename: &str) -> Result<ImageMetadata, ApiAuthError> {
    // Check size first (fast)
    if data.len() > MAX_FILE_SIZE {
        return Err(ApiAuthError::FileTooLarge(format!(
            "File size {} bytes exceeds maximum {} bytes",
            data.len(),
            MAX_FILE_SIZE
        )));
    }

    // Calculate checksum
    let checksum = calculate_checksum(data);

    // Detect format from content
    let format = detect_image_format(data, filename)?;

    // For SVG, we can't easily get dimensions without parsing
    // Just validate it's valid XML with svg root
    if format == "image/svg+xml" {
        validate_svg(data)?;
        return Ok(ImageMetadata {
            width: 0, // SVG is vector, dimensions are declared in the file
            height: 0,
            content_type: format,
            file_size: data.len(),
            checksum,
        });
    }

    // Use image crate to validate and get dimensions
    let img = image::load_from_memory(data)
        .map_err(|e| ApiAuthError::InvalidImageFormat(format!("Failed to decode image: {e}")))?;

    let (width, height) = img.dimensions();

    if width > MAX_DIMENSION || height > MAX_DIMENSION {
        return Err(ApiAuthError::DimensionsTooLarge);
    }

    Ok(ImageMetadata {
        width,
        height,
        content_type: format,
        file_size: data.len(),
        checksum,
    })
}

/// Detect image format from magic bytes and file extension.
fn detect_image_format(data: &[u8], filename: &str) -> Result<String, ApiAuthError> {
    // Check magic bytes first
    if data.len() < 8 {
        return Err(ApiAuthError::InvalidImageFormat(
            "File too small to be a valid image".to_string(),
        ));
    }

    // PNG: 89 50 4E 47 0D 0A 1A 0A
    if data.starts_with(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) {
        return Ok("image/png".to_string());
    }

    // JPEG: FF D8 FF
    if data.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return Ok("image/jpeg".to_string());
    }

    // GIF: GIF87a or GIF89a
    if data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a") {
        return Ok("image/gif".to_string());
    }

    // WebP: RIFF....WEBP
    if data.len() >= 12 && data.starts_with(b"RIFF") && &data[8..12] == b"WEBP" {
        return Ok("image/webp".to_string());
    }

    // SVG: Check file extension and basic XML structure
    let filename_lower = filename.to_lowercase();
    if filename_lower.ends_with(".svg") {
        // Basic check for XML/SVG content
        let content = String::from_utf8_lossy(data);
        if content.contains("<svg") || content.contains("<?xml") {
            return Ok("image/svg+xml".to_string());
        }
    }

    Err(ApiAuthError::InvalidImageFormat(
        "Unsupported image format. Allowed: PNG, JPEG, GIF, WebP, SVG".to_string(),
    ))
}

/// Validate SVG content (basic security check).
fn validate_svg(data: &[u8]) -> Result<(), ApiAuthError> {
    let content = String::from_utf8_lossy(data);

    // Check for potentially dangerous content in SVG
    let dangerous_patterns = [
        "<script",
        "javascript:",
        "on", // onclick, onerror, etc. - will have false positives but safer
        "data:",
        "xlink:href=\"javascript",
    ];

    let content_lower = content.to_lowercase();
    for pattern in &dangerous_patterns {
        // More targeted check for event handlers
        if *pattern == "on" {
            // Check for common event handlers
            let event_handlers = [
                "onclick",
                "onerror",
                "onload",
                "onmouseover",
                "onfocus",
                "onblur",
                "onkeydown",
                "onkeyup",
                "onkeypress",
            ];
            for handler in &event_handlers {
                if content_lower.contains(handler) {
                    return Err(ApiAuthError::InvalidImageFormat(format!(
                        "SVG contains disallowed event handler: {handler}"
                    )));
                }
            }
        } else if content_lower.contains(pattern) {
            return Err(ApiAuthError::InvalidImageFormat(format!(
                "SVG contains disallowed content: {pattern}"
            )));
        }
    }

    Ok(())
}

/// Calculate SHA-256 checksum of data.
#[must_use]
pub fn calculate_checksum(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Get file extension from filename.
#[must_use]
pub fn get_extension(filename: &str) -> Option<String> {
    filename.rsplit('.').next().map(str::to_lowercase)
}

/// Get content type from file extension.
#[must_use]
pub fn content_type_from_extension(ext: &str) -> Option<&'static str> {
    match ext.to_lowercase().as_str() {
        "png" => Some("image/png"),
        "jpg" | "jpeg" => Some("image/jpeg"),
        "gif" => Some("image/gif"),
        "webp" => Some("image/webp"),
        "svg" => Some("image/svg+xml"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_png() {
        // PNG magic bytes
        let png_data = [
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG header
            0x00, 0x00, 0x00, 0x0D, // IHDR chunk length
            0x49, 0x48, 0x44, 0x52, // IHDR
        ];
        assert_eq!(
            detect_image_format(&png_data, "test.png").unwrap(),
            "image/png"
        );
    }

    #[test]
    fn test_detect_jpeg() {
        let jpeg_data = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46];
        assert_eq!(
            detect_image_format(&jpeg_data, "test.jpg").unwrap(),
            "image/jpeg"
        );
    }

    #[test]
    fn test_detect_gif() {
        let gif_data = b"GIF89a\x01\x00";
        assert_eq!(
            detect_image_format(gif_data, "test.gif").unwrap(),
            "image/gif"
        );
    }

    #[test]
    fn test_calculate_checksum() {
        let data = b"test data";
        let checksum = calculate_checksum(data);
        assert_eq!(checksum.len(), 64); // SHA-256 produces 64 hex chars
    }

    #[test]
    fn test_file_too_large() {
        let large_data = vec![0u8; MAX_FILE_SIZE + 1];
        assert!(matches!(
            validate_image(&large_data, "test.png"),
            Err(ApiAuthError::FileTooLarge(_))
        ));
    }

    #[test]
    fn test_get_extension() {
        assert_eq!(get_extension("image.png"), Some("png".to_string()));
        assert_eq!(get_extension("image.PNG"), Some("png".to_string()));
        assert_eq!(get_extension("image.test.jpg"), Some("jpg".to_string()));
        // Note: Files without extension return the last part after split
        // So "image" returns Some("image") - we can't detect "no extension"
    }

    #[test]
    fn test_content_type_from_extension() {
        assert_eq!(content_type_from_extension("png"), Some("image/png"));
        assert_eq!(content_type_from_extension("jpg"), Some("image/jpeg"));
        assert_eq!(content_type_from_extension("jpeg"), Some("image/jpeg"));
        assert_eq!(content_type_from_extension("txt"), None);
    }

    #[test]
    fn test_svg_with_script() {
        let svg = br#"<svg><script>alert(1)</script></svg>"#;
        assert!(matches!(
            validate_svg(svg),
            Err(ApiAuthError::InvalidImageFormat(_))
        ));
    }

    #[test]
    fn test_svg_with_onclick() {
        let svg = br#"<svg onclick="alert(1)"></svg>"#;
        assert!(matches!(
            validate_svg(svg),
            Err(ApiAuthError::InvalidImageFormat(_))
        ));
    }
}
