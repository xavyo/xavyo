//! Slug generation service for unique tenant slugs.

use sqlx::PgPool;
use xavyo_db::models::Tenant;

/// Service for generating unique tenant slugs.
#[derive(Clone)]
pub struct SlugService {
    pool: PgPool,
}

impl SlugService {
    /// Create a new slug service.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Generate a URL-safe slug from an organization name.
    ///
    /// Transforms the name by:
    /// - Converting to lowercase
    /// - Replacing spaces and underscores with hyphens
    /// - Removing non-alphanumeric characters (except hyphens)
    /// - Collapsing multiple hyphens into one
    /// - Trimming leading/trailing hyphens
    ///
    /// This is a pure function that doesn't require database access.
    pub fn generate_slug(name: &str) -> String {
        let slug: String = name
            .to_lowercase()
            .chars()
            .map(|c| {
                if c.is_alphanumeric() {
                    c
                } else if c == ' ' || c == '_' || c == '-' {
                    '-'
                } else {
                    // Skip other characters
                    '\0'
                }
            })
            .filter(|&c| c != '\0')
            .collect();

        // Collapse multiple hyphens and trim
        let mut result = String::new();
        let mut last_was_hyphen = true; // Start true to trim leading hyphens

        for c in slug.chars() {
            if c == '-' {
                if !last_was_hyphen {
                    result.push(c);
                    last_was_hyphen = true;
                }
            } else {
                result.push(c);
                last_was_hyphen = false;
            }
        }

        // Trim trailing hyphen
        if result.ends_with('-') {
            result.pop();
        }

        result
    }

    /// Generate a unique slug, appending a numeric suffix if necessary.
    ///
    /// If the base slug already exists, tries slug-2, slug-3, etc.
    /// up to a maximum of 100 attempts.
    pub async fn generate_unique_slug(
        &self,
        name: &str,
    ) -> Result<String, crate::error::TenantError> {
        let base_slug = Self::generate_slug(name);

        if base_slug.is_empty() {
            return Err(crate::error::TenantError::Validation(
                "organization_name must contain at least one alphanumeric character".to_string(),
            ));
        }

        // Check if base slug is available
        if !Tenant::slug_exists(&self.pool, &base_slug)
            .await
            .map_err(|e| crate::error::TenantError::Database(e.to_string()))?
        {
            return Ok(base_slug);
        }

        // Try with numeric suffixes
        for i in 2..=100 {
            let candidate = format!("{}-{}", base_slug, i);
            if !Tenant::slug_exists(&self.pool, &candidate)
                .await
                .map_err(|e| crate::error::TenantError::Database(e.to_string()))?
            {
                return Ok(candidate);
            }
        }

        Err(crate::error::TenantError::SlugConflict(
            "Unable to generate unique slug after 100 attempts".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These tests only test the generate_slug method since
    // generate_unique_slug requires a database connection.

    #[test]
    fn test_generate_slug_simple() {
        assert_eq!(SlugService::generate_slug("Acme Corp"), "acme-corp");
    }

    #[test]
    fn test_generate_slug_lowercase() {
        assert_eq!(SlugService::generate_slug("ACME CORP"), "acme-corp");
    }

    #[test]
    fn test_generate_slug_underscores() {
        assert_eq!(SlugService::generate_slug("Acme_Corp"), "acme-corp");
    }

    #[test]
    fn test_generate_slug_special_chars() {
        assert_eq!(SlugService::generate_slug("Acme Corp!@#$%"), "acme-corp");
    }

    #[test]
    fn test_generate_slug_multiple_spaces() {
        assert_eq!(SlugService::generate_slug("Acme   Corp"), "acme-corp");
    }

    #[test]
    fn test_generate_slug_leading_trailing() {
        assert_eq!(SlugService::generate_slug("  Acme Corp  "), "acme-corp");
    }

    #[test]
    fn test_generate_slug_with_numbers() {
        assert_eq!(
            SlugService::generate_slug("Acme Corp 2024"),
            "acme-corp-2024"
        );
    }

    #[test]
    fn test_generate_slug_already_hyphenated() {
        assert_eq!(SlugService::generate_slug("acme-corp"), "acme-corp");
    }

    #[test]
    fn test_generate_slug_mixed() {
        assert_eq!(
            SlugService::generate_slug("  My--Org__Name  "),
            "my-org-name"
        );
    }
}
