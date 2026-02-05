//! Tenant context extraction from HTTP requests.
//!
//! Provides functions to extract tenant ID from headers and JWT claims.

use crate::config::TenantConfig;
use crate::error::TenantError;
use http::Request;
use xavyo_core::TenantId;

/// Wrapper around `TenantId` for request extensions.
///
/// This struct is inserted into Axum request extensions when a valid
/// tenant context is extracted. It can be accessed in handlers via
/// `Extension<TenantContext>` or simply `Extension<TenantId>`.
///
/// # Example
///
/// ```rust,ignore
/// use axum::Extension;
/// use xavyo_tenant::TenantContext;
///
/// async fn handler(
///     Extension(ctx): Extension<TenantContext>,
/// ) -> String {
///     format!("Tenant: {}", ctx.tenant_id())
/// }
/// ```
#[derive(Debug, Clone, Copy)]
pub struct TenantContext {
    tenant_id: TenantId,
}

impl TenantContext {
    /// Create a new tenant context.
    #[must_use]
    pub fn new(tenant_id: TenantId) -> Self {
        Self { tenant_id }
    }

    /// Get the tenant ID.
    #[must_use]
    pub fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }
}

impl From<TenantId> for TenantContext {
    fn from(tenant_id: TenantId) -> Self {
        Self::new(tenant_id)
    }
}

impl From<TenantContext> for TenantId {
    fn from(ctx: TenantContext) -> Self {
        ctx.tenant_id
    }
}

/// Extract tenant ID from the HTTP request.
///
/// This function tries to extract the tenant ID from:
/// 1. Request extensions (if auth middleware has already set TenantId)
/// 2. X-Tenant-ID header (or custom header from config)
///
/// Returns `Err(TenantError::Missing)` if no tenant context is found.
/// Returns `Err(TenantError::InvalidFormat)` if the tenant ID is not a valid UUID.
///
/// # Example
///
/// ```rust,ignore
/// use xavyo_tenant::{extract_tenant_id, TenantConfig};
///
/// let config = TenantConfig::default();
/// let tenant_id = extract_tenant_id(&request, &config)?;
/// ```
pub fn extract_tenant_id<B>(
    req: &Request<B>,
    config: &TenantConfig,
) -> Result<TenantId, TenantError> {
    // 1. Check if TenantId was already set by auth middleware (e.g., API key auth)
    // F113: API key middleware sets TenantId in extensions before TenantLayer runs
    if let Some(tenant_id) = req.extensions().get::<TenantId>() {
        return Ok(*tenant_id);
    }

    // 2. Fall back to header extraction
    extract_from_header(req, &config.header_name)
}

/// Extract tenant ID from an HTTP header.
///
/// # Arguments
///
/// * `req` - The HTTP request
/// * `header_name` - The header name to check (e.g., "X-Tenant-ID")
///
/// # Errors
///
/// Returns `TenantError::Missing` if the header is not present.
/// Returns `TenantError::InvalidFormat` if the header value is not a valid UUID.
pub fn extract_from_header<B>(
    req: &Request<B>,
    header_name: &str,
) -> Result<TenantId, TenantError> {
    let header_value = req.headers().get(header_name).ok_or(TenantError::Missing)?;

    let value_str = header_value
        .to_str()
        .map_err(|_| TenantError::InvalidFormat("Header value is not valid UTF-8".to_string()))?;

    let trimmed = value_str.trim();

    if trimmed.is_empty() {
        return Err(TenantError::Missing);
    }

    trimmed
        .parse::<TenantId>()
        .map_err(|_| TenantError::InvalidFormat(format!("'{trimmed}' is not a valid UUID")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Request;

    fn make_request_with_header(header_name: &str, header_value: &str) -> Request<()> {
        Request::builder()
            .header(header_name, header_value)
            .body(())
            .unwrap()
    }

    fn make_request_without_headers() -> Request<()> {
        Request::builder().body(()).unwrap()
    }

    #[test]
    fn test_extract_from_header_valid_uuid() {
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        let req = make_request_with_header("X-Tenant-ID", uuid);

        let result = extract_from_header(&req, "X-Tenant-ID");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().to_string(), uuid);
    }

    #[test]
    fn test_extract_from_header_with_whitespace() {
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        let req = make_request_with_header("X-Tenant-ID", &format!("  {}  ", uuid));

        let result = extract_from_header(&req, "X-Tenant-ID");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().to_string(), uuid);
    }

    #[test]
    fn test_extract_from_header_missing() {
        let req = make_request_without_headers();

        let result = extract_from_header(&req, "X-Tenant-ID");
        assert!(matches!(result, Err(TenantError::Missing)));
    }

    #[test]
    fn test_extract_from_header_empty() {
        let req = make_request_with_header("X-Tenant-ID", "");

        let result = extract_from_header(&req, "X-Tenant-ID");
        assert!(matches!(result, Err(TenantError::Missing)));
    }

    #[test]
    fn test_extract_from_header_whitespace_only() {
        let req = make_request_with_header("X-Tenant-ID", "   ");

        let result = extract_from_header(&req, "X-Tenant-ID");
        assert!(matches!(result, Err(TenantError::Missing)));
    }

    #[test]
    fn test_extract_from_header_invalid_uuid() {
        let req = make_request_with_header("X-Tenant-ID", "not-a-uuid");

        let result = extract_from_header(&req, "X-Tenant-ID");
        assert!(matches!(result, Err(TenantError::InvalidFormat(_))));
    }

    #[test]
    fn test_extract_from_header_custom_header_name() {
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        let req = make_request_with_header("X-Custom-Tenant", uuid);

        let result = extract_from_header(&req, "X-Custom-Tenant");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().to_string(), uuid);
    }

    #[test]
    fn test_extract_tenant_id_with_config() {
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        let req = make_request_with_header("X-Tenant-ID", uuid);
        let config = TenantConfig::default();

        let result = extract_tenant_id(&req, &config);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().to_string(), uuid);
    }

    #[test]
    fn test_extract_tenant_id_custom_header_config() {
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        let req = make_request_with_header("X-Org-ID", uuid);
        let config = TenantConfig::builder().header_name("X-Org-ID").build();

        let result = extract_tenant_id(&req, &config);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().to_string(), uuid);
    }

    #[test]
    fn test_tenant_context_conversions() {
        let tenant_id = TenantId::new();
        let ctx = TenantContext::new(tenant_id);

        assert_eq!(ctx.tenant_id(), tenant_id);

        let ctx_from: TenantContext = tenant_id.into();
        assert_eq!(ctx_from.tenant_id(), tenant_id);

        let id_from: TenantId = ctx.into();
        assert_eq!(id_from, tenant_id);
    }
}
