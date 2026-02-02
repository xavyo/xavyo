//! Middleware components for authentication API.

pub mod api_key;
pub mod ip_filter;
pub mod jwt_auth;
pub mod permission_guard;
pub mod rate_limit;
pub mod session_activity;

pub use api_key::{api_key_auth_middleware, ApiKeyContext, ApiKeyError};
pub use ip_filter::{extract_client_ip, ip_filter_middleware};
pub use jwt_auth::{jwt_auth_middleware, JwtPublicKey, JwtPublicKeys, ServiceAccountMarker};
pub use permission_guard::{
    check_resource_scope, is_super_admin, permission_guard_layer, permission_guard_middleware,
    require_permission, require_scope, require_super_admin_middleware, PermissionGuard,
    PermissionGuardState, ScopeCheckResult,
};
pub use rate_limit::{
    rate_limit_middleware, signup_rate_limit_middleware, signup_rate_limiter, EmailRateLimiter,
    RateLimitConfig, RateLimitKey, RateLimiter, DEFAULT_MAX_ATTEMPTS, DEFAULT_WINDOW_SECS,
    EMAIL_IP_RATE_LIMIT_MAX, EMAIL_RATE_LIMIT_MAX, EMAIL_RATE_LIMIT_WINDOW_SECS,
    SIGNUP_RATE_LIMIT_MAX, SIGNUP_RATE_LIMIT_WINDOW_SECS,
};
pub use session_activity::session_activity_middleware;
