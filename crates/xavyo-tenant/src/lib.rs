//! # xavyo-tenant
//!
//! Tower/Axum middleware for multi-tenant context extraction and validation.
//!
//! This library provides middleware that automatically extracts tenant context
//! from incoming HTTP requests and makes it available to route handlers via
//! Axum request extensions.
//!
//! ## Features
//!
//! - **Header Extraction**: Extract tenant ID from `X-Tenant-ID` header
//! - **JWT Support**: Extract tenant ID from JWT `tid` claim (when auth middleware provides claims)
//! - **Validation**: Validate tenant ID format (UUID)
//! - **Error Responses**: Return structured JSON 401 errors for invalid/missing context
//! - **Composability**: Standard Tower Layer/Service for middleware composition
//!
//! ## Quick Start
//!
//! ```rust,ignore
//! use xavyo_tenant::TenantLayer;
//! use axum::{Router, Extension, routing::get};
//! use xavyo_core::TenantId;
//!
//! async fn list_users(
//!     Extension(tenant_id): Extension<TenantId>,
//! ) -> String {
//!     format!("Users for tenant: {}", tenant_id)
//! }
//!
//! let app = Router::new()
//!     .route("/api/users", get(list_users))
//!     .layer(TenantLayer::new());
//! ```
//!
//! ## Database Integration with xavyo-db
//!
//! After the middleware extracts the tenant context, you can use it with
//! xavyo-db to set the `PostgreSQL` session variable for Row-Level Security:
//!
//! ```rust,ignore
//! use axum::{Extension, extract::State};
//! use xavyo_core::TenantId;
//! use xavyo_db::{DbPool, set_tenant_context};
//!
//! async fn list_users(
//!     Extension(tenant_id): Extension<TenantId>,
//!     State(pool): State<DbPool>,
//! ) -> Result<String, StatusCode> {
//!     let mut tx = pool.begin().await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
//!     set_tenant_context(&mut *tx, tenant_id).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
//!
//!     // Now all queries on tenant-scoped tables are automatically filtered
//!     // by the current tenant via RLS policies
//!
//!     tx.commit().await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
//!     Ok(format!("Users for tenant: {}", tenant_id))
//! }
//! ```
//!
//! ## Custom Configuration
//!
//! ```rust,ignore
//! use xavyo_tenant::{TenantLayer, TenantConfig};
//!
//! let config = TenantConfig::builder()
//!     .header_name("X-Tenant-ID")
//!     .require_tenant(true)
//!     .build();
//!
//! let app = Router::new()
//!     .route("/api/users", get(list_users))
//!     .layer(TenantLayer::with_config(config));
//! ```

mod config;
mod error;
mod extract;
mod layer;
mod service;

pub use config::{TenantConfig, TenantConfigBuilder};
pub use error::{ErrorResponse, TenantError};
pub use extract::{extract_tenant_id, TenantContext};
pub use layer::TenantLayer;
pub use service::TenantService;
