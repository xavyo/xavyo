//! Proxy configuration module for the xavyo CLI
//!
//! This module handles HTTP, HTTPS, and SOCKS5 proxy configuration,
//! supporting both environment variables and CLI flag overrides.

mod config;

#[allow(unused_imports)]
pub use config::{
    global_proxy_config, init_global_proxy, mask_proxy_credentials, validate_proxy_url,
    ProxyConfig, ProxyCredentials,
};
