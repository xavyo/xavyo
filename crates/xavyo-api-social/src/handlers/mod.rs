//! HTTP handlers for social authentication.

pub mod admin;
pub mod authorize;
pub mod callback;
pub mod link;
pub mod unlink;

pub use admin::{disable_provider, list_providers, update_provider};
pub use authorize::{authorize, available_providers};
pub use callback::{callback_apple_post, callback_get, JwtTokens};
pub use link::{initiate_link, link_account, list_connections};
pub use unlink::unlink_account;
