//! Services for OIDC Federation.

pub mod auth_flow;
pub mod claims;
pub mod discovery;
pub mod encryption;
pub mod hrd;
pub mod idp_config;
pub mod jwks_cache;
pub mod provisioning;
pub mod token_issuer;
pub mod token_verifier;
pub mod validation;

pub use auth_flow::{AuthFlowService, IdTokenClaims, InitiateAuthInput};
pub use claims::ClaimsService;
pub use discovery::{DiscoveredEndpoints, DiscoveryService};
pub use encryption::EncryptionService;
pub use hrd::{HrdResult, HrdService};
pub use idp_config::IdpConfigService;
pub use jwks_cache::{JwksCache, JwksCacheStats, DEFAULT_JWKS_CACHE_TTL};
pub use provisioning::ProvisioningService;
pub use token_issuer::{IssuedTokens, TokenIssuerConfig, TokenIssuerService};
pub use token_verifier::{TokenVerifierService, VerificationConfig, VerifiedToken};
pub use validation::ValidationService;
