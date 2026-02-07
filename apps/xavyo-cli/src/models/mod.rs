//! Data models for the xavyo CLI

pub mod agent;
pub mod api_key;
pub mod api_session;
pub mod audit;
pub mod authorize;
pub mod config;
pub mod connector;
mod credentials;
mod device_code;
pub mod doctor;
pub mod governance;
pub mod group;
mod health;
pub mod operation;
pub mod platform;
pub mod policy;
mod provision;
pub mod release;
pub mod service_account;
mod session;
mod signup;
pub mod tenant;
pub mod token;
pub mod tool;
pub mod upgrade;
pub mod user;
pub mod webhook;

// Public re-exports for external consumers of the crate
#[allow(unused_imports)]
pub use agent::{AgentListResponse, AgentResponse, CreateAgentRequest};
#[allow(unused_imports)]
pub use authorize::{AuthorizationContext, AuthorizeRequest, AuthorizeResponse};
#[allow(unused_imports)]
pub use config::{
    AgentConfig, ApplyAction, ApplyChange, ApplyResult, ApplySummary, ToolConfig, XavyoConfig,
};
pub use credentials::Credentials;
pub use device_code::DeviceCodeResponse;
#[allow(unused_imports)]
pub use doctor::{DiagnosticCheck, DiagnosticReport, DiagnosticStatus};
pub use health::{HealthResponse, HealthStatus};
#[allow(unused_imports)]
pub use platform::{PackageManager, Platform};
pub use provision::{ProvisionRequest, ProvisionResponse};
#[allow(unused_imports)]
pub use release::{Asset, GitHubAsset, GitHubRelease, Release};
pub use session::Session;
pub use signup::SignupResponse;
#[allow(unused_imports)]
pub use tenant::{TenantCurrentOutput, TenantRole};
pub use token::TokenResponse;
#[allow(unused_imports)]
pub use tool::{CreateToolRequest, ToolListResponse, ToolResponse};
#[allow(unused_imports)]
pub use upgrade::{UpgradeCheckJson, UpgradeInfo, UpgradeResultJson};
