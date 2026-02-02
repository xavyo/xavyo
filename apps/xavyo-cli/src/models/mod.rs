//! Data models for the xavyo CLI

pub mod agent;
pub mod authorize;
pub mod config;
mod credentials;
mod device_code;
pub mod doctor;
mod health;
pub mod platform;
mod provision;
pub mod release;
mod session;
mod signup;
pub mod token;
pub mod tool;
pub mod upgrade;

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
pub use token::TokenResponse;
#[allow(unused_imports)]
pub use tool::{CreateToolRequest, ToolListResponse, ToolResponse};
#[allow(unused_imports)]
pub use upgrade::{UpgradeCheckJson, UpgradeInfo, UpgradeResultJson};
