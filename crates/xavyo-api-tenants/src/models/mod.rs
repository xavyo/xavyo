//! Request and response models for tenant provisioning API.

pub mod api_keys;
pub mod delete;
pub mod oauth_clients;
pub mod plan;
pub mod provision;
pub mod settings;
pub mod suspend;
pub mod usage;

pub use api_keys::{ApiKeyInfo, ApiKeyListResponse, RotateApiKeyRequest, RotateApiKeyResponse};
pub use delete::{
    DeleteTenantRequest, DeleteTenantResponse, DeletedTenantInfo, DeletedTenantListResponse,
    RestoreTenantResponse,
};
pub use oauth_clients::{
    OAuthClientDetails, OAuthClientListResponse, RotateOAuthSecretRequest,
    RotateOAuthSecretResponse,
};
pub use provision::{
    AdminInfo, EndpointInfo, OAuthClientInfo, ProvisionContext, ProvisionTenantRequest,
    ProvisionTenantResponse, TenantInfo,
};
pub use settings::{GetSettingsResponse, UpdateSettingsRequest, UpdateSettingsResponse};
pub use suspend::{
    ReactivateTenantResponse, SuspendTenantRequest, SuspendTenantResponse, TenantStatusResponse,
};
pub use usage::{
    UsageHistoryQuery, UsageHistoryResponse, UsageLimits, UsageMetrics, UsagePeriod, UsageResponse,
};

// Plan Management exports (F-PLAN-MGMT)
pub use plan::{
    DowngradePlanRequest, PendingDowngradeInfo, PlanChangeEntry, PlanChangeResponse,
    PlanDefinitionResponse, PlanHistoryResponse, PlanLimitsResponse, PlansListResponse,
    UpgradePlanRequest,
};
