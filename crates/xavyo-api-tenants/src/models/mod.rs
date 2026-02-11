//! Request and response models for tenant provisioning API.

pub mod api_keys;
pub mod delete;
pub mod invitations;
pub mod oauth_clients;
pub mod plan;
pub mod provision;
pub mod settings;
pub mod suspend;
pub mod usage;

pub use api_keys::{
    ApiKeyInfo, ApiKeyListResponse, ApiKeyUsageDailyEntry, ApiKeyUsageHourlyEntry,
    ApiKeyUsageResponse, ApiKeyUsageSummary, CreateApiKeyRequest, CreateApiKeyResponse,
    GetApiKeyUsageQuery, IntrospectApiKeyResponse, RotateApiKeyRequest, RotateApiKeyResponse,
    ScopeDefinition, ScopeInfo, SCOPE_DEFINITIONS, VALID_SCOPE_ACTIONS, VALID_SCOPE_PREFIXES,
};
// F-055: Re-export helper function
pub use api_keys::get_scope_info;
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
    ProvisionTenantResponse, TenantInfo, TokenInfo,
};
pub use settings::{
    check_restricted_fields, GetSettingsResponse, TenantUserUpdateSettingsRequest,
    UpdateSettingsRequest, UpdateSettingsResponse, RESTRICTED_SETTINGS_FIELDS,
};
pub use suspend::{
    ReactivateTenantResponse, SuspendTenantRequest, SuspendTenantResponse, TenantStatusResponse,
};
pub use usage::{
    UsageHistoryQuery, UsageHistoryResponse, UsageLimits, UsageMetrics, UsagePeriod, UsageResponse,
};

// F-057: Tenant Invitations
pub use invitations::{
    AcceptInvitationRequest, AcceptInvitationResponse, CreateInvitationRequest,
    InvitationListResponse, InvitationResponse, ListInvitationsQuery,
};

// Plan Management exports (F-PLAN-MGMT)
pub use plan::{
    DowngradePlanRequest, PendingDowngradeInfo, PlanChangeEntry, PlanChangeResponse,
    PlanDefinitionResponse, PlanHistoryResponse, PlanLimitsResponse, PlansListResponse,
    UpgradePlanRequest,
};
